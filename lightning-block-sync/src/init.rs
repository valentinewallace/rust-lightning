use crate::{BlockSource, BlockSourceResult, Cache, ChainListener, ChainNotifier};
use crate::poll::{ChainPoller, Validate, ValidatedBlockHeader};

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::hash_types::BlockHash;
use bitcoin::network::constants::Network;

use lightning::chain;
use lightning::chain::chainmonitor::ChainMonitor;
use lightning::chain::chaininterface;
use lightning::chain::channelmonitor;
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::chain::keysinterface;
use lightning::ln::channelmanager::ChannelManager;
use lightning::util::logger;

use std::cell::RefCell;
use std::ops::Deref;

/// Performs a one-time sync of chain listeners using a single *trusted* block source, bringing each
/// listener's view of the chain from its paired block hash to `block_source`'s best chain tip.
///
/// Upon success, the returned header can be used to initialize [`SpvClient`]. In the case of
/// failure, each listener may be left at a different block hash than the one it was originally
/// paired with.
///
/// Useful during startup to bring the [`ChannelManager`] and each [`ChannelMonitor`] in sync before
/// switching to [`SpvClient`]. For example:
///
/// ```
/// use bitcoin::hash_types::BlockHash;
/// use bitcoin::network::constants::Network;
///
/// use lightning::chain;
/// use lightning::chain::Watch;
/// use lightning::chain::chainmonitor::ChainMonitor;
/// use lightning::chain::channelmonitor;
/// use lightning::chain::channelmonitor::ChannelMonitor;
/// use lightning::chain::chaininterface::BroadcasterInterface;
/// use lightning::chain::chaininterface::FeeEstimator;
/// use lightning::chain::keysinterface;
/// use lightning::chain::keysinterface::KeysInterface;
/// use lightning::ln::channelmanager::ChannelManager;
/// use lightning::ln::channelmanager::ChannelManagerReadArgs;
/// use lightning::util::config::UserConfig;
/// use lightning::util::logger::Logger;
/// use lightning::util::ser::ReadableArgs;
///
/// use lightning_block_sync::*;
///
/// use std::cell::RefCell;
/// use std::io::Cursor;
///
/// async fn init_sync<
/// 	B: BlockSource,
/// 	K: KeysInterface<Signer = S>,
/// 	S: keysinterface::Sign,
/// 	T: BroadcasterInterface,
/// 	F: FeeEstimator,
/// 	L: Logger,
/// 	C: chain::Filter,
/// 	P: channelmonitor::Persist<S>,
/// >(
/// 	block_source: &mut B,
/// 	chain_monitor: &ChainMonitor<S, &C, &T, &F, &L, &P>,
/// 	config: UserConfig,
/// 	keys_manager: &K,
/// 	tx_broadcaster: &T,
/// 	fee_estimator: &F,
/// 	logger: &L,
/// 	persister: &P,
/// ) {
/// 	let serialized_monitor = "...";
/// 	let (monitor_block_hash, mut monitor) = <(BlockHash, ChannelMonitor<S>)>::read(
/// 		&mut Cursor::new(&serialized_monitor), keys_manager).unwrap();
///
/// 	let serialized_manager = "...";
/// 	let (manager_block_hash, mut manager) = {
/// 		let read_args = ChannelManagerReadArgs::new(
/// 			keys_manager,
/// 			fee_estimator,
/// 			chain_monitor,
/// 			tx_broadcaster,
/// 			logger,
/// 			config,
/// 			vec![&mut monitor],
/// 		);
/// 		<(BlockHash, ChannelManager<S, &ChainMonitor<S, &C, &T, &F, &L, &P>, &T, &K, &F, &L>)>::read(
/// 			&mut Cursor::new(&serialized_manager), read_args).unwrap()
/// 	};
///
/// 	let mut cache = UnboundedCache::new();
/// 	let mut monitor_listener = (RefCell::new(monitor), tx_broadcaster, fee_estimator, logger);
/// 	let mut manager_listener = &manager;
/// 	let listeners = vec![
/// 		(monitor_block_hash, &mut monitor_listener as &mut dyn ChainListener),
/// 		(manager_block_hash, &mut manager_listener as &mut dyn ChainListener),
/// 	];
/// 	let chain_tip =
/// 		init::sync_listeners(block_source, Network::Bitcoin, &mut cache, listeners).await.unwrap();
///
/// 	let monitor = monitor_listener.0.into_inner();
/// 	chain_monitor.watch_channel(monitor.get_funding_txo().0, monitor);
///
/// 	let chain_poller = poll::ChainPoller::new(block_source, Network::Bitcoin);
/// 	let chain_listener = (&chain_monitor, &manager_listener);
/// 	let spv_client = SpvClient::new(chain_tip, chain_poller, &mut cache, chain_listener);
/// }
/// ```
///
/// [`SpvClient`]: ../struct.SpvClient.html
/// [`ChannelManager`]: ../../lightning/ln/channelmanager/struct.ChannelManager.html
/// [`ChannelMonitor`]: ../../lightning/chain/channelmonitor/struct.ChannelMonitor.html
pub async fn sync_listeners<B: BlockSource, C: Cache>(
	block_source: &mut B,
	network: Network,
	header_cache: &mut C,
	mut chain_listeners: Vec<(BlockHash, &mut dyn ChainListener)>,
) -> BlockSourceResult<ValidatedBlockHeader> {
	let (best_block_hash, best_block_height) = block_source.get_best_block().await?;
	let new_header = block_source
		.get_header(&best_block_hash, best_block_height).await?
		.validate(best_block_hash)?;

	// Fetch the header for the block hash paired with each listener.
	let mut chain_listeners_with_old_headers = Vec::new();
	for (old_block, chain_listener) in chain_listeners.drain(..) {
		let old_header = match header_cache.look_up(&old_block) {
			Some(header) => *header,
			None => block_source
				.get_header(&old_block, None).await?
				.validate(old_block)?
		};
		chain_listeners_with_old_headers.push((old_header, chain_listener))
	}

	// Find differences and disconnect blocks for each listener individually.
	let mut chain_poller = ChainPoller::new(block_source, network);
	let mut chain_listeners_at_height = Vec::new();
	let mut most_common_ancestor = None;
	let mut most_connected_blocks = Vec::new();
	for (old_header, chain_listener) in chain_listeners_with_old_headers.drain(..) {
		// Disconnect any stale blocks, but keep them in the cache for the next iteration.
		let header_cache = &mut ReadOnlyCache(header_cache);
		let mut chain_notifier = ChainNotifier { header_cache };
		let difference =
			chain_notifier.find_difference(new_header, &old_header, &mut chain_poller).await?;
		chain_notifier.disconnect_blocks(
			difference.disconnected_blocks,
			&mut DynamicChainListener(chain_listener),
		);

		// Keep track of the most common ancestor and all blocks connected across all listeners.
		chain_listeners_at_height.push((difference.common_ancestor.height, chain_listener));
		if difference.connected_blocks.len() > most_connected_blocks.len() {
			most_common_ancestor = Some(difference.common_ancestor);
			most_connected_blocks = difference.connected_blocks;
		}
	}

	// Connect new blocks for all listeners at once to avoid re-fetching blocks.
	if let Some(common_ancestor) = most_common_ancestor {
		let mut chain_notifier = ChainNotifier { header_cache };
		let mut chain_listener = ChainListenerSet(chain_listeners_at_height);
		chain_notifier.connect_blocks(
			common_ancestor,
			most_connected_blocks,
			&mut chain_poller,
			&mut chain_listener,
		).await.or_else(|(e, _)| Err(e))?;
	}

	Ok(new_header)
}

/// A wrapper to make a cache read-only.
///
/// Used to prevent losing headers that may be needed to disconnect blocks common to more than one
/// listener.
struct ReadOnlyCache<'a, C: Cache>(&'a mut C);

impl<'a, C: Cache> Cache for ReadOnlyCache<'a, C> {
	fn look_up(&self, block_hash: &BlockHash) -> Option<&ValidatedBlockHeader> {
		self.0.look_up(block_hash)
	}

	fn block_connected(&mut self, _block_hash: BlockHash, _block_header: ValidatedBlockHeader) {
		unreachable!()
	}

	fn block_disconnected(&mut self, _block_hash: &BlockHash) -> Option<ValidatedBlockHeader> {
		None
	}
}

/// Wrapper for supporting dynamically sized chain listeners.
struct DynamicChainListener<'a>(&'a mut dyn ChainListener);

impl<'a> ChainListener for DynamicChainListener<'a> {
	fn block_connected(&self, _block: &Block, _height: u32) {
		unreachable!()
	}

	fn block_disconnected(&self, header: &BlockHeader, height: u32) {
		self.0.block_disconnected(header, height)
	}
}

/// A set of dynamically sized chain listeners, each paired with a starting block height.
struct ChainListenerSet<'a>(Vec<(u32, &'a mut dyn ChainListener)>);

impl<'a> ChainListener for ChainListenerSet<'a> {
	fn block_connected(&self, block: &Block, height: u32) {
		for (starting_height, chain_listener) in self.0.iter() {
			if height > *starting_height {
				chain_listener.block_connected(block, height);
			}
		}
	}

	fn block_disconnected(&self, _header: &BlockHeader, _height: u32) {
		unreachable!()
	}
}

impl<S, B: Deref, F: Deref, L: Deref> ChainListener for (RefCell<ChannelMonitor<S>>, B, F, L)
where
	S: keysinterface::Sign,
	B::Target: chaininterface::BroadcasterInterface,
	F::Target: chaininterface::FeeEstimator,
	L::Target: logger::Logger,
{
	fn block_connected(&self, block: &Block, height: u32) {
		let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
		self.0.borrow_mut().block_connected(&block.header, &txdata, height, &*self.1, &*self.2, &*self.3);
	}

	fn block_disconnected(&self, header: &BlockHeader, height: u32) {
		self.0.borrow_mut().block_disconnected(header, height, &*self.1, &*self.2, &*self.3);
	}
}

impl<S, M: Deref, B: Deref, K: Deref, F: Deref, L: Deref> ChainListener for &ChannelManager<S, M, B, K, F, L>
where
	S: keysinterface::Sign,
	M::Target: chain::Watch<S>,
	B::Target: chaininterface::BroadcasterInterface,
	K::Target: keysinterface::KeysInterface<Signer = S>,
	F::Target: chaininterface::FeeEstimator,
	L::Target: logger::Logger,
{
	fn block_connected(&self, block: &Block, height: u32) {
		let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
		ChannelManager::block_connected(self, &block.header, &txdata, height);
	}

	fn block_disconnected(&self, header: &BlockHeader, _height: u32) {
		ChannelManager::block_disconnected(self, header);
	}
}

impl<S, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref> ChainListener for &ChainMonitor<S, C, T, F, L, P>
where
	S: keysinterface::Sign,
	C::Target: chain::Filter,
	T::Target: chaininterface::BroadcasterInterface,
	F::Target: chaininterface::FeeEstimator,
	L::Target: logger::Logger,
	P::Target: channelmonitor::Persist<S>,
{
	fn block_connected(&self, block: &Block, height: u32) {
		let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
		ChainMonitor::block_connected(self, &block.header, &txdata, height);
	}

	fn block_disconnected(&self, header: &BlockHeader, height: u32) {
		ChainMonitor::block_disconnected(self, header, height);
	}
}

impl<T: ChainListener, U: ChainListener> ChainListener for (&T, &U) {
	fn block_connected(&self, block: &Block, height: u32) {
		self.0.block_connected(block, height);
		self.1.block_connected(block, height);
	}

	fn block_disconnected(&self, header: &BlockHeader, height: u32) {
		self.0.block_disconnected(header, height);
		self.1.block_disconnected(header, height);
	}
}

#[cfg(test)]
mod tests {
	use crate::test_utils::{Blockchain, MockChainListener};
	use super::*;

	use bitcoin::network::constants::Network;

	#[tokio::test]
	async fn sync_from_same_chain() {
		let mut chain = Blockchain::default().with_height(4);

		let mut listener_1 = MockChainListener::new()
			.expect_block_connected(*chain.at_height(2))
			.expect_block_connected(*chain.at_height(3))
			.expect_block_connected(*chain.at_height(4));
		let mut listener_2 = MockChainListener::new()
			.expect_block_connected(*chain.at_height(3))
			.expect_block_connected(*chain.at_height(4));
		let mut listener_3 = MockChainListener::new()
			.expect_block_connected(*chain.at_height(4));

		let listeners = vec![
			(chain.at_height(1).block_hash, &mut listener_1 as &mut dyn ChainListener),
			(chain.at_height(2).block_hash, &mut listener_2 as &mut dyn ChainListener),
			(chain.at_height(3).block_hash, &mut listener_3 as &mut dyn ChainListener),
		];
		let mut cache = chain.header_cache(0..=4);
		match sync_listeners(&mut chain, Network::Bitcoin, &mut cache, listeners).await {
			Ok(header) => assert_eq!(header, chain.tip()),
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[tokio::test]
	async fn sync_from_different_chains() {
		let mut main_chain = Blockchain::default().with_height(4);
		let fork_chain_1 = main_chain.fork_at_height(1);
		let fork_chain_2 = main_chain.fork_at_height(2);
		let fork_chain_3 = main_chain.fork_at_height(3);

		let mut listener_1 = MockChainListener::new()
			.expect_block_disconnected(*fork_chain_1.at_height(4))
			.expect_block_disconnected(*fork_chain_1.at_height(3))
			.expect_block_disconnected(*fork_chain_1.at_height(2))
			.expect_block_connected(*main_chain.at_height(2))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));
		let mut listener_2 = MockChainListener::new()
			.expect_block_disconnected(*fork_chain_2.at_height(4))
			.expect_block_disconnected(*fork_chain_2.at_height(3))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));
		let mut listener_3 = MockChainListener::new()
			.expect_block_disconnected(*fork_chain_3.at_height(4))
			.expect_block_connected(*main_chain.at_height(4));

		let listeners = vec![
			(fork_chain_1.tip().block_hash, &mut listener_1 as &mut dyn ChainListener),
			(fork_chain_2.tip().block_hash, &mut listener_2 as &mut dyn ChainListener),
			(fork_chain_3.tip().block_hash, &mut listener_3 as &mut dyn ChainListener),
		];
		let mut cache = fork_chain_1.header_cache(2..=4);
		cache.extend(fork_chain_2.header_cache(3..=4));
		cache.extend(fork_chain_3.header_cache(4..=4));
		match sync_listeners(&mut main_chain, Network::Bitcoin, &mut cache, listeners).await {
			Ok(header) => assert_eq!(header, main_chain.tip()),
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[tokio::test]
	async fn sync_from_overlapping_chains() {
		let mut main_chain = Blockchain::default().with_height(4);
		let fork_chain_1 = main_chain.fork_at_height(1);
		let fork_chain_2 = fork_chain_1.fork_at_height(2);
		let fork_chain_3 = fork_chain_2.fork_at_height(3);

		let mut listener_1 = MockChainListener::new()
			.expect_block_disconnected(*fork_chain_1.at_height(4))
			.expect_block_disconnected(*fork_chain_1.at_height(3))
			.expect_block_disconnected(*fork_chain_1.at_height(2))
			.expect_block_connected(*main_chain.at_height(2))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));
		let mut listener_2 = MockChainListener::new()
			.expect_block_disconnected(*fork_chain_2.at_height(4))
			.expect_block_disconnected(*fork_chain_2.at_height(3))
			.expect_block_disconnected(*fork_chain_2.at_height(2))
			.expect_block_connected(*main_chain.at_height(2))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));
		let mut listener_3 = MockChainListener::new()
			.expect_block_disconnected(*fork_chain_3.at_height(4))
			.expect_block_disconnected(*fork_chain_3.at_height(3))
			.expect_block_disconnected(*fork_chain_3.at_height(2))
			.expect_block_connected(*main_chain.at_height(2))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));

		let listeners = vec![
			(fork_chain_1.tip().block_hash, &mut listener_1 as &mut dyn ChainListener),
			(fork_chain_2.tip().block_hash, &mut listener_2 as &mut dyn ChainListener),
			(fork_chain_3.tip().block_hash, &mut listener_3 as &mut dyn ChainListener),
		];
		let mut cache = fork_chain_1.header_cache(2..=4);
		cache.extend(fork_chain_2.header_cache(3..=4));
		cache.extend(fork_chain_3.header_cache(4..=4));
		match sync_listeners(&mut main_chain, Network::Bitcoin, &mut cache, listeners).await {
			Ok(header) => assert_eq!(header, main_chain.tip()),
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[tokio::test]
	async fn cache_connected_and_keep_disconnected_blocks() {
		let mut main_chain = Blockchain::default().with_height(2);
		let fork_chain = main_chain.fork_at_height(1);
		let new_tip = main_chain.tip();
		let old_tip = fork_chain.tip();

		let mut listener = MockChainListener::new()
			.expect_block_disconnected(*old_tip)
			.expect_block_connected(*new_tip);

		let listeners = vec![(old_tip.block_hash, &mut listener as &mut dyn ChainListener)];
		let mut cache = fork_chain.header_cache(2..=2);
		match sync_listeners(&mut main_chain, Network::Bitcoin, &mut cache, listeners).await {
			Ok(_) => {
				assert!(cache.contains_key(&new_tip.block_hash));
				assert!(cache.contains_key(&old_tip.block_hash));
			},
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}
}
