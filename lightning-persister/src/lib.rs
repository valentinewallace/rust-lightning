extern crate lightning;
extern crate bitcoin;
extern crate libc;

use bitcoin::hashes::hex::ToHex;
use lightning::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateErr};
use lightning::chain::channelmonitor;
use lightning::chain::keysinterface::ChannelKeys;
use lightning::chain::transaction::OutPoint;
use lightning::util::ser::{Writeable, Readable};
use std::fs;
use std::io::Error;
use std::path::Path;

#[cfg(test)]
use {
	bitcoin::{BlockHash, Txid},
	bitcoin::hashes::hex::FromHex,
	std::collections::HashMap,
	std::io::Cursor
};

#[cfg(not(target_os = "windows"))]
use std::os::unix::io::AsRawFd;

/// FilesystemPersister persists channel data on disk, where each channel's
/// data is stored in a file named after its funding outpoint.
///
/// Warning: this module does the best it can with calls to persist data, but it
/// can only guarantee that the data is passed to the drive. It is up to the
/// drive manufacturers to do the actual persistence properly, which they often
/// don't (especially on consumer-grade hardware). Therefore, it is up to the
/// user to validate their entire storage stack, to ensure the writes are
/// persistent.
/// Corollary: especially when dealing with larger amounts of money, it is best
/// practice to have multiple channel data backups and not rely only on one
/// FilesystemPersister.
pub struct FilesystemPersister {
	path_to_channel_data: String,
}

trait DiskWriteable {
	fn write(&self, writer: &mut fs::File) -> Result<(), Error>;
}

impl<ChanSigner: ChannelKeys + Writeable> DiskWriteable for ChannelMonitor<ChanSigner> {
	fn write(&self, writer: &mut fs::File) -> Result<(), Error> {
		self.write_for_disk(writer)
	}
}

impl FilesystemPersister {
	/// Initialize a new FilesystemPersister and set the path to the individual channels'
	/// files.
	pub fn new(path_to_channel_data: String) -> Self {
		return Self {
			path_to_channel_data,
		}
	}

	fn get_full_filepath(&self, funding_txo: OutPoint) -> String {
		let path = Path::new(&self.path_to_channel_data);
		let mut path_buf = path.to_path_buf();
		path_buf.push(format!("{}_{}", funding_txo.txid.to_hex(), funding_txo.index));
		path_buf.to_str().unwrap().to_string()
	}

	// Utility to write a file to disk.
	fn write_channel_data(&self, funding_txo: OutPoint, monitor: &dyn DiskWriteable) -> std::io::Result<()> {
		fs::create_dir_all(&self.path_to_channel_data)?;
		// Do a crazy dance with lots of fsync()s to be overly cautious here...
		// We never want to end up in a state where we've lost the old data, or end up using the
		// old data on power loss after we've returned.
		// The way to atomically write a file on Unix platforms is:
		// open(tmpname), write(tmpfile), fsync(tmpfile), close(tmpfile), rename(), fsync(dir)
		let filename = self.get_full_filepath(funding_txo);
		let tmp_filename = filename.clone() + ".tmp";

		{
			// Note that going by rust-lang/rust@d602a6b, on MacOS it is only safe to use
			// rust stdlib 1.36 or higher.
			let mut f = fs::File::create(&tmp_filename)?;
			monitor.write(&mut f)?;
			f.sync_all()?;
		}
		fs::rename(&tmp_filename, &filename)?;
		// Fsync the parent directory on Unix.
		#[cfg(not(target_os = "windows"))]
		{
			let path_str = filename.clone();
			let path = Path::new(&path_str).parent().unwrap();
			let dir_file = fs::OpenOptions::new().read(true).open(path)?;
			unsafe { libc::fsync(dir_file.as_raw_fd()); }
		}
		Ok(())
	}

	#[cfg(test)]
	fn load_channel_data<ChanSigner: ChannelKeys + Readable + Writeable>(&self) ->
		Result<HashMap<OutPoint, ChannelMonitor<ChanSigner>>, ChannelMonitorUpdateErr> {
		if let Err(_) = fs::create_dir_all(&self.path_to_channel_data) {
			return Err(ChannelMonitorUpdateErr::PermanentFailure);
		}
		let mut res = HashMap::new();
		for file_option in fs::read_dir(&self.path_to_channel_data).unwrap() {
			let file = file_option.unwrap();
			let file_name = file.file_name();
			let filename = file_name.to_str();
			if !filename.is_some() || !filename.unwrap().is_ascii() || filename.unwrap().len() < 65 {
				return Err(ChannelMonitorUpdateErr::PermanentFailure);
			}

			let txid = Txid::from_hex(filename.unwrap().split_at(64).0);
			if txid.is_err() { return Err(ChannelMonitorUpdateErr::PermanentFailure); }

			let index = filename.unwrap().split_at(65).1.split('.').next().unwrap().parse();
			if index.is_err() { return Err(ChannelMonitorUpdateErr::PermanentFailure); }

			let contents = fs::read(&file.path());
			if contents.is_err() { return Err(ChannelMonitorUpdateErr::PermanentFailure); }

			if let Ok((_, loaded_monitor)) =
				<(BlockHash, ChannelMonitor<ChanSigner>)>::read(&mut Cursor::new(&contents.unwrap())) {
				res.insert(OutPoint { txid: txid.unwrap(), index: index.unwrap() }, loaded_monitor);
			} else {
				return Err(ChannelMonitorUpdateErr::PermanentFailure);
			}
		}
		Ok(res)
	}
}

impl<ChanSigner: ChannelKeys + Readable + Writeable + Send + Sync> channelmonitor::Persist<ChanSigner> for FilesystemPersister {
	fn persist_new_channel(&self, funding_txo: OutPoint, monitor: &ChannelMonitor<ChanSigner>) -> Result<(), ChannelMonitorUpdateErr> {
		self.write_channel_data(funding_txo, monitor)
		  .map_err(|_| ChannelMonitorUpdateErr::PermanentFailure)
	}

	fn update_persisted_channel(&self, funding_txo: OutPoint, _update: &ChannelMonitorUpdate, monitor: &ChannelMonitor<ChanSigner>) -> Result<(), ChannelMonitorUpdateErr> {
		self.write_channel_data(funding_txo, monitor)
		  .map_err(|_| ChannelMonitorUpdateErr::PermanentFailure)
	}
}

#[cfg(test)]
mod tests {
	extern crate lightning;
	extern crate bitcoin;
	use crate::FilesystemPersister;
	use bitcoin::blockdata::block::{Block, BlockHeader};
	use DiskWriteable;
	use Error;
	use lightning::{check_closed_broadcast, check_added_monitors};
	use lightning::ln::features::InitFeatures;
	use lightning::ln::functional_test_utils::*;
	use lightning::ln::msgs::ErrorAction;
	use lightning::util::enforcing_trait_impls::EnforcingChannelKeys;
	use lightning::util::events::{MessageSendEventsProvider, MessageSendEvent};
	use lightning::util::ser::Writer;
	use lightning::util::test_utils;
	use std::fs;
	#[cfg(not(target_os = "windows"))]
	use {
		bitcoin::hashes::hex::FromHex,
		bitcoin::hashes::sha256::Hash as Sha256,
		bitcoin::hashes::Hash,
		bitcoin::Txid,
		lightning::{unwrap_send_err, get_payment_preimage_hash},
		lightning::chain::transaction::OutPoint,
		lightning::ln::channelmanager::{PaymentSendFailure, PaymentPreimage, PaymentHash},
		lightning::routing::router::get_route,
		lightning::util::errors::APIError,
		std::io,
	};
	#[cfg(target_os = "windows")]
	use {
		lightning::get_event_msg,
		lightning::ln::msgs::ChannelMessageHandler,
		lightning::util::events::EventsProvider,
	};

	struct TestWriteable{}
	impl DiskWriteable for TestWriteable{
		fn write(&self, writer: &mut fs::File) -> Result<(), Error> {
			writer.write_all(&[42; 1])
		}
	}

	#[test]
	fn test_filesystem_persister() {
		// Create the nodes, giving them FilesystemPersisters for data persisters.
		let persister_0 = FilesystemPersister::new("persister0".to_string());
		let persister_1 = FilesystemPersister::new("persister1".to_string());
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let chain_mon_0 = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[0].chain_source), &chanmon_cfgs[0].tx_broadcaster, &chanmon_cfgs[0].logger, &chanmon_cfgs[0].fee_estimator, &persister_0);
		let chain_mon_1 = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[1].chain_source), &chanmon_cfgs[1].tx_broadcaster, &chanmon_cfgs[1].logger, &chanmon_cfgs[1].fee_estimator, &persister_1);
		node_cfgs[0].chain_monitor = chain_mon_0;
		node_cfgs[1].chain_monitor = chain_mon_1;
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		// Check that the persisted channel data is empty before any channels are
		// open.
		let mut persisted_chan_data_0 = persister_0.load_channel_data::<EnforcingChannelKeys>().unwrap();
		assert_eq!(persisted_chan_data_0.keys().len(), 0);
		let mut persisted_chan_data_1 = persister_1.load_channel_data::<EnforcingChannelKeys>().unwrap();
		assert_eq!(persisted_chan_data_1.keys().len(), 0);

		// Helper to make sure the channel is on the expected update ID.
		macro_rules! check_persisted_data {
			($expected_update_id: expr) => {
				persisted_chan_data_0 = persister_0.load_channel_data::<EnforcingChannelKeys>().unwrap();
				assert_eq!(persisted_chan_data_0.keys().len(), 1);
				for mon in persisted_chan_data_0.values() {
					assert_eq!(mon.get_latest_update_id(), $expected_update_id);
				}
				persisted_chan_data_1 = persister_1.load_channel_data::<EnforcingChannelKeys>().unwrap();
				assert_eq!(persisted_chan_data_1.keys().len(), 1);
				for mon in persisted_chan_data_1.values() {
					assert_eq!(mon.get_latest_update_id(), $expected_update_id);
				}
			}
		}

		// Create some initial channel and check that a channel was persisted.
		let _ = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
		check_persisted_data!(0);

		// Send a few payments and make sure the monitors are updated to the latest.
		send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000, 8_000_000);
		check_persisted_data!(5);
		send_payment(&nodes[1], &vec!(&nodes[0])[..], 4000000, 4_000_000);
		check_persisted_data!(10);

		// Close the channel and make sure everything is persisted as expected.
		// Force close because cooperative close doesn't result in any persisted
		// updates.
		nodes[0].node.force_close_channel(&nodes[0].node.list_channels()[0].channel_id);
		check_closed_broadcast!(nodes[0], false);
		check_added_monitors!(nodes[0], 1);

		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);

		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		connect_block(&nodes[1], &Block { header, txdata: vec![node_txn[0].clone(), node_txn[0].clone()]}, 1);
		check_closed_broadcast!(nodes[1], false);
		check_added_monitors!(nodes[1], 1);
		check_persisted_data!(11);

		fs::remove_dir_all("persister0").unwrap();
		fs::remove_dir_all("persister1").unwrap();
	}

	// Windows ignores the read-only flag for folders.
	#[cfg(not(target_os = "windows"))]
	#[test]
	fn test_readonly_dir() {
		let persister = FilesystemPersister::new("persister".to_string());
		let test_writeable = TestWriteable{};
		let test_txo = OutPoint {
			txid: Txid::from_hex("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be").unwrap(),
			index: 0
		};
		// Create the persister's directory and set it to read-only.
		let path = &persister.path_to_channel_data;
		fs::create_dir_all(path).unwrap();
		let mut perms = fs::metadata(path).unwrap().permissions();
		perms.set_readonly(true);
		fs::set_permissions(path, perms).unwrap();
		match persister.write_channel_data(test_txo, &test_writeable) {
			Err(e) => {
				assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
			}
			_ => panic!("Unexpected error message")
		}
		fs::remove_dir_all("persister").unwrap();
	}

	// Windows ignores the read-only flag for folders.
	#[cfg(not(target_os = "windows"))]
	#[test]
	fn test_perm_failure_force_close() {
		// Create the nodes, giving them FilesystemPersisters for data persisters.
		// The persisters need different directory names to not conflict with the
		// other FilesystemPersister tests, hence suffixing them with 2 and 3
		// instead of 0 and 1.
		let persister_0 = FilesystemPersister::new("persister2".to_string());
		let persister_1 = FilesystemPersister::new("persister3".to_string());
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let chain_mon_0 = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[0].chain_source), &chanmon_cfgs[0].tx_broadcaster, &chanmon_cfgs[0].logger, &chanmon_cfgs[0].fee_estimator, &persister_0);
		let chain_mon_1 = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[1].chain_source), &chanmon_cfgs[1].tx_broadcaster, &chanmon_cfgs[1].logger, &chanmon_cfgs[1].fee_estimator, &persister_1);
		node_cfgs[0].chain_monitor = chain_mon_0;
		node_cfgs[1].chain_monitor = chain_mon_1;
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

		// Set the persister's directory to read-only, which should result in
		// returning a permanent failure on the next attempted update.
		let path = &persister_0.path_to_channel_data;
		let mut perms = fs::metadata(path).unwrap().permissions();
		perms.set_readonly(true);
		fs::set_permissions(path, perms).unwrap();

		// Attempt an update, then check that the channel is force closed in
		// response to the permanent failure.
		let logger = test_utils::TestLogger::new();
		let (_, payment_hash) = get_payment_preimage_hash!(&nodes[0]);
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		unwrap_send_err!(nodes[0].node.send_payment(&route, payment_hash, &None), true, APIError::ChannelUnavailable {..}, {});
		check_added_monitors!(nodes[0], 2);
		let events_1 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 2);
		match events_1[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		};
		match events_1[1] {
			MessageSendEvent::HandleError { node_id, .. } => assert_eq!(node_id, nodes[1].node.get_our_node_id()),
			_ => panic!("Unexpected event"),
		};
		assert_eq!(nodes[0].node.list_channels().len(), 0);

		let mut perms = fs::metadata(path).unwrap().permissions();
		perms.set_readonly(false);
		fs::set_permissions(path, perms).unwrap();
		fs::remove_dir_all("persister2").unwrap();
		fs::remove_dir_all("persister3").unwrap();
	}

	#[cfg(target_os = "windows")]
	#[test]
	fn test_fail_on_open() {
		// Create the nodes, giving them FilesystemPersisters for data persisters.
		// But, give them invalid directory names and test that the channel fails
		// to open because the directories fail to be created. There don't seem to
		// be invalid filename characters on Unix that Rust doesn't handle, hence
		// why the test is Windows-only.
		let persister_0 = FilesystemPersister::new(":<>/".to_string());
		let persister_1 = FilesystemPersister::new(":<>>/".to_string());
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let chain_mon_0 = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[0].chain_source), &chanmon_cfgs[0].tx_broadcaster, &chanmon_cfgs[0].logger, &chanmon_cfgs[0].fee_estimator, &persister_0);
		let chain_mon_1 = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[1].chain_source), &chanmon_cfgs[1].tx_broadcaster, &chanmon_cfgs[1].logger, &chanmon_cfgs[1].fee_estimator, &persister_1);
		node_cfgs[0].chain_monitor = chain_mon_0;
		node_cfgs[1].chain_monitor = chain_mon_1;
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		// Manually exchange the messages and check that no monitor is added.
		let channel_value = 800_000;
		nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value, 0, 42, None).unwrap();
		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id()));
		nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), InitFeatures::known(), &get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id()));

		let (temporary_channel_id, _, funding_output) = create_funding_transaction(&nodes[0], channel_value, 42);

		nodes[0].node.funding_transaction_generated(&temporary_channel_id, funding_output);
		check_added_monitors!(nodes[0], 0);

		nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id()));
		check_added_monitors!(nodes[0], 0);
		nodes[1].logger.assert_log_contains("lightning::chain::chainmonitor".to_string(), "Failed to persist new channel data".to_string(), 1);
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
	}
}
