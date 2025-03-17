// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Provides data structures and functions for creating and managing Offers messages,
//! facilitating communication, and handling Bolt12 messages and payments.

use core::ops::Deref;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use bitcoin::block::Header;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

#[allow(unused_imports)]
use crate::prelude::*;

use crate::chain::BestBlock;
use crate::ln::inbound_payment;
use crate::onion_message::async_payments::AsyncPaymentsMessage;
use crate::onion_message::messenger::{MessageRouter, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::routing::router::Router;
use crate::sign::EntropySource;
use crate::sync::{Mutex, RwLock};

#[cfg(feature = "dnssec")]
use crate::onion_message::dns_resolution::DNSResolverMessage;

/// A Bolt12 Offers code and flow utility provider, which facilitates utilities for
/// Bolt12 builder generation, and Onion message handling.
///
/// [`OffersMessageFlow`] is parameterized by a number of components to achieve this.
///
/// - [`EntropySource`] for providing random data needed for cryptographic operations
/// - [`MessageRouter`] for finding message paths when initiating and retrying onion messages
/// - [`Router`] for finding payment paths when initiating Botl12 payments.
pub struct OffersMessageFlow<ES: Deref, MR: Deref, R: Deref>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
	R::Target: Router,
{
	chain_hash: ChainHash,
	best_block: RwLock<BestBlock>,

	our_network_pubkey: PublicKey,
	highest_seen_timestamp: AtomicUsize,
	inbound_payment_key: inbound_payment::ExpandedKey,

	secp_ctx: Secp256k1<secp256k1::All>,
	entropy_source: ES,

	message_router: MR,
	router: R,

	#[cfg(not(any(test, feature = "_test_utils")))]
	pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,

	pending_async_payments_messages: Mutex<Vec<(AsyncPaymentsMessage, MessageSendInstructions)>>,

	#[cfg(feature = "dnssec")]
	pending_dns_onion_messages: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,
}

impl<ES: Deref, MR: Deref, R: Deref> OffersMessageFlow<ES, MR, R>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
	R::Target: Router,
{
	/// Creates a new [`OffersMessageFlow`]
	pub fn new(
		chain_hash: ChainHash, best_block: BestBlock, our_network_pubkey: PublicKey,
		current_timestamp: u32, inbound_payment_key: inbound_payment::ExpandedKey,
		entropy_source: ES, message_router: MR, router: R,
	) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		Self {
			chain_hash,
			best_block: RwLock::new(best_block),

			our_network_pubkey,
			highest_seen_timestamp: AtomicUsize::new(current_timestamp as usize),
			inbound_payment_key,

			secp_ctx,
			entropy_source,

			message_router,
			router,

			pending_offers_messages: Mutex::new(Vec::new()),
			pending_async_payments_messages: Mutex::new(Vec::new()),
			#[cfg(feature = "dnssec")]
			pending_dns_onion_messages: Mutex::new(Vec::new()),
		}
	}

	/// Gets the node_id held by this [`OffersMessageFlow`]`
	pub fn get_our_node_id(&self) -> PublicKey {
		self.our_network_pubkey
	}

	fn duration_since_epoch(&self) -> Duration {
		#[cfg(not(feature = "std"))]
		let now = Duration::from_secs(self.highest_seen_timestamp.load(Ordering::Acquire) as u64);
		#[cfg(feature = "std")]
		let now = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
		now
	}

	fn best_block_updated(&self, header: &Header) {
		macro_rules! max_time {
			($timestamp: expr) => {
				loop {
					// Update $timestamp to be the max of its current value and the block
					// timestamp. This should keep us close to the current time without relying on
					// having an explicit local time source.
					// Just in case we end up in a race, we loop until we either successfully
					// update $timestamp or decide we don't need to.
					let old_serial = $timestamp.load(Ordering::Acquire);
					if old_serial >= header.time as usize {
						break;
					}
					if $timestamp
						.compare_exchange(
							old_serial,
							header.time as usize,
							Ordering::AcqRel,
							Ordering::Relaxed,
						)
						.is_ok()
					{
						break;
					}
				}
			};
		}

		max_time!(self.highest_seen_timestamp);
	}
}
