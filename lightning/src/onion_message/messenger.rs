// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! LDK sends, receives, and forwards onion messages via the [`OnionMessenger`]. See its docs for
//! more information.

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
use bitcoin::secp256k1::ecdh::SharedSecret;

use chain::keysinterface::{InMemorySigner, KeysInterface, KeysManager, Recipient, Sign};
use ln::msgs::{self, OnionMessageHandler};
use ln::onion_utils;
use super::blinded_route::{BlindedRoute, ForwardTlvs, ReceiveTlvs};
use super::packet::{ForwardControlTlvs, Packet, Payload, ReceiveControlTlvs};
use super::utils;
use util::events::{MessageSendEvent, MessageSendEventsProvider};
use util::logger::Logger;

use core::mem;
use core::ops::Deref;
use sync::{Arc, Mutex};
use prelude::*;

/// A sender, receiver and forwarder of onion messages. In upcoming releases, this object will be
/// used to retrieve invoices and fulfill invoice requests from [offers]. Currently, only sending
/// and receiving empty onion messages is supported.
///
/// To set up the [`OnionMessenger`], provide it to the [`PeerManager`] via
/// [`MessageHandler::onion_message_handler`], or directly if you're initializing the `PeerManager`
/// via [`PeerManager::new_channel_only`].
///
/// # Example
///
/// ```
/// # extern crate bitcoin;
/// # use bitcoin::hashes::_export::_core::time::Duration;
/// # use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
/// # use lightning::chain::keysinterface::{KeysManager, KeysInterface};
/// # use lightning::onion_message::{BlindedRoute, Destination, OnionMessenger};
/// # use lightning::util::logger::{Logger, Record};
/// # use std::sync::Arc;
/// # struct FakeLogger {};
/// # impl Logger for FakeLogger {
/// #     fn log(&self, record: &Record) { unimplemented!() }
/// # }
/// # let seed = [42u8; 32];
/// # let time = Duration::from_secs(123456);
/// # let keys_manager = KeysManager::new(&seed, time.as_secs(), time.subsec_nanos());
/// # let logger = Arc::new(FakeLogger {});
/// # let node_secret = SecretKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
/// # let secp_ctx = Secp256k1::new();
/// # let hop_node_id1 = PublicKey::from_secret_key(&secp_ctx, &node_secret);
/// # let hop_node_id2 = hop_node_id1.clone();
/// # let destination_node_id = hop_node_id1.clone();
/// #
/// // Create the onion messenger. This must use the same `keys_manager` as is passed to your
/// // ChannelManager.
/// let onion_messenger = OnionMessenger::new(&keys_manager, logger);
///
/// // Send an empty onion message to a node id.
/// let intermediate_hops = vec![hop_node_id1, hop_node_id2];
/// onion_messenger.send_onion_message(intermediate_hops, Destination::Node(destination_node_id));
///
/// // Create a blinded route to yourself, for someone to send an onion message to.
/// # let your_node_id = hop_node_id1.clone();
/// let hops = vec![hop_node_id1, hop_node_id2, your_node_id];
/// let blinded_route = BlindedRoute::new(hops, &&keys_manager, &secp_ctx).unwrap();
///
/// // Send an empty onion message to a blinded route.
/// # let intermediate_hops = vec![hop_node_id1, hop_node_id2];
/// onion_messenger.send_onion_message(intermediate_hops, Destination::BlindedRoute(blinded_route));
/// ```
///
/// [offers]: <https://github.com/lightning/bolts/pull/798>
/// [`OnionMessenger`]: crate::onion_message::OnionMessenger
/// [`PeerManager`]: crate::ln::peer_handler::PeerManager
/// [`MessageHandler::onion_message_handler`]: crate::ln::peer_handler::MessageHandler::onion_message_handler
/// [`PeerManager::new_channel_only`]: crate::ln::peer_handler::PeerManager::new_channel_only
pub struct OnionMessenger<Signer: Sign, K: Deref, L: Deref>
	where K::Target: KeysInterface<Signer = Signer>,
	      L::Target: Logger,
{
	keys_manager: K,
	logger: L,
	pending_msg_events: Mutex<Vec<MessageSendEvent>>,
	secp_ctx: Secp256k1<secp256k1::All>,
	// Coming soon:
	// invoice_handler: InvoiceHandler,
	// custom_handler: CustomHandler, // handles custom onion messages
}

/// The destination of an onion message.
pub enum Destination {
	/// We're sending this onion message to a node.
	Node(PublicKey),
	/// We're sending this onion message to a blinded route.
	BlindedRoute(BlindedRoute),
}

impl Destination {
	pub(super) fn num_hops(&self) -> usize {
		match self {
			Destination::Node(_) => 1,
			Destination::BlindedRoute(BlindedRoute { blinded_hops, .. }) => blinded_hops.len(),
		}
	}
}

/// Errors that may occur when [sending an onion message].
///
/// [sending an onion message]: OnionMessenger::send_onion_message
#[derive(Debug, PartialEq)]
pub enum SendError {
	/// Errored computing onion message packet keys.
	Secp256k1(secp256k1::Error),
	/// Because implementations such as Eclair will drop onion messages where the message packet
	/// exceeds 32834 bytes, we refuse to send messages where the packet exceeds this size.
	TooBigPacket,
	/// The provided [destination] was an invalid [blinded route], due to having 0 blinded hops.
	///
	/// [destination]: Destination
	/// [blinded route]: super::blinded_route::BlindedRoute
	MissingBlindedHops,
}

impl<Signer: Sign, K: Deref, L: Deref> OnionMessenger<Signer, K, L>
	where K::Target: KeysInterface<Signer = Signer>,
	      L::Target: Logger,
{
	/// Constructs a new `OnionMessenger` to send, forward, and delegate received onion messages to
	/// their respective handlers.
	pub fn new(keys_manager: K, logger: L) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&keys_manager.get_secure_random_bytes());
		OnionMessenger {
			keys_manager,
			pending_msg_events: Mutex::new(Vec::new()),
			secp_ctx,
			logger,
		}
	}

	/// Send an empty onion message to `destination`, routing it through `intermediate_nodes`.
	pub fn send_onion_message(&self, intermediate_nodes: Vec<PublicKey>, destination: Destination) -> Result<(), SendError> {
		if let Destination::BlindedRoute(BlindedRoute { ref blinded_hops, .. }) = destination {
			if blinded_hops.len() == 0 {
				return Err(SendError::MissingBlindedHops);
			}
		}
		let blinding_secret_bytes = self.keys_manager.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
		let (introduction_node_id, blinding_point) = if intermediate_nodes.len() != 0 {
			(intermediate_nodes[0].clone(), PublicKey::from_secret_key(&self.secp_ctx, &blinding_secret))
		} else {
			match destination {
				Destination::Node(pk) => (pk.clone(), PublicKey::from_secret_key(&self.secp_ctx, &blinding_secret)),
				Destination::BlindedRoute(BlindedRoute { introduction_node_id, blinding_point, .. }) =>
					(introduction_node_id.clone(), blinding_point.clone()),
			}
		};
		let (control_tlvs_keys, onion_packet_keys) = utils::construct_sending_keys(
			&self.secp_ctx, &intermediate_nodes, &destination, &blinding_secret)
			.map_err(|e| SendError::Secp256k1(e))?;
		let payloads = utils::build_payloads(intermediate_nodes, destination, control_tlvs_keys);

		let prng_seed = self.keys_manager.get_secure_random_bytes();
		let onion_packet = onion_utils::construct_onion_message_packet(
			payloads, onion_packet_keys, prng_seed).map_err(|()| SendError::TooBigPacket)?;

		let mut pending_msg_events = self.pending_msg_events.lock().unwrap();
		pending_msg_events.push(MessageSendEvent::SendOnionMessage {
			node_id: introduction_node_id,
			msg: msgs::OnionMessage {
				blinding_point,
				len: onion_packet.len(),
				onion_routing_packet: onion_packet,
			}
		});
		Ok(())
	}
}

impl<Signer: Sign, K: Deref, L: Deref> OnionMessageHandler for OnionMessenger<Signer, K, L>
	where K::Target: KeysInterface<Signer = Signer>,
	      L::Target: Logger,
{
	/// Handle an incoming onion message. Currently, if a message was destined for us we will log, but
	/// soon we'll delegate the onion message to a handler that can generate invoices or send
	/// payments.
	fn handle_onion_message(&self, _peer_node_id: &PublicKey, msg: &msgs::OnionMessage) {
		let node_secret = match self.keys_manager.get_node_secret(Recipient::Node) {
			Ok(secret) => secret,
			Err(e) => {
				log_trace!(self.logger, "Failed to retrieve node secret: {:?}", e);
				return
			}
		};
		let control_tlvs_ss = SharedSecret::new(&msg.blinding_point, &node_secret);
		let onion_decode_shared_secret = {
			let blinding_factor = {
				let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
				hmac.input(control_tlvs_ss.as_ref());
				Hmac::from_engine(hmac).into_inner()
			};
			let mut blinded_priv = node_secret.clone();
			if let Err(e) = blinded_priv.mul_assign(&blinding_factor) {
				log_trace!(self.logger, "Failed to compute blinded public key: {}", e);
				return
			}
			SharedSecret::new(&msg.onion_routing_packet.public_key, &blinded_priv).secret_bytes()
		};
		match onion_utils::decode_next_message_hop(onion_decode_shared_secret, &msg.onion_routing_packet.hop_data[..], msg.onion_routing_packet.hmac, control_tlvs_ss) {
			Ok(onion_utils::MessageHop::Receive(Payload::Receive {
				control_tlvs: ReceiveControlTlvs::Unblinded(ReceiveTlvs { path_id })
			})) => {
				log_info!(self.logger, "Received an onion message with path_id: {:02x?}", path_id);
			},
			Ok(onion_utils::MessageHop::Forward {
				next_hop_data:
					Payload::Forward(ForwardControlTlvs::Unblinded(ForwardTlvs {
						next_node_id, next_blinding_override
					})),
				next_hop_hmac, new_packet_bytes
			}) => {
				// TODO: we need to check whether `next_node_id` is our node, in which case this is a dummy
				// blinded hop and this onion message is destined for us. In this situation, we should keep
				// unwrapping the onion layers to get to the final payload. Since we don't have the option
				// of creating blinded routes with dummy hops currently, we should be ok to not handle this
				// for now.
				let new_pubkey = match onion_utils::next_hop_packet_pubkey(&self.secp_ctx, msg.onion_routing_packet.public_key, &onion_decode_shared_secret) {
					Ok(pk) => pk,
					Err(e) => {
						log_trace!(self.logger, "Failed to compute next hop packet pubkey: {}", e);
						return
					}
				};
				let outgoing_packet = Packet {
					version: 0,
					public_key: new_pubkey,
					hop_data: new_packet_bytes.to_vec(),
					hmac: next_hop_hmac.clone(),
				};

				let mut pending_msg_events = self.pending_msg_events.lock().unwrap();
				pending_msg_events.push(MessageSendEvent::SendOnionMessage {
					node_id: next_node_id,
					msg: msgs::OnionMessage {
						blinding_point: match next_blinding_override {
							Some(blinding_point) => blinding_point,
							None => {
								let blinding_factor = {
									let mut sha = Sha256::engine();
									sha.input(&msg.blinding_point.serialize()[..]);
									sha.input(control_tlvs_ss.as_ref());
									Sha256::from_engine(sha).into_inner()
								};
								let mut next_blinding_point = msg.blinding_point.clone();
								if let Err(e) = next_blinding_point.mul_assign(&self.secp_ctx, &blinding_factor[..]) {
									log_trace!(self.logger, "Failed to compute next blinding point: {}", e);
									return
								}
								next_blinding_point
							},
						},
						len: outgoing_packet.len(),
						onion_routing_packet: outgoing_packet,
					},
				});
			},
			Err(e) => {
				log_trace!(self.logger, "Errored decoding onion message packet: {:?}", e);
			},
			_ => {
				log_trace!(self.logger, "Received bogus onion message packet, either the sender encoded a final hop as a forwarding hop or vice versa");
			},
		};
	}
}

impl<Signer: Sign, K: Deref, L: Deref> MessageSendEventsProvider for OnionMessenger<Signer, K, L>
	where K::Target: KeysInterface<Signer = Signer>,
	      L::Target: Logger,
{
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		let mut pending_msg_events = self.pending_msg_events.lock().unwrap();
		let mut ret = Vec::new();
		mem::swap(&mut ret, &mut *pending_msg_events);
		ret
	}
}

/// Useful for simplifying the parameters of [`SimpleArcChannelManager`] and
/// [`SimpleArcPeerManager`]. See their docs for more details.
///
///[`SimpleArcChannelManager`]: crate::ln::channelmanager::SimpleArcChannelManager
///[`SimpleArcPeerManager`]: crate::ln::peer_handler::SimpleArcPeerManager
pub type SimpleArcOnionMessenger<L> = OnionMessenger<InMemorySigner, Arc<KeysManager>, Arc<L>>;
/// Useful for simplifying the parameters of [`SimpleRefChannelManager`] and
/// [`SimpleRefPeerManager`]. See their docs for more details.
///
///[`SimpleRefChannelManager`]: crate::ln::channelmanager::SimpleRefChannelManager
///[`SimpleRefPeerManager`]: crate::ln::peer_handler::SimpleRefPeerManager
pub type SimpleRefOnionMessenger<'a, 'b, L> = OnionMessenger<InMemorySigner, &'a KeysManager, &'b L>;

