// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! XXX

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::key::{PublicKey, SecretKey};

use chain::keysinterface::{InMemorySigner, KeysInterface, KeysManager, Recipient, Sign};
use ln::msgs;
use ln::msgs::OnionMessageHandler;
use ln::onion_utils;
use util::errors::APIError;
use util::events::{MessageSendEvent, MessageSendEventsProvider};

use core::mem;
use core::ops::Deref;
use sync::{Arc, Mutex};

/// XXX
pub type SimpleArcOnionMessager = OnionMessager<InMemorySigner, Arc<KeysManager>>;
/// XXX
pub type SimpleRefOnionMessager<'a> = OnionMessager<InMemorySigner, &'a KeysManager>;

/// XXX
pub struct OnionMessager<Signer: Sign, K: Deref>
	where K::Target: KeysInterface<Signer = Signer>
{
	keys_manager: K,
	pending_msg_events: Mutex<Vec<MessageSendEvent>>,
	secp_ctx: Secp256k1<secp256k1::All>,
}

impl<Signer: Sign, K: Deref> OnionMessager<Signer, K>
	where K::Target: KeysInterface<Signer = Signer>,
{
	/// XXX
	pub fn new(keys_manager: K) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&keys_manager.get_secure_random_bytes());
		OnionMessager {
			keys_manager,
			pending_msg_events: Mutex::new(Vec::new()),
			secp_ctx,
		}
	}

	/// XXX
	/// * utilize non-None reply paths
	/// * make recipient a Destination that also works for blinded routes
	pub fn send_onion_message(&self, recipient: PublicKey, intermediate_nodes: Vec<PublicKey>) -> Result<(), APIError> {
		let prng_seed = self.keys_manager.get_secure_random_bytes();
		let session_priv_bytes = self.keys_manager.get_secure_random_bytes();
		let session_priv = SecretKey::from_slice(&session_priv_bytes[..]).expect("RNG is busted");

		let blinding_point = PublicKey::from_secret_key(&self.secp_ctx, &session_priv);

		let (encrypted_data_keys, onion_packet_keys) = onion_utils::construct_onion_message_keys(
			&self.secp_ctx, intermediate_nodes.iter().chain(vec![recipient].iter()).collect(), &session_priv)
			.map_err(|_| APIError::RouteError{err: "Pubkey along hop was maliciously selected"})?;
		let mut onion_payloads_path: Vec<PublicKey> = intermediate_nodes.into_iter()
			.chain(vec![recipient].into_iter()).collect();
		let first_hop_pk: PublicKey = onion_payloads_path.remove(0);
		let onion_payloads = onion_utils::build_onion_message_payloads(onion_payloads_path)?;
		// XXX route_size_insane check
		let onion_packet = onion_utils::construct_onion_message_packet(
			onion_payloads, encrypted_data_keys, onion_packet_keys, prng_seed);
		let mut pending_msg_events = self.pending_msg_events.lock().unwrap();
		println!("VMW: queueing onion message in pending_msg_events");
		pending_msg_events.push(MessageSendEvent::SendOnionMessage {
			node_id: first_hop_pk,
			msg: msgs::OnionMessage {
				blinding_point,
				len: 1366,
				onion_routing_packet: onion_packet,
			}
		});
		Ok(())
	}
}

impl<Signer: Sign, K: Deref> OnionMessageHandler for OnionMessager<Signer, K>
	where K::Target: KeysInterface<Signer = Signer>
{
	fn handle_onion_message(&self, _peer_node_id: &PublicKey, msg: &msgs::OnionMessage) {
		println!("VMW: received onion message");
		// TODO: add length check
		let node_secret = self.keys_manager.get_node_secret(Recipient::Node).unwrap(); // XXX no unwrap
		let encrypted_data_ss = {
			let mut arr = [0; 32];
			arr.copy_from_slice(&SharedSecret::new(&msg.blinding_point, &node_secret));
			arr
		};
		let onion_decode_shared_secret = {
			let blinding_factor = {
				let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
				hmac.input(&encrypted_data_ss[..]);
				Hmac::from_engine(hmac).into_inner()
			};
			let mut blinded_priv = node_secret.clone();
			blinded_priv.mul_assign(&blinding_factor).unwrap(); // XXX no unwrap
			let mut arr = [0; 32];
			arr.copy_from_slice(&SharedSecret::new(&msg.onion_routing_packet.public_key.unwrap(), &blinded_priv)[..]);
			arr
		};
		let next_hop = match onion_utils::decode_next_hop(onion_decode_shared_secret, &msg.onion_routing_packet.hop_data[..], msg.onion_routing_packet.hmac, None, Some(encrypted_data_ss)) {
			Ok(res) => res,
			Err(e) => {
				println!("VMW: errored in decode_next_hop: {:?}", e); // XXX logger instead
				return
			}
		};
		match next_hop {
			onion_utils::Hop::Receive(onion_utils::Payload::Message(msgs::OnionMsgPayload {
				format: msgs::OnionMsgPayloadFormat::Receive { path_id }
			})) => {
				println!("VMW: received onion message!! path_id: {:?}", path_id); // XXX logger instead
			},
			onion_utils::Hop::Forward {
				next_hop_data: onion_utils::Payload::Message(msgs::OnionMsgPayload {
					format: msgs::OnionMsgPayloadFormat::Forward {
						next_blinding_override,
						next_node_id,
						..
					},
				}),
				next_hop_hmac,
				new_packet_bytes
			} => {
				let mut new_pubkey = msg.onion_routing_packet.public_key.unwrap();

				let blinding_factor = {
					let mut sha = Sha256::engine();
					sha.input(&new_pubkey.serialize()[..]);
					sha.input(&onion_decode_shared_secret);
					Sha256::from_engine(sha).into_inner()
				};

				let public_key = if let Err(e) = new_pubkey.mul_assign(&self.secp_ctx, &blinding_factor[..]) {
					Err(e)
				} else { Ok(new_pubkey) };

				let outgoing_packet = msgs::OnionPacket {
					version: 0,
					public_key,
					hop_data: new_packet_bytes,
					hmac: next_hop_hmac.clone(),
				};

				let mut pending_msg_events = self.pending_msg_events.lock().unwrap();
				pending_msg_events.push(MessageSendEvent::SendOnionMessage {
					node_id: next_node_id,
					msg: msgs::OnionMessage {
						blinding_point: next_blinding_override.unwrap_or_else(|| {
							let blinding_factor = {
								let mut sha = Sha256::engine();
								sha.input(&msg.blinding_point.serialize()[..]); // E(i)
													sha.input(&encrypted_data_ss[..]);
													Sha256::from_engine(sha).into_inner()
							};
							let mut next_blinding_point = msg.blinding_point.clone();
							next_blinding_point.mul_assign(&self.secp_ctx, &blinding_factor[..]).unwrap();
							next_blinding_point
						}),
						len: 1366, // XXX
						onion_routing_packet: outgoing_packet,
					},
				});
			},
			_ => panic!() // XXX
		}
	}
}

impl<Signer: Sign, K: Deref> MessageSendEventsProvider for OnionMessager<Signer, K>
where K::Target: KeysInterface<Signer = Signer>
{
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		let mut pending_msg_events = self.pending_msg_events.lock().unwrap();
		let mut ret = Vec::new();
		mem::swap(&mut ret, &mut *pending_msg_events);
		ret
	}
}

