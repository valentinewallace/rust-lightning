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
use util::ser::Writeable;

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
 	pub fn send_onion_message(&self, recipient: Destination, intermediate_nodes: Vec<PublicKey>) -> Result<(), APIError> {
		let blinding_secret_bytes = self.keys_manager.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
		let blinded_route = blinded_route(blinding_secret, intermediate_nodes, recipient);

		let session_priv_bytes = self.keys_manager.get_secure_random_bytes();
		let session_priv = SecretKey::from_slice(&session_priv_bytes[..]).expect("RNG is busted");
		let blinded_hop_pks = blinded_route.blinded_hops.iter().map(|blinded_node| &blinded_node.blinded_node_id);
		let onion_packet_keys = compute_packet_pubkeys_and_shared_secrets(session_priv, blinded_hop_pks).unwrap();

		let prng_seed = self.keys_manager.get_secure_random_bytes();
		let onion_packet = onion_utils::construct_onion_message_packet(blinded_route.blinded_hops.iter().map(|blinded_node| &blinded_node.encrypted_payload).collect(), onion_packet_keys, prng_seed);

		// let blinding_point = PublicKey::from_secret_key(&self.secp_ctx, &session_priv);
		// let node_secret = self.keys_manager.get_node_secret(Recipient::Node).unwrap(); // XXX no unwrap
		// let encrypted_data_ss = SharedSecret::new(&blinding_point, &node_secret);
    //
		// let last_known_node_id = recipient.node_id();
		// let blinded_route = recipient.blinded_route();
		// // let (enc_data_onion_keys, onion_packet_keys) = construct_path_keys(&self.secp_ctx, intermediate_nodes.iter().chain(vec![last_known_node_id].iter()).collect(), &session_priv, &encrypted_data_ss)
		// let (encrypted_data_keys, onion_packet_keys) = construct_path_keys(&self.secp_ctx, intermediate_nodes.iter().chain(vec![last_known_node_id].iter()).collect(), &blinded_route,  &session_priv)
		//   .map_err(|_| APIError::RouteError{err: "Pubkey along hop was maliciously selected"})?;
		// let mut onion_payloads_path: Vec<PublicKey> = intermediate_nodes.into_iter().chain(vec![last_known_node_id].into_iter()).collect();
		// let first_hop_pk: PublicKey = onion_payloads_path.remove(0);
		// // let mut intermediate_payloads = onion_utils::build_intermediate_onion_message_payloads(onion_payloads_path)?;
		// let blinded_path = blinded_path(onion_payloads_path, encrypted_data_keys, blinded_route).unwrap();
    //
		// XXX route_size_insane check
		// this will next no longer take the enc_data keys, and instead a list of encoded packets
		// let onion_packet = onion_utils::construct_onion_message_packet(blinded_path, onion_packet_keys, prng_seed);
		let mut pending_msg_events = self.pending_msg_events.lock().unwrap();
		pending_msg_events.push(MessageSendEvent::SendOnionMessage {
			node_id: blinded_route.introduction_node_id,
			msg: msgs::OnionMessage {
				blinding_point: blinded_route.blinding_point,
				len: 1366,
				onion_routing_packet: onion_packet,
			}
		});
		// let (encrypted_data_keys, onion_packet_keys) = construct_path_keys(
		//   &self.secp_ctx, intermediate_nodes.iter().chain(vec![recipient].iter()).collect(), &session_priv)
		//   .map_err(|_| APIError::RouteError{err: "Pubkey along hop was maliciously selected"})?;
		// let mut onion_payloads_path: Vec<PublicKey> = intermediate_nodes.into_iter()
		//   .chain(vec![recipient].into_iter()).collect();
		// let first_hop_pk: PublicKey = onion_payloads_path.remove(0);
		// let onion_payloads = build_onion_message_payloads(onion_payloads_path)?;
		// // XXX route_size_insane check
		// let onion_packet = onion_utils::construct_onion_message_packet(
		//   onion_payloads, encrypted_data_keys, onion_packet_keys, prng_seed);
		// let mut pending_msg_events = self.pending_msg_events.lock().unwrap();
		// println!("VMW: queueing onion message in pending_msg_events");
		// pending_msg_events.push(MessageSendEvent::SendOnionMessage {
		//   node_id: first_hop_pk,
		//   msg: msgs::OnionMessage {
		//     blinding_point,
		//     len: 1366,
		//     onion_routing_packet: onion_packet,
		//   }
		// });
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

/// XXX
pub struct BlindedNode {
	/// XXX
	pub blinded_node_id: PublicKey,
	/// XXX
	pub encrypted_payload: Vec<u8>,
}

/// XXX
pub struct BlindedRoute {
	/// XXX
	pub introduction_node_id: PublicKey,
	/// XXX
	pub blinding_point: PublicKey,
	/// XXX
	pub blinded_hops: Vec<BlindedNode>,
}

/// XXX
pub enum Destination {
	/// XXX
	Node(PublicKey),
	/// XXX
	BlindedRoute(BlindedRoute),
}

impl Destination {
	fn node_id(&self) -> PublicKey {
		match self {
			Destination::Node(pk) => pk.clone(),
			Destination::BlindedRoute(BlindedRoute { introduction_node_id, .. }) => {
				introduction_node_id.clone()
			}
		}
	}
	fn blinded_route(self) -> Option<BlindedRoute> {
		match self {
			Destination::Node(_) => None,
			Destination::BlindedRoute(route) => Some(route),
		}
	}
}

fn blinded_route(blinding_secret: SecretKey, intermediate_nodes: Vec<PublicKey>, recipient: Destination) -> Result<BlindedRoute, ()> {
	let mut blinded_nodes = Vec::new();


	let (unblinded_last_hop_pk, unblinded_last_hop_next_blinding) = match recipient {
		Destination::Node(pk) => (pk.clone(), None),
		Destination::BlindedRoute(BlindedRoute { introduction_node_id, blinding_point, .. }) => (introduction_node_id.clone(), ),
	};

	let mut unblinded_intermediate_payloads = intermediate_nodes.iter().skip(1).map(|pk| (pk, None)).chain(vec![(unblinded_last_hop_pk, unblinded_last_hop_next_blinding)].iter()).map(|(unblinded_hop_pk, next_blinding_override) {
		let payload = msgs::OnionMsgPayload {
			format: msgs::OnionMsgPayloadFormat::Forward {
				next_node_id: unblinded_hop_pk,
				next_blinding_override,
			}
		};
		payload.encode()
	}).collect();

	// let unblinded_last_payload = msgs::OnionMsgPayload // start here

	//   next().map_or(Vec::new(), |pk| {
  //
	// }).collect();
	// let intermediate_unblinded_payloads = if intermediate_nodes.len() != 0 {
	//   intermediate_nodes.iter().skip(1).next().map(
	// }
	// intermediate_nodes.iter().map(|pk| {
	//   blinded_nodes.push(BlindedNode {
	//     blinded_node_id:
	//   });
	// });
	let mut e = blinding_secret;

}

fn blind_payload(payload: msgs::OnionMsgPayload) ->

#[inline]
fn keys_callback<T: secp256k1::Signing + secp256k1::Verification, FType: FnMut(SharedSecret, [u8; 32], PublicKey, SharedSecret)> (secp_ctx: &Secp256k1<T>, path: Vec<&PublicKey>, session_priv: &SecretKey, mut callback: FType) -> Result<(), secp256k1::Error> {
	let mut msg_blinding_point_priv = session_priv.clone();
	let mut msg_blinding_point = PublicKey::from_secret_key(secp_ctx, &msg_blinding_point_priv);
	let mut onion_packet_pubkey_priv = msg_blinding_point_priv.clone();
	let mut onion_packet_pubkey = msg_blinding_point.clone();

	for pk in path.into_iter() {
		let encrypted_data_ss = SharedSecret::new(pk, &msg_blinding_point_priv);

		let onion_packet_blinding_factor = {
			let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
			hmac.input(&encrypted_data_ss[..]);
			Hmac::from_engine(hmac).into_inner()
		};
		let mut blinded_hop_pk = pk.clone();
		blinded_hop_pk.mul_assign(secp_ctx, &onion_packet_blinding_factor)?;
		let onion_packet_ss = SharedSecret::new(&blinded_hop_pk, &onion_packet_pubkey_priv);

		callback(onion_packet_ss, onion_packet_blinding_factor, onion_packet_pubkey, encrypted_data_ss);

		let msg_blinding_point_blinding_factor = {
			let mut sha = Sha256::engine();
			sha.input(&msg_blinding_point.serialize()[..]);
			sha.input(&encrypted_data_ss[..]);
			Sha256::from_engine(sha).into_inner()
		};

		msg_blinding_point_priv.mul_assign(&msg_blinding_point_blinding_factor)?;
		msg_blinding_point = PublicKey::from_secret_key(secp_ctx, &msg_blinding_point_priv);

		let onion_packet_pubkey_blinding_factor = {
			let mut sha = Sha256::engine();
			sha.input(&onion_packet_pubkey.serialize()[..]);
			sha.input(&onion_packet_ss[..]);
			Sha256::from_engine(sha).into_inner()
		};
		onion_packet_pubkey.mul_assign(secp_ctx, &onion_packet_pubkey_blinding_factor)?;
		onion_packet_pubkey_priv.mul_assign(&onion_packet_pubkey_blinding_factor)?;
	}
	Ok(())
}
#[inline]
fn keys_callback_2<T: secp256k1::Signing + secp256k1::Verification>(secp_ctx: &Secp256k1<T>, blinded_path: &BlindedRoute, session_priv: &SecretKey) -> Result<Vec<onion_utils::OnionKeys>, secp256k1::Error> {
	let mut res = Vec::new();

	// let mut msg_blinding_point_priv = session_priv.clone();
	// let mut msg_blinding_point = blinded_path.blinding_point.clone();
	let mut onion_packet_pubkey_priv = session_priv.clone();
	let mut onion_packet_pubkey = PublicKey::from_secret_key(secp_ctx, &onion_packet_pubkey_priv);

	for blinded_node_pk in blinded_path.blinded_hops.into_iter() {
		// let encrypted_data_ss = SharedSecret::new(pk, &msg_blinding_point_priv);
    //
		// let onion_packet_blinding_factor = {
		//   let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
		//   hmac.input(&encrypted_data_ss[..]);
		//   Hmac::from_engine(hmac).into_inner()
		// };
		// let mut blinded_hop_pk = pk.clone();
		// blinded_hop_pk.mul_assign(secp_ctx, &onion_packet_blinding_factor)?;
		let onion_packet_ss = SharedSecret::new(&blinded_node_pk, &onion_packet_pubkey_priv);

		let (rho, mu) = onion_utils::gen_rho_mu_from_shared_secret(&onion_packet_ss[..]);
		res.push(onion_utils::OnionKeys {
			#[cfg(test)]
			shared_secret: onion_packet_ss,
			#[cfg(test)]
			blinding_factor: [0; 32],
			ephemeral_pubkey: onion_packet_pubkey,
			rho,
			mu,
		});

		// let msg_blinding_point_blinding_factor = {
		//   let mut sha = Sha256::engine();
		//   sha.input(&msg_blinding_point.serialize()[..]);
		//   sha.input(&encrypted_data_ss[..]);
		//   Sha256::from_engine(sha).into_inner()
		// };

		// msg_blinding_point_priv.mul_assign(&msg_blinding_point_blinding_factor)?;
		// msg_blinding_point.mul_assign(&msg_blinding_point_blinding_factor)?;
		// msg_blinding_point = PublicKey::from_secret_key(secp_ctx, &msg_blinding_point_priv);

		let onion_packet_pubkey_blinding_factor = {
			let mut sha = Sha256::engine();
			sha.input(&onion_packet_pubkey.serialize()[..]);
			sha.input(&onion_packet_ss[..]);
			Sha256::from_engine(sha).into_inner()
		};
		onion_packet_pubkey.mul_assign(secp_ctx, &onion_packet_pubkey_blinding_factor)?;
		onion_packet_pubkey_priv.mul_assign(&onion_packet_pubkey_blinding_factor)?;
	}
	Ok(res)
}

fn construct_path_keys<T: secp256k1::Signing + secp256k1::Verification>(secp_ctx: &Secp256k1<T>, path: Vec<&PublicKey>, blinded_route: &Option<BlindedRoute>, session_priv: &SecretKey) -> Result<(Vec<[u8; 32]>, Vec<onion_utils::OnionKeys>), secp256k1::Error> {
	let mut encrypted_data_keys = Vec::with_capacity(path.len());
	let mut onion_packet_keys = Vec::with_capacity(path.len());

	keys_callback(secp_ctx, path.clone(), session_priv, |onion_packet_ss, _blinding_factor, ephemeral_pubkey, encrypted_data_ss| {
		let (rho, _) = onion_utils::gen_rho_mu_from_shared_secret(&encrypted_data_ss[..]);
		encrypted_data_keys.push(rho);

		let (rho, mu) = onion_utils::gen_rho_mu_from_shared_secret(&onion_packet_ss[..]);
		onion_packet_keys.push(onion_utils::OnionKeys {
			#[cfg(test)]
			shared_secret: onion_packet_ss,
			#[cfg(test)]
			blinding_factor: _blinding_factor,
			ephemeral_pubkey,
			rho,
			mu,
		});

	})?;

	if let Some(route) = blinded_route {
		let additional_packet_keys = keys_callback_2(secp_ctx, route, session_priv);
		// XXX add keys to onion_packet_keys
	}
	Ok((encrypted_data_keys, onion_packet_keys))
}

pub(super) fn blinded_path(intermediate_nodes: Vec<PublicKey>, encrypted_data_keys: Vec<[u8; 32]>, blinded_route: Option<BlindedRoute>) -> Result<Vec<Vec<u8>>, std::io::Error> {
	// Marshall intermediate payloads.
	let mut intermediate_payloads = Vec::new();
	let num_intermed = intermediate_nodes.len();
	for (idx, pk) in intermediate_nodes.into_iter().enumerate() {
		intermediate_payloads.push(msgs::OnionMsgPayload {
			format: msgs::OnionMsgPayloadFormat::Forward {
				next_node_id: pk,
				next_blinding_override: if idx == num_intermed - 1 {
					if let Some(ref path) = blinded_route { Some(path.blinding_point.clone()) } else { None }
				} else { None },
			}
		});
	}

	let mut res = Vec::new();
	let final_node_key =
	let mut all_keys = encrypted_data_keys.chunks_exact(encrypted_data_keys.len() - 1);
	let intermediate_keys = all_keys.next().unwrap(); // XXX no unwrap
	for (payload, rho) in intermediate_payloads.into_iter().zip(intermediate_keys.into_iter()) {
		res.push((payload, rho).encode());
	}
	if let Some(path) = blinded_route {
		for hop in path.blinded_hops.iter() {
			let mut encoded_payload = Vec::new();
			encode_varint_length_prefixed_tlv!(&mut encoded_payload, {
				(4, hop.encrypted_payload, vec_type)
			});
			res.push(encoded_payload);
		}
	} else {
		let msg = msgs::OnionMsgPayload {
			format: msgs::OnionMsgPayloadFormat::Receive {
				path_id: None, // XXX non-None path_id
			}
		};
		res.push((msg, &all_keys.remainder()[0]).encode()); // XXX
	}
	Ok(res)
}
