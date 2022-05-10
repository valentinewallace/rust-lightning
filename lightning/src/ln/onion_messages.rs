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

fn encode_payloads(blinded_route: &BlindedRoute) -> Result<Vec<Vec<u8>>, msgs::DecodeError> {
	let mut final_res = Vec::new();
	for blinded_node in blinded_route.blinded_hops.iter() {
		let mut res = Vec::new();
		let _ = encode_varint_length_prefixed_tlv!(&mut res, {
			(4, blinded_node.encrypted_payload, vec_type)
		});
		final_res.push(res);
	}
	Ok(final_res)
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
 	pub fn send_onion_message(&self, recipient: Destination, intermediate_nodes: Vec<PublicKey>) -> Result<(), ()> {
		let blinding_secret_bytes = self.keys_manager.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
		let (blinded_route, onion_packet_keys) = blinded_route(blinding_secret, intermediate_nodes, recipient).unwrap(); // XXX no unwrap

		let session_priv_bytes = self.keys_manager.get_secure_random_bytes();
		let session_priv = SecretKey::from_slice(&session_priv_bytes[..]).expect("RNG is busted");
		let onion_packet_payloads = encode_payloads(&blinded_route).unwrap();

		let prng_seed = self.keys_manager.get_secure_random_bytes();
		// let onion_packet = onion_utils::construct_onion_message_packet(blinded_route.blinded_hops.iter().map(|blinded_node| &blinded_node.encrypted_payload).collect(), onion_packet_keys, prng_seed);
		let onion_packet = onion_utils::construct_onion_message_packet(onion_packet_payloads, onion_packet_keys, prng_seed);

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
			let ss = SharedSecret::new(&msg.blinding_point, &node_secret);
			println!("VMW: encrypted data shared secret: {:?}", ss);
			arr.copy_from_slice(&ss);
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
			let ss = SharedSecret::new(&msg.onion_routing_packet.public_key.unwrap(), &blinded_priv);
			println!("VMW: onion decode shared secret: {:?}", ss);
			arr.copy_from_slice(&ss[..]);
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
#[derive(Clone)]
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

impl BlindedRoute {
	/// XXX
	pub fn new<Signer: Sign, K: Deref>(node_pks: Vec<PublicKey>, keys_manager: K) -> Self
		where K::Target: KeysInterface<Signer = Signer>,
	{
		let secp_ctx = Secp256k1::new();
		let blinding_secret_bytes = keys_manager.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
		let (encrypted_data_keys, _onion_packet_keys, blinded_node_pks) = construct_path_keys(&secp_ctx, node_pks.clone().iter().collect(), Vec::new(), &blinding_secret).unwrap(); // XXX no unwrap
		let mut blinded_hops = Vec::with_capacity(node_pks.len());
		for (idx, pk) in node_pks.iter().skip(1).enumerate() {
			let encrypted_payload = (msgs::OnionMsgPayload {
				format: msgs::OnionMsgPayloadFormat::Forward {
					next_node_id: pk.clone(),
					next_blinding_override: None,
				}
			}, encrypted_data_keys[idx].clone(), false).encode();
			blinded_hops.push(BlindedNode {
				blinded_node_id: blinded_node_pks[idx].clone(),
				encrypted_payload,
			});
		}
		blinded_hops.push(BlindedNode {
			blinded_node_id: blinded_node_pks[blinded_node_pks.len() - 1].clone(),
			encrypted_payload: (msgs::OnionMsgPayload {
				format: msgs::OnionMsgPayloadFormat::Receive {
					path_id: Some([42; 32]),
				},
			}, encrypted_data_keys[encrypted_data_keys.len() - 1].clone(), false).encode(),
		});
		BlindedRoute {
			introduction_node_id: node_pks[0].clone(),
			blinding_point: PublicKey::from_secret_key(&secp_ctx, &blinding_secret),
			blinded_hops,
		}
	}
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

fn blinded_route(blinding_secret: SecretKey, intermediate_nodes: Vec<PublicKey>, destination: Destination) -> Result<(BlindedRoute, Vec<onion_utils::OnionKeys>), ()> {
	let (unblinded_last_hop_pk, unblinded_last_hop_next_blinding, blinded_pks) = match destination {
		Destination::Node(pk) => (pk.clone(), None, Vec::new()),
		Destination::BlindedRoute(BlindedRoute { introduction_node_id, blinding_point, ref blinded_hops }) =>
			(introduction_node_id.clone(), Some(blinding_point.clone()), blinded_hops.iter().map(|hop| hop.blinded_node_id.clone()).collect()),
	};

	let secp_ctx = Secp256k1::new();
	let (encrypted_data_keys, onion_packet_keys, blinded_node_pks) = construct_path_keys(&secp_ctx, intermediate_nodes.iter().chain(
		vec![&unblinded_last_hop_pk].into_iter()).collect(), blinded_pks, &blinding_secret).unwrap(); // XXX no unwrap

	let unblinded_intermediate_pks: Vec<(&PublicKey, Option<PublicKey>)> = intermediate_nodes.iter().skip(1).map(|pk| (pk, None))
		.chain(vec![(&unblinded_last_hop_pk, unblinded_last_hop_next_blinding)].into_iter()).collect();
	println!("VMW: unblinded intermediate pks: {:?}", unblinded_intermediate_pks);
	let mut blinded_hops = Vec::new();
	for (idx, (pk, next_blinding_override)) in unblinded_intermediate_pks.iter().enumerate() {
		let encrypted_payload = (msgs::OnionMsgPayload {
			format: msgs::OnionMsgPayloadFormat::Forward {
				next_node_id: *pk.clone(),
				next_blinding_override: *next_blinding_override,
			}
		}, encrypted_data_keys[idx].clone(), false).encode();
		blinded_hops.push(BlindedNode {
			blinded_node_id: blinded_node_pks[idx].clone(),
			encrypted_payload,
		});
	}

	if let Destination::BlindedRoute(BlindedRoute { blinded_hops: ref hops, .. }) = destination {
		for hop in hops {
			blinded_hops.push(hop.clone()); // XXX no clone
		}
	} else {
		blinded_hops.push(BlindedNode {
			blinded_node_id: blinded_node_pks[blinded_node_pks.len() - 1].clone(),
			encrypted_payload: (msgs::OnionMsgPayload {
				format: msgs::OnionMsgPayloadFormat::Receive {
					path_id: None,
				},
			}, encrypted_data_keys[encrypted_data_keys.len() - 1].clone(), false).encode(),
		});
	}
	// XXX test the case of 0 intermediate hops and a Destination::Node
	let (introduction_node_id, blinding_point) = if intermediate_nodes.len() != 0 {
		(intermediate_nodes[0].clone(), PublicKey::from_secret_key(&secp_ctx, &blinding_secret))
	} else {
		match destination {
			Destination::BlindedRoute(BlindedRoute { introduction_node_id, blinding_point, .. }) =>
				(introduction_node_id.clone(), blinding_point.clone()),
			Destination::Node(pk) => (pk.clone(), PublicKey::from_secret_key(&secp_ctx, &blinding_secret))
		}
	};
	Ok((BlindedRoute {
		introduction_node_id,
		blinding_point,
		blinded_hops,
	}, onion_packet_keys))
}

#[inline]
fn keys_callback<T: secp256k1::Signing + secp256k1::Verification, FType: FnMut(PublicKey, SharedSecret, [u8; 32], PublicKey, SharedSecret)> (secp_ctx: &Secp256k1<T>, unblinded_path: Vec<&PublicKey>, blinded_path: Vec<PublicKey>, session_priv: &SecretKey, mut callback: FType) -> Result<(), secp256k1::Error> {
	let mut msg_blinding_point_priv = session_priv.clone();
	let mut msg_blinding_point = PublicKey::from_secret_key(secp_ctx, &msg_blinding_point_priv);
	let mut onion_packet_pubkey_priv = msg_blinding_point_priv.clone();
	let mut onion_packet_pubkey = msg_blinding_point.clone();

	for (pk, blinded) in unblinded_path.into_iter().map(|unblinded_pk| (unblinded_pk.clone(), false))
		.chain(blinded_path.into_iter().map(|blinded_pk| (blinded_pk, true))) {
		let encrypted_data_ss = SharedSecret::new(&pk, &msg_blinding_point_priv);

		let onion_packet_blinding_factor = {
			let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
			hmac.input(&encrypted_data_ss[..]);
			Hmac::from_engine(hmac).into_inner()
		};
		let blinded_hop_pk = if blinded { pk.clone() } else {
			let mut unblinded_pk = pk.clone();
			unblinded_pk.mul_assign(secp_ctx, &onion_packet_blinding_factor)?;
			unblinded_pk
		};
		let onion_packet_ss = SharedSecret::new(&blinded_hop_pk, &onion_packet_pubkey_priv);
		println!("VMW: constructing onion keys, onion packet ss: {:?}, encrypted data ss: {:?}", onion_packet_ss, encrypted_data_ss);

		callback(blinded_hop_pk, onion_packet_ss, onion_packet_blinding_factor, onion_packet_pubkey, encrypted_data_ss);

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

// fn construct_path_keys<T: secp256k1::Signing + secp256k1::Verification>(secp_ctx: &Secp256k1<T>, path: &Vec<PublicKey>, session_priv: &SecretKey) -> Result<(Vec<[u8; 32]>, Vec<onion_utils::OnionKeys>), secp256k1::Error> {
fn construct_path_keys<T: secp256k1::Signing + secp256k1::Verification>(secp_ctx: &Secp256k1<T>, unblinded_path: Vec<&PublicKey>, blinded_path: Vec<PublicKey>, session_priv: &SecretKey) -> Result<(Vec<[u8; 32]>, Vec<onion_utils::OnionKeys>, Vec<PublicKey>), secp256k1::Error> {
	let mut encrypted_data_keys = Vec::with_capacity(unblinded_path.len() + blinded_path.len());
	let mut onion_packet_keys = Vec::with_capacity(unblinded_path.len() + blinded_path.len());
	let mut blinded_node_pks = Vec::with_capacity(unblinded_path.len() + blinded_path.len());

	keys_callback(secp_ctx, unblinded_path.clone(), blinded_path.clone(), session_priv, |blinded_hop_pubkey, onion_packet_ss, _blinding_factor, ephemeral_pubkey, encrypted_data_ss| {
		blinded_node_pks.push(blinded_hop_pubkey);
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

	// if let Some(route) = blinded_route {
	//   let additional_packet_keys = keys_callback_2(secp_ctx, route, session_priv);
		// XXX add keys to onion_packet_keys
	// }
	Ok((encrypted_data_keys, onion_packet_keys, blinded_node_pks))
}
