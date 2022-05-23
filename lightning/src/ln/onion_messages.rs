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
use ln::msgs::{self, DecodeError, OnionMessageHandler};
use ln::onion_utils;
use util::chacha20poly1305rfc::{ChaChaPoly1305Reader, ChaCha20Poly1305RFC};
use util::events::{MessageSendEvent, MessageSendEventsProvider};
use util::ser::{self, BigSize, FixedLengthReader, Readable, ReadableArgs, Writeable, Writer};

use core::mem;
use core::ops::Deref;
use io::{self, Cursor, Read};
use sync::{Arc, Mutex};

pub(crate) struct Payload {
	encrypted_tlvs: EncryptedTlvs,
}

impl Writeable for Payload {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match &self.encrypted_tlvs {
			EncryptedTlvs::Blinded(encrypted_bytes) => {
				encode_varint_length_prefixed_tlv!(w, {
					(4, encrypted_bytes, vec_type)
				});
			},
			EncryptedTlvs::Unblinded((control_tlvs, ss)) => {
				BigSize(1 + 1 + control_tlvs.serialized_length() as u64 + 16).write(w)?;
				BigSize(4).write(w)?;
				BigSize(control_tlvs.serialized_length() as u64 + 16).write(w)?;
				let (rho, _) = onion_utils::gen_rho_mu_from_shared_secret(&ss[..]);
				let mut chacha = ChaCha20Poly1305RFC::new(&rho, &[0; 12], &[]);
				chacha.encode_and_encrypt(&control_tlvs, w)?;
			}
		}
		Ok(())
	}
}

impl ReadableArgs<SharedSecret> for Payload {
	fn read<R: Read>(mut r: &mut R, encrypted_tlvs_ss: SharedSecret) -> Result<Self, DecodeError> {
		use bitcoin::consensus::encode::{Decodable, Error, VarInt};
		let v: VarInt = Decodable::consensus_decode(&mut r)
			.map_err(|e| match e {
				Error::Io(ioe) => DecodeError::from(ioe),
				_ => DecodeError::InvalidValue
			})?;
		if v.0 == 0 { // 0-length payload
			return Err(DecodeError::InvalidValue)
		}

		let mut rd = FixedLengthReader::new(r, v.0);
		let mut _reply_path_bytes: Option<Vec<u8>> = Some(Vec::new());
		let mut control_tlvs: Option<ControlTlvs> = None;
		let (rho, _) = onion_utils::gen_rho_mu_from_shared_secret(&encrypted_tlvs_ss[..]);
		let mut chacha_poly = ChaCha20Poly1305RFC::new(&rho, &[0; 12], &[]);
		decode_tlv_stream!(&mut rd, {
			(2, _reply_path_bytes, vec_type),
			(4, control_tlvs, (chacha, chacha_poly))
		});
		rd.eat_remaining().map_err(|_| DecodeError::ShortRead)?;

		if control_tlvs.is_none() {
			return Err(DecodeError::InvalidValue)
		}

		Ok(Payload {
			encrypted_tlvs: EncryptedTlvs::Unblinded((control_tlvs.unwrap(), encrypted_tlvs_ss)),
		})
	}
}

pub(crate) enum EncryptedTlvs {
	Blinded(Vec<u8>),
	Unblinded((ControlTlvs, SharedSecret)),
}

#[derive(Debug)]
pub(crate) enum ControlTlvs {
	Receive {
		path_id: Option<[u8; 32]>,
	},
	Forward {
		next_node_id: PublicKey,
		next_blinding_override: Option<PublicKey>,
	},
}

impl Writeable for ControlTlvs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			ControlTlvs::Receive { path_id } => {
				encode_tlv_stream!(writer, {
					(6, path_id, option)
				});
			},
			ControlTlvs::Forward { next_node_id, next_blinding_override } => {
				encode_tlv_stream!(writer, {
					(4, next_node_id, required),
					(8, next_blinding_override, option)
				});
			},
		}
		Ok(())
	}
}

impl Readable for ControlTlvs {
	fn read<R: Read>(mut r: &mut R) -> Result<Self, DecodeError> {
		let mut _padding: Option<Vec<u8>> = Some(Vec::new());
		let mut _short_channel_id: Option<u64> = None;
		let mut next_node_id: Option<PublicKey> = None;
		let mut path_id: Option<[u8; 32]> = None;
		let mut next_blinding_override: Option<PublicKey> = None;
		decode_tlv_stream!(&mut r, {
			(1, _padding, vec_type),
			(2, _short_channel_id, option),
			(4, next_node_id, option),
			(6, path_id, option),
			(8, next_blinding_override, option),
		});

		let valid_fwd_fmt  = next_node_id.is_some() && path_id.is_none();
		let valid_recv_fmt = next_node_id.is_none() && next_blinding_override.is_none();

		let payload_fmt = if valid_fwd_fmt {
			ControlTlvs::Forward {
				next_node_id: next_node_id.unwrap(),
				next_blinding_override,
			}
		} else if valid_recv_fmt {
			ControlTlvs::Receive {
				path_id,
			}
		} else {
			return Err(DecodeError::InvalidValue)
		};
		Ok(payload_fmt)
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
		let (encrypted_data_keys, _, blinded_node_pks) = construct_path_keys(&secp_ctx, &node_pks, None, &blinding_secret).unwrap(); // XXX no unwrap
		let mut blinded_hops = Vec::with_capacity(node_pks.len());
		for (idx, pk) in node_pks.iter().skip(1).enumerate() {
			let encrypted_data = (msgs::EncryptedData::Forward {
				next_node_id: pk.clone(),
				next_blinding_override: None,
			}).encode();
			let encrypted_payload = encrypt_encrypted_data(encrypted_data, encrypted_data_keys[idx]);
			blinded_hops.push(BlindedNode {
				blinded_node_id: blinded_node_pks[idx].clone(),
				encrypted_payload,
			});
		}

		// Add the recipient final payload.
		let encrypted_data = (msgs::EncryptedData::Receive { path_id: Some([42; 32]) }).encode();
		let encrypted_payload = encrypt_encrypted_data(encrypted_data, encrypted_data_keys[encrypted_data_keys.len() - 1]);
		blinded_hops.push(BlindedNode {
			blinded_node_id: blinded_node_pks[blinded_node_pks.len() - 1].clone(),
			encrypted_payload
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
	fn num_hops(&self) -> usize {
		match self {
			Destination::Node(_) => 1,
			Destination::BlindedRoute(BlindedRoute { blinded_hops, .. }) => blinded_hops.len(),
		}
	}
}

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
	pub fn send_onion_message(&self, intermediate_nodes: Vec<PublicKey>, destination: Destination) -> Result<(), ()> {
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
		let (encrypted_data_keys, onion_packet_keys, _) = construct_path_keys(
			&self.secp_ctx,
			&intermediate_nodes,
			Some(&destination), &blinding_secret).unwrap(); // XXX no unwrap
		let payloads = build_payloads(intermediate_nodes, destination, encrypted_data_keys);

		let prng_seed = self.keys_manager.get_secure_random_bytes();
		let onion_packet = onion_utils::construct_onion_message_packet(payloads, onion_packet_keys, prng_seed);

		// XXX route_size_insane check
		let mut pending_msg_events = self.pending_msg_events.lock().unwrap();
		pending_msg_events.push(MessageSendEvent::SendOnionMessage {
			node_id: introduction_node_id,
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
		// TODO: add length check
		let node_secret = self.keys_manager.get_node_secret(Recipient::Node).unwrap(); // XXX no unwrap
		let encrypted_data_ss = SharedSecret::new(&msg.blinding_point, &node_secret);
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
			onion_utils::Hop::Receive(onion_utils::Payload::Message(Payload {
				encrypted_tlvs
			})) => {
				match encrypted_tlvs {
					EncryptedTlvs::Unblinded((ControlTlvs::Receive { path_id }, _)) => {
						println!("VMW: received onion message!! path_id: {:?}", path_id); // XXX logger instead
					},
					_ => unreachable!() // XXX
				}
			},
			onion_utils::Hop::Forward {
				next_hop_data: onion_utils::Payload::Message(Payload {
					encrypted_tlvs: EncryptedTlvs::Unblinded((control_tlvs, _)),
				}),
				next_hop_hmac,
				new_packet_bytes
			} => {
				let (next_node_id, next_blinding_override) = match control_tlvs {
					ControlTlvs::Receive { path_id } => {
						println!("VMW: received onion message!! path_id: {:?}", path_id); // XXX logger instead
						return
					},
					ControlTlvs::Forward { next_node_id, next_blinding_override} =>
						(next_node_id, next_blinding_override)
				};
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

fn build_payloads(intermediate_nodes: Vec<PublicKey>, destination: Destination, mut encrypted_tlvs_keys: Vec<SharedSecret>) -> Vec<Payload> {
	let num_intermediate_nodes = intermediate_nodes.len();
	let num_payloads = num_intermediate_nodes + destination.num_hops();
	assert!(encrypted_tlvs_keys.len() >= intermediate_nodes.len() + 1);
	let mut payloads = Vec::with_capacity(num_payloads);
	let mut enc_tlv_keys = encrypted_tlvs_keys.drain(..);
	for pk in intermediate_nodes.into_iter().skip(1) {
		payloads.push(Payload {
			encrypted_tlvs: EncryptedTlvs::Unblinded((ControlTlvs::Forward {
				next_node_id: pk,
				next_blinding_override: None,
			}, enc_tlv_keys.next().unwrap()))
		});
	}
	match destination {
		Destination::Node(pk) => {
			if num_intermediate_nodes != 0 {
				payloads.push(Payload {
					encrypted_tlvs: EncryptedTlvs::Unblinded((ControlTlvs::Forward {
						next_node_id: pk,
						next_blinding_override: None,
					}, enc_tlv_keys.next().unwrap()))
				});
			}
			payloads.push(Payload {
				encrypted_tlvs: EncryptedTlvs::Unblinded((ControlTlvs::Receive {
					path_id: None,
				}, enc_tlv_keys.next().unwrap()))
			});
		},
		Destination::BlindedRoute(BlindedRoute { introduction_node_id, blinding_point, blinded_hops }) => {
			if num_intermediate_nodes != 0 {
				payloads.push(Payload {
					encrypted_tlvs: EncryptedTlvs::Unblinded((ControlTlvs::Forward {
						next_node_id: introduction_node_id,
						next_blinding_override: Some(blinding_point),
					}, enc_tlv_keys.next().unwrap()))
				});
			}
			for hop in blinded_hops {
				payloads.push(Payload {
					encrypted_tlvs: EncryptedTlvs::Blinded(hop.encrypted_payload),
				});
			}
		}
	}
	payloads
}

fn encrypt_encrypted_data(encrypted_data: Vec<u8>, encrypted_data_ss: SharedSecret) -> Vec<u8> {
	let mut encrypted_data = encrypted_data.clone();
	let (rho, _) = onion_utils::gen_rho_mu_from_shared_secret(&encrypted_data_ss[..]);
	let mut chacha = ChaCha20Poly1305RFC::new(&rho, &[0; 12], &[]);
	let mut tag = [0; 16];
	chacha.encrypt_in_place(&mut encrypted_data, &mut tag);
	encrypted_data.extend_from_slice(&tag);
	encrypted_data
}

#[inline]
fn keys_callback<T: secp256k1::Signing + secp256k1::Verification, FType: FnMut(PublicKey, SharedSecret, [u8; 32], PublicKey, SharedSecret)> (secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, destination: Option<&Destination>, session_priv: &SecretKey, mut callback: FType) -> Result<(), secp256k1::Error> {
	let mut msg_blinding_point_priv = session_priv.clone();
	let mut msg_blinding_point = PublicKey::from_secret_key(secp_ctx, &msg_blinding_point_priv);
	let mut onion_packet_pubkey_priv = msg_blinding_point_priv.clone();
	let mut onion_packet_pubkey = msg_blinding_point.clone();

	macro_rules! build_keys {
		($pk: expr, $blinded: expr) => {
			let encrypted_data_ss = SharedSecret::new(&$pk, &msg_blinding_point_priv);

			let hop_pk_blinding_factor = {
				let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
				hmac.input(&encrypted_data_ss[..]);
				Hmac::from_engine(hmac).into_inner()
			};
			let blinded_hop_pk = if $blinded { $pk.clone() } else {
				let mut unblinded_pk = $pk.clone();
				unblinded_pk.mul_assign(secp_ctx, &hop_pk_blinding_factor)?;
				unblinded_pk
			};
			let onion_packet_ss = SharedSecret::new(&blinded_hop_pk, &onion_packet_pubkey_priv);

			callback(blinded_hop_pk, onion_packet_ss, hop_pk_blinding_factor, onion_packet_pubkey, encrypted_data_ss);

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
		};
	}

	for pk in unblinded_path {
		build_keys!(pk, false);
	}
	if let Some(dest) = destination {
		match dest {
			Destination::Node(pk) => {
				build_keys!(pk, false);
			},
			Destination::BlindedRoute(BlindedRoute { blinded_hops, .. }) => {
				for hop in blinded_hops {
					build_keys!(hop.blinded_node_id, true);
				}
			},
		}
	}
	Ok(())
}

fn construct_path_keys<T: secp256k1::Signing + secp256k1::Verification>(secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, destination: Option<&Destination>, session_priv: &SecretKey) -> Result<(Vec<SharedSecret>, Vec<onion_utils::OnionKeys>, Vec<PublicKey>), secp256k1::Error> {
	let mut encrypted_data_keys = Vec::with_capacity(unblinded_path.len());
	let mut onion_packet_keys = Vec::with_capacity(unblinded_path.len());
	let mut blinded_node_pks = Vec::with_capacity(unblinded_path.len());

	keys_callback(secp_ctx, unblinded_path, destination, session_priv, |blinded_hop_pubkey, onion_packet_ss, _blinding_factor, ephemeral_pubkey, encrypted_data_ss| {
		blinded_node_pks.push(blinded_hop_pubkey);
		encrypted_data_keys.push(encrypted_data_ss);

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

	Ok((encrypted_data_keys, onion_packet_keys, blinded_node_pks))
}

/// XXX
pub type SimpleArcOnionMessager = OnionMessager<InMemorySigner, Arc<KeysManager>>;
/// XXX
pub type SimpleRefOnionMessager<'a> = OnionMessager<InMemorySigner, &'a KeysManager>;

