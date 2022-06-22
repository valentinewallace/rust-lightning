// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Onion Messages: sending, receiving, forwarding, and ancillary utilities live here
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
use bitcoin::secp256k1::ecdh::SharedSecret;

use chain::keysinterface::{InMemorySigner, KeysInterface, KeysManager, Sign};
use ln::msgs::{self, DecodeError, OnionMessageHandler};
use ln::onion_utils;
use util::chacha20poly1305rfc::ChaChaPolyWriteAdapter;
use util::events::{MessageSendEvent, MessageSendEventsProvider};
use util::logger::Logger;
use util::ser::{IgnoringLengthReadable, LengthRead, LengthReadable, Readable, VecWriter, Writeable, Writer};

use core::mem;
use core::ops::Deref;
use io::{self, Read};
use prelude::*;
use sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Packet {
	pub(crate) version: u8,
	pub(crate) public_key: PublicKey,
	// Unlike the onion packets used for payments, onion message packets can have payloads greater than 1300 bytes.
	pub(crate) hop_data: Vec<u8>,
	pub(crate) hmac: [u8; 32],
}

impl Writeable for Packet {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.version.write(w)?;
		self.public_key.write(w)?;
		w.write_all(&self.hop_data)?;
		self.hmac.write(w)?;
		Ok(())
	}
}

impl LengthReadable for Packet {
	fn read<R: LengthRead>(r: &mut R) -> Result<Self, DecodeError> {
		if r.total_bytes() < 66 {
			return Err(DecodeError::InvalidValue)
		}
		let version = Readable::read(r)?;
		let public_key = {
			let mut buf = [0u8;33];
			r.read_exact(&mut buf)?;
			PublicKey::from_slice(&buf).map_err(|_| DecodeError::InvalidValue)?
		};
		// 1 (version) + 33 (pubkey) + 32 (HMAC) = 66
		let mut hop_data = vec![0; r.total_bytes() as usize - 66];
		for i in 0..r.total_bytes() - 66 {
			let byte: u8 = Readable::read(r)?;
			hop_data[i as usize] = byte;
		}
		let hmac = Readable::read(r)?;
		Ok(Packet {
			version,
			public_key,
			hop_data,
			hmac,
		})
	}
}

/// Onion messages have "control" TLVs and "data" TLVs. Control TLVs are used to control the
/// direction and routing of an onion message from hop to hop, whereas data TLVs contain the onion
/// message content itself.
pub(crate) enum ControlTlvs {
	/// Control TLVs for the final recipient of an onion message.
	Receive {
		/// If `path_id` is `Some`, it is used to identify the blinded route that this onion message is
		/// sending to. This is useful for receivers to check that said blinded route is being used in
		/// the right context.
		path_id: Option<[u8; 32]>
	},
	/// Control TLVs for an intermediate forwarder of an onion message.
	Forward {
		/// The node id of the next hop in the onion message's path.
		next_node_id: PublicKey,
		/// Senders of onion messages have the option of specifying an overriding `blinding_point`
		/// for forwarding nodes along the path. If this field is absent, forwarding nodes will
		/// calculate the next hop's blinding point by multiplying the blinding point that they
		/// received by a blinding factor.
		next_blinding_override: Option<PublicKey>,
	}
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
		let mut _padding: Option<IgnoringLengthReadable> = None;
		let mut _short_channel_id: Option<u64> = None;
		let mut next_node_id: Option<PublicKey> = None;
		let mut path_id: Option<[u8; 32]> = None;
		let mut next_blinding_override: Option<PublicKey> = None;
		decode_tlv_stream!(&mut r, {
			(1, _padding, (option: LengthReadable)),
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

/// Used to construct the blinded hops portion of a blinded route. These hops cannot be identified
/// by outside observers and thus can be used to hide the identity of the recipient.
pub struct BlindedHop {
	/// The blinded node id of this hop in a blinded route.
	pub blinded_node_id: PublicKey,
	/// The encrypted payload intended for this hop in a blinded route.
	// If we're sending to this blinded route, this payload will later be encoded into the
	// [`EncryptedTlvs`] for the hop when constructing the onion packet for sending.
	//
	// [`EncryptedTlvs`]: EncryptedTlvs
	pub encrypted_payload: Vec<u8>,
}

/// Onion messages can be sent and received to blinded routes, which serve to hide the identity of
/// the recipient.
pub struct BlindedRoute {
	/// To send to a blinded route, the sender first finds a route to the unblinded
	/// `introduction_node_id`, which can unblind its [`encrypted_payload`] to find out the onion
	/// message's next hop and forward it along.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub introduction_node_id: PublicKey,
	/// Creators of blinded routes supply the introduction node id's `blinding_point`, which the
	/// introduction node will use in decrypting its [`encrypted_payload`] to forward the onion
	/// message.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub blinding_point: PublicKey,
	/// The hops composing the blinded route.
	pub blinded_hops: Vec<BlindedHop>,
}

impl BlindedRoute {
	/// Create a blinded route to be forwarded along `node_pks`. The last node pubkey in `node_pks`
	/// will be the destination node.
	pub fn new<Signer: Sign, K: Deref, T: secp256k1::Signing + secp256k1::Verification>
		(node_pks: Vec<PublicKey>, keys_manager: &K, secp_ctx: &Secp256k1<T>) -> Result<Self, ()>
		where K::Target: KeysInterface<Signer = Signer>,
	{
		if node_pks.len() <= 1 { return Err(()) }
		let blinding_secret_bytes = keys_manager.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
		let (mut encrypted_data_keys, mut blinded_node_pks) = construct_blinded_route_keys(secp_ctx, &node_pks, &blinding_secret).map_err(|_| ())?;
		let mut blinded_hops = Vec::with_capacity(node_pks.len());
		debug_assert_eq!(encrypted_data_keys.len(), blinded_node_pks.len());
		let mut enc_tlvs_keys = encrypted_data_keys.drain(..);
		let mut blinded_pks = blinded_node_pks.drain(..);

		for pk in node_pks.iter().skip(1) {
			let encrypted_tlvs = ControlTlvs::Forward {
				next_node_id: pk.clone(),
				next_blinding_override: None,
			};
			blinded_hops.push(BlindedHop {
				blinded_node_id: blinded_pks.next().unwrap(),
				encrypted_payload: Self::encrypt_payload(encrypted_tlvs, enc_tlvs_keys.next().unwrap()),
			});
		}

		// Add the recipient final payload.
		let encrypted_tlvs = ControlTlvs::Receive { path_id: Some([42; 32]) };
		blinded_hops.push(BlindedHop {
			blinded_node_id: blinded_pks.next().unwrap(),
			encrypted_payload: Self::encrypt_payload(encrypted_tlvs, enc_tlvs_keys.next().unwrap()),
		});

		Ok(BlindedRoute {
			introduction_node_id: node_pks[0].clone(),
			blinding_point: PublicKey::from_secret_key(secp_ctx, &blinding_secret),
			blinded_hops,
		})
	}

	fn encrypt_payload(payload: ControlTlvs, encrypted_tlvs_ss: [u8; 32]) -> Vec<u8> {
		let mut writer = VecWriter(Vec::new());
		let write_adapter = ChaChaPolyWriteAdapter::new(encrypted_tlvs_ss, &payload);
		write_adapter.write(&mut writer).expect("In-memory writes cannot fail");
		writer.0
	}
}

/// A sender, receiver and forwarder of onion messages. In upcoming releases, this object will be
/// used to retrieve invoices and fulfill invoice requests from offers.
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
}

impl<Signer: Sign, K: Deref, L: Deref> OnionMessageHandler for OnionMessenger<Signer, K, L>
	where K::Target: KeysInterface<Signer = Signer>,
				L::Target: Logger,
{
	fn handle_onion_message(&self, _peer_node_id: &PublicKey, msg: &msgs::OnionMessage) {}
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

#[inline]
fn construct_keys_callback<
	T: secp256k1::Signing + secp256k1::Verification,
	FType: FnMut(PublicKey, SharedSecret, [u8; 32], PublicKey, [u8; 32])>
	(secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, session_priv: &SecretKey, mut callback: FType)
	-> Result<(), secp256k1::Error> {
	let mut msg_blinding_point_priv = session_priv.clone();
	let mut msg_blinding_point = PublicKey::from_secret_key(secp_ctx, &msg_blinding_point_priv);
	let mut onion_packet_pubkey_priv = msg_blinding_point_priv.clone();
	let mut onion_packet_pubkey = msg_blinding_point.clone();

	macro_rules! build_keys {
		($pk: expr, $blinded: expr) => {
			let encrypted_data_ss = SharedSecret::new(&$pk, &msg_blinding_point_priv);

			let hop_pk_blinding_factor = {
				let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
				hmac.input(encrypted_data_ss.as_ref());
				Hmac::from_engine(hmac).into_inner()
			};
			let blinded_hop_pk = if $blinded { $pk.clone() } else {
				let mut unblinded_pk = $pk.clone();
				unblinded_pk.mul_assign(secp_ctx, &hop_pk_blinding_factor)?;
				unblinded_pk
			};
			let onion_packet_ss = SharedSecret::new(&blinded_hop_pk, &onion_packet_pubkey_priv);

			let (rho, _) = onion_utils::gen_rho_mu_from_shared_secret(encrypted_data_ss.as_ref());
			callback(blinded_hop_pk, onion_packet_ss, hop_pk_blinding_factor, onion_packet_pubkey, rho);

			let msg_blinding_point_blinding_factor = {
				let mut sha = Sha256::engine();
				sha.input(&msg_blinding_point.serialize()[..]);
				sha.input(encrypted_data_ss.as_ref());
				Sha256::from_engine(sha).into_inner()
			};

			msg_blinding_point_priv.mul_assign(&msg_blinding_point_blinding_factor)?;
			msg_blinding_point = PublicKey::from_secret_key(secp_ctx, &msg_blinding_point_priv);

			let onion_packet_pubkey_blinding_factor = {
				let mut sha = Sha256::engine();
				sha.input(&onion_packet_pubkey.serialize()[..]);
				sha.input(onion_packet_ss.as_ref());
				Sha256::from_engine(sha).into_inner()
			};
			onion_packet_pubkey.mul_assign(secp_ctx, &onion_packet_pubkey_blinding_factor)?;
			onion_packet_pubkey_priv.mul_assign(&onion_packet_pubkey_blinding_factor)?;
		};
	}

	for pk in unblinded_path {
		build_keys!(pk, false);
	}
	Ok(())
}

/// Construct keys for creating a blinded route along the given `unblinded_path`.
///
/// Returns: `(encrypted_tlvs_keys, blinded_node_ids)`
/// where the encrypted tlvs keys are used to encrypt the blinded route's blinded payloads and the
/// blinded node ids are used to set the [`BlindedHop::blinded_node_id`]s of the [`BlindedRoute`].
fn construct_blinded_route_keys<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, session_priv: &SecretKey
) -> Result<(Vec<[u8; 32]>, Vec<PublicKey>), secp256k1::Error> {
	let mut encrypted_data_keys = Vec::with_capacity(unblinded_path.len());
	let mut blinded_node_pks = Vec::with_capacity(unblinded_path.len());

	construct_keys_callback(secp_ctx, unblinded_path, session_priv, |blinded_hop_pubkey, _, _, _, encrypted_data_ss| {
		blinded_node_pks.push(blinded_hop_pubkey);
		encrypted_data_keys.push(encrypted_data_ss);
	})?;

	Ok((encrypted_data_keys, blinded_node_pks))
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
