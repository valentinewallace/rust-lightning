// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Onion Messages: sending, receiving, forwarding, and ancillary utilities live here
//!
//! Onion messages are multi-purpose messages sent between peers over the lightning network. In the
//! near future, they will be used to communicate invoices for [Offers], unlocking use cases such as
//! static invoices, refunds and proof of payer. Further, you will be able to accept payments
//! without revealing your node id through the use of [blinded routes].
//!
//! # Example
//!
//! ```
//! # use lightning::chain::keysinterface::{KeysManager, KeysInterface};
//! # use lightning::onion_message::{BlindedRoute, OnionMessenger};
//! # use lightning::util::logger::{Logger, Record};
//! # struct FakeLogger {};
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: &Record) { unimplemented!() }
//! # }
//! # let seed = [42u8; 32];
//! # let time = Duration::from_secs(123456);
//! # let keys_manager = Arc::new(KeysManager::new(seed, time.as_secs(), time.subsec_nanos()));
//! # let logger = Arc::new(FakeLogger {});
//! # let node_secret = SecretKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
//! # let hop_node_id1 = PublicKey::from_secret_key(&secp_ctx, &node_secret);
//! # let hop_node_id2 = hop_node_id1.clone();
//! # let destination_node_id = hop_node_id1.clone();
//! #
//! // Create the onion messenger. This must use the same `keys_manager` as is passed to your
//! // ChannelManager.
//! let onion_messenger = OnionMessenger::new(keys_manager, logger);
//!
//! // Hook up the OnionMessenger to your PeerManager, for sending and receiving messages on the
//! // wire.
//! # let chan_handler = IgnoringMessageHandler {};
//! # let route_handler = IgnoringMessageHandler {};
//! # let custom_message_handler = IgnoringMessageHandler {};
//! # let rand_bytes = [0; 32];
//! let message_handler = MessageHandler { chan_handler, route_handler, onion_messenger };
//! let peer_manager = PeerManager::new(message_handler, node_secret, &rand_bytes, logger,
//! custom_message_handler);
//!
//! // Send an empty onion message to a node id.
//! let intermediate_hops = vec![hop_node_id1, hop_node_id2];
//! onion_messenger.send_onion_message(intermediate_hops, Destination::Node(destination_node_id));
//!
//! // Create a blinded route to yourself, for someone to send an onion message to.
//! # let secp_ctx = Secp256k1::new();
//! # let your_node_id = hop_node_id1.clone();
//! let hops = vec![hop_node_id_1, hop_node_id_2, your_node_id];
//! let blinded_route = BlindedRoute::new(hops, keys_manager, &secp_ctx).unwrap();
//!
//! // Send an empty onion message to a blinded route.
//! onion_messenger.send_onion_message(intermediate_hops, Destination::BlindedRoute(blinded_route));
//! ```
//!
//! [Offers]: https://github.com/lightning/bolts/pull/798
//! [blinded routes]: crate::onion_message::BlindedRoute
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
use bitcoin::secp256k1::ecdh::SharedSecret;

use chain::keysinterface::{InMemorySigner, KeysInterface, KeysManager, Recipient, Sign};
use ln::msgs::{self, DecodeError, OnionMessageHandler};
use ln::onion_utils;
use util::chacha20poly1305rfc::{ChaChaPolyReadAdapter, ChaChaPolyWriteAdapter};
use util::events::{MessageSendEvent, MessageSendEventsProvider};
use util::logger::Logger;
use util::ser::{FixedLengthReader, IgnoringLengthReadable, LengthRead, LengthReadable, LengthReadableArgs, Readable, ReadableArgs, VecWriter, Writeable, Writer};

use core::mem;
use core::ops::Deref;
use io::{self, Read};
use prelude::*;
use sync::{Arc, Mutex};

// Per the spec, an onion message packet's `hop_data` field length should be
// SMALL_PACKET_HOP_DATA_LEN if it fits, else BIG_PACKET_HOP_DATA_LEN if it fits.
pub(crate) const SMALL_PACKET_HOP_DATA_LEN: usize = 1300;
pub(crate) const BIG_PACKET_HOP_DATA_LEN: usize = 32768;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Packet {
	pub(crate) version: u8,
	pub(crate) public_key: PublicKey,
	// Unlike the onion packets used for payments, onion message packets can have payloads greater than 1300 bytes.
	pub(crate) hop_data: Vec<u8>,
	pub(crate) hmac: [u8; 32],
}

impl Packet {
	fn len(&self) -> u16 {
		// 32 (hmac) + 33 (public_key) + 1 (version) = 66
		self.hop_data.len() as u16 + 66
	}
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

/// The payload of an onion message.
pub(crate) struct Payload {
	/// Onion message payloads contain an encrypted TLV stream, containing both "control" TLVs and
	/// sometimes user-provided custom "data" TLVs. See [`EncryptedTlvs`] for more information.
	encrypted_tlvs: EncryptedTlvs,
	// Coming soon:
	// * `message: Message` field
	// * `reply_path: Option<BlindedRoute>` field
}

// Coming soon:
// enum Message {
// 	InvoiceRequest(InvoiceRequest),
// 	Invoice(Invoice),
//	InvoiceError(InvoiceError),
//	CustomMessage<T>,
// }

/// We want to avoid encoding and encrypting separately in order to avoid an intermediate Vec, thus
/// we encode and encrypt at the same time using the secret provided as the second parameter here.
impl Writeable for (Payload, [u8; 32]) {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match &self.0.encrypted_tlvs {
			EncryptedTlvs::Blinded(encrypted_bytes) => {
				encode_varint_length_prefixed_tlv!(w, {
					(4, encrypted_bytes, vec_type)
				})
			},
			EncryptedTlvs::Unblinded(control_tlvs) => {
				let write_adapter = ChaChaPolyWriteAdapter::new(self.1, &control_tlvs);
				encode_varint_length_prefixed_tlv!(w, {
					(4, write_adapter, required)
				})
			}
		}
		Ok(())
	}
}

/// Reads of `Payload`s are parameterized by the `rho` of a `SharedSecret`, which is used to decrypt
/// the onion message payload's `encrypted_data` field.
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
		// TODO: support reply paths
		let mut _reply_path_bytes: Option<Vec<u8>> = Some(Vec::new());
		let mut read_adapter: Option<ChaChaPolyReadAdapter<ControlTlvs>> = None;
		let (rho, _) = onion_utils::gen_rho_mu_from_shared_secret(&encrypted_tlvs_ss.secret_bytes());
		decode_tlv_stream!(&mut rd, {
			(2, _reply_path_bytes, vec_type),
			(4, read_adapter, (option: LengthReadableArgs, rho))
		});
		rd.eat_remaining().map_err(|_| DecodeError::ShortRead)?;

		if read_adapter.is_none() {
			return Err(DecodeError::InvalidValue)
		}

		Ok(Payload {
			encrypted_tlvs: EncryptedTlvs::Unblinded(read_adapter.unwrap().readable),
		})
	}
}

/// Onion messages contain an encrypted TLV stream. This can be supplied by someone else, in the
/// case that we're sending to a blinded route, or created by us if we're constructing payloads for
/// unblinded hops in the onion message's path.
pub(crate) enum EncryptedTlvs {
	/// If we're sending to a blinded route, the node that constructed the blinded route has provided
	/// our onion message's `EncryptedTlvs`, already encrypted and encoded into bytes.
	Blinded(Vec<u8>),
	/// If we're receiving an onion message or constructing an onion message to send through any
	/// unblinded nodes, we'll need to construct the onion message's `EncryptedTlvs` in their
	/// unblinded state to avoid encoding them into an intermediate `Vec`.
	// Below will later have an additional Vec<CustomTlv>
	Unblinded(ControlTlvs),
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
		if node_pks.len() < 2 { return Err(()) }
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
		let encrypted_tlvs = ControlTlvs::Receive { path_id: None };
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

/// The destination of an onion message.
pub enum Destination {
	/// We're sending this onion message to a node.
	Node(PublicKey),
	/// We're sending this onion message to a blinded route.
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

/// Errors that may occur when [sending an onion message].
///
/// [sending an onion message]: OnionMessenger::send_onion_message
#[derive(Debug)]
pub enum SendError {
	/// Errored computing onion message packet keys.
	Secp256k1(secp256k1::Error),
	/// The provided [destination] was invalid.
	///
	/// [destination]: Destination
	InvalidDestination(&'static str),
	/// Because implementations such as Eclair will drop onion messages where the message packet
	/// exceeds 32834 bytes, we refuse to send messages where the packet exceeds this size.
	TooBigPacket,
}

/// A sender, receiver and forwarder of onion messages. In upcoming releases, this object will be
/// used to retrieve invoices and fulfill invoice requests from [offers].
///
/// [offers]: https://github.com/lightning/bolts/pull/798
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

	/// Send an empty onion message to `destination`, routing it through `intermediate_nodes`.
	pub fn send_onion_message(&self, intermediate_nodes: Vec<PublicKey>, destination: Destination) -> Result<(), SendError> {
		if let Destination::BlindedRoute(BlindedRoute { ref blinded_hops, .. }) = destination {
			if blinded_hops.len() == 0 {
				return Err(SendError::InvalidDestination("Blinded routes can't have 0 hops"));
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
		let (encrypted_data_keys, onion_packet_keys) = construct_sending_keys(
			&self.secp_ctx, &intermediate_nodes, &destination, &blinding_secret)
			.map_err(|e| SendError::Secp256k1(e))?;
		let payloads = build_payloads(intermediate_nodes, destination, encrypted_data_keys);

		// Check whether the onion message is too big to send.
		let payloads_serialized_len = payloads.iter()
			.fold(0, |total, next_payload| total + next_payload.serialized_length() + 32 /* HMAC */ );
		if payloads_serialized_len > BIG_PACKET_HOP_DATA_LEN {
			return Err(SendError::TooBigPacket)
		}

		let prng_seed = self.keys_manager.get_secure_random_bytes();
		let onion_packet = onion_utils::construct_onion_message_packet(payloads, onion_packet_keys, prng_seed);

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
	fn handle_onion_message(&self, _peer_node_id: &PublicKey, msg: &msgs::OnionMessage) {
		let node_secret = match self.keys_manager.get_node_secret(Recipient::Node) {
			Ok(secret) => secret,
			Err(e) => {
				log_trace!(self.logger, "Failed to retrieve node secret: {:?}", e);
				return
			}
		};
		let encrypted_data_ss = SharedSecret::new(&msg.blinding_point, &node_secret);
		let onion_decode_shared_secret = {
			let blinding_factor = {
				let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
				hmac.input(encrypted_data_ss.as_ref());
				Hmac::from_engine(hmac).into_inner()
			};
			let mut blinded_priv = node_secret.clone();
			if let Err(e) = blinded_priv.mul_assign(&blinding_factor) {
				log_trace!(self.logger, "Failed to compute blinded public key: {}", e);
				return
			}
			SharedSecret::new(&msg.onion_routing_packet.public_key, &blinded_priv).secret_bytes()
		};
		match onion_utils::decode_next_message_hop(onion_decode_shared_secret, &msg.onion_routing_packet.hop_data[..], msg.onion_routing_packet.hmac, encrypted_data_ss) {
			Ok(onion_utils::MessageHop::Receive(Payload {
				encrypted_tlvs: EncryptedTlvs::Unblinded(ControlTlvs::Receive { path_id })
			})) => {
				log_info!(self.logger, "Received an onion message with path_id: {:02x?}", path_id);
			},
			Ok(onion_utils::MessageHop::Forward {
				next_hop_data: Payload {
					encrypted_tlvs: EncryptedTlvs::Unblinded(ControlTlvs::Receive { path_id }),
				}, .. }) => {
				// We received an onion message that had fake extra hops at the end of its blinded route.
				// TODO support adding extra hops to blinded routes and test this case
				log_info!(self.logger, "Received an onion message with path_id: {:02x?}", path_id);
			},
			Ok(onion_utils::MessageHop::Forward {
				next_hop_data: Payload {
					encrypted_tlvs: EncryptedTlvs::Unblinded(ControlTlvs::Forward { next_node_id, next_blinding_override }),
				},
				next_hop_hmac, new_packet_bytes
			}) => {
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
									sha.input(encrypted_data_ss.as_ref());
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
			_ => {} // Unreachable unless someone encodes a `Forward` payload as the final payload, which
			        // is bogus and should be fine to drop
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

/// Build an onion message's payloads for encoding in the onion packet.
fn build_payloads(intermediate_nodes: Vec<PublicKey>, destination: Destination, mut encrypted_tlvs_keys: Vec<[u8; 32]>) -> Vec<(Payload, [u8; 32])> {
	let num_intermediate_nodes = intermediate_nodes.len();
	let num_payloads = num_intermediate_nodes + destination.num_hops();
	assert_eq!(encrypted_tlvs_keys.len(), num_payloads);
	let mut payloads = Vec::with_capacity(num_payloads);
	let mut enc_tlv_keys = encrypted_tlvs_keys.drain(..);
	for pk in intermediate_nodes.into_iter().skip(1) {
		payloads.push((Payload {
			encrypted_tlvs: EncryptedTlvs::Unblinded(ControlTlvs::Forward {
				next_node_id: pk,
				next_blinding_override: None,
			})
		}, enc_tlv_keys.next().unwrap()));
	}
	match destination {
		Destination::Node(pk) => {
			if num_intermediate_nodes != 0 {
				payloads.push((Payload {
					encrypted_tlvs: EncryptedTlvs::Unblinded(ControlTlvs::Forward {
						next_node_id: pk,
						next_blinding_override: None,
					})
				}, enc_tlv_keys.next().unwrap()));
			}
			payloads.push((Payload {
				encrypted_tlvs: EncryptedTlvs::Unblinded(ControlTlvs::Receive {
					path_id: None,
				})
			}, enc_tlv_keys.next().unwrap()));
		},
		Destination::BlindedRoute(BlindedRoute { introduction_node_id, blinding_point, blinded_hops }) => {
			if num_intermediate_nodes != 0 {
				payloads.push((Payload {
					encrypted_tlvs: EncryptedTlvs::Unblinded(ControlTlvs::Forward {
						next_node_id: introduction_node_id,
						next_blinding_override: Some(blinding_point),
					})
				}, enc_tlv_keys.next().unwrap()));
			}
			for hop in blinded_hops {
				payloads.push((Payload {
					encrypted_tlvs: EncryptedTlvs::Blinded(hop.encrypted_payload),
				}, enc_tlv_keys.next().unwrap()));
			}
		}
	}
	payloads
}

#[inline]
fn construct_keys_callback<
	T: secp256k1::Signing + secp256k1::Verification,
	FType: FnMut(PublicKey, SharedSecret, [u8; 32], PublicKey, [u8; 32])>
	(secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, destination: Option<&Destination>, session_priv: &SecretKey, mut callback: FType)
	-> Result<(), secp256k1::Error> {
	let mut msg_blinding_point_priv = session_priv.clone();
	let mut msg_blinding_point = PublicKey::from_secret_key(secp_ctx, &msg_blinding_point_priv);
	let mut onion_packet_pubkey_priv = msg_blinding_point_priv.clone();
	let mut onion_packet_pubkey = msg_blinding_point.clone();

	macro_rules! build_keys {
		($pk: expr, $blinded: expr) => {{
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
			(encrypted_data_ss, onion_packet_ss)
		}}
	}

	macro_rules! build_keys_in_loop {
		($pk: expr, $blinded: expr) => {
			let (encrypted_data_ss, onion_packet_ss) = build_keys!($pk, $blinded);

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
		build_keys_in_loop!(pk, false);
	}
	if let Some(dest) = destination {
		match dest {
			Destination::Node(pk) => {
				build_keys!(pk, false);
			},
			Destination::BlindedRoute(BlindedRoute { blinded_hops, .. }) => {
				for hop in blinded_hops {
					build_keys_in_loop!(hop.blinded_node_id, true);
				}
			},
		}
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

	construct_keys_callback(secp_ctx, unblinded_path, None, session_priv, |blinded_hop_pubkey, _, _, _, encrypted_data_ss| {
		blinded_node_pks.push(blinded_hop_pubkey);
		encrypted_data_keys.push(encrypted_data_ss);
	})?;

	Ok((encrypted_data_keys, blinded_node_pks))
}

/// Construct keys for sending an onion message along the given `path`.
///
/// Returns: `(encrypted_tlvs_keys, onion_packet_keys)`
/// where the encrypted tlvs keys are used to encrypt the [`EncryptedTlvs`] of the onion message and the
/// onion packet keys are used to encrypt the onion packet.
fn construct_sending_keys<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, destination: &Destination, session_priv: &SecretKey
) -> Result<(Vec<[u8; 32]>, Vec<onion_utils::OnionKeys>), secp256k1::Error> {
	let num_hops = unblinded_path.len() + destination.num_hops();
	let mut encrypted_data_keys = Vec::with_capacity(num_hops);
	let mut onion_packet_keys = Vec::with_capacity(num_hops);

	construct_keys_callback(secp_ctx, unblinded_path, Some(destination), session_priv, |_, onion_packet_ss, _blinding_factor, ephemeral_pubkey, encrypted_data_ss| {
		encrypted_data_keys.push(encrypted_data_ss);

		let (rho, mu) = onion_utils::gen_rho_mu_from_shared_secret(onion_packet_ss.as_ref());
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

	Ok((encrypted_data_keys, onion_packet_keys))
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

#[cfg(test)]
mod tests {
	use chain::keysinterface::{KeysInterface, Recipient};
	use ln::msgs::OnionMessageHandler;
	use onion_message::{BlindedRoute, Destination, OnionMessenger};
	use util::enforcing_trait_impls::EnforcingSigner;
	use util::events::{MessageSendEvent, MessageSendEventsProvider};
	use util::test_utils;

	use bitcoin::network::constants::Network;
	use bitcoin::secp256k1::{PublicKey, Secp256k1};

	use sync::Arc;

	struct MessengerNode {
		keys_manager: Arc<test_utils::TestKeysInterface>,
		messenger: OnionMessenger<EnforcingSigner, Arc<test_utils::TestKeysInterface>, Arc<test_utils::TestLogger>>,
		logger: Arc<test_utils::TestLogger>,
	}

	impl MessengerNode {
		fn get_node_pk(&self) -> PublicKey {
			let secp_ctx = Secp256k1::new();
			PublicKey::from_secret_key(&secp_ctx, &self.keys_manager.get_node_secret(Recipient::Node).unwrap())
		}
	}

	fn create_nodes(num_messengers: u8) -> Vec<MessengerNode> {
		let mut res = Vec::new();
		for i in 0..num_messengers {
			let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
			let seed = [i as u8; 32];
			let keys_manager = Arc::new(test_utils::TestKeysInterface::new(&seed, Network::Testnet));
			res.push(MessengerNode {
				keys_manager: keys_manager.clone(),
				messenger: OnionMessenger::new(keys_manager, logger.clone()),
				logger,
			});
		}
		res
	}

	fn pass_along_path(path: Vec<&MessengerNode>, expected_path_id: Option<[u8; 32]>) {
		let mut prev_node = path[0];
		for (idx, node) in path.iter().enumerate().skip(1) {
			let events = prev_node.messenger.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			let onion_msg = match &events[0] {
				MessageSendEvent::SendOnionMessage { msg, .. } => msg.clone(),
				_ => panic!("Unexpected event"),
			};
			node.messenger.handle_onion_message(&prev_node.get_node_pk(), &onion_msg);
			if idx == path.len() - 1 {
				node.logger.assert_log_contains(
					"lightning::onion_message".to_string(),
					format!("Received an onion message with path_id: {:02x?}", expected_path_id).to_string(), 1);
				break
			}
			prev_node = node;
		}
	}

	#[test]
	fn one_hop() {
		let mut nodes = create_nodes(2);
		let (node1, node2) = (nodes.remove(0), nodes.remove(0));

		node1.messenger.send_onion_message(vec![], Destination::Node(node2.get_node_pk())).unwrap();
		pass_along_path(vec![&node1, &node2], None);
	}

	#[test]
	fn two_unblinded_hops() {
		let mut nodes = create_nodes(3);
		let (node1, node2, node3) = (nodes.remove(0), nodes.remove(0), nodes.remove(0));

		node1.messenger.send_onion_message(vec![node2.get_node_pk()], Destination::Node(node3.get_node_pk())).unwrap();
		pass_along_path(vec![&node1, &node2, &node3], None);
	}

	#[test]
	fn two_unblinded_two_blinded() {
		let mut nodes = create_nodes(5);
		let (node1, node2, node3, node4, node5) = (nodes.remove(0), nodes.remove(0), nodes.remove(0), nodes.remove(0), nodes.remove(0));

		let secp_ctx = Secp256k1::new();
		let blinded_route = BlindedRoute::new(vec![node4.get_node_pk(), node5.get_node_pk()], &node5.keys_manager, &secp_ctx).unwrap();

		node1.messenger.send_onion_message(vec![node2.get_node_pk(), node3.get_node_pk()], Destination::BlindedRoute(blinded_route)).unwrap();
		pass_along_path(vec![&node1, &node2, &node3, &node4, &node5], None);
	}

	#[test]
	fn three_blinded_hops() {
		let mut nodes = create_nodes(4);
		let (node1, node2, node3, node4) = (nodes.remove(0), nodes.remove(0), nodes.remove(0), nodes.remove(0));

		let secp_ctx = Secp256k1::new();
		let blinded_route = BlindedRoute::new(vec![node2.get_node_pk(), node3.get_node_pk(), node4.get_node_pk()], &node4.keys_manager, &secp_ctx).unwrap();

		node1.messenger.send_onion_message(vec![], Destination::BlindedRoute(blinded_route)).unwrap();
		pass_along_path(vec![&node1, &node2, &node3, &node4], None);
	}
}
