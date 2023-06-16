//! Data structures and methods for constructing [`BlindedPath`]s to send a payment over.
//!
//! [`BlindedPath`]: crate::blinded_path::BlindedPath

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use crate::blinded_path::BlindedHop;
use crate::blinded_path::utils;
use crate::io;
use crate::ln::features::BlindedHopFeatures;
use crate::ln::msgs::DecodeError;
use crate::prelude::*;
use crate::util::ser::{Readable, Writeable, Writer};

/// Data to construct a [`BlindedHop`] for sending a payment over.
///
/// [`BlindedHop`]: crate::blinded_path::BlindedHop
pub enum BlindedPaymentTlvs {
	/// This blinded payment data is to be forwarded.
	Forward {
		/// The short channel id this payment is being forwarded over.
		short_channel_id: u64,
		/// Payment parameters for relaying over this channel.
		payment_relay: PaymentRelay,
		/// Payment constraints when relaying over this channel.
		payment_constraints: PaymentConstraints,
		/// Supported and required features when relaying a payment onion containing this object's
		/// corresponding [`BlindedHop`].
		///
		/// [`BlindedHop`]: crate::blinded_path::BlindedHop
		features: BlindedHopFeatures,
	},
	/// This blinded payment data is to be received.
	Receive {
		/// Used to identify the blinded path that this payment is sending to. This is useful for
		/// receivers to check that said blinded path is being used in the right context.
		path_id: Option<[u8; 32]>,
		/// Constraints for the receiver of this payment.
		payment_constraints: PaymentConstraints,
		/// Supported and required features when receiving a payment containing this object's
		/// corresponding [`BlindedHop`].
		///
		/// [`BlindedHop`]: crate::blinded_path::BlindedHop
		features: BlindedHopFeatures,
	},
}

/// Parameters for relaying over a given [`BlindedHop`].
///
/// [`BlindedHop`]: crate::blinded_path::BlindedHop
pub struct PaymentRelay {
	/// Number of blocks subtracted from an incoming HTLC's `cltv_expiry` for this [`BlindedHop`].
	///
	///[`BlindedHop`]: crate::blinded_path::BlindedHop
	pub cltv_expiry_delta: u16,
	/// Liquidity fee charged (in millionths of the amount transferred) for relaying a payment over
	/// this [`BlindedHop`], (i.e., 10,000 is 1%).
	///
	///[`BlindedHop`]: crate::blinded_path::BlindedHop
	pub fee_proportional_millionths: u32,
	/// Base fee charged (in millisatoshi) for relaying a payment over this [`BlindedHop`].
	///
	///[`BlindedHop`]: crate::blinded_path::BlindedHop
	pub fee_base_msat: u32,
}

/// Constraints for relaying over a given [`BlindedHop`].
///
/// [`BlindedHop`]: crate::blinded_path::BlindedHop
pub struct PaymentConstraints {
	/// The maximum total CLTV delta that is acceptable when relaying a payment over this
	/// [`BlindedHop`].
	///
	///[`BlindedHop`]: crate::blinded_path::BlindedHop
	pub max_cltv_expiry: u32,
	/// The minimum value, in msat, that may be relayed over this [`BlindedHop`].
	pub htlc_minimum_msat: u64,
}

impl Writeable for BlindedPaymentTlvs {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		// TODO: write padding
		match self {
			Self::Forward { short_channel_id, payment_relay, payment_constraints, features } => {
				encode_tlv_stream!(w, {
					(2, short_channel_id, required),
					(10, payment_relay, required),
					(12, payment_constraints, required),
					(14, features, required),
				});
			},
			Self::Receive { path_id, payment_constraints, features } => {
				encode_tlv_stream!(w, {
					(6, path_id, option),
					(12, payment_constraints, required),
					(14, features, required),
				});
			}
		}
		Ok(())
	}
}

impl Readable for BlindedPaymentTlvs {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		_init_and_decode_tlv_stream!(r, {
			(1, _padding, option),
			(2, scid, option),
			(6, path_id, option),
			(10, payment_relay, option),
			(12, payment_constraints, required),
			(14, features, required),
		});
		if let Some(short_channel_id) = scid {
			if path_id.is_some() { return Err(DecodeError::InvalidValue) }
			Ok(BlindedPaymentTlvs::Forward {
				short_channel_id,
				payment_relay: payment_relay.ok_or_else(|| DecodeError::InvalidValue)?,
				payment_constraints: payment_constraints.0.unwrap(),
				features: features.0.unwrap(),
			})
		} else {
			if payment_relay.is_some() { return Err(DecodeError::InvalidValue) }
			Ok(BlindedPaymentTlvs::Receive {
				path_id,
				payment_constraints: payment_constraints.0.unwrap(),
				features: features.0.unwrap(),
			})
		}
	}
}

/// Construct blinded payment hops for the given `unblinded_path`.
pub(super) fn blinded_hops<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &[(PublicKey, BlindedPaymentTlvs)], session_priv: &SecretKey
) -> Result<Vec<BlindedHop>, secp256k1::Error> {
	let mut blinded_hops = Vec::with_capacity(unblinded_path.len());
	let mut curr_hop_idx = 0;
	utils::construct_keys_callback(
		secp_ctx, unblinded_path.iter().map(|(pk, _)| pk), None, session_priv,
		|blinded_node_id, _, _, encrypted_payload_ss, _, _| {
			blinded_hops.push(BlindedHop {
				blinded_node_id,
				encrypted_payload: utils::encrypt_payload(&unblinded_path[curr_hop_idx].1, encrypted_payload_ss),
			});
			curr_hop_idx += 1;
		})?;
	Ok(blinded_hops)
}

impl_writeable_msg!(PaymentRelay, {
	cltv_expiry_delta,
	fee_proportional_millionths,
	fee_base_msat
}, {});

impl_writeable_msg!(PaymentConstraints, {
	max_cltv_expiry,
	htlc_minimum_msat
}, {});
