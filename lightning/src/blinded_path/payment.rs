//! Data structures and methods for constructing [`BlindedPath`]s to send a payment over.
//!
//! [`BlindedPath`]: crate::blinded_path::BlindedPath

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
use core::convert::TryFrom;
use crate::blinded_path::BlindedHop;
use crate::blinded_path::utils;
use crate::io;
use crate::ln::PaymentSecret;
use crate::ln::features::BlindedHopFeatures;
use crate::ln::msgs::DecodeError;
use crate::offers::invoice::BlindedPayInfo;
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
		/// Used to authenticate the sender of a payment to the receiver and tie MPP HTLCs together.
		payment_secret: PaymentSecret,
		/// Constraints for the receiver of this payment.
		payment_constraints: PaymentConstraints,
		/// Supported and required features when receiving a payment containing this object's
		/// corresponding [`BlindedHop`].
		///
		/// [`BlindedHop`]: crate::blinded_path::BlindedHop
		features: BlindedHopFeatures,
	},
}

impl BlindedPaymentTlvs {
	// The fee used to get from the current hop to the next hop in the path.
	fn fee_base_msat(&self) -> u32 {
		match self {
			Self::Forward { payment_relay, .. } => payment_relay.fee_base_msat,
			_ => 0,
		}
	}
	// The fee used to get from the current hop to the next hop in the path.
	fn fee_proportional_millionths(&self) -> u32 {
		match self {
			Self::Forward { payment_relay, .. } => payment_relay.fee_proportional_millionths,
			_ => 0,
		}
	}
	// The delta used to get from the current hop to the next hop in the path.
	fn cltv_expiry_delta(&self) -> u16 {
		match self {
			Self::Forward { payment_relay, .. } => payment_relay.cltv_expiry_delta,
			_ => 0,
		}
	}
	fn htlc_minimum_msat(&self) -> u64 {
		match self {
			Self::Forward { payment_constraints, .. } | Self::Receive { payment_constraints, .. } =>
				payment_constraints.htlc_minimum_msat,
		}
	}
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
			Self::Receive { payment_secret, payment_constraints, features } => {
				encode_tlv_stream!(w, {
					(6, payment_secret, required),
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
			(6, payment_secret, option),
			(10, payment_relay, option),
			(12, payment_constraints, required),
			(14, features, required),
		});
		if let Some(short_channel_id) = scid {
			if payment_secret.is_some() { return Err(DecodeError::InvalidValue) }
			Ok(BlindedPaymentTlvs::Forward {
				short_channel_id,
				payment_relay: payment_relay.ok_or(DecodeError::InvalidValue)?,
				payment_constraints: payment_constraints.0.unwrap(),
				features: features.0.unwrap(),
			})
		} else {
			if payment_relay.is_some() { return Err(DecodeError::InvalidValue) }
			Ok(BlindedPaymentTlvs::Receive {
				payment_secret: payment_secret.ok_or(DecodeError::InvalidValue)?,
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
		|blinded_node_id, _, _, encrypted_payload_rho, _, _| {
			blinded_hops.push(BlindedHop {
				blinded_node_id,
				encrypted_payload: utils::encrypt_payload(&unblinded_path[curr_hop_idx].1, encrypted_payload_rho),
			});
			curr_hop_idx += 1;
		})?;
	Ok(blinded_hops)
}

pub(super) fn compute_payinfo(
	path: &[(PublicKey, BlindedPaymentTlvs)]
) -> Result<BlindedPayInfo, ()> {
	let mut curr_base_fee: u128 = 0;
	let mut curr_prop_mil: u128 = 0;
	for (_, payment_tlvs) in path.iter().rev().skip(1) {
		let next_base_fee = payment_tlvs.fee_base_msat() as u128;
		let next_prop_mil = payment_tlvs.fee_proportional_millionths() as u128;
		curr_base_fee =
			((next_base_fee * 1_000_000 + (curr_base_fee * (1_000_000 + next_prop_mil))) + 1_000_000 - 1)
			 / 1_000_000;
		curr_prop_mil =
			(((curr_prop_mil + next_prop_mil) * 1_000_000 + curr_prop_mil * next_prop_mil) + 1_000_000 - 1)
			 / 1_000_000;
	}
	Ok(BlindedPayInfo {
		fee_base_msat: u32::try_from(curr_base_fee).map_err(|_| ())?,
		fee_proportional_millionths: u32::try_from(curr_prop_mil).map_err(|_| ())?,
		cltv_expiry_delta: path.iter().map(|(_, tlvs)| tlvs.cltv_expiry_delta())
			.try_fold(0u16, |acc, delta| acc.checked_add(delta)).ok_or(())?,
		htlc_minimum_msat: path.iter().map(|(_, tlvs)| tlvs.htlc_minimum_msat()).max().unwrap_or(0),
		// TODO: this field isn't present in route blinding encrypted data
		htlc_maximum_msat: 21_000_000 * 100_000_000 * 1_000, // Total bitcoin supply
		// TODO: when there are blinded hop features, take the subset of them here
		features: BlindedHopFeatures::empty(),
	})
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

#[cfg(test)]
mod tests {
	use bitcoin::secp256k1::PublicKey;
	use crate::blinded_path::payment::{BlindedPaymentTlvs, PaymentConstraints, PaymentRelay};
	use crate::ln::PaymentSecret;
	use crate::ln::features::BlindedHopFeatures;

	#[test]
	fn compute_payinfo() {
		// Taken from the spec example for aggregating blinded payment info.
		let dummy_pk = PublicKey::from_slice(&[2; 33]).unwrap();
		let path = vec![(dummy_pk, BlindedPaymentTlvs::Forward {
			short_channel_id: 0,
			payment_relay: PaymentRelay {
				cltv_expiry_delta: 144,
				fee_proportional_millionths: 500,
				fee_base_msat: 100,
			},
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: 0,
				htlc_minimum_msat: 100,
			},
			features: BlindedHopFeatures::empty(),
		}), (dummy_pk, BlindedPaymentTlvs::Forward {
			short_channel_id: 0,
			payment_relay: PaymentRelay {
				cltv_expiry_delta: 144,
				fee_proportional_millionths: 500,
				fee_base_msat: 100,
			},
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: 0,
				htlc_minimum_msat: 1_000,
			},
			features: BlindedHopFeatures::empty(),
		}), (dummy_pk, BlindedPaymentTlvs::Receive {
			payment_secret: PaymentSecret([0; 32]),
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: 0,
				htlc_minimum_msat: 1,
			},
			features: BlindedHopFeatures::empty(),
		})];
		let blinded_payinfo = super::compute_payinfo(&path[..]).unwrap();
		assert_eq!(blinded_payinfo.fee_base_msat, 201);
		assert_eq!(blinded_payinfo.fee_proportional_millionths, 1001);
		assert_eq!(blinded_payinfo.cltv_expiry_delta, 288);
		assert_eq!(blinded_payinfo.htlc_minimum_msat, 1_000);
	}

	#[test]
	fn compute_payinfo_1_hop() {
		let dummy_pk = PublicKey::from_slice(&[2; 33]).unwrap();
		let path = vec![(dummy_pk, BlindedPaymentTlvs::Receive {
			payment_secret: PaymentSecret([0; 32]),
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: 0,
				htlc_minimum_msat: 1,
			},
			features: BlindedHopFeatures::empty(),
		})];
		let blinded_payinfo = super::compute_payinfo(&path[..]).unwrap();
		assert_eq!(blinded_payinfo.fee_base_msat, 0);
		assert_eq!(blinded_payinfo.fee_proportional_millionths, 0);
		assert_eq!(blinded_payinfo.cltv_expiry_delta, 0);
		assert_eq!(blinded_payinfo.htlc_minimum_msat, 1);
	}
}
