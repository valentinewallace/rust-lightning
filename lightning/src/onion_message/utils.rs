// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Onion message utility methods live here.

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
use bitcoin::secp256k1::ecdh::SharedSecret;

use ln::onion_utils;
use super::messenger::Destination;
use super::packet::{ForwardControlTlvs, Payload, ReceiveControlTlvs};
use super::blinded_route::{BlindedRoute, ForwardTlvs, ReceiveTlvs};

use prelude::*;

/// Build an onion message's payloads for encoding in the onion packet.
pub(super) fn build_payloads(intermediate_nodes: Vec<PublicKey>, destination: Destination, reply_path: Option<BlindedRoute>, mut encrypted_tlvs_keys: Vec<[u8; 32]>) -> Vec<(Payload, [u8; 32])> {
	let num_intermediate_nodes = intermediate_nodes.len();
	let num_payloads = num_intermediate_nodes + destination.num_hops();
	debug_assert_eq!(encrypted_tlvs_keys.len(), num_payloads);
	let mut payloads = Vec::with_capacity(num_payloads);
	let mut enc_tlv_keys = encrypted_tlvs_keys.drain(..);
	for pk in intermediate_nodes.into_iter().skip(1) {
		payloads.push((Payload::Forward(ForwardControlTlvs::Unblinded(
			ForwardTlvs {
				next_node_id: pk,
				next_blinding_override: None,
			}
		)), enc_tlv_keys.next().unwrap()));
	}
	match destination {
		Destination::Node(pk) => {
			if num_intermediate_nodes != 0 {
				payloads.push((Payload::Forward(ForwardControlTlvs::Unblinded(
					ForwardTlvs {
						next_node_id: pk,
						next_blinding_override: None,
					}
				)), enc_tlv_keys.next().unwrap()));
			}
			payloads.push((Payload::Receive {
				control_tlvs: ReceiveControlTlvs::Unblinded(ReceiveTlvs { path_id: None }),
				reply_path,
			}, enc_tlv_keys.next().unwrap()));
		},
		Destination::BlindedRoute(BlindedRoute { introduction_node_id, blinding_point, mut blinded_hops }) => {
			if num_intermediate_nodes != 0 {
				payloads.push((Payload::Forward(ForwardControlTlvs::Unblinded(
					ForwardTlvs {
						next_node_id: introduction_node_id,
						next_blinding_override: Some(blinding_point),
					}
				)), enc_tlv_keys.next().unwrap()));
			}
			let num_hops = blinded_hops.len();
			let mut hops = blinded_hops.drain(..);
			let mut idx = 0;
			while idx != num_hops - 1 {
				payloads.push((Payload::Forward(ForwardControlTlvs::Blinded(hops.next().unwrap().encrypted_payload)),
				enc_tlv_keys.next().unwrap()));
				idx += 1;
			}
			payloads.push((Payload::Receive {
				control_tlvs: ReceiveControlTlvs::Blinded(hops.next().unwrap().encrypted_payload),
				reply_path,
			}, enc_tlv_keys.next().unwrap()));
		}
	}
	payloads
}

#[inline]
fn construct_keys_callback<T: secp256k1::Signing + secp256k1::Verification,
	FType: FnMut(PublicKey, SharedSecret, [u8; 32], PublicKey, [u8; 32])>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, destination: Option<&Destination>,
	session_priv: &SecretKey, mut callback: FType
) -> Result<(), secp256k1::Error> {
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
/// Returns: `(encrypted_payload_keys, blinded_node_ids)`
/// where the former are for encrypting [`super::BlindedHop::encrypted_payload`] and the latter for
/// [`super::BlindedHop::blinded_node_id`].
pub(super) fn construct_blinded_route_keys<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, session_priv: &SecretKey
) -> Result<(Vec<[u8; 32]>, Vec<PublicKey>), secp256k1::Error> {
	let mut encrypted_payload_keys = Vec::with_capacity(unblinded_path.len());
	let mut blinded_node_pks = Vec::with_capacity(unblinded_path.len());

 	construct_keys_callback(secp_ctx, unblinded_path, None, session_priv, |blinded_hop_pubkey, _, _, _, encrypted_payload_ss| {
		blinded_node_pks.push(blinded_hop_pubkey);
		encrypted_payload_keys.push(encrypted_payload_ss);
	})?;

	Ok((encrypted_payload_keys, blinded_node_pks))
}

/// Construct keys for sending an onion message along the given `unblinded_path` to the given
/// `destination`.
///
/// Returns: `(control_tlvs_keys, onion_packet_keys)`
/// where the former are for encrypting the control TLVs of the onion message and the latter for
/// encrypting the onion packet.
pub(super) fn construct_sending_keys<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, destination: &Destination, session_priv: &SecretKey
) -> Result<(Vec<[u8; 32]>, Vec<onion_utils::OnionKeys>), secp256k1::Error> {
	let num_hops = unblinded_path.len() + destination.num_hops();
	let mut control_tlvs_keys = Vec::with_capacity(num_hops);
	let mut onion_packet_keys = Vec::with_capacity(num_hops);

	construct_keys_callback(secp_ctx, unblinded_path, Some(destination), session_priv, |_, onion_packet_ss, _blinding_factor, ephemeral_pubkey, control_tlvs_ss| {
		control_tlvs_keys.push(control_tlvs_ss);

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

	Ok((control_tlvs_keys, onion_packet_keys))
}
