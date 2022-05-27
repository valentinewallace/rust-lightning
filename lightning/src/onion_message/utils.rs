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

use prelude::*;

#[inline]
fn construct_keys_callback<T: secp256k1::Signing + secp256k1::Verification,
	FType: FnMut(PublicKey, SharedSecret, [u8; 32], PublicKey, [u8; 32])>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>,
	session_priv: &SecretKey, mut callback: FType
) -> Result<(), secp256k1::Error> {
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
/// Returns: `(encrypted_payload_keys, blinded_node_ids)`
/// where the former are for encrypting [`super::BlindedHop::encrypted_payload`] and the latter for
/// [`super::BlindedHop::blinded_node_id`].
pub(super) fn construct_blinded_route_keys<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, session_priv: &SecretKey
) -> Result<(Vec<[u8; 32]>, Vec<PublicKey>), secp256k1::Error> {
	let mut encrypted_payload_keys = Vec::with_capacity(unblinded_path.len());
	let mut blinded_node_pks = Vec::with_capacity(unblinded_path.len());

	construct_keys_callback(secp_ctx, unblinded_path, session_priv, |blinded_hop_pubkey, _, _, _, encrypted_payload_ss| {
		blinded_node_pks.push(blinded_hop_pubkey);
		encrypted_payload_keys.push(encrypted_payload_ss);
	})?;

	Ok((encrypted_payload_keys, blinded_node_pks))
}
