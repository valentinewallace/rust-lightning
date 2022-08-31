// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `offer` messages.

use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hash_types::BlockHash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::PublicKey;
use core::time::Duration;
use ln::features::OfferFeatures;
use util::ser::WithLength;

use prelude::*;

#[cfg(feature = "std")]
use std::time::SystemTime;


///
#[derive(Clone, Debug)]
pub struct Offer {
	bytes: Vec<u8>,
	contents: OfferContents,
}

///
#[derive(Clone, Debug)]
pub(crate) struct OfferContents {
	chains: Option<Vec<BlockHash>>,
	metadata: Option<Vec<u8>>,
	amount: Option<Amount>,
	description: String,
	features: Option<OfferFeatures>,
	absolute_expiry: Option<Duration>,
	issuer: Option<String>,
	paths: Option<Vec<BlindedPath>>,
	quantity_min: Option<u64>,
	quantity_max: Option<u64>,
	node_id: Option<PublicKey>,
}

impl Offer {
	///
	pub fn chain(&self) -> BlockHash {
		// TODO: Update once spec is finalized
		self.contents.chains
			.as_ref()
			.and_then(|chains| chains.first().copied())
			.unwrap_or_else(|| genesis_block(Network::Bitcoin).block_hash())
	}

	///
	pub fn metadata(&self) -> Option<&Vec<u8>> {
		self.contents.metadata.as_ref()
	}

	///
	pub fn amount(&self) -> Option<&Amount> {
		self.contents.amount.as_ref()
	}

	///
	pub fn description(&self) -> &String {
		&self.contents.description
	}

	///
	pub fn features(&self) -> Option<&OfferFeatures> {
		self.contents.features.as_ref()
	}

	///
	pub fn absolute_expiry(&self) -> Option<Duration> {
		self.contents.absolute_expiry
	}

	///
	#[cfg(feature = "std")]
	pub fn is_expired(&self) -> bool {
		match self.absolute_expiry() {
			Some(seconds_from_epoch) => match SystemTime::UNIX_EPOCH.elapsed() {
				Ok(elapsed) => elapsed > seconds_from_epoch,
				Err(_) => false,
			},
			None => false,
		}
	}

	///
	pub fn issuer(&self) -> Option<&String> {
		self.contents.issuer.as_ref()
	}

	///
	pub fn paths(&self) -> Option<&Vec<BlindedPath>> {
		self.contents.paths.as_ref()
	}

	///
	pub fn quantity_min(&self) -> u64 {
		self.contents.quantity_min.unwrap_or(1)
	}

	///
	pub fn quantity_max(&self) -> u64 {
		self.contents.quantity_max.unwrap_or_else(||
			self.contents.quantity_min.map_or(1, |_| u64::max_value()))
	}

	///
	pub fn node_id(&self) -> PublicKey {
		self.contents.node_id.unwrap_or_else(||
			self.contents.paths.as_ref().unwrap().first().unwrap().path.0.last().unwrap().node_id)
	}
}

/// The amount required for an item in an [`Offer`] denominated in either bitcoin or another
/// currency.
#[derive(Clone, Debug)]
pub enum Amount {
	/// An amount of bitcoin.
	Bitcoin {
		/// The amount in millisatoshi.
		amount_msats: u64,
	},
	/// An amount of currency specified using ISO 4712.
	Currency {
		/// The currency that the amount is denominated in.
		iso4217_code: CurrencyCode,
		/// The amount in the currency unit adjusted by the ISO 4712 exponent (e.g., USD cents).
		amount: u64,
	},
}

/// An ISO 4712 three-letter currency code (e.g., USD).
pub type CurrencyCode = [u8; 3];

#[derive(Clone, Debug)]
///
pub struct BlindedPath {
	blinding: PublicKey,
	path: WithLength<Vec<OnionMessagePath>, u8>,
}

#[derive(Clone, Debug)]
struct OnionMessagePath {
	node_id: PublicKey,
	encrypted_recipient_data: Vec<u8>,
}
