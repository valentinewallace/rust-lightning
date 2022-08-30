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
use core::convert::TryFrom;
use core::num::NonZeroU64;
use core::ops::{Bound, RangeBounds};
use core::str::FromStr;
use core::time::Duration;
use io;
use ln::features::OfferFeatures;
use offers::parse::{Bech32Encode, ParseError, SemanticError};
use util::ser::{WithLength, Writeable, Writer};

use prelude::*;

#[cfg(feature = "std")]
use std::time::SystemTime;

///
pub struct OfferBuilder {
	offer: OfferContents,
}

impl OfferBuilder {
	///
	pub fn new(description: String, node_id: PublicKey) -> Self {
		let offer = OfferContents {
			chains: None, metadata: None, amount: None, description, features: None,
			absolute_expiry: None, issuer: None, paths: None, quantity_min: None,
			quantity_max: None, node_id: Some(node_id),
		};
		OfferBuilder { offer }
	}

	///
	pub fn chain(mut self, network: Network) -> Self {
		let chains = self.offer.chains.get_or_insert_with(Vec::new);
		let block_hash = genesis_block(network).block_hash();
		if !chains.contains(&block_hash) {
			chains.push(block_hash);
		}

		self
	}

	///
	pub fn metadata(mut self, metadata: Vec<u8>) -> Self {
		self.offer.metadata = Some(metadata);
		self
	}

	///
	pub fn amount(mut self, amount: Amount) -> Self {
		self.offer.amount = Some(amount);
		self
	}

	///
	pub fn features(mut self, features: OfferFeatures) -> Self {
		self.offer.features = Some(features);
		self
	}

	///
	pub fn absolute_expiry(mut self, absolute_expiry: Duration) -> Self {
		self.offer.absolute_expiry = Some(absolute_expiry);
		self
	}

	///
	pub fn issuer(mut self, issuer: String) -> Self {
		self.offer.issuer = Some(issuer);
		self
	}

	///
	pub fn path(mut self, path: BlindedPath) -> Self {
		self.offer.paths.get_or_insert_with(Vec::new).push(path);
		self
	}

	///
	pub fn quantity_fixed(mut self, quantity: NonZeroU64) -> Self {
		let quantity = Some(quantity.get()).filter(|quantity| *quantity != 1);
		self.offer.quantity_min = quantity;
		self.offer.quantity_max = quantity;
		self
	}

	///
	pub fn quantity_range<R: RangeBounds<NonZeroU64>>(mut self, quantity: R) -> Self {
		self.offer.quantity_min = match quantity.start_bound() {
			Bound::Included(n) => Some(n.get()),
			Bound::Excluded(_) => unreachable!(),
			Bound::Unbounded => Some(1),
		};
		self.offer.quantity_max = match quantity.end_bound() {
			Bound::Included(n) => Some(n.get()),
			Bound::Excluded(n) => Some(n.get() - 1),
			Bound::Unbounded => None,
		};

		// Use a minimal encoding whenever 1 can be inferred.
		if let Some(1) = self.offer.quantity_min {
			match self.offer.quantity_max {
				Some(1) => {
					self.offer.quantity_min = None;
					self.offer.quantity_max = None;
				},
				Some(_) => {
					self.offer.quantity_min = None;
				},
				None => {},
			}
		}

		// Assume quantity isn't supported if the range is empty.
		if self.offer.quantity_min() > self.offer.quantity_max() {
			self.offer.quantity_min = None;
			self.offer.quantity_max = None;
		}

		self
	}

	///
	pub fn build(self) -> Offer {
		let mut bytes = Vec::new();
		self.offer.write(&mut bytes).unwrap();

		Offer {
			bytes,
			contents: self.offer,
		}
	}
}

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
		self.contents.chain()
	}

	///
	pub fn metadata(&self) -> Option<&Vec<u8>> {
		self.contents.metadata.as_ref()
	}

	///
	pub fn amount(&self) -> Option<&Amount> {
		self.contents.amount()
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
		self.contents.quantity_min()
	}

	///
	pub fn quantity_max(&self) -> u64 {
		self.contents.quantity_max()
	}

	///
	pub fn is_valid_quantity(&self, quantity: u64) -> bool {
		self.contents.is_valid_quantity(quantity)
	}

	///
	pub fn node_id(&self) -> PublicKey {
		self.contents.node_id.unwrap()
	}

	#[cfg(test)]
	fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	#[cfg(test)]
	fn to_bytes(&self) -> Vec<u8> {
		let mut buffer = Vec::new();
		self.contents.write(&mut buffer).unwrap();
		buffer
	}

	#[cfg(test)]
	fn as_tlv_stream(&self) -> reference::OfferTlvStream {
		self.contents.as_tlv_stream()
	}
}

impl AsRef<[u8]> for Offer {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
	}
}

impl OfferContents {
	pub fn chain(&self) -> BlockHash {
		// TODO: Update once spec is finalized
		self.chains
			.as_ref()
			.and_then(|chains| chains.first().copied())
			.unwrap_or_else(|| genesis_block(Network::Bitcoin).block_hash())
	}

	pub fn amount(&self) -> Option<&Amount> {
		self.amount.as_ref()
	}

	pub fn quantity_min(&self) -> u64 {
		self.quantity_min.unwrap_or(1)
	}

	pub fn quantity_max(&self) -> u64 {
		self.quantity_max.unwrap_or_else(||
			self.quantity_min.map_or(1, |_| u64::max_value()))
	}

	pub fn is_valid_quantity(&self, quantity: u64) -> bool {
		if self.quantity_min.is_none() && self.quantity_max.is_none() {
			false
		} else {
			quantity >= self.quantity_min() && quantity <= self.quantity_max()
		}
	}

	fn as_tlv_stream(&self) -> reference::OfferTlvStream {
		let (currency, amount) = match &self.amount {
			None => (None, None),
			Some(Amount::Bitcoin { amount_msats }) => (None, Some(amount_msats.into())),
			Some(Amount::Currency { iso4217_code, amount }) => (
				Some(iso4217_code), Some(amount.into())
			),
		};

		reference::OfferTlvStream {
			chains: self.chains.as_ref().map(Into::into),
			metadata: self.metadata.as_ref().map(Into::into),
			currency,
			amount,
			description: Some((&self.description).into()),
			features: self.features.as_ref(),
			absolute_expiry: self.absolute_expiry.map(|duration| duration.as_secs().into()),
			paths: self.paths.as_ref().map(Into::into),
			issuer: self.issuer.as_ref().map(Into::into),
			quantity_min: self.quantity_min.map(Into::into),
			quantity_max: self.quantity_max.map(Into::into),
			node_id: self.node_id.as_ref(),
		}
	}
}

impl Writeable for OfferContents {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.as_tlv_stream().write(writer)
	}
}

/// The amount required for an item in an [`Offer`] denominated in either bitcoin or another
/// currency.
#[derive(Clone, Debug, PartialEq)]
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

tlv_stream!(struct OfferTlvStream {
	(2, chains: Vec<BlockHash>),
	(4, metadata: Vec<u8>),
	(6, currency: CurrencyCode),
	(8, amount: u64),
	(10, description: String),
	(12, features: OfferFeatures),
	(14, absolute_expiry: u64),
	(16, paths: Vec<BlindedPath>),
	(18, issuer: String),
	(20, quantity_min: u64),
	(22, quantity_max: u64),
	(24, node_id: PublicKey),
});

#[derive(Clone, Debug, PartialEq)]
///
pub struct BlindedPath {
	blinding: PublicKey,
	path: WithLength<Vec<OnionMessagePath>, u8>,
}

impl_writeable!(BlindedPath, { blinding, path });

#[derive(Clone, Debug, PartialEq)]
struct OnionMessagePath {
	node_id: PublicKey,
	encrypted_recipient_data: Vec<u8>,
}
impl_writeable!(OnionMessagePath, { node_id, encrypted_recipient_data });

impl Bech32Encode for Offer {
	type TlvStream = OfferTlvStream;

	const BECH32_HRP: &'static str = "lno";
}

impl FromStr for Offer {
	type Err = ParseError;

	fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
		let (tlv_stream, bytes) = Offer::from_bech32_str(s)?;
		let contents = OfferContents::try_from(tlv_stream)?;
		Ok(Offer { bytes, contents })
	}
}

impl TryFrom<OfferTlvStream> for OfferContents {
	type Error = SemanticError;

	fn try_from(tlv_stream: OfferTlvStream) -> Result<Self, Self::Error> {
		let OfferTlvStream {
			chains, metadata, currency, amount, description, features, absolute_expiry, paths,
			issuer, quantity_min, quantity_max, node_id,
		} = tlv_stream;

		let supported_chains = [
			genesis_block(Network::Bitcoin).block_hash(),
			genesis_block(Network::Testnet).block_hash(),
			genesis_block(Network::Signet).block_hash(),
			genesis_block(Network::Regtest).block_hash(),
		];
		let chains = match chains.map(Into::<Vec<_>>::into) {
			None => None,
			Some(chains) => match chains.first() {
				None => Some(chains),
				Some(chain) if supported_chains.contains(chain) => Some(chains),
				_ => return Err(SemanticError::UnsupportedChain),
			},
		};

		let metadata = metadata.map(Into::into);

		let amount = match (currency, amount.map(Into::into)) {
			(None, None) => None,
			(None, Some(amount_msats)) => Some(Amount::Bitcoin { amount_msats }),
			(Some(_), None) => return Err(SemanticError::UnexpectedCurrency),
			(Some(iso4217_code), Some(amount)) => Some(Amount::Currency { iso4217_code, amount }),
		};

		let description = match description {
			None => return Err(SemanticError::MissingDescription),
			Some(description) => description.into(),
		};

		let absolute_expiry = absolute_expiry
			.map(Into::into)
			.map(|seconds_from_epoch| Duration::from_secs(seconds_from_epoch));

		let issuer = issuer.map(Into::into);

		let paths = match paths.map(Into::<Vec<_>>::into) {
			Some(paths) if paths.is_empty() => return Err(SemanticError::MissingPaths),
			paths => paths,
		};

		let quantity_min = quantity_min.map(Into::into);
		let quantity_max = quantity_max.map(Into::into);
		if let Some(quantity_min) = quantity_min {
			if quantity_min < 1 {
				return Err(SemanticError::InvalidQuantity);
			}

			if let Some(quantity_max) = quantity_max {
				if quantity_min > quantity_max {
					return Err(SemanticError::InvalidQuantity);
				}
			}
		}

		if let Some(quantity_max) = quantity_max {
			if quantity_max < 1 {
				return Err(SemanticError::InvalidQuantity);
			}
		}

		if node_id.is_none() {
			return Err(SemanticError::MissingNodeId);
		}

		Ok(OfferContents {
			chains, metadata, amount, description, features, absolute_expiry, issuer, paths,
			quantity_min, quantity_max, node_id,
		})
	}
}

impl core::fmt::Display for Offer {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		self.fmt_bech32_str(f)
	}
}

#[cfg(test)]
mod tests {
	use super::{Amount, BlindedPath, OfferBuilder, OnionMessagePath};

	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::network::constants::Network;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use core::num::NonZeroU64;
	use core::time::Duration;
	use ln::features::OfferFeatures;

	fn pubkey() -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &privkey())
	}

	fn privkey() -> SecretKey {
		SecretKey::from_slice(&[42; 32]).unwrap()
	}

	fn blinded_pubkey(byte: u8) -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &blinded_privkey(byte))
	}

	fn blinded_privkey(byte: u8) -> SecretKey {
		SecretKey::from_slice(&[byte; 32]).unwrap()
	}

	#[test]
	fn builds_offer_with_defaults() {
		let offer = OfferBuilder::new("foo".into(), pubkey()).build();
		let tlv_stream = offer.as_tlv_stream();

		assert_eq!(offer.as_bytes(), &offer.to_bytes()[..]);
		assert_eq!(offer.chain(), genesis_block(Network::Bitcoin).block_hash());
		assert_eq!(offer.metadata(), None);
		assert_eq!(offer.amount(), None);
		assert_eq!(offer.description(), "foo");
		assert_eq!(offer.features(), None);
		assert_eq!(offer.absolute_expiry(), None);
		assert!(!offer.is_expired());
		assert_eq!(offer.paths(), None);
		assert_eq!(offer.issuer(), None);
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), 1);
		assert_eq!(offer.node_id(), pubkey());

		assert_eq!(tlv_stream.chains, None);
		assert_eq!(tlv_stream.metadata, None);
		assert_eq!(tlv_stream.currency, None);
		assert_eq!(tlv_stream.amount, None);
		assert_eq!(tlv_stream.description, Some((&String::from("foo")).into()));
		assert_eq!(tlv_stream.features, None);
		assert_eq!(tlv_stream.absolute_expiry, None);
		assert_eq!(tlv_stream.paths, None);
		assert_eq!(tlv_stream.issuer, None);
		assert_eq!(tlv_stream.quantity_min, None);
		assert_eq!(tlv_stream.quantity_max, None);
		assert_eq!(tlv_stream.node_id, Some(&pubkey()));
	}

	#[test]
	fn builds_offer_with_chains() {
		let block_hash = genesis_block(Network::Bitcoin).block_hash();
		let block_hashes = vec![
			genesis_block(Network::Bitcoin).block_hash(),
			genesis_block(Network::Testnet).block_hash(),
		];

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.chain(Network::Bitcoin)
			.build();
		assert_eq!(offer.chain(), block_hash);
		assert_eq!(offer.as_tlv_stream().chains, Some((&vec![block_hash]).into()));

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.chain(Network::Bitcoin)
			.chain(Network::Bitcoin)
			.build();
		assert_eq!(offer.chain(), block_hash);
		assert_eq!(offer.as_tlv_stream().chains, Some((&vec![block_hash]).into()));

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.chain(Network::Bitcoin)
			.chain(Network::Testnet)
			.build();
		assert_eq!(offer.chain(), block_hashes[0]);
		assert_eq!(offer.as_tlv_stream().chains, Some((&block_hashes).into()));
	}

	#[test]
	fn builds_offer_with_metadata() {
		let offer = OfferBuilder::new("foo".into(), pubkey())
			.metadata(vec![42; 32])
			.build();
		assert_eq!(offer.metadata(), Some(&vec![42; 32]));
		assert_eq!(offer.as_tlv_stream().metadata, Some((&vec![42; 32]).into()));

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.metadata(vec![42; 32])
			.metadata(vec![43; 32])
			.build();
		assert_eq!(offer.metadata(), Some(&vec![43; 32]));
		assert_eq!(offer.as_tlv_stream().metadata, Some((&vec![43; 32]).into()));
	}

	#[test]
	fn builds_offer_with_amount() {
		let bitcoin_amount = Amount::Bitcoin { amount_msats: 1000 };
		let currency_amount = Amount::Currency { iso4217_code: *b"USD", amount: 10 };

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.amount(bitcoin_amount.clone())
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.amount(), Some(&bitcoin_amount));
		assert_eq!(tlv_stream.amount, Some(1000.into()));
		assert_eq!(tlv_stream.currency, None);

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.amount(currency_amount.clone())
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.amount(), Some(&currency_amount));
		assert_eq!(tlv_stream.amount, Some(10.into()));
		assert_eq!(tlv_stream.currency, Some(b"USD"));

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.amount(currency_amount.clone())
			.amount(bitcoin_amount.clone())
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(tlv_stream.amount, Some(1000.into()));
		assert_eq!(tlv_stream.currency, None);
	}

	#[test]
	fn builds_offer_with_features() {
		let offer = OfferBuilder::new("foo".into(), pubkey())
			.features(OfferFeatures::known())
			.build();
		assert_eq!(offer.features(), Some(&OfferFeatures::known()));
		assert_eq!(offer.as_tlv_stream().features, Some(&OfferFeatures::known()));

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.features(OfferFeatures::known())
			.features(OfferFeatures::empty())
			.build();
		assert_eq!(offer.features(), Some(&OfferFeatures::empty()));
		assert_eq!(offer.as_tlv_stream().features, Some(&OfferFeatures::empty()));
	}

	#[test]
	fn builds_offer_with_absolute_expiry() {
		let future_expiry = Duration::from_secs(u64::max_value());
		let past_expiry = Duration::from_secs(0);

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.absolute_expiry(future_expiry)
			.build();
		assert!(!offer.is_expired());
		assert_eq!(offer.absolute_expiry(), Some(future_expiry));
		assert_eq!(offer.as_tlv_stream().absolute_expiry, Some(future_expiry.as_secs().into()));

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.absolute_expiry(future_expiry)
			.absolute_expiry(past_expiry)
			.build();
		assert!(offer.is_expired());
		assert_eq!(offer.absolute_expiry(), Some(past_expiry));
		assert_eq!(offer.as_tlv_stream().absolute_expiry, Some(past_expiry.as_secs().into()));
	}

	#[test]
	fn builds_offer_with_paths() {
		// TODO: Use more realistic data
		let paths = vec![
			BlindedPath {
				blinding: pubkey(),
				path: vec![
					OnionMessagePath {
						node_id: blinded_pubkey(43), encrypted_recipient_data: vec![0; 43],
					},
					OnionMessagePath {
						node_id: blinded_pubkey(44), encrypted_recipient_data: vec![0; 44],
					},
				].into(),
			},
			BlindedPath {
				blinding: pubkey(),
				path: vec![
					OnionMessagePath {
						node_id: blinded_pubkey(45), encrypted_recipient_data: vec![0; 45],
					},
					OnionMessagePath {
						node_id: blinded_pubkey(46), encrypted_recipient_data: vec![0; 46],
					},
				].into(),
			},
		];

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.path(paths[0].clone())
			.path(paths[1].clone())
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.paths(), Some(&paths));
		assert_eq!(offer.node_id(), pubkey());
		assert_ne!(pubkey(), blinded_pubkey(44));
		assert_eq!(tlv_stream.paths, Some((&paths).into()));
		assert_eq!(tlv_stream.node_id, Some(&pubkey()));
	}

	#[test]
	fn builds_offer_with_issuer() {
		let offer = OfferBuilder::new("foo".into(), pubkey())
			.issuer("bar".into())
			.build();
		assert_eq!(offer.issuer(), Some(&String::from("bar")));
		assert_eq!(offer.as_tlv_stream().issuer, Some((&String::from("bar")).into()));

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.issuer("bar".into())
			.issuer("baz".into())
			.build();
		assert_eq!(offer.issuer(), Some(&String::from("baz")));
		assert_eq!(offer.as_tlv_stream().issuer, Some((&String::from("baz")).into()));
	}

	#[test]
	fn builds_offer_with_fixed_quantity() {
		let one = NonZeroU64::new(1).unwrap();
		let five = NonZeroU64::new(5).unwrap();
		let ten = NonZeroU64::new(10).unwrap();

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.quantity_fixed(one)
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), 1);
		assert_eq!(tlv_stream.quantity_min, None);
		assert_eq!(tlv_stream.quantity_max, None);

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.quantity_fixed(ten)
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 10);
		assert_eq!(offer.quantity_max(), 10);
		assert_eq!(tlv_stream.quantity_min, Some(10.into()));
		assert_eq!(tlv_stream.quantity_max, Some(10.into()));

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.quantity_fixed(ten)
			.quantity_fixed(five)
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 5);
		assert_eq!(offer.quantity_max(), 5);
		assert_eq!(tlv_stream.quantity_min, Some(5.into()));
		assert_eq!(tlv_stream.quantity_max, Some(5.into()));

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.quantity_range(..ten)
			.quantity_fixed(five)
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 5);
		assert_eq!(offer.quantity_max(), 5);
		assert_eq!(tlv_stream.quantity_min, Some(5.into()));
		assert_eq!(tlv_stream.quantity_max, Some(5.into()));
	}

	#[test]
	fn builds_offer_with_quantity_range() {
		let one = NonZeroU64::new(1).unwrap();
		let five = NonZeroU64::new(5).unwrap();
		let ten = NonZeroU64::new(10).unwrap();

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.quantity_range(..)
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), u64::max_value());
		assert_eq!(tlv_stream.quantity_min, Some(1.into()));
		assert_eq!(tlv_stream.quantity_max, None);

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.quantity_range(..ten)
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), 9);
		assert_eq!(tlv_stream.quantity_min, None);
		assert_eq!(tlv_stream.quantity_max, Some(9.into()));

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.quantity_range(one..ten)
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), 9);
		assert_eq!(tlv_stream.quantity_min, None);
		assert_eq!(tlv_stream.quantity_max, Some(9.into()));

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.quantity_range(five..=ten)
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 5);
		assert_eq!(offer.quantity_max(), 10);
		assert_eq!(tlv_stream.quantity_min, Some(5.into()));
		assert_eq!(tlv_stream.quantity_max, Some(10.into()));

		let one = NonZeroU64::new(1).unwrap();
		let offer = OfferBuilder::new("foo".into(), pubkey())
			.quantity_range(one..=one)
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), 1);
		assert_eq!(tlv_stream.quantity_min, None);
		assert_eq!(tlv_stream.quantity_max, None);

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.quantity_range(five..=five)
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 5);
		assert_eq!(offer.quantity_max(), 5);
		assert_eq!(tlv_stream.quantity_min, Some(5.into()));
		assert_eq!(tlv_stream.quantity_max, Some(5.into()));

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.quantity_range(ten..five)
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), 1);
		assert_eq!(tlv_stream.quantity_min, None);
		assert_eq!(tlv_stream.quantity_max, None);

		let offer = OfferBuilder::new("foo".into(), pubkey())
			.quantity_fixed(five)
			.quantity_range(..ten)
			.build();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), 9);
		assert_eq!(tlv_stream.quantity_min, None);
		assert_eq!(tlv_stream.quantity_max, Some(9.into()));
	}
}

#[cfg(test)]
mod bolt12_tests {
	use super::{Offer, ParseError};
	use bitcoin::bech32;
	use ln::msgs::DecodeError;

	#[test]
	fn encodes_offer_as_bech32_without_checksum() {
		let encoded_offer = "lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy";
		let offer = dbg!(encoded_offer.parse::<Offer>().unwrap());
		let reencoded_offer = offer.to_string();
		dbg!(reencoded_offer.parse::<Offer>().unwrap());
		assert_eq!(reencoded_offer, encoded_offer);
	}

	#[test]
	fn parses_bech32_encoded_offers() {
		let offers = [
			// BOLT 12 test vectors
			"lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
			"l+no1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
			"l+no1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
			"lno1qcp4256ypqpq+86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn0+0fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0+sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qs+y",
			"lno1qcp4256ypqpq+ 86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn0+  0fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0+\nsqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43l+\r\nastpwuh73k29qs+\r  y",
			// Two blinded paths
			"lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0yg06qg2qdd7t628sgykwj5kuc837qmlv9m9gr7sq8ap6erfgacv26nhp8zzcqgzhdvttlk22pw8fmwqqrvzst792mj35ypylj886ljkcmug03wg6heqqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6muh550qsfva9fdes0ruph7ctk2s8aqq06r4jxj3msc448wzwy9sqs9w6ckhlv55zuwnkuqqxc9qhu24h9rggzflyw04l9d3hcslzu340jqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
		];
		for encoded_offer in &offers {
			if let Err(e) = encoded_offer.parse::<Offer>() {
				panic!("Invalid offer ({:?}): {}", e, encoded_offer);
			}
		}
	}

	#[test]
	fn fails_parsing_bech32_encoded_offers_with_invalid_continuations() {
		let offers = [
			// BOLT 12 test vectors
			"lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy+",
			"lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy+ ",
			"+lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
			"+ lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
			"ln++o1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
		];
		for encoded_offer in &offers {
			match encoded_offer.parse::<Offer>() {
				Ok(_) => panic!("Valid offer: {}", encoded_offer),
				Err(e) => assert_eq!(e, ParseError::InvalidContinuation),
			}
		}

	}

	#[test]
	fn fails_parsing_bech32_encoded_offer_with_invalid_hrp() {
		let encoded_offer = "lni1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy";
		match encoded_offer.parse::<Offer>() {
			Ok(_) => panic!("Valid offer: {}", encoded_offer),
			Err(e) => assert_eq!(e, ParseError::InvalidBech32Hrp),
		}
	}

	#[test]
	fn fails_parsing_bech32_encoded_offer_with_invalid_bech32_data() {
		let encoded_offer = "lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qso";
		match encoded_offer.parse::<Offer>() {
			Ok(_) => panic!("Valid offer: {}", encoded_offer),
			Err(e) => assert_eq!(e, ParseError::Bech32(bech32::Error::InvalidChar('o'))),
		}
	}

	#[test]
	fn fails_parsing_bech32_encoded_offer_with_invalid_tlv_data() {
		let encoded_offer = "lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsyqqqqq";
		match encoded_offer.parse::<Offer>() {
			Ok(_) => panic!("Valid offer: {}", encoded_offer),
			Err(e) => assert_eq!(e, ParseError::Decode(DecodeError::InvalidValue)),
		}
	}
}
