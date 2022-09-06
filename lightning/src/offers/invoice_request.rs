// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_request` messages.

use bitcoin::hash_types::BlockHash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::schnorr::Signature;
use core::convert::TryFrom;
use core::str::FromStr;
use io;
use ln::features::OfferFeatures;
use offers::merkle::{SignatureTlvStream, self};
use offers::offer::{Amount, OfferContents, OfferTlvStream, self};
use offers::parse::{Bech32Encode, ParseError, SemanticError};
use offers::payer::{PayerContents, PayerTlvStream, self};
use util::ser::{Readable, WithoutLength, Writeable, Writer};

///
pub struct InvoiceRequest {
	bytes: Vec<u8>,
	contents: InvoiceRequestContents,
}

///
pub(crate) struct InvoiceRequestContents {
	payer: PayerContents,
	offer: OfferContents,
	chain: Option<BlockHash>,
	amount_msats: Option<u64>,
	features: Option<OfferFeatures>,
	quantity: Option<u64>,
	payer_id: PublicKey,
	payer_note: Option<String>,
	signature: Option<Signature>,
}

impl InvoiceRequest {
	///
	pub fn payer_info(&self) -> Option<&Vec<u8>> {
		self.contents.payer.0.as_ref()
	}

	///
	pub fn chain(&self) -> BlockHash {
		self.contents.chain.unwrap_or_else(|| self.contents.offer.chain())
	}

	///
	pub fn amount_msats(&self) -> Option<u64> {
		self.contents.amount_msats
	}

	///
	pub fn features(&self) -> Option<&OfferFeatures> {
		self.contents.features.as_ref()
	}

	///
	pub fn quantity(&self) -> Option<u64> {
		self.contents.quantity
	}

	///
	pub fn payer_id(&self) -> PublicKey {
		self.contents.payer_id
	}

	///
	pub fn payer_note(&self) -> Option<&String> {
		self.contents.payer_note.as_ref()
	}

	///
	pub fn signature(&self) -> Option<Signature> {
		self.contents.signature
	}
}

impl AsRef<[u8]> for InvoiceRequest {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
	}
}

impl InvoiceRequestContents {
	pub(super) fn as_tlv_stream(&self) -> ReferencedFullInvoiceRequestTlvStream {
		let payer = payer::reference::PayerTlvStream {
			payer_info: self.payer.0.as_ref().map(Into::into),
		};

		let offer = self.offer.as_tlv_stream();

		let invoice_request = reference::InvoiceRequestTlvStream {
			chain: self.chain.as_ref(),
			amount: self.amount_msats.map(Into::into),
			features: self.features.as_ref(),
			quantity: self.quantity.map(Into::into),
			payer_id: Some(&self.payer_id),
			payer_note: self.payer_note.as_ref().map(Into::into),
		};

		let signature = merkle::reference::SignatureTlvStream {
			signature: self.signature.as_ref(),
		};

		(payer, offer, invoice_request, signature)
	}
}

impl Writeable for InvoiceRequest {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)
	}
}

impl Writeable for InvoiceRequestContents {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.as_tlv_stream().write(writer)
	}
}

impl TryFrom<Vec<u8>> for InvoiceRequest {
	type Error = ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let tlv_stream: FullInvoiceRequestTlvStream = Readable::read(&mut &bytes[..])?;
		let contents = InvoiceRequestContents::try_from(tlv_stream)?;
		Ok(InvoiceRequest { bytes, contents })
	}
}

tlv_stream!(struct InvoiceRequestTlvStream {
	(80, chain: BlockHash),
	(82, amount: u64),
	(84, features: OfferFeatures),
	(86, quantity: u64),
	(88, payer_id: PublicKey),
	(89, payer_note: String),
});

impl Bech32Encode for InvoiceRequest {
	type TlvStream = FullInvoiceRequestTlvStream;

	const BECH32_HRP: &'static str = "lnr";
}

type FullInvoiceRequestTlvStream =
	(PayerTlvStream, OfferTlvStream, InvoiceRequestTlvStream, SignatureTlvStream);

type ReferencedFullInvoiceRequestTlvStream<'a> = (
	payer::reference::PayerTlvStream<'a>,
	offer::reference::OfferTlvStream<'a>,
	reference::InvoiceRequestTlvStream<'a>,
	merkle::reference::SignatureTlvStream<'a>,
);

impl FromStr for InvoiceRequest {
	type Err = ParseError;

	fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
		let (tlv_stream, bytes) = InvoiceRequest::from_bech32_str(s)?;
		let contents = InvoiceRequestContents::try_from(tlv_stream)?;

		if let Some(signature) = &contents.signature {
			let tag = concat!("lightning", "invoice_request", "signature");
			merkle::verify_signature(signature, tag, &bytes, contents.payer_id)?;
		}

		Ok(InvoiceRequest { bytes, contents })
	}
}

impl TryFrom<FullInvoiceRequestTlvStream> for InvoiceRequestContents {
	type Error = SemanticError;

	fn try_from(tlv_stream: FullInvoiceRequestTlvStream) -> Result<Self, Self::Error> {
		let (
			PayerTlvStream { payer_info },
			offer_tlv_stream,
			InvoiceRequestTlvStream { chain, amount, features, quantity, payer_id, payer_note },
			SignatureTlvStream { signature },
		) = tlv_stream;

		let payer = PayerContents(payer_info.map(Into::into));
		let offer = OfferContents::try_from(offer_tlv_stream)?;

		let chain = match chain {
			None => None,
			Some(chain) if chain == offer.chain() => Some(chain),
			Some(_) => return Err(SemanticError::UnsupportedChain),
		};

		// TODO: Determine whether quantity should be accounted for
		let amount_msats = match (offer.amount(), amount.map(Into::into)) {
			// TODO: Handle currency case
			(Some(Amount::Currency { .. }), _) => return Err(SemanticError::UnexpectedCurrency),
			(Some(_), None) => return Err(SemanticError::MissingAmount),
			(Some(Amount::Bitcoin { amount_msats: offer_amount_msats }), Some(amount_msats)) => {
				if amount_msats < *offer_amount_msats {
					return Err(SemanticError::InsufficientAmount);
				} else {
					Some(amount_msats)
				}
			},
			(_, amount_msats) => amount_msats,
		};

		if let Some(features) = &features {
			if features.requires_unknown_bits() {
				return Err(SemanticError::UnknownRequiredFeatures);
			}
		}

		let quantity = match quantity.map(Into::into) {
			None if !offer.expects_quantity() => None,
			Some(quantity) if offer.is_valid_quantity(quantity) => Some(quantity),
			_ => return Err(SemanticError::InvalidQuantity),
		};

		let payer_id = match payer_id {
			None => return Err(SemanticError::MissingPayerId),
			Some(payer_id) => payer_id,
		};

		let payer_note = payer_note.map(Into::into);

		Ok(InvoiceRequestContents {
			payer, offer, chain, amount_msats, features, quantity, payer_id, payer_note, signature,
		})
	}
}

impl core::fmt::Display for InvoiceRequest {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		self.fmt_bech32_str(f)
	}
}
