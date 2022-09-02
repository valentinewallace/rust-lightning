// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_request` messages.

use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hash_types::BlockHash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{Message, PublicKey, self};
use bitcoin::secp256k1::schnorr::Signature;
use core::convert::TryFrom;
use core::str::FromStr;
use io;
use ln::features::OfferFeatures;
use offers::merkle::{SignatureTlvStream, self};
use offers::offer::{Offer, OfferContents, OfferTlvStream, self};
use offers::parse::{Bech32Encode, ParseError, SemanticError};
use offers::payer::{PayerContents, PayerTlvStream, self};
use util::ser::{Readable, WithoutLength, Writeable, Writer};

///
const SIGNATURE_TAG: &'static str = concat!("lightning", "invoice_request", "signature");

/// Builds an [`InvoiceRequest`] from an [`Offer`] for the user-pays-merchant flow.
///
/// ```
/// extern crate bitcoin;
/// extern crate lightning;
///
/// use bitcoin::network::constants::Network;
/// use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
/// use lightning::ln::features::OfferFeatures;
/// use lightning::offers::Offer;
/// use lightning::util::ser::Writeable;
///
/// # fn parse() -> Result<(), lightning::offers::ParseError> {
/// let secp_ctx = Secp256k1::new();
/// let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32])?);
/// let pubkey = PublicKey::from(keys);
/// let mut buffer = Vec::new();
///
/// "lno1qcp4256ypq"
///     .parse::<Offer>()?
///     .request_invoice(pubkey)
///     .payer_info(vec![42; 64])
///     .chain(Network::Testnet)?
///     .amount_msats(1000)?
///     .features(OfferFeatures::known())
///     .quantity(5)?
///     .payer_note("foo".to_string())
///     .build()?
///     .sign(|digest| secp_ctx.sign_schnorr_no_aux_rand(digest, &keys))?
///     .write(&mut buffer)
///     .unwrap();
/// # Ok(())
/// # }
/// ```
pub struct InvoiceRequestBuilder<'a> {
	offer: &'a Offer,
	invoice_request: InvoiceRequestContents,
}

impl<'a> InvoiceRequestBuilder<'a> {
	pub(super) fn new(offer: &'a Offer, payer_id: PublicKey) -> Self {
		Self {
			offer,
			invoice_request: InvoiceRequestContents {
				payer: PayerContents(None), offer: offer.contents.clone(), chain: None,
				amount_msats: None, features: None, quantity: None, payer_id, payer_note: None,
				signature: None,
			},
		}
	}

	///
	pub fn payer_info(mut self, payer_info: Vec<u8>) -> Self {
		self.invoice_request.payer = PayerContents(Some(payer_info));
		self
	}

	///
	pub fn chain(mut self, network: Network) -> Result<Self, SemanticError> {
		let block_hash = genesis_block(network).block_hash();
		if !self.offer.supports_chain(block_hash) {
			return Err(SemanticError::UnsupportedChain)
		}

		self.invoice_request.chain = Some(block_hash);
		Ok(self)
	}

	///
	pub fn amount_msats(mut self, amount_msats: u64) -> Result<Self, SemanticError> {
		if !self.offer.is_sufficient_amount(amount_msats) {
			return Err(SemanticError::InsufficientAmount);
		}

		self.invoice_request.amount_msats = Some(amount_msats);
		Ok(self)
	}

	///
	pub fn features(mut self, features: OfferFeatures) -> Self {
		self.invoice_request.features = Some(features);
		self
	}

	///
	pub fn quantity(mut self, quantity: u64) -> Result<Self, SemanticError> {
		if !self.offer.is_valid_quantity(quantity) {
			return Err(SemanticError::InvalidQuantity);
		}

		self.invoice_request.quantity = Some(quantity);
		Ok(self)
	}

	///
	pub fn payer_note(mut self, payer_note: String) -> Self {
		self.invoice_request.payer_note = Some(payer_note);
		self
	}

	/// Builds the [`InvoiceRequest`] after checking for valid semantics.
	pub fn build(self) -> Result<UnsignedInvoiceRequest<'a>, SemanticError> {
		let chain = self.invoice_request.chain.unwrap_or_else(|| self.offer.implied_chain());
		if !self.offer.supports_chain(chain) {
			return Err(SemanticError::UnsupportedChain);
		}

		if self.offer.amount().is_some() && self.invoice_request.amount_msats.is_none() {
			return Err(SemanticError::MissingAmount);
		}

		if self.offer.expects_quantity() && self.invoice_request.quantity.is_none() {
			return Err(SemanticError::InvalidQuantity);
		}

		let InvoiceRequestBuilder { offer, invoice_request } = self;
		Ok(UnsignedInvoiceRequest { offer, invoice_request })
	}
}

/// A semantically valid [`InvoiceRequest`] that hasn't been signed.
pub struct UnsignedInvoiceRequest<'a> {
	offer: &'a Offer,
	invoice_request: InvoiceRequestContents,
}

impl<'a> UnsignedInvoiceRequest<'a> {
	/// Signs the invoice request using the given function.
	pub fn sign<F>(mut self, sign: F) -> Result<InvoiceRequest, secp256k1::Error>
	where F: FnOnce(&Message) -> Signature
	{
		// Use the offer bytes instead of the offer TLV stream as the offer may have contained
		// unknown TLV records, which are not stored in `OfferContents`.
		let (payer_tlv_stream, _offer_tlv_stream, invoice_request_tlv_stream, _) =
			self.invoice_request.as_tlv_stream();
		let offer_bytes = WithoutLength(&self.offer.bytes);
		let unsigned_tlv_stream = (payer_tlv_stream, offer_bytes, invoice_request_tlv_stream);

		let mut bytes = Vec::new();
		unsigned_tlv_stream.write(&mut bytes).unwrap();

		let pubkey = self.invoice_request.payer_id;
		let signature = merkle::sign_message(sign, SIGNATURE_TAG, &bytes, pubkey)?;
		self.invoice_request.signature = Some(signature);

		// Append the signature TLV record to the bytes.
		let signature_tlv_stream = merkle::reference::SignatureTlvStream {
			signature: self.invoice_request.signature.as_ref(),
		};
		signature_tlv_stream.write(&mut bytes).unwrap();

		Ok(InvoiceRequest {
			bytes,
			contents: self.invoice_request,
		})
	}
}

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
			merkle::verify_signature(signature, SIGNATURE_TAG, &bytes, contents.payer_id)?;
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

		if !offer.supports_chain(chain.unwrap_or_else(|| offer.implied_chain())) {
			return Err(SemanticError::UnsupportedChain);
		}

		// TODO: Determine whether quantity should be accounted for
		let amount_msats = match (offer.amount(), amount.map(Into::into)) {
			// TODO: Handle currency case
			(Some(_), None) => return Err(SemanticError::MissingAmount),
			(Some(_), Some(amount_msats)) => {
				if !offer.is_sufficient_amount(amount_msats) {
					return Err(SemanticError::InsufficientAmount);
				} else {
					Some(amount_msats)
				}
			},
			(None, amount_msats) => amount_msats,
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
