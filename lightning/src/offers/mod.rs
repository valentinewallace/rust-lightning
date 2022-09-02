//!

use bitcoin::hash_types::BlockHash;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::cmp::fixed_time_eq;
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::secp256k1::ecdsa::Signature;
use onion_message::BlindedRoute;
use ln::PaymentHash;
use ln::features::InvoiceFeatures;

use prelude::*;
use core::time::Duration;

pub struct Offer {
	bytes: Vec<u8>,
	chains: Option<Vec<BlockHash>>,
	metadata: Option<Vec<u8>>,
	amount_msat: Option<u64>,
	description: String,
	features: Option<InvoiceFeatures>,
	absolute_expiry: Option<Duration>,
	issuer: Option<String>,
	paths: Option<Vec<BlindedRoute>>,
	quantity_min: Option<u64>,
	quantity_max: Option<u64>,
	node_id: Option<PublicKey>,
}

pub struct InvoiceRequest {
	bytes: Vec<u8>,
	offer: Offer,
	chain: Option<BlockHash>,
	amount_msat: Option<u64>,
	features: Option<InvoiceFeatures>,
	quantity: Option<u64>,
	payer_id: Option<PublicKey>,
	payer_note: Option<String>,
	payer_info: Option<Vec<u8>>,
	signature: Option<Signature>,
}

pub struct Invoice {
	invoice_request_payer_info: Vec<u8>,
	invoice_request: InvoiceRequest,
	paths: Option<Vec<BlindedRoute>>,
	blindedpay: Option<Vec<u8>>,
	created_at: u64,
	payment_hash: PaymentHash,
	relative_expiry: Option<Duration>,
	// invoice_fallbacks: fallback_addrs,
	features: Option<InvoiceFeatures>,
	amount_msat: Option<u64>,
	code: Option<String>,
	signature: Option<Signature>,
}

const IV_LEN: usize = 16;

///
pub fn verify(invoice_req: &InvoiceRequest, _highest_seen_timestamp: u64, secret: &SecretKey) -> Result<(), ()> {
	if invoice_req.offer.metadata.is_none() {
		return Err(())
	}
	let mut hmac = calc_offer_hmac(&invoice_req.offer, secret);
	// Check that we issued this offer to begin with.
	if !fixed_time_eq(&invoice_req.offer.metadata.as_ref().unwrap(), &hmac.split_at_mut(IV_LEN).0) {
		return Err(())
	}
	// Next, check that these invoice_req fields are valid:
	// * chain
	// * amount_msat
	// * features
	// * quantity
	// * expiry using highest_seen_timestamp
	// * signature using invoice_request_payer_id

	// Finally, return Ok so the caller can get an invoice and send it back to the requester
	Ok(())
}

fn calc_offer_hmac(offer: &Offer, secret: &SecretKey) -> [u8; 32] {
	let mut hmac = HmacEngine::<Sha256>::new(&secret[..]);
	hmac.input(&offer.amount_msat.unwrap().to_be_bytes()); // TODO no unwrap
	// TODO: input all other offer fields besides the metadata field (and figure out how to do
	// this cleanly)
	// TODO: how2backwards compat if new fields are added?
	Hmac::from_engine(hmac).into_inner()
}

///
pub fn verify_invoice(invoice: &Invoice, _highest_seen_timestamp: u64, _chain: BlockHash, secret: &SecretKey) -> Result<(), ()> {
	if invoice.invoice_request.payer_info.is_none() {
		return Err(())
	}
	let mut hmac = calc_invoice_request_hmac(&invoice.invoice_request, secret);
	// Check that we issued the invoice request to begin with.
	if !fixed_time_eq(&invoice.invoice_request.payer_info.as_ref().unwrap(), &hmac.split_at_mut(IV_LEN).0) {
		return Err(())
	}

	// Next, check the following invoice fields are valid:
	// * created_at and relative_expiry using highest_seen_timestamp
	// * features
	// * amount_msat
	// * signature if offer_node_id is Some, otherwise make sure the signature is None

	// Finally, return Ok so the caller can pay the invoice
	Ok(())
}

fn calc_invoice_request_hmac(invoice_req: &InvoiceRequest, secret: &SecretKey) -> [u8; 32] {
	let mut hmac = HmacEngine::<Sha256>::new(&secret[..]);
	hmac.input(&invoice_req.amount_msat.unwrap().to_be_bytes()); // TODO no unwrap
	// TODO: input all other request fields besides the payer_info field (and figure out how to do
	// this cleanly)
	// TODO: how2backwards compat if new fields are added?
	Hmac::from_engine(hmac).into_inner()
}
