// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::io;
use crate::io::Read;
use crate::ln::msgs::DecodeError;
use crate::offers::nonce::Nonce;
use crate::offers::offer::Offer;
use crate::onion_message::messenger::Responder;
use crate::sync::Mutex;
use crate::util::ser::{Readable, Writeable, Writer};
use core::sync::atomic::AtomicU8;
use core::time::Duration;
#[cfg(async_payments)]
use {
	crate::blinded_path::message::{AsyncPaymentsContext, BlindedMessagePath, MessageContext},
	crate::blinded_path::payment::{AsyncBolt12OfferContext, BlindedPaymentPath, PaymentContext},
	crate::ln::channelmanager::enqueue_onion_message_with_reply_paths,
	crate::ln::inbound_payment,
	crate::offers::offer::{Amount, DerivedMetadata, OfferBuilder},
	crate::offers::parse::Bolt12SemanticError,
	crate::offers::signer,
	crate::offers::static_invoice::{StaticInvoiceBuilder, DEFAULT_RELATIVE_EXPIRY},
	crate::onion_message::async_payments::{
		AsyncPaymentsMessage, OfferPaths, OfferPathsRequest, ServeStaticInvoice,
	},
	crate::onion_message::messenger::{MessageSendInstructions, ResponseInstruction},
	crate::sign::EntropySource,
	crate::util::logger::Logger,
	bitcoin::constants::ChainHash,
	bitcoin::secp256k1,
	bitcoin::secp256k1::{PublicKey, Secp256k1},
	bolt11_invoice::PaymentSecret,
	core::ops::Deref,
	core::sync::atomic::Ordering,
};

// Used to expire reply paths created by us when exchanging static invoice server onion messages. We
// expect these onion messages to be exchanged quickly, but add some buffer for no-std users who
// rely on block timestamps.
const REPLY_PATH_RELATIVE_EXPIRY: Duration = Duration::from_secs(2 * 60 * 60);

struct AsyncReceiveOffer {
	offer: Offer,

	/// The below fields are used to generate and persist a new static invoice with the invoice
	/// server, if the invoice is expiring prior to the corresponding offer.
	offer_nonce: Nonce,
	update_static_invoice_path: Responder,
	static_invoice_absolute_expiry: Duration,
	invoice_update_attempts: u8,
}

impl_writeable_tlv_based!(AsyncReceiveOffer, {
	(0, offer, required),
	(2, offer_nonce, required),
	(4, update_static_invoice_path, required),
	(6, static_invoice_absolute_expiry, required),
	(8, invoice_update_attempts, (static_value, 0)),
});

/// If we are an async recipient, on startup we interactively build an offer and static invoice with
/// an always-online node that will serve static invoices on our behalf. Once the offer is built and
/// the static invoice is confirmed as persisted by the server, use this struct to cache the offer
/// and metadata to update the static invoice in `ChannelManager`.
pub(super) struct AsyncReceiveOfferCache {
	offers: Mutex<Vec<AsyncReceiveOffer>>,
	/// Used to limit the number of times we request paths for our offer from the static invoice
	/// server.
	#[allow(unused)] // TODO: remove when we get rid of async payments cfg flag
	offer_paths_request_attempts: AtomicU8,
}

impl AsyncReceiveOfferCache {
	pub(super) fn new() -> Self {
		Self { offers: Mutex::new(Vec::new()), offer_paths_request_attempts: AtomicU8::new(0) }
	}
}

#[cfg(async_payments)]
impl AsyncReceiveOfferCache {
	// If we have more than three hours before our offers expire, don't bother requesting new paths.
	const OFFER_RELATIVE_EXPIRY_BUFFER: Duration = Duration::from_secs(3 * 60 * 60);

	// We want to have 3 unexpired offers cached at any given time to mitigate too much reuse of the
	// same offer.
	const NUM_CACHED_OFFERS_TARGET: usize = 3;

	// The max number of times we'll attempt to request offer paths or attempt to refresh a static
	// invoice before giving up.
	const MAX_UPDATE_ATTEMPTS: u8 = 3;

	pub(super) fn check_refresh_cache<CBP, ES: Deref, L: Deref>(
		&self, paths_to_static_invoice_server: &[BlindedMessagePath], create_blinded_paths: CBP,
		expanded_key: &inbound_payment::ExpandedKey, entropy: ES, duration_since_epoch: Duration,
		logger: &L,
		pending_async_payments_messages: &Mutex<
			Vec<(AsyncPaymentsMessage, MessageSendInstructions)>,
		>,
	) where
		CBP: Fn(MessageContext) -> Result<Vec<BlindedMessagePath>, ()>,
		ES::Target: EntropySource,
		L::Target: Logger,
	{
		if paths_to_static_invoice_server.is_empty() {
			return;
		}

		let needs_new_offers = self.check_expire_offers(duration_since_epoch)
			&& self.offer_paths_request_attempts.load(Ordering::Relaxed)
				< Self::MAX_UPDATE_ATTEMPTS;

		if needs_new_offers {
			let nonce = Nonce::from_entropy_source(entropy);
			let context = MessageContext::AsyncPayments(AsyncPaymentsContext::OfferPaths {
				nonce,
				hmac: signer::hmac_for_offer_paths_context(nonce, expanded_key),
				path_absolute_expiry: duration_since_epoch
					.saturating_add(REPLY_PATH_RELATIVE_EXPIRY),
			});
			let reply_paths =
				match create_blinded_paths(context) {
					Ok(paths) => paths,
					Err(()) => {
						log_error!(logger, "Failed to create blinded paths when requesting async receive offer paths");
						return;
					},
				};

			self.offer_paths_request_attempts.fetch_add(1, Ordering::Relaxed);
			let message = AsyncPaymentsMessage::OfferPathsRequest(OfferPathsRequest {});
			enqueue_onion_message_with_reply_paths(
				message,
				paths_to_static_invoice_server,
				reply_paths,
				&mut pending_async_payments_messages.lock().unwrap(),
			);
		}
	}

	/// Removes expired offers from our cache, returning whether new offers are needed.
	fn check_expire_offers(&self, duration_since_epoch: Duration) -> bool {
		let mut offers = self.offers.lock().unwrap();
		offers.retain(|offer| {
			if offer.offer.is_expired_no_std(duration_since_epoch) {
				self.offer_paths_request_attempts.store(0, Ordering::Relaxed);
				return false;
			}
			true
		});

		let num_unexpiring_offers = offers
			.iter()
			.filter(|offer| {
				let offer_expiry = offer.offer.absolute_expiry().unwrap_or(Duration::MAX);
				let min_offer_expiry =
					duration_since_epoch.saturating_add(Self::OFFER_RELATIVE_EXPIRY_BUFFER);
				offer_expiry > min_offer_expiry
			})
			.count();

		num_unexpiring_offers < Self::NUM_CACHED_OFFERS_TARGET
	}

	pub(super) fn handle_offer_paths<ES: Deref, L: Deref, CBP, CBPP>(
		&self, message: OfferPaths, context: AsyncPaymentsContext, responder: Responder,
		create_blinded_paths: CBP, create_blinded_payment_paths: CBPP,
		expanded_key: &inbound_payment::ExpandedKey, duration_since_epoch: Duration,
		our_node_id: PublicKey, chain_hash: ChainHash, entropy: ES,
		secp_ctx: &Secp256k1<secp256k1::All>, logger: &L,
	) -> Option<(ServeStaticInvoice, ResponseInstruction)>
	where
		ES::Target: EntropySource,
		L::Target: Logger,
		CBP: Fn(MessageContext) -> Result<Vec<BlindedMessagePath>, ()>,
		CBPP: Fn(
			Option<u64>,
			PaymentSecret,
			PaymentContext,
			u32,
		) -> Result<Vec<BlindedPaymentPath>, ()>,
	{
		match context {
			AsyncPaymentsContext::OfferPaths { nonce, hmac, path_absolute_expiry } => {
				if let Err(()) = signer::verify_offer_paths_context(nonce, hmac, expanded_key) {
					return None;
				}
				if duration_since_epoch > path_absolute_expiry {
					return None;
				}
			},
			_ => return None,
		}

		if !self.check_expire_offers(duration_since_epoch) {
			return None;
		}

		// Require at least two hours before we'll need to start the process of creating a new offer.
		const MIN_OFFER_PATHS_RELATIVE_EXPIRY: Duration = Duration::from_secs(2 * 60 * 60)
			.saturating_add(AsyncReceiveOfferCache::OFFER_RELATIVE_EXPIRY_BUFFER);
		let min_offer_paths_absolute_expiry =
			duration_since_epoch.saturating_add(MIN_OFFER_PATHS_RELATIVE_EXPIRY);
		let offer_paths_absolute_expiry =
			message.paths_absolute_expiry.unwrap_or(Duration::from_secs(u64::MAX));
		if offer_paths_absolute_expiry < min_offer_paths_absolute_expiry {
			log_error!(
				logger,
				"Received offer paths with too-soon absolute Unix epoch expiry: {}",
				offer_paths_absolute_expiry.as_secs()
			);
			return None;
		}

		let (offer, offer_nonce) = {
			let (offer_builder, offer_nonce) =
				match create_async_receive_offer_builder(
					message.paths,
					our_node_id,
					chain_hash,
					expanded_key,
					&*entropy,
					secp_ctx,
				) {
					Ok((builder, nonce)) => (builder, nonce),
					Err(e) => {
						log_error!(logger, "Failed to create offer builder when replying to OfferPaths message: {:?}", e);
						return None;
					},
				};
			match offer_builder.absolute_expiry(offer_paths_absolute_expiry).build() {
				Ok(offer) => (offer, offer_nonce),
				Err(e) => {
					log_error!(
						logger,
						"Failed to build offer when replying to OfferPaths message: {:?}",
						e
					);
					return None;
				},
			}
		};

		let (serve_invoice_message, reply_path_context) = match create_serve_static_invoice_message(
			offer.clone(),
			offer_nonce,
			responder.clone(),
			create_blinded_payment_paths,
			create_blinded_paths,
			expanded_key,
			entropy,
			secp_ctx,
			duration_since_epoch,
			logger,
		) {
			Ok((msg, context)) => (msg, context),
			Err(()) => return None,
		};

		let context = MessageContext::AsyncPayments(reply_path_context);
		Some((serve_invoice_message, responder.respond_with_reply_path(context)))
	}

	pub(super) fn handle_static_invoice_persisted(
		&self, context: AsyncPaymentsContext, expanded_key: &inbound_payment::ExpandedKey,
		duration_since_epoch: Duration,
	) -> bool {
		let (offer, offer_nonce, update_static_invoice_path, static_invoice_absolute_expiry) =
			match context {
				AsyncPaymentsContext::StaticInvoicePersisted {
					offer,
					offer_nonce,
					update_static_invoice_path,
					static_invoice_absolute_expiry,
					nonce,
					hmac,
					path_absolute_expiry,
				} => {
					if let Err(()) =
						signer::verify_static_invoice_persisted_context(nonce, hmac, expanded_key)
					{
						return false;
					}

					if duration_since_epoch > path_absolute_expiry
						|| duration_since_epoch > static_invoice_absolute_expiry
						|| offer.is_expired_no_std(duration_since_epoch)
					{
						return false;
					}

					(offer, offer_nonce, update_static_invoice_path, static_invoice_absolute_expiry)
				},
				_ => return false,
			};

		let mut offers = self.offers.lock().unwrap();
		match offers.iter_mut().find(|cached_offer| cached_offer.offer.id() == offer.id()) {
			Some(async_receive_offer) => {
				debug_assert_eq!(
					async_receive_offer.update_static_invoice_path,
					update_static_invoice_path
				);
				debug_assert_eq!(async_receive_offer.offer_nonce, offer_nonce);
				async_receive_offer.static_invoice_absolute_expiry = static_invoice_absolute_expiry;
				async_receive_offer.invoice_update_attempts = 0;
			},
			None => {
				const MAX_OFFERS: usize = 100;
				if offers.len() >= MAX_OFFERS { return false }
				offers.push(AsyncReceiveOffer {
					offer,
					offer_nonce,
					update_static_invoice_path,
					static_invoice_absolute_expiry,
					invoice_update_attempts: 0,
				});
			},
		}

		true
	}
}

#[cfg(async_payments)]
fn create_serve_static_invoice_message<'a, 'b, CBPP, CBMP, ES: Deref, L: Deref>(
	offer: Offer, offer_nonce: Nonce, update_static_invoice_path: Responder,
	create_blinded_payment_paths: CBPP, create_blinded_message_paths: CBMP,
	expanded_key: &'b inbound_payment::ExpandedKey, entropy: ES,
	secp_ctx: &'b Secp256k1<secp256k1::All>, duration_since_epoch: Duration, logger: &L,
) -> Result<(ServeStaticInvoice, AsyncPaymentsContext), ()>
where
	CBPP:
		Fn(Option<u64>, PaymentSecret, PaymentContext, u32) -> Result<Vec<BlindedPaymentPath>, ()>,
	CBMP: Fn(MessageContext) -> Result<Vec<BlindedMessagePath>, ()>,
	ES::Target: EntropySource,
	L::Target: Logger,
{
	let offer_relative_expiry = offer
		.absolute_expiry()
		.unwrap_or_else(|| Duration::from_secs(u64::MAX))
		.saturating_sub(duration_since_epoch);

	// Set our invoices to expire after at most two weeks, so we'll need to refresh them using the
	// reply path to the `OfferPaths` message.
	let static_invoice_relative_expiry = Duration::from_secs(core::cmp::min(
		offer_relative_expiry.as_secs(),
		DEFAULT_RELATIVE_EXPIRY.as_secs(),
	));

	let static_invoice = create_static_invoice_builder(
		&offer,
		offer_nonce,
		Some(static_invoice_relative_expiry),
		create_blinded_payment_paths,
		create_blinded_message_paths,
		expanded_key,
		&*entropy,
		secp_ctx,
		duration_since_epoch,
	)
	.and_then(|builder| builder.build_and_sign(secp_ctx))
	.map_err(|e| {
		log_error!(
			logger,
			"Failed to create static invoice when replying to OfferPaths message: {:?}",
			e
		);
		()
	})?;

	let reply_path_context = {
		let nonce = Nonce::from_entropy_source(entropy);
		let hmac = signer::hmac_for_static_invoice_persisted_context(nonce, expanded_key);
		AsyncPaymentsContext::StaticInvoicePersisted {
			offer,
			offer_nonce,
			update_static_invoice_path,
			static_invoice_absolute_expiry: static_invoice
				.created_at()
				.saturating_add(static_invoice.relative_expiry()),
			nonce,
			hmac,
			path_absolute_expiry: duration_since_epoch.saturating_add(REPLY_PATH_RELATIVE_EXPIRY),
		}
	};

	Ok((ServeStaticInvoice { invoice: static_invoice }, reply_path_context))
}

#[cfg(async_payments)]
pub(super) fn create_async_receive_offer_builder<'a, ES: Deref>(
	message_paths_to_always_online_node: Vec<BlindedMessagePath>, our_node_id: PublicKey,
	chain_hash: ChainHash, expanded_key: &'a inbound_payment::ExpandedKey, entropy: ES,
	secp_ctx: &'a Secp256k1<secp256k1::All>,
) -> Result<(OfferBuilder<'a, DerivedMetadata, secp256k1::All>, Nonce), Bolt12SemanticError>
where
	ES::Target: EntropySource,
{
	if message_paths_to_always_online_node.is_empty() {
		return Err(Bolt12SemanticError::MissingPaths);
	}

	let nonce = Nonce::from_entropy_source(entropy);
	let mut builder =
		OfferBuilder::deriving_signing_pubkey(our_node_id, expanded_key, nonce, secp_ctx)
			.chain_hash(chain_hash);

	for path in message_paths_to_always_online_node {
		builder = builder.path(path);
	}

	Ok((builder.into(), nonce))
}

#[cfg(async_payments)]
pub(super) fn create_static_invoice_builder<'a, 'b, CBPP, CBMP, ES: Deref>(
	offer: &'a Offer, offer_nonce: Nonce, relative_expiry: Option<Duration>,
	create_blinded_payment_paths: CBPP, create_blinded_message_paths: CBMP,
	expanded_key: &'b inbound_payment::ExpandedKey, entropy: ES,
	secp_ctx: &'b Secp256k1<secp256k1::All>, duration_since_epoch: Duration,
) -> Result<StaticInvoiceBuilder<'a>, Bolt12SemanticError>
where
	CBPP:
		Fn(Option<u64>, PaymentSecret, PaymentContext, u32) -> Result<Vec<BlindedPaymentPath>, ()>,
	CBMP: Fn(MessageContext) -> Result<Vec<BlindedMessagePath>, ()>,
	ES::Target: EntropySource,
{
	let payment_context = PaymentContext::AsyncBolt12Offer(AsyncBolt12OfferContext { offer_nonce });
	let amount_msat = offer.amount().and_then(|amount| match amount {
		Amount::Bitcoin { amount_msats } => Some(amount_msats),
		Amount::Currency { .. } => None,
	});

	let relative_expiry = relative_expiry.unwrap_or(DEFAULT_RELATIVE_EXPIRY);
	let relative_expiry_secs: u32 = relative_expiry.as_secs().try_into().unwrap_or(u32::MAX);

	let created_at = duration_since_epoch;
	let payment_secret = inbound_payment::create_for_spontaneous_payment(
		expanded_key,
		amount_msat,
		relative_expiry_secs,
		created_at.as_secs(),
		None,
	)
	.map_err(|()| Bolt12SemanticError::InvalidAmount)?;

	let payment_paths = create_blinded_payment_paths(
		amount_msat,
		payment_secret,
		payment_context,
		relative_expiry_secs,
	)
	.map_err(|()| Bolt12SemanticError::MissingPaths)?;

	let nonce = Nonce::from_entropy_source(entropy);
	let hmac = signer::hmac_for_held_htlc_available_context(nonce, expanded_key);
	let path_absolute_expiry = Duration::from_secs(inbound_payment::calculate_absolute_expiry(
		created_at.as_secs(),
		relative_expiry_secs,
	));
	let context = MessageContext::AsyncPayments(AsyncPaymentsContext::InboundPayment {
		nonce,
		hmac,
		path_absolute_expiry,
	});
	let async_receive_message_paths =
		create_blinded_message_paths(context).map_err(|()| Bolt12SemanticError::MissingPaths)?;

	StaticInvoiceBuilder::for_offer_using_derived_keys(
		offer,
		payment_paths,
		async_receive_message_paths,
		created_at,
		expanded_key,
		offer_nonce,
		secp_ctx,
	)
	.map(|inv| inv.allow_mpp().relative_expiry(relative_expiry_secs))
}

impl Writeable for AsyncReceiveOfferCache {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		let offers = self.offers.lock().unwrap();
		write_tlv_fields!(w, {
			(0, *offers, required_vec),
			// offer_paths_request_attempts always resets to 0 on read
		});
		Ok(())
	}
}

impl Readable for AsyncReceiveOfferCache {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(r, {
			(0, offers, required_vec),
		});
		let offers: Vec<AsyncReceiveOffer> = offers;
		Ok(Self { offers: Mutex::new(offers), offer_paths_request_attempts: AtomicU8::new(0) })
	}
}
