// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Message handling for async payments.

use crate::blinded_path::message::{AsyncPaymentsContext, BlindedMessagePath};
use crate::io;
use crate::ln::msgs::DecodeError;
use crate::offers::static_invoice::StaticInvoice;
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::packet::OnionMessageContents;
use crate::prelude::*;
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};

use core::time::Duration;

// TLV record types for the `onionmsg_tlv` TLV stream as defined in BOLT 4.
// TODO: document static invoice server onion message payload types in a bLIP.
const OFFER_PATHS_REQ_TLV_TYPE: u64 = 65538;
const OFFER_PATHS_TLV_TYPE: u64 = 65540;
const SERVE_INVOICE_TLV_TYPE: u64 = 65542;
const INVOICE_PERSISTED_TLV_TYPE: u64 = 65544;
const HELD_HTLC_AVAILABLE_TLV_TYPE: u64 = 72;
const RELEASE_HELD_HTLC_TLV_TYPE: u64 = 74;

/// A handler for an [`OnionMessage`] containing an async payments message as its payload.
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
pub trait AsyncPaymentsMessageHandler {
	/// Handle an [`OfferPathsRequest`] message. If the message was sent over paths that we previously
	/// provided to an async recipient via [`UserConfig::paths_to_static_invoice_server`], an
	/// [`OfferPaths`] message should be returned.
	///
	/// [`UserConfig::paths_to_static_invoice_server`]: crate::util::config::UserConfig::paths_to_static_invoice_server
	fn handle_offer_paths_request(
		&self, message: OfferPathsRequest, context: AsyncPaymentsContext,
		responder: Option<Responder>,
	) -> Option<(OfferPaths, ResponseInstruction)>;

	/// Handle an [`OfferPaths`] message. If this is in response to an [`OfferPathsRequest`] that
	/// we previously sent as an async recipient, we should build an [`Offer`] containing the
	/// included [`OfferPaths::paths`] and a corresponding [`StaticInvoice`], and reply with
	/// [`ServeStaticInvoice`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	fn handle_offer_paths(
		&self, message: OfferPaths, context: AsyncPaymentsContext, responder: Option<Responder>,
	) -> Option<(ServeStaticInvoice, ResponseInstruction)>;

	/// Handle a [`ServeStaticInvoice`] message. If this is in response to an [`OfferPaths`] message
	/// we previously sent, a [`StaticInvoicePersisted`] message should be sent once the message is
	/// handled.
	fn handle_serve_static_invoice(
		&self, message: ServeStaticInvoice, context: AsyncPaymentsContext,
		responder: Option<Responder>,
	);

	/// Handle a [`StaticInvoicePersisted`] message. If this is in response to a
	/// [`ServeStaticInvoice`] message we previously sent as an async recipient, then the offer we
	/// generated on receipt of a previous [`OfferPaths`] message is now ready to be used for async
	/// payments.
	fn handle_static_invoice_persisted(
		&self, message: StaticInvoicePersisted, context: AsyncPaymentsContext,
	);

	/// Handle a [`HeldHtlcAvailable`] message. A [`ReleaseHeldHtlc`] should be returned to release
	/// the held funds.
	fn handle_held_htlc_available(
		&self, message: HeldHtlcAvailable, context: AsyncPaymentsContext,
		responder: Option<Responder>,
	) -> Option<(ReleaseHeldHtlc, ResponseInstruction)>;

	/// Handle a [`ReleaseHeldHtlc`] message. If authentication of the message succeeds, an HTLC
	/// should be released to the corresponding payee.
	fn handle_release_held_htlc(&self, message: ReleaseHeldHtlc, context: AsyncPaymentsContext);

	/// Release any [`AsyncPaymentsMessage`]s that need to be sent.
	///
	/// Typically, this is used for messages initiating an async payment flow rather than in response
	/// to another message.
	fn release_pending_messages(&self) -> Vec<(AsyncPaymentsMessage, MessageSendInstructions)> {
		vec![]
	}
}

/// Possible async payment messages sent and received via an [`OnionMessage`].
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[derive(Clone, Debug)]
pub enum AsyncPaymentsMessage {
	/// A request for [`BlindedMessagePath`]s from a static invoice server.
	OfferPathsRequest(OfferPathsRequest),

	/// [`BlindedMessagePath`]s to be included in an async recipient's [`Offer::paths`], sent in
	/// response to an [`OfferPathsRequest`].
	///
	/// [`Offer::paths`]: crate::offers::offer::Offer::paths
	OfferPaths(OfferPaths),

	/// A request to serve a [`StaticInvoice`] on behalf of an async recipient.
	ServeStaticInvoice(ServeStaticInvoice),

	/// Confirms that a [`StaticInvoice`] was persisted by a static invoice server and the
	/// corresponding [`Offer`] is ready to be used to receive async payments. Sent in response to a
	/// [`ServeStaticInvoice`] message.
	///
	/// [`Offer`]: crate::offers::offer::Offer
	StaticInvoicePersisted(StaticInvoicePersisted),

	/// An HTLC is being held upstream for the often-offline recipient, to be released via
	/// [`ReleaseHeldHtlc`].
	HeldHtlcAvailable(HeldHtlcAvailable),

	/// Releases the HTLC corresponding to an inbound [`HeldHtlcAvailable`] message.
	ReleaseHeldHtlc(ReleaseHeldHtlc),
}

/// A request for [`BlindedMessagePath`]s from a static invoice server. These paths will be used
/// in the async recipient's [`Offer::paths`], so payers can request [`StaticInvoice`]s from the
/// static invoice server.
///
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[derive(Clone, Debug)]
pub struct OfferPathsRequest {}

/// [`BlindedMessagePath`]s to be included in an async recipient's [`Offer::paths`], sent in
/// response to an [`OfferPathsRequest`].
///
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[derive(Clone, Debug)]
pub struct OfferPaths {
	/// The paths that should be included in the async recipient's [`Offer::paths`].
	///
	/// [`Offer::paths`]: crate::offers::offer::Offer::paths
	pub paths: Vec<BlindedMessagePath>,
	/// The time as duration since the Unix epoch at which the [`Self::paths`] expire.
	pub paths_absolute_expiry: Option<Duration>,
}

/// Indicates that a [`StaticInvoice`] should be provided by a static invoice server in response to
/// [`InvoiceRequest`]s from payers behalf of an async recipient.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
#[derive(Clone, Debug)]
pub struct ServeStaticInvoice {
	/// The invoice that should be served by the static invoice server. Once this invoice has been
	/// persisted, the [`Responder`] accompanying this message should be used to send
	/// [`StaticInvoicePersisted`] to the recipient to confirm that the offer corresponding to the
	/// invoice is ready to receive async payments.
	pub invoice: StaticInvoice,
	// TODO: include blinded paths to forward the invreq to the async recipient
	// pub invoice_request_paths: Vec<BlindedMessagePath>,
}

/// Confirms that a [`StaticInvoice`] was persisted by a static invoice server and the
/// corresponding [`Offer`] is ready to be used to receive async payments. Sent in response to a
/// [`ServeStaticInvoice`] message.
///
/// [`Offer`]: crate::offers::offer::Offer
#[derive(Clone, Debug)]
pub struct StaticInvoicePersisted {}

/// An HTLC destined for the recipient of this message is being held upstream. The reply path
/// accompanying this onion message should be used to send a [`ReleaseHeldHtlc`] response, which
/// will cause the upstream HTLC to be released.
#[derive(Clone, Debug)]
pub struct HeldHtlcAvailable {}

/// Releases the HTLC corresponding to an inbound [`HeldHtlcAvailable`] message.
#[derive(Clone, Debug)]
pub struct ReleaseHeldHtlc {}

impl OnionMessageContents for OfferPaths {
	fn tlv_type(&self) -> u64 {
		OFFER_PATHS_TLV_TYPE
	}
	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		"Offer Paths".to_string()
	}
	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		"Offer Paths"
	}
}

impl OnionMessageContents for ServeStaticInvoice {
	fn tlv_type(&self) -> u64 {
		SERVE_INVOICE_TLV_TYPE
	}
	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		"Serve Static Invoice".to_string()
	}
	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		"Serve Static Invoice"
	}
}

impl OnionMessageContents for ReleaseHeldHtlc {
	fn tlv_type(&self) -> u64 {
		RELEASE_HELD_HTLC_TLV_TYPE
	}
	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		"Release Held HTLC".to_string()
	}
	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		"Release Held HTLC"
	}
}

impl_writeable_tlv_based!(OfferPathsRequest, {});

impl_writeable_tlv_based!(OfferPaths, {
	(0, paths, required_vec),
	(2, paths_absolute_expiry, option),
});

impl_writeable_tlv_based!(ServeStaticInvoice, {
	(0, invoice, required),
});

impl_writeable_tlv_based!(StaticInvoicePersisted, {});

impl_writeable_tlv_based!(HeldHtlcAvailable, {});

impl_writeable_tlv_based!(ReleaseHeldHtlc, {});

impl AsyncPaymentsMessage {
	/// Returns whether `tlv_type` corresponds to a TLV record for async payment messages.
	pub fn is_known_type(tlv_type: u64) -> bool {
		match tlv_type {
			OFFER_PATHS_REQ_TLV_TYPE
			| OFFER_PATHS_TLV_TYPE
			| SERVE_INVOICE_TLV_TYPE
			| INVOICE_PERSISTED_TLV_TYPE
			| HELD_HTLC_AVAILABLE_TLV_TYPE
			| RELEASE_HELD_HTLC_TLV_TYPE => true,
			_ => false,
		}
	}
}

impl OnionMessageContents for AsyncPaymentsMessage {
	fn tlv_type(&self) -> u64 {
		match self {
			Self::OfferPathsRequest(_) => OFFER_PATHS_REQ_TLV_TYPE,
			Self::OfferPaths(msg) => msg.tlv_type(),
			Self::ServeStaticInvoice(msg) => msg.tlv_type(),
			Self::StaticInvoicePersisted(_) => INVOICE_PERSISTED_TLV_TYPE,
			Self::HeldHtlcAvailable(_) => HELD_HTLC_AVAILABLE_TLV_TYPE,
			Self::ReleaseHeldHtlc(msg) => msg.tlv_type(),
		}
	}
	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		match &self {
			Self::OfferPathsRequest(_) => "Offer Paths Request".to_string(),
			Self::OfferPaths(msg) => msg.msg_type(),
			Self::ServeStaticInvoice(msg) => msg.msg_type(),
			Self::StaticInvoicePersisted(_) => "Static Invoice Persisted".to_string(),
			Self::HeldHtlcAvailable(_) => "Held HTLC Available".to_string(),
			Self::ReleaseHeldHtlc(msg) => msg.msg_type(),
		}
	}
	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		match &self {
			Self::OfferPathsRequest(_) => "Offer Paths Request",
			Self::OfferPaths(msg) => msg.msg_type(),
			Self::ServeStaticInvoice(msg) => msg.msg_type(),
			Self::StaticInvoicePersisted(_) => "Static Invoice Persisted",
			Self::HeldHtlcAvailable(_) => "Held HTLC Available",
			Self::ReleaseHeldHtlc(msg) => msg.msg_type(),
		}
	}
}

impl Writeable for AsyncPaymentsMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::OfferPathsRequest(message) => message.write(w),
			Self::OfferPaths(message) => message.write(w),
			Self::ServeStaticInvoice(message) => message.write(w),
			Self::StaticInvoicePersisted(message) => message.write(w),
			Self::HeldHtlcAvailable(message) => message.write(w),
			Self::ReleaseHeldHtlc(message) => message.write(w),
		}
	}
}

impl ReadableArgs<u64> for AsyncPaymentsMessage {
	fn read<R: io::Read>(r: &mut R, tlv_type: u64) -> Result<Self, DecodeError> {
		match tlv_type {
			OFFER_PATHS_REQ_TLV_TYPE => Ok(Self::OfferPathsRequest(Readable::read(r)?)),
			OFFER_PATHS_TLV_TYPE => Ok(Self::OfferPaths(Readable::read(r)?)),
			SERVE_INVOICE_TLV_TYPE => Ok(Self::ServeStaticInvoice(Readable::read(r)?)),
			INVOICE_PERSISTED_TLV_TYPE => Ok(Self::StaticInvoicePersisted(Readable::read(r)?)),
			HELD_HTLC_AVAILABLE_TLV_TYPE => Ok(Self::HeldHtlcAvailable(Readable::read(r)?)),
			RELEASE_HELD_HTLC_TLV_TYPE => Ok(Self::ReleaseHeldHtlc(Readable::read(r)?)),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}
