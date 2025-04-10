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
	offer_paths_request_attempts: AtomicU8,
}

impl AsyncReceiveOfferCache {
	pub(super) fn new() -> Self {
		Self { offers: Mutex::new(Vec::new()), offer_paths_request_attempts: AtomicU8::new(0) }
	}
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
