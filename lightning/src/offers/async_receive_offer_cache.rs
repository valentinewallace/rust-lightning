// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and methods for caching offers that we interactively build with a static invoice
//! server as an async recipient. The static invoice server will serve the resulting invoices to
//! payers on our behalf when we're offline.

use crate::blinded_path::message::BlindedMessagePath;
use crate::io;
use crate::io::Read;
use crate::ln::msgs::DecodeError;
use crate::offers::nonce::Nonce;
use crate::offers::offer::Offer;
use crate::onion_message::messenger::Responder;
use crate::prelude::*;
use crate::util::ser::{Readable, Writeable, Writer};
use core::time::Duration;

/// The status of this offer in the cache.
#[derive(Clone)]
enum OfferStatus {
	/// This offer has been returned to the user from the cache, so it needs to be stored until it
	/// expires and its invoice needs to be kept updated.
	Used,
	/// This offer has not yet been returned to the user, and is safe to replace to ensure we always
	/// have a maximally fresh offer. We always want to have at least 1 offer in this state,
	/// preferably a few so we can respond to user requests for new offers without returning the same
	/// one multiple times. Returning a new offer each time is better for privacy.
	Ready {
		/// If this offer's invoice has been persisted for some time, it's safe to replace to ensure we
		/// always have the freshest possible offer available when the user goes to pull an offer from
		/// the cache.
		invoice_confirmed_persisted_at: Duration,
	},
	// This offer's invoice is not yet confirmed as persisted by the static invoice server.
	Pending,
}

#[derive(Clone)]
struct AsyncReceiveOffer {
	offer: Offer,
	/// Whether this offer is used, ready for use, or pending invoice persistence with the static
	/// invoice server.
	status: OfferStatus,

	/// The below fields are used to generate and persist a new static invoice with the invoice
	/// server. We support automatically rotating the invoice for long-lived offers so users don't
	/// have to update the offer they've posted on e.g. their website if fees change or the invoices'
	/// payment paths become otherwise outdated.
	offer_nonce: Nonce,
	update_static_invoice_path: Responder,
}

impl_writeable_tlv_based_enum!(OfferStatus,
	(0, Used) => {},
	(1, Ready) => {
		(0, invoice_confirmed_persisted_at, required),
	},
	(2, Pending) => {},
);

impl_writeable_tlv_based!(AsyncReceiveOffer, {
	(0, offer, required),
	(2, offer_nonce, required),
	(4, status, required),
	(6, update_static_invoice_path, required),
});

/// If we are an often-offline recipient, we'll want to interactively build offers and static
/// invoices with an always-online node that will serve those static invoices to payers on our
/// behalf when we are offline.
///
/// This struct is used to cache those interactively built offers, and should be passed into
/// [`OffersMessageFlow`] on startup as well as persisted whenever an offer or invoice is updated.
///
/// [`OffersMessageFlow`]: crate::offers::flow::OffersMessageFlow
pub struct AsyncReceiveOfferCache {
	offers: Vec<Option<AsyncReceiveOffer>>,
	/// Used to limit the number of times we request paths for our offer from the static invoice
	/// server.
	#[allow(unused)] // TODO: remove when we get rid of async payments cfg flag
	offer_paths_request_attempts: u8,
	/// Used to determine whether enough time has passed since our last request for offer paths that
	/// more requests should be allowed to go out.
	#[allow(unused)] // TODO: remove when we get rid of async payments cfg flag
	last_offer_paths_request_timestamp: Duration,
	///
	#[allow(unused)] // TODO: remove when we get rid of async payments cfg flag
	paths_to_static_invoice_server: Vec<BlindedMessagePath>,
	///
	#[allow(unused)] // TODO: remove when we get rid of async payments cfg flag
	max_invoices_stored_by_server: u8,
}

impl AsyncReceiveOfferCache {
	/// Creates an empty [`AsyncReceiveOfferCache`] to be passed into [`OffersMessageFlow`].
	///
	/// [`OffersMessageFlow`]: crate::offers::flow::OffersMessageFlow
	pub fn new() -> Self {
		Self {
			offers: Vec::new(),
			offer_paths_request_attempts: 0,
			last_offer_paths_request_timestamp: Duration::from_secs(0),
			paths_to_static_invoice_server: Vec::new(),
			max_invoices_stored_by_server: 0,
		}
	}

	///
	pub(super) fn paths_to_static_invoice_server(&self) -> Vec<BlindedMessagePath> {
		self.paths_to_static_invoice_server.clone()
	}

	///
	pub fn set_paths_to_static_invoice_server(
		&mut self, paths_to_static_invoice_server: Vec<BlindedMessagePath>,
		max_invoices_stored_by_server: u8,
	) -> Result<(), ()> {
		if paths_to_static_invoice_server.is_empty() || max_invoices_stored_by_server == 0 {
			return Err(());
		}

		self.paths_to_static_invoice_server = paths_to_static_invoice_server;
		self.max_invoices_stored_by_server = max_invoices_stored_by_server;
		if self.offers.is_empty() {
			let num_offers =
				core::cmp::min(max_invoices_stored_by_server as usize, MAX_CACHED_OFFERS_TARGET);
			//
			self.offers = vec![None; num_offers];
		}
		Ok(())
	}
}

// The target number of offers we want to have cached at any given time, to mitigate too much
// reuse of the same offer.
#[cfg(async_payments)]
const MAX_CACHED_OFFERS_TARGET: usize = 10;

// The max number of times we'll attempt to request offer paths or attempt to refresh a static
// invoice before giving up.
#[cfg(async_payments)]
const MAX_UPDATE_ATTEMPTS: u8 = 3;

// If we have an offer that is replaceable and its invoice was confirmed as persisted more than 2
// hours ago, we can go ahead and refresh it because we always want to have the freshest offer
// possible when a user goes to retrieve a cached offer.
#[cfg(async_payments)]
const OFFER_REFRESH_THRESHOLD: Duration = Duration::from_secs(2 * 60 * 60);

// Require offer paths that we receive to last at least 3 months.
#[cfg(async_payments)]
const MIN_OFFER_PATHS_RELATIVE_EXPIRY_SECS: u64 = 3 * 30 * 24 * 60 * 60;

#[cfg(async_payments)]
impl AsyncReceiveOfferCache {
	/// Remove expired offers from the cache, returning whether new offers are needed.
	pub(super) fn prune_expired_offers(
		&mut self, duration_since_epoch: Duration, timer_tick_occurred: bool,
	) -> bool {
		// Remove expired offers from the cache.
		let mut offer_was_removed = false;
		for offer_opt in self.offers.iter_mut() {
			let offer_is_expired = offer_opt
				.as_ref()
				.map_or(false, |offer| offer.offer.is_expired_no_std(duration_since_epoch));
			if offer_is_expired {
				offer_opt.take();
				offer_was_removed = true;
			}
		}

		// Allow more offer paths requests to be sent out in a burst roughly once per minute, or if an
		// offer was removed.
		if timer_tick_occurred || offer_was_removed {
			self.reset_offer_paths_request_attempts()
		}

		self.needs_new_offer_idx(duration_since_epoch).is_some()
			&& self.offer_paths_request_attempts < MAX_UPDATE_ATTEMPTS
	}

	/// Returns whether the new paths we've just received from the static invoice server should be used
	/// to build a new offer.
	pub(super) fn should_build_offer_with_paths(
		&self, offer_paths: &[BlindedMessagePath], offer_paths_absolute_expiry_secs: Option<u64>,
		duration_since_epoch: Duration,
	) -> bool {
		if self.needs_new_offer_idx(duration_since_epoch).is_none() {
			return false;
		}

		// Require the offer that would be built using these paths to last at least a few months.
		let min_offer_paths_absolute_expiry =
			duration_since_epoch.as_secs().saturating_add(MIN_OFFER_PATHS_RELATIVE_EXPIRY_SECS);
		let offer_paths_absolute_expiry = offer_paths_absolute_expiry_secs.unwrap_or(u64::MAX);
		if offer_paths_absolute_expiry < min_offer_paths_absolute_expiry {
			return false;
		}

		// Check that we don't have any current offers that already contain these paths
		self.offers_with_idx().all(|(_, offer)| offer.offer.paths() != offer_paths)
	}

	///
	pub(super) fn cache_pending_offer(
		&mut self, offer: Offer, offer_paths_absolute_expiry_secs: Option<u64>, offer_nonce: Nonce,
		update_static_invoice_path: Responder, duration_since_epoch: Duration,
	) -> Result<u8, ()> {
		if !self.should_build_offer_with_paths(
			offer.paths(),
			offer_paths_absolute_expiry_secs,
			duration_since_epoch,
		) {
			return Err(());
		}

		self.prune_expired_offers(duration_since_epoch, false);

		let idx = match self.needs_new_offer_idx(duration_since_epoch) {
			Some(idx) => idx,
			None => return Err(()),
		};

		if idx >= self.offers.len() {
			debug_assert!(false);
			return Err(());
		}
		self.offers[idx] = Some(AsyncReceiveOffer {
			offer,
			offer_nonce,
			status: OfferStatus::Pending,
			update_static_invoice_path,
		});

		Ok(idx.try_into().map_err(|_| ())?)
	}

	fn needs_new_offer_idx(&self, duration_since_epoch: Duration) -> Option<usize> {
		// If we have any empty offer slots, return the first one we find
		let mut offers_opt_iter = self.offers.iter().enumerate();
		let empty_slot_idx_opt =
			offers_opt_iter.find_map(|(idx, offer_opt)| offer_opt.is_none().then(|| idx));
		if empty_slot_idx_opt.is_some() {
			return empty_slot_idx_opt;
		}

		// If all of our offers are already used or pending, then none are available to be replaced
		let no_replaceable_offers = self.offers_with_idx().all(|(_, offer)| {
			matches!(offer.status, OfferStatus::Used)
				|| matches!(offer.status, OfferStatus::Pending)
		});
		if no_replaceable_offers {
			return None;
		}

		// If we only have 1 offer that is available for payments, then none are available to be
		// replaced
		let num_payable_offers = self
			.offers_with_idx()
			.filter(|(_, offer)| {
				matches!(offer.status, OfferStatus::Used)
					|| matches!(offer.status, OfferStatus::Ready { .. })
			})
			.count();
		if num_payable_offers <= 1 {
			return None;
		}

		// Filter for offers that were last updated more than two hours ago, so they are stale enough
		// to warrant replacement
		let two_hours_ago = duration_since_epoch.saturating_sub(OFFER_REFRESH_THRESHOLD);
		self.offers_with_idx()
			.filter_map(|(idx, offer)| match offer.status {
				OfferStatus::Ready { invoice_confirmed_persisted_at } => {
					Some((idx, offer, invoice_confirmed_persisted_at))
				},
				_ => None,
			})
			.filter(|(_, _, invoice_confirmed_persisted_at)| {
				*invoice_confirmed_persisted_at < two_hours_ago
			})
			// Get the stalest offer and return its index
			.min_by(|a, b| a.2.cmp(&b.2))
			.map(|(idx, _, _)| idx)
	}

	/// Returns an iterator over (offer_idx, offer)
	fn offers_with_idx(&self) -> impl Iterator<Item = (usize, &AsyncReceiveOffer)> {
		self.offers.iter().enumerate().filter_map(|(idx, offer_opt)| {
			if let Some(offer) = offer_opt {
				Some((idx, offer))
			} else {
				None
			}
		})
	}

	// Indicates that onion messages requesting new offer paths have been sent to the static invoice
	// server. Calling this method allows the cache to self-limit how many requests are sent, in case
	// the server goes unresponsive.
	pub(super) fn new_offers_requested(&mut self, duration_since_epoch: Duration) {
		self.offer_paths_request_attempts += 1;
		self.last_offer_paths_request_timestamp = duration_since_epoch;
	}

	/// Called on timer tick (roughly once per minute) to allow another MAX_UPDATE_ATTEMPTS offer
	/// paths requests to go out.
	fn reset_offer_paths_request_attempts(&mut self) {
		self.offer_paths_request_attempts = 0;
		self.last_offer_paths_request_timestamp = Duration::from_secs(0);
	}
}

impl Writeable for AsyncReceiveOfferCache {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(w, {
			(0, self.offers, required_vec),
			(2, self.paths_to_static_invoice_server, required_vec),
			(4, self.max_invoices_stored_by_server, required),
			// offer paths request retry info always resets on restart
		});
		Ok(())
	}
}

impl Readable for AsyncReceiveOfferCache {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(r, {
			(0, offers, required_vec),
			(2, paths_to_static_invoice_server, required_vec),
			(4, max_invoices_stored_by_server, required),
		});
		let offers: Vec<Option<AsyncReceiveOffer>> = offers;
		Ok(Self {
			offers,
			offer_paths_request_attempts: 0,
			last_offer_paths_request_timestamp: Duration::from_secs(0),
			paths_to_static_invoice_server,
			max_invoices_stored_by_server: max_invoices_stored_by_server.0.unwrap(),
		})
	}
}
