// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! XXX

use bitcoin::secp256k1::key::PublicKey;
use chain::keysinterface::KeysInterface;
use util::events::{EventHandler, EventsProvider, MessageSendEvent, MessageSendEventsProvider};

use core::ops::Deref;

/// XXX
pub struct OnionMessager<K: Deref>
	where K::Target: KeysInterface,
{
	keys_manager: K,
	pending_msg_events: Vec<MessageSendEvent>,
	custom_messages_received: Vec<CustomOnionPayload>,
}

struct CustomOnionPayload {
	custom_tlvs: Vec<CustomTlv>,
}

/// XXX
#[derive(Debug)]
pub struct CustomTlv {
	/// XXX
	pub typ: u64, // XXX can this be smaller?
	/// XXX
	pub value: Vec<u8>,
}

/// XXX
pub enum Destination {
	/// XXX
	Node(PublicKey),
	/// XXX
	BlindedRoute(BlindedRoute)
}

/// XXX
pub struct BlindedRoute {}

/// XXX
pub struct ReplyPath {}
