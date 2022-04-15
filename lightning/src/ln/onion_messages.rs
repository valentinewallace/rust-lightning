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
use chain::keysinterface::{KeysInterface, KeysManager, Sign};
use util::events::{EventHandler, EventsProvider, MessageSendEvent, MessageSendEventsProvider};

use core::ops::Deref;
use sync::Arc;

/// XXX
pub type SimpleArcOnionMessager = OnionMessager<Arc<KeysManager>>;
/// XXX
pub type SimpleRefOnionMessager<'a> = OnionMessager<&'a KeysManager>;

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
pub struct OnionMessager<Signer: Sign, K: Deref>
	where K::Target: KeysInterface<Signer = Signer>
{
	keys_manager: K,
	pending_msg_events: Vec<MessageSendEvent>,
	custom_messages_received: Vec<CustomOnionPayload>,
}

impl<Signer: Sign, K: Deref> OnionMessager<Signer, K>
	where K::Target: KeysInterface<Signer = Signer>,
{
	/// XXX
	pub fn new(keys_manager: K) -> Self {
		OnionMessager {
			keys_manager,
			pending_msg_events: Vec::new(),
			custom_messages_received: Vec::new(),
		}
	}
}

impl OnionMessageHandler for OnionMessager {
	fn handle_onion_message(&self, peer_node_id: &PublicKey, msg: &msgs::OnionMessage) {
	}
}

