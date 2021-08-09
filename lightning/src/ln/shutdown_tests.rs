// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests of our shutdown and closing_signed negotiation logic.

use chain::keysinterface::KeysInterface;
use chain::transaction::OutPoint;
use ln::{PaymentPreimage, PaymentHash};
use ln::channelmanager::PaymentSendFailure;
use routing::router::get_route;
use ln::features::{InitFeatures, InvoiceFeatures};
use ln::msgs;
use ln::msgs::{ChannelMessageHandler, ErrorAction};
use ln::script::ShutdownScript;
use util::test_utils;
use util::test_utils::OnGetShutdownScriptpubkey;
use util::events::{Event, MessageSendEvent, MessageSendEventsProvider};
use util::errors::APIError;
use util::config::UserConfig;

use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;

use regex;

use core::default::Default;
use core::num::NonZeroU8;

use ln::functional_test_utils::*;
use ln::msgs::OptionalField::Present;

#[test]
fn pre_funding_lock_shutdown_test() {
	// Test sending a shutdown prior to funding_locked after funding generation
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 8000000, 0, InitFeatures::known(), InitFeatures::known());
	mine_transaction(&nodes[0], &tx);
	mine_transaction(&nodes[1], &tx);

	nodes[0].node.close_channel(&OutPoint { txid: tx.txid(), index: 0 }.to_channel_id(), None).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_shutdown);

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	assert!(node_1_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());
}

#[test]
fn updates_shutdown_wait() {
	// Test sending a shutdown with outstanding updates pending
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (our_payment_preimage, _, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100000);

	nodes[0].node.close_channel(&chan_1.2, None).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_shutdown);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[0]);

	let net_graph_msg_handler0 = &nodes[0].net_graph_msg_handler;
	let net_graph_msg_handler1 = &nodes[1].net_graph_msg_handler;
	let route_1 = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler0.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), Some(InvoiceFeatures::known()), None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
	let route_2 = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler1.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), Some(InvoiceFeatures::known()), None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
	unwrap_send_err!(nodes[0].node.send_payment(&route_1, payment_hash, &Some(payment_secret)), true, APIError::ChannelUnavailable {..}, {});
	unwrap_send_err!(nodes[1].node.send_payment(&route_2, payment_hash, &Some(payment_secret)), true, APIError::ChannelUnavailable {..}, {});

	assert!(nodes[2].node.claim_funds(our_payment_preimage));
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	expect_payment_forwarded!(nodes[1], Some(1000), false);
	check_added_monitors!(nodes[1], 1);
	let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fail_htlcs.is_empty());
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());
	assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { ref payment_preimage } => {
			assert_eq!(our_payment_preimage, *payment_preimage);
		},
		_ => panic!("Unexpected event"),
	}

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	assert!(node_1_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
}

#[test]
fn htlc_fail_async_shutdown() {
	// Test HTLCs fail if shutdown starts even if messages are delivered out-of-order
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (_, our_payment_hash, our_payment_secret) = get_payment_preimage_hash!(nodes[2]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), Some(InvoiceFeatures::known()), None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, our_payment_hash, &Some(our_payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert_eq!(updates.update_add_htlcs.len(), 1);
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());

	nodes[1].node.close_channel(&chan_1.2, None).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_shutdown);
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &updates.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	commitment_signed_dance!(nodes[1], nodes[0], (), false, true, false);

	let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fulfill_htlcs.is_empty());
	assert_eq!(updates_2.update_fail_htlcs.len(), 1);
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);

	expect_payment_failed!(nodes[0], our_payment_hash, false);

	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2);
	match msg_events[0] {
		MessageSendEvent::PaymentFailureNetworkUpdate { update: msgs::HTLCFailChannelUpdate::ChannelUpdateMessage { ref msg }} => {
			assert_eq!(msg.contents.short_channel_id, chan_1.0.contents.short_channel_id);
		},
		_ => panic!("Unexpected event"),
	}
	let node_0_closing_signed = match msg_events[1] {
		MessageSendEvent::SendClosingSigned { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	assert!(node_1_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
}

fn do_test_shutdown_rebroadcast(recv_count: u8) {
	// Test that shutdown/closing_signed is re-sent on reconnect with a variable number of
	// messages delivered prior to disconnect
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	let (our_payment_preimage, _, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100000);

	nodes[1].node.close_channel(&chan_1.2, None).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	if recv_count > 0 {
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_shutdown);
		let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
		if recv_count > 1 {
			nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
		}
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let node_0_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let node_1_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &node_0_reestablish);
	let node_1_2nd_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	assert!(node_1_shutdown == node_1_2nd_shutdown);

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &node_1_reestablish);
	let node_0_2nd_shutdown = if recv_count > 0 {
		let node_0_2nd_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_2nd_shutdown);
		node_0_2nd_shutdown
	} else {
		let node_0_chan_update = get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());
		assert_eq!(node_0_chan_update.contents.flags & 2, 0); // "disabled" flag must not be set as we just reconnected.
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_2nd_shutdown);
		get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id())
	};
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_2nd_shutdown);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	assert!(nodes[2].node.claim_funds(our_payment_preimage));
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	expect_payment_forwarded!(nodes[1], Some(1000), false);
	check_added_monitors!(nodes[1], 1);
	let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fail_htlcs.is_empty());
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());
	assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { ref payment_preimage } => {
			assert_eq!(our_payment_preimage, *payment_preimage);
		},
		_ => panic!("Unexpected event"),
	}

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	if recv_count > 0 {
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
		let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
		let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
		assert!(node_0_2nd_closing_signed.is_some());
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let node_1_2nd_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	if recv_count == 0 {
		// If all closing_signeds weren't delivered we can just resume where we left off...
		let node_0_2nd_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &node_1_2nd_reestablish);
		let node_0_msgs = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(node_0_msgs.len(), 2);
		let node_0_2nd_closing_signed = match node_0_msgs[1] {
			MessageSendEvent::SendClosingSigned { ref msg, .. } => {
				assert_eq!(node_0_closing_signed, *msg);
				msg.clone()
			},
			_ => panic!(),
		};

		let node_0_3rd_shutdown = match node_0_msgs[0] {
			MessageSendEvent::SendShutdown { ref msg, .. } => {
				assert_eq!(node_0_2nd_shutdown, *msg);
				msg.clone()
			},
			_ => panic!(),
		};
		assert!(node_0_2nd_shutdown == node_0_3rd_shutdown);

		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &node_0_2nd_reestablish);
		let node_1_3rd_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
		assert!(node_1_3rd_shutdown == node_1_2nd_shutdown);

		nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_3rd_shutdown);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_3rd_shutdown);

		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed);
		let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
		let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.unwrap());
		let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
		assert!(node_1_none.is_none());
	} else {
		// If one node, however, received + responded with an identical closing_signed we end
		// up erroring and node[0] will try to broadcast its own latest commitment transaction.
		// There isn't really anything better we can do simply, but in the future we might
		// explore storing a set of recently-closed channels that got disconnected during
		// closing_signed and avoiding broadcasting local commitment txn for some timeout to
		// give our counterparty enough time to (potentially) broadcast a cooperative closing
		// transaction.
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &node_1_2nd_reestablish);
		let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		if let MessageSendEvent::HandleError { ref action, .. } = msg_events[0] {
			match action {
				&ErrorAction::SendErrorMessage { ref msg } => {
					nodes[1].node.handle_error(&nodes[0].node.get_our_node_id(), &msg);
					assert_eq!(msg.channel_id, chan_1.2);
				},
				_ => panic!("Unexpected event!"),
			}
		} else { panic!("Needed SendErrorMessage close"); }

		// get_closing_signed_broadcast usually eats the BroadcastChannelUpdate for us and
		// checks it, but in this case nodes[1] didn't ever get a chance to receive a
		// closing_signed so we do it ourselves
		check_closed_broadcast!(nodes[1], false);
		check_added_monitors!(nodes[1], 1);
	}

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
}

#[test]
fn test_shutdown_rebroadcast() {
	do_test_shutdown_rebroadcast(0);
	do_test_shutdown_rebroadcast(1);
	do_test_shutdown_rebroadcast(2);
}

#[test]
fn test_upfront_shutdown_script() {
	// BOLT 2 : Option upfront shutdown script, if peer commit its closing_script at channel opening
	// enforce it at shutdown message

	let mut config = UserConfig::default();
	config.channel_options.announced_channel = true;
	config.peer_channel_config_limits.force_announced_channel_preference = false;
	config.channel_options.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// We test that in case of peer committing upfront to a script, if it changes at closing, we refuse to sign
	let flags = InitFeatures::known();
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1000000, 1000000, flags.clone(), flags.clone());
	nodes[0].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), None).unwrap();
	let mut node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[2].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script().to_p2sh();
	// Test we enforce upfront_scriptpbukey if by providing a diffrent one at closing that  we disconnect peer
	nodes[2].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
    assert!(regex::Regex::new(r"Got shutdown request with a scriptpubkey \([A-Fa-f0-9]+\) which did not match their previous scriptpubkey.").unwrap().is_match(check_closed_broadcast!(nodes[2], true).unwrap().data.as_str()));
	check_added_monitors!(nodes[2], 1);

	// We test that in case of peer committing upfront to a script, if it doesn't change at closing, we sign
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1000000, 1000000, flags.clone(), flags.clone());
	nodes[0].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), None).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[2].node.get_our_node_id());
	// We test that in case of peer committing upfront to a script, if it oesn't change at closing, we sign
	nodes[2].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[0].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}

	// We test that if case of peer non-signaling we don't enforce committed script at channel opening
	let flags_no = InitFeatures::known().clear_upfront_shutdown_script();
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, flags_no, flags.clone());
	nodes[0].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), None).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_1_shutdown);
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[0].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}

	// We test that if user opt-out, we provide a zero-length script at channel opening and we are able to close
	// channel smoothly, opt-out is from channel initiator here
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 1, 0, 1000000, 1000000, flags.clone(), flags.clone());
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), None).unwrap();
	check_added_monitors!(nodes[1], 1);
	let node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}

	//// We test that if user opt-out, we provide a zero-length script at channel opening and we are able to close
	//// channel smoothly
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, flags.clone(), flags.clone());
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), None).unwrap();
	check_added_monitors!(nodes[1], 1);
	let node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::SendClosingSigned { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_unsupported_anysegwit_upfront_shutdown_script() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Use a non-v0 segwit script supported by option_shutdown_anysegwit
	let node_features = InitFeatures::known().clear_shutdown_anysegwit();
	let anysegwit_shutdown_script = Builder::new()
		.push_int(16)
		.push_slice(&[0, 40])
		.into_script();

	// Check script when handling an open_channel message
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();
	let mut open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	open_channel.shutdown_scriptpubkey = Present(anysegwit_shutdown_script.clone());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), node_features.clone(), &open_channel);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
			assert_eq!(node_id, nodes[0].node.get_our_node_id());
			assert_eq!(msg.data, "Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: Script(OP_PUSHNUM_16 OP_PUSHBYTES_2 0028)");
		},
		_ => panic!("Unexpected event"),
	}

	// Check script when handling an accept_channel message
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &open_channel);
	let mut accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	accept_channel.shutdown_scriptpubkey = Present(anysegwit_shutdown_script.clone());
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), node_features, &accept_channel);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
			assert_eq!(msg.data, "Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: Script(OP_PUSHNUM_16 OP_PUSHBYTES_2 0028)");
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_invalid_upfront_shutdown_script() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();

	// Use a segwit v0 script with an unsupported witness program
	let mut open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	open_channel.shutdown_scriptpubkey = Present(Builder::new().push_int(0)
		.push_slice(&[0, 0])
		.into_script());
	nodes[0].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &open_channel);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
			assert_eq!(node_id, nodes[0].node.get_our_node_id());
			assert_eq!(msg.data, "Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: Script(OP_0 OP_PUSHBYTES_2 0000)");
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_segwit_v0_shutdown_script() {
	let mut config = UserConfig::default();
	config.channel_options.announced_channel = true;
	config.peer_channel_config_limits.force_announced_channel_preference = false;
	config.channel_options.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), None).unwrap();
	check_added_monitors!(nodes[1], 1);

	// Use a segwit v0 script supported even without option_shutdown_anysegwit
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_int(0)
		.push_slice(&[0; 20])
		.into_script();
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::SendClosingSigned { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_anysegwit_shutdown_script() {
	let mut config = UserConfig::default();
	config.channel_options.announced_channel = true;
	config.peer_channel_config_limits.force_announced_channel_preference = false;
	config.channel_options.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), None).unwrap();
	check_added_monitors!(nodes[1], 1);

	// Use a non-v0 segwit script supported by option_shutdown_anysegwit
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_int(16)
		.push_slice(&[0, 0])
		.into_script();
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::SendClosingSigned { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_unsupported_anysegwit_shutdown_script() {
	let mut config = UserConfig::default();
	config.channel_options.announced_channel = true;
	config.peer_channel_config_limits.force_announced_channel_preference = false;
	config.channel_options.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let mut node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	node_cfgs[0].features = InitFeatures::known().clear_shutdown_anysegwit();
	node_cfgs[1].features = InitFeatures::known().clear_shutdown_anysegwit();
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Check that using an unsupported shutdown script fails and a supported one succeeds.
	let supported_shutdown_script = chanmon_cfgs[1].keys_manager.get_shutdown_scriptpubkey();
	let unsupported_shutdown_script =
		ShutdownScript::new_witness_program(NonZeroU8::new(16).unwrap(), &[0, 40]).unwrap();
	chanmon_cfgs[1].keys_manager
		.expect(OnGetShutdownScriptpubkey { returns: unsupported_shutdown_script.clone() })
		.expect(OnGetShutdownScriptpubkey { returns: supported_shutdown_script });

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, node_cfgs[0].features.clone(), node_cfgs[1].features.clone());
	match nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), None) {
		Err(APIError::IncompatibleShutdownScript { script }) => {
			assert_eq!(script.into_inner(), unsupported_shutdown_script.clone().into_inner());
		},
		Err(e) => panic!("Unexpected error: {:?}", e),
		Ok(_) => panic!("Expected error"),
	}
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), None).unwrap();
	check_added_monitors!(nodes[1], 1);

	// Use a non-v0 segwit script unsupported without option_shutdown_anysegwit
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = unsupported_shutdown_script.into_inner();
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_cfgs[1].features, &node_0_shutdown);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[1] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
			assert_eq!(msg.data, "Got a nonstandard scriptpubkey (60020028) from remote peer".to_owned());
		},
		_ => panic!("Unexpected event"),
	}
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_invalid_shutdown_script() {
	let mut config = UserConfig::default();
	config.channel_options.announced_channel = true;
	config.peer_channel_config_limits.force_announced_channel_preference = false;
	config.channel_options.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), None).unwrap();
	check_added_monitors!(nodes[1], 1);

	// Use a segwit v0 script with an unsupported witness program
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_int(0)
		.push_slice(&[0, 0])
		.into_script();
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[1] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
			assert_eq!(msg.data, "Got a nonstandard scriptpubkey (00020000) from remote peer".to_owned())
		},
		_ => panic!("Unexpected event"),
	}
	check_added_monitors!(nodes[0], 1);
}

fn do_test_closing_signed_reinit_timeout(timeout_step: u8) {
	// The range-based closing signed negotiation allows the funder to restart the process with a
	// new range if the previous range did not overlap. This allows implementations to request user
	// intervention allowing users to enter a new fee range. We do not implement the sending side
	// of this, instead opting to allow users to enter an explicit "willing to pay up to X to avoid
	// force-closing" value and relying on that instead.
	//
	// Here we run test the fundee side of that restart mechanism, implementing the funder side of
	// it manually.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;

	send_payment(&nodes[0], &[&nodes[1]], 8_000_000);

	nodes[0].node.close_channel(&chan_id, None).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_shutdown);

	{
		// Now we set nodes[1] to require a relatively high feerate for closing. This should result
		// in it rejecting nodes[0]'s initial closing_signed, giving nodes[0] a chance to try
		// again.
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock *= 10;
	}

	let mut node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	assert!(node_0_closing_signed.fee_satoshis <= 500);

	if timeout_step != 0 {
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
		// At this point nodes[1] should send back a warning message indicating it disagrees with the
		// given channel-closing fee. Currently we do not implement warning messages so instead we
		// remain silent here.
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		// Now deliver a mutated closing_signed indicating a higher acceptable fee range, which
		// nodes[1] should happily accept and respond to.
		node_0_closing_signed.fee_range.as_mut().unwrap().max_fee_satoshis *= 10;
		{
			let mut lock;
			get_channel_ref!(nodes[0], lock, chan_id).closing_fee_limits.as_mut().unwrap().1 *= 10;
		}
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
		let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
		let node_0_2nd_closing_signed = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
		if timeout_step > 1 {
			nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.1.unwrap());
		}
	}

	if timeout_step <= 1 {
		assert!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	} else {
		assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	}

	nodes[1].node.timer_tick_occurred();
	nodes[1].node.timer_tick_occurred();

	let txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(txn.len(), 1);
	assert_eq!(txn[0].output.len(), 2);

	// If we timed out we should have a P2WPKH and P2WSH output, otherwise both should be P2WPKH.
	if timeout_step <= 1 {
		assert!((txn[0].output[0].script_pubkey.len() == 20+1+1 &&
		         txn[0].output[1].script_pubkey.len() == 32+1+1) ||
		        (txn[0].output[1].script_pubkey.len() == 20+1+1 &&
		         txn[0].output[0].script_pubkey.len() == 32+1+1));
		check_closed_broadcast!(nodes[1], true);
		check_added_monitors!(nodes[1], 1);
	} else {
		assert_eq!(txn[0].output[0].script_pubkey.len(), 20+1+1);
		assert_eq!(txn[0].output[1].script_pubkey.len(), 20+1+1);

		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				assert_eq!(msg.contents.flags & 2, 2);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

#[test]
fn test_closing_signed_reinit_timeout() {
	do_test_closing_signed_reinit_timeout(0);
	do_test_closing_signed_reinit_timeout(1);
	do_test_closing_signed_reinit_timeout(2);
}
