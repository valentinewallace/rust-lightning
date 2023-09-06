// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::secp256k1::Secp256k1;
use crate::blinded_path::BlindedPath;
use crate::blinded_path::payment::{ForwardNode, ForwardTlvs, PaymentConstraints, PaymentRelay, ReceiveTlvs};
use crate::events::MessageSendEventsProvider;
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields, RetryableSendFailure};
use crate::ln::features::BlindedHopFeatures;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::outbound_payment::Retry;
use crate::prelude::*;
use crate::routing::router::{PaymentParameters, RouteParameters};

#[test]
fn simple_blinded_payment() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let mut cfg = test_default_channel_config();
	// Test the fee_proportional_millionths specified in the blinded path's payment constraints.
	cfg.channel_config.forwarding_fee_proportional_millionths = 100;
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, Some(cfg), None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	let chan_upd = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0).0.contents;

	let amt_msat = 5000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[3], Some(amt_msat), None);
	let intermediate_nodes = vec![ForwardNode {
		node_id: nodes[2].node.get_our_node_id(),
		tlvs: ForwardTlvs {
			short_channel_id: chan_upd.short_channel_id,
			payment_relay: PaymentRelay {
				cltv_expiry_delta: chan_upd.cltv_expiry_delta,
				fee_proportional_millionths: chan_upd.fee_proportional_millionths,
				fee_base_msat: chan_upd.fee_base_msat,
			},
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: u32::max_value(),
				htlc_minimum_msat: chan_upd.htlc_minimum_msat,
			},
			features: BlindedHopFeatures::empty(),
		},
		htlc_maximum_msat: chan_upd.htlc_maximum_msat,
	}];
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: chan_upd.htlc_minimum_msat,
		},
	};
	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::new_for_payment(
		&intermediate_nodes[..], nodes[3].node.get_our_node_id(), payee_tlvs,
		chan_upd.htlc_maximum_msat, &chanmon_cfgs[3].keys_manager, &secp_ctx
	).unwrap();

	let route_params = RouteParameters {
		payment_params: PaymentParameters::blinded(vec![blinded_path]),
		final_value_msat: amt_msat
	};
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2], &nodes[3]]], amt_msat, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3]], payment_preimage);
}

#[test]
fn blinded_intercept_payment() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut intercept_forwards_config = test_default_channel_config();
	intercept_forwards_config.accept_intercept_htlcs = true;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, Some(intercept_forwards_config), None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	let (channel_id, chan_upd) = (chan.2, chan.0.contents);

	let amt_msat = 5000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);
	let intercept_scid = nodes[1].node.get_intercept_scid();
	let intermediate_nodes = vec![ForwardNode {
		node_id: nodes[1].node.get_our_node_id(),
		tlvs: ForwardTlvs {
			short_channel_id: intercept_scid,
			payment_relay: PaymentRelay {
				cltv_expiry_delta: chan_upd.cltv_expiry_delta,
				fee_proportional_millionths: chan_upd.fee_proportional_millionths,
				fee_base_msat: chan_upd.fee_base_msat,
			},
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: u32::max_value(),
				htlc_minimum_msat: chan_upd.htlc_minimum_msat,
			},
			features: BlindedHopFeatures::empty(),
		},
		htlc_maximum_msat: chan_upd.htlc_maximum_msat,
	}];
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: chan_upd.htlc_minimum_msat,
		},
	};
	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::new_for_payment(
		&intermediate_nodes[..], nodes[2].node.get_our_node_id(), payee_tlvs,
		chan_upd.htlc_maximum_msat, &chanmon_cfgs[2].keys_manager, &secp_ctx
	).unwrap();

	let route_params = RouteParameters {
		payment_params: PaymentParameters::blinded(vec![blinded_path]),
		final_value_msat: amt_msat
	};
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(),
		PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	let payment_event = {
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], &payment_event.commitment_msg, false, true);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (intercept_id, expected_outbound_amount_msat) = match events[0] {
		crate::events::Event::HTLCIntercepted {
			intercept_id, expected_outbound_amount_msat, payment_hash: pmt_hash,
			requested_next_hop_scid: short_channel_id, ..
		} => {
			assert_eq!(pmt_hash, payment_hash);
			assert_eq!(short_channel_id, intercept_scid);
			(intercept_id, expected_outbound_amount_msat)
		},
		_ => panic!()
	};

	nodes[1].node.forward_intercepted_htlc(intercept_id, &channel_id, nodes[2].node.get_our_node_id(),
		expected_outbound_amount_msat).unwrap();
	expect_pending_htlcs_forwardable!(nodes[1]);

	let payment_event = {
		{
			let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();
		}
		let mut events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[2], nodes[1], &payment_event.commitment_msg, false, true);
	expect_pending_htlcs_forwardable!(nodes[2]);

	expect_payment_claimable!(&nodes[2], payment_hash, payment_secret, amt_msat, None,
		nodes[2].node.get_our_node_id());
	do_claim_payment_along_route(&nodes[0], &vec!(&vec!(&nodes[1], &nodes[2])[..]), false, payment_preimage);
	expect_payment_sent(&nodes[0], payment_preimage, Some(Some(1000)), true, true);
}

#[test]
fn one_hop_blinded_path() {
	do_one_hop_blinded_path(true);
	do_one_hop_blinded_path(false);
}

fn do_one_hop_blinded_path(success: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_upd = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0).0.contents;

	let amt_msat = 5000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[1], Some(amt_msat), None);
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: chan_upd.htlc_minimum_msat,
		},
	};
	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::new_for_payment(
		&[], nodes[1].node.get_our_node_id(), payee_tlvs, chan_upd.htlc_maximum_msat,
		&chanmon_cfgs[1].keys_manager, &secp_ctx
	).unwrap();

	let route_params = RouteParameters {
		payment_params: PaymentParameters::blinded(vec![blinded_path]),
		final_value_msat: amt_msat
	};
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(),
	PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1]]], amt_msat, payment_hash, payment_secret);
	if success {
		claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);
	} else {
		fail_payment(&nodes[0], &[&nodes[1]], payment_hash);
	}
}

#[test]
fn min_htlc() {
	// The min htlc of a blinded path is the max (htlc_min - following_fees) along the path. Make sure
	// the payment succeeds when we calculate the min htlc this way.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let mut node_1_cfg = test_default_channel_config();
	node_1_cfg.channel_handshake_config.our_htlc_minimum_msat = 2000;
	node_1_cfg.channel_config.forwarding_fee_base_msat = 1000;
	node_1_cfg.channel_config.forwarding_fee_proportional_millionths = 100_000;
	let mut node_2_cfg = test_default_channel_config();
	node_2_cfg.channel_handshake_config.our_htlc_minimum_msat = 5000;
	node_2_cfg.channel_config.forwarding_fee_base_msat = 200;
	node_2_cfg.channel_config.forwarding_fee_proportional_millionths = 150_000;
	let mut node_3_cfg = test_default_channel_config();
	node_3_cfg.channel_handshake_config.our_htlc_minimum_msat = 2000;
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, Some(node_1_cfg), Some(node_2_cfg), Some(node_3_cfg)]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let (min_accepted_htlc_node_1, min_accepted_htlc_node_2, chan_upd_1_2)  = {
		let (chan_upd_1_2, chan_upd_2_1, _, _) =
			create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
		(chan_upd_2_1.contents.htlc_minimum_msat, chan_upd_1_2.contents.htlc_minimum_msat,
		 chan_upd_1_2.contents)
	};
	let chan_upd_2_3 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0).0.contents;

	let min_htlc_msat = 4174; // the resulting htlc min
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[3], Some(min_htlc_msat), None);
	let intermediate_nodes = vec![ForwardNode {
		node_id: nodes[1].node.get_our_node_id(),
		tlvs: ForwardTlvs {
			short_channel_id: chan_upd_1_2.short_channel_id,
			payment_relay: PaymentRelay {
				cltv_expiry_delta: chan_upd_1_2.cltv_expiry_delta,
				fee_proportional_millionths: chan_upd_1_2.fee_proportional_millionths,
				fee_base_msat: chan_upd_1_2.fee_base_msat,
			},
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: u32::max_value(),
				htlc_minimum_msat: min_accepted_htlc_node_1,
			},
			features: BlindedHopFeatures::empty(),
		},
		htlc_maximum_msat: chan_upd_1_2.htlc_maximum_msat,
	}, ForwardNode {
		node_id: nodes[2].node.get_our_node_id(),
		tlvs: ForwardTlvs {
			short_channel_id: chan_upd_2_3.short_channel_id,
			payment_relay: PaymentRelay {
				cltv_expiry_delta: chan_upd_2_3.cltv_expiry_delta,
				fee_proportional_millionths: chan_upd_2_3.fee_proportional_millionths,
				fee_base_msat: chan_upd_2_3.fee_base_msat,
			},
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: u32::max_value(),
				htlc_minimum_msat: min_accepted_htlc_node_2,
			},
			features: BlindedHopFeatures::empty(),
		},
		htlc_maximum_msat: chan_upd_1_2.htlc_maximum_msat,
	}];
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: chan_upd_2_3.htlc_minimum_msat,
		},
	};
	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::new_for_payment(
		&intermediate_nodes[..], nodes[3].node.get_our_node_id(), payee_tlvs,
		chan_upd_2_3.htlc_maximum_msat, &chanmon_cfgs[3].keys_manager, &secp_ctx
	).unwrap();
	assert_eq!(min_htlc_msat, blinded_path.0.htlc_minimum_msat);

	let route_params = RouteParameters {
		payment_params: PaymentParameters::blinded(vec![blinded_path.clone()]),
		final_value_msat: min_htlc_msat,
	};
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2], &nodes[3]]], min_htlc_msat, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3]], payment_preimage);

	// Paying 1 less than the min fails.
	let route_params = RouteParameters {
		payment_params: PaymentParameters::blinded(vec![blinded_path]),
		final_value_msat: min_htlc_msat - 1,
	};
	if let Err(e) = nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)) {
		assert_eq!(e, RetryableSendFailure::RouteNotFound);
	} else { panic!() }
}
