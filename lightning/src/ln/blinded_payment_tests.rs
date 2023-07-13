// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::secp256k1::Secp256k1;
use crate::blinded_path;
use crate::blinded_path::BlindedPath;
use crate::blinded_path::payment::{ForwardNode, ForwardTlvs, PaymentConstraints, PaymentRelay, ReceiveTlvs};
use crate::events::{Event, HTLCDestination, MessageSendEvent, MessageSendEventsProvider};
use crate::ln::PaymentSecret;
use crate::ln::channelmanager;
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields, RetryableSendFailure};
use crate::ln::features::{BlindedHopFeatures, Bolt12InvoiceFeatures};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs;
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::onion_utils::INVALID_ONION_BLINDING;
use crate::ln::outbound_payment::Retry;
use crate::prelude::*;
use crate::routing::router::{PaymentParameters, RouteParameters};
use crate::util::config::UserConfig;

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
fn blinded_mpp() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	let mut secp_ctx = Secp256k1::new();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 0, 2);
	let chan_upd_1_3 = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents;
	let chan_upd_2_3 = create_announced_chan_between_nodes(&nodes, 2, 3).0.contents;

	let amt_msat = 15_000_000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[3], Some(amt_msat), None);
	let mut blinded_paths = Vec::new();
	for (idx, chan_upd) in [chan_upd_1_3, chan_upd_2_3].iter().enumerate() {
		let intermediate_nodes = vec![ForwardNode {
			node_id: nodes[idx + 1].node.get_our_node_id(),
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
		let blinded_path = BlindedPath::new_for_payment(
			&intermediate_nodes[..], nodes[3].node.get_our_node_id(), payee_tlvs,
			chan_upd.htlc_maximum_msat, &chanmon_cfgs[3].keys_manager, &secp_ctx
		).unwrap();
		blinded_paths.push(blinded_path);
	}

	let bolt12_features: Bolt12InvoiceFeatures =
		channelmanager::provided_invoice_features(&UserConfig::default()).to_context();
	let route_params = RouteParameters {
		payment_params: PaymentParameters::blinded(blinded_paths)
			.with_bolt12_features(bolt12_features).unwrap(),
		final_value_msat: amt_msat,
	};
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 2);

	let expected_route: &[&[&Node]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	pass_along_path(&nodes[0], expected_route[0], amt_msat, payment_hash.clone(),
		Some(payment_secret), ev.clone(), false, None);

	let ev = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
	pass_along_path(&nodes[0], expected_route[1], amt_msat, payment_hash.clone(),
		Some(payment_secret), ev.clone(), true, None);
	claim_payment_along_route(&nodes[0], expected_route, false, payment_preimage);
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

#[test]
#[cfg(feature = "std")]
fn prop_fees_rng() {
	do_prop_fees_rng(true);
	do_prop_fees_rng(false);
}

#[cfg(feature = "std")]
fn do_prop_fees_rng(send_min: bool) {
	use std::hash::{BuildHasher, Hasher};
	// Ensure the proportional fees are calculated correctly for `BlindedPayInfo`.
	let chanmon_cfgs = create_chanmon_cfgs(5);
	const PROP_LIMIT: u64 = 1_000_000;
	let base_limit: u64 = if send_min { 1_000_000 } else { 15_000_000 };
	const MIN_HTLC_LIMIT: u64 = 15_000_000;
	let node_cfgs = create_node_cfgs(5, &chanmon_cfgs);

	let mut node_1_cfg = test_default_channel_config();
	node_1_cfg.channel_config.forwarding_fee_base_msat =
		(std::collections::hash_map::RandomState::new().build_hasher().finish() % base_limit) as u32;
	node_1_cfg.channel_config.forwarding_fee_proportional_millionths =
		(std::collections::hash_map::RandomState::new().build_hasher().finish() % PROP_LIMIT) as u32;
	if send_min {
		node_1_cfg.channel_handshake_config.our_htlc_minimum_msat =
		(std::collections::hash_map::RandomState::new().build_hasher().finish() % MIN_HTLC_LIMIT) as u64;
	}

	let mut node_2_cfg = test_default_channel_config();
	node_2_cfg.channel_config.forwarding_fee_base_msat =
		(std::collections::hash_map::RandomState::new().build_hasher().finish() % base_limit) as u32;
	node_2_cfg.channel_config.forwarding_fee_proportional_millionths =
		(std::collections::hash_map::RandomState::new().build_hasher().finish() % PROP_LIMIT) as u32;
	if send_min {
		node_2_cfg.channel_handshake_config.our_htlc_minimum_msat =
			(std::collections::hash_map::RandomState::new().build_hasher().finish() % MIN_HTLC_LIMIT) as u64;
	}

	let mut node_3_cfg = test_default_channel_config();
	node_3_cfg.channel_config.forwarding_fee_base_msat =
		(std::collections::hash_map::RandomState::new().build_hasher().finish() % base_limit) as u32;
	node_3_cfg.channel_config.forwarding_fee_proportional_millionths =
		(std::collections::hash_map::RandomState::new().build_hasher().finish() % PROP_LIMIT) as u32;
	if send_min {
		node_3_cfg.channel_handshake_config.our_htlc_minimum_msat =
			(std::collections::hash_map::RandomState::new().build_hasher().finish() % MIN_HTLC_LIMIT) as u64;
	}

	let node_chanmgrs = create_node_chanmgrs(5, &node_cfgs, &[None, Some(node_1_cfg), Some(node_2_cfg), Some(node_3_cfg), None]);
	let nodes = create_network(5, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let (node_1_min_htlc, chan_upd_1_2) = {
		let (chan_upd_1_2, chan_upd_2_1, _, _) = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
		(chan_upd_2_1.contents.htlc_minimum_msat, chan_upd_1_2.contents)
	};
	let chan_upd_2_3 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0).0.contents;
	let chan_upd_3_4 = create_announced_chan_between_nodes_with_value(&nodes, 3, 4, 1_000_000, 0).0.contents;

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
				htlc_minimum_msat: node_1_min_htlc,
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
				htlc_minimum_msat: chan_upd_1_2.htlc_minimum_msat,
			},
			features: BlindedHopFeatures::empty(),
		},
		htlc_maximum_msat: chan_upd_1_2.htlc_maximum_msat,
	}, ForwardNode {
		node_id: nodes[3].node.get_our_node_id(),
		tlvs: ForwardTlvs {
			short_channel_id: chan_upd_3_4.short_channel_id,
			payment_relay: PaymentRelay {
				cltv_expiry_delta: chan_upd_3_4.cltv_expiry_delta,
				fee_proportional_millionths: chan_upd_3_4.fee_proportional_millionths,
				fee_base_msat: chan_upd_3_4.fee_base_msat,
			},
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: u32::max_value(),
				htlc_minimum_msat: chan_upd_2_3.htlc_minimum_msat,
			},
			features: BlindedHopFeatures::empty(),
		},
		htlc_maximum_msat: chan_upd_1_2.htlc_maximum_msat,
	}];
	let mut payee_tlvs = ReceiveTlvs {
		payment_secret: PaymentSecret([0; 32]), // filled in later
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: chan_upd_3_4.htlc_minimum_msat,
		},
	};
	let amt_msat = if send_min {
		blinded_path::payment::test_compute_payinfo(&intermediate_nodes[..], &payee_tlvs,
			chan_upd_3_4.htlc_maximum_msat).unwrap().htlc_minimum_msat
	} else { 100_000 };
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[4], Some(amt_msat), None);
	payee_tlvs.payment_secret = payment_secret;
	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::new_for_payment(
		&intermediate_nodes[..], nodes[4].node.get_our_node_id(), payee_tlvs,
		chan_upd_2_3.htlc_maximum_msat, &chanmon_cfgs[4].keys_manager, &secp_ctx
	).unwrap();

	let route_params = RouteParameters {
		payment_params: PaymentParameters::blinded(vec![blinded_path.clone()]),
		final_value_msat: amt_msat
	};
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let event = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	let expected_path = &[&nodes[1], &nodes[2], &nodes[3], &nodes[4]];
	let mut args = PassAlongPathArgs::new(&nodes[0], expected_path, amt_msat, payment_hash, Some(payment_secret), event, None);
	args.overpay_limit = if send_min { 40 } else {
		3 // Allow up to 1 sat overpayment per intermediate hop
	};
	do_pass_along_path(args);

	nodes[4].node.claim_funds(payment_preimage);
	let expected_route = &[&expected_path[..]];
	let mut claim_args = ClaimAlongRouteArgs::new(&nodes[0], &expected_route[..], payment_preimage);
	claim_args.is_blinded = true;
	let expected_fee = pass_claimed_payment_along_route(claim_args);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	if let Event::PaymentSent { fee_paid_msat, .. } = events[0] {
		assert!(fee_paid_msat.unwrap() <= expected_fee + if send_min { 40 } else { 3 });
		assert!(fee_paid_msat.unwrap() >= expected_fee);
	} else { panic!(); }
	check_added_monitors!(nodes[0], 1);
	if send_min {
		let route_params = RouteParameters {
			payment_params: PaymentParameters::blinded(vec![blinded_path]),
			final_value_msat: amt_msat - 1,
		};
		if let Err(e) = nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)) {
			assert_eq!(e, RetryableSendFailure::RouteNotFound);
		} else { panic!() }
	}
}

#[test]
fn high_prop_fees() {
	// Previously, the (rng-found) feerates below caught a bug where an intermediate node would
	// calculate an amt_to_forward that underpaid them by 1 msat, caused by rounding up the outbound
	// amount on top of an already rounded-up total routing fee. Ensure that we'll conditionally round
	// down intermediate nodes' outbound amounts based on whether rounding up will result in
	// undercharging for relay.
	let chanmon_cfgs = create_chanmon_cfgs(5);
	let node_cfgs = create_node_cfgs(5, &chanmon_cfgs);

	let mut node_1_cfg = test_default_channel_config();
	node_1_cfg.channel_config.forwarding_fee_base_msat = 247371;
	node_1_cfg.channel_config.forwarding_fee_proportional_millionths = 86552;

	let mut node_2_cfg = test_default_channel_config();
	node_2_cfg.channel_config.forwarding_fee_base_msat = 198921;
	node_2_cfg.channel_config.forwarding_fee_proportional_millionths = 681759;

	let mut node_3_cfg = test_default_channel_config();
	node_3_cfg.channel_config.forwarding_fee_base_msat = 132845;
	node_3_cfg.channel_config.forwarding_fee_proportional_millionths = 552561;

	let node_chanmgrs = create_node_chanmgrs(5, &node_cfgs, &[None, Some(node_1_cfg), Some(node_2_cfg), Some(node_3_cfg), None]);
	let nodes = create_network(5, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_upd_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0).0.contents;
	let chan_upd_2_3 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0).0.contents;
	let chan_upd_3_4 = create_announced_chan_between_nodes_with_value(&nodes, 3, 4, 1_000_000, 0).0.contents;

	let amt_msat = 100_000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[4], Some(amt_msat), None);
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
				htlc_minimum_msat: chan_upd_1_2.htlc_minimum_msat,
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
				htlc_minimum_msat: chan_upd_2_3.htlc_minimum_msat,
			},
			features: BlindedHopFeatures::empty(),
		},
		htlc_maximum_msat: chan_upd_1_2.htlc_maximum_msat,
	}, ForwardNode {
		node_id: nodes[3].node.get_our_node_id(),
		tlvs: ForwardTlvs {
			short_channel_id: chan_upd_3_4.short_channel_id,
			payment_relay: PaymentRelay {
				cltv_expiry_delta: chan_upd_3_4.cltv_expiry_delta,
				fee_proportional_millionths: chan_upd_3_4.fee_proportional_millionths,
				fee_base_msat: chan_upd_3_4.fee_base_msat,
			},
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: u32::max_value(),
				htlc_minimum_msat: chan_upd_3_4.htlc_minimum_msat,
			},
			features: BlindedHopFeatures::empty(),
		},
		htlc_maximum_msat: chan_upd_1_2.htlc_maximum_msat,
	}];
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: 1,
		},
	};
	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::new_for_payment(
		&intermediate_nodes[..], nodes[4].node.get_our_node_id(), payee_tlvs,
		chan_upd_2_3.htlc_maximum_msat, &chanmon_cfgs[4].keys_manager, &secp_ctx
	).unwrap();

	let route_params = RouteParameters {
		payment_params: PaymentParameters::blinded(vec![blinded_path]),
		final_value_msat: amt_msat
	};
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2], &nodes[3], &nodes[4]]], amt_msat, payment_hash, payment_secret);
	nodes[4].node.claim_funds(payment_preimage);
	let expected_path = &[&nodes[1], &nodes[2], &nodes[3], &nodes[4]];
	let expected_route = &[&expected_path[..]];
	let mut args = ClaimAlongRouteArgs::new(&nodes[0], &expected_route[..], payment_preimage);
	args.is_blinded = true;
	let expected_fee = pass_claimed_payment_along_route(args);
	expect_payment_sent!(nodes[0], payment_preimage, Some(expected_fee));
}

#[test]
fn fail_blinded_payment() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	let chan_upd = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0).0.contents;

	let amt_msat = 5000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[3], Some(amt_msat), None);
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
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(),
		PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2], &nodes[3]]], amt_msat, payment_hash,
		payment_secret);

	nodes[3].node.fail_htlc_backwards(&payment_hash);
	expect_pending_htlcs_forwardable_conditions(nodes[3].node.get_and_clear_pending_events(),
		&[HTLCDestination::FailedPayment { payment_hash }]);
	nodes[3].node.process_pending_htlc_forwards();

	// The last node should fail back with malformed since it's not the intro node.
	check_added_monitors!(nodes[3], 1);
	let (update_fail_malformed, commitment_signed) = {
		let msg_events = nodes[3].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		match msg_events[0] {
			MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate {
				ref update_fail_malformed_htlcs, ref commitment_signed, ..
			}, .. } => {
				assert_eq!(update_fail_malformed_htlcs.len(), 1);
				(update_fail_malformed_htlcs[0].clone(), commitment_signed.clone())
			},
			_ => panic!("Unexpected event"),
		}
	};
	assert_eq!(update_fail_malformed.sha256_of_onion, [0; 32]);
	assert_eq!(update_fail_malformed.failure_code, INVALID_ONION_BLINDING);
	nodes[2].node.handle_update_fail_malformed_htlc(&nodes[3].node.get_our_node_id(), &update_fail_malformed);
	do_commitment_signed_dance(&nodes[2], &nodes[3], &commitment_signed, true, false);

	// The intro node fails back with the invalid_onion_blinding error.
	let (update_fail, commitment_signed) = {
		let msg_events = nodes[2].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		match msg_events[0] {
			MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate {
				ref update_fail_htlcs, ref commitment_signed, ..
			}, .. } => {
				assert_eq!(update_fail_htlcs.len(), 1);
				(update_fail_htlcs[0].clone(), commitment_signed.clone())
			},
			_ => panic!("Unexpected event"),
		}
	};
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &update_fail);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &commitment_signed, true, false);

	let (final_update_fail, commitment_signed) = {
		let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		match msg_events[0] {
			MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate {
				ref update_fail_htlcs, ref commitment_signed, ..
			}, .. } => {
				assert_eq!(update_fail_htlcs.len(), 1);
				(update_fail_htlcs[0].clone(), commitment_signed.clone())
			},
			_ => panic!("Unexpected event"),
		}
	};
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &final_update_fail);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &commitment_signed, false, false);
	let failure_evs = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(failure_evs.len(), 2);
	match &failure_evs[0] {
		Event::PaymentPathFailed {
			payment_hash: ref ev_payment_hash, payment_failed_permanently, ref error_code, ref error_data,
			..
		} => {
			assert_eq!(payment_hash, *ev_payment_hash);
			assert!(!payment_failed_permanently);
			assert_eq!(error_code, &Some(INVALID_ONION_BLINDING));
			assert_eq!(error_data, &Some(vec![0; 32]));
		},
			_ => panic!("Unexpected event"),
	}
}
