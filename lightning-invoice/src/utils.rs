//! Convenient utilities to create an invoice.

use {CreationError, Currency, DEFAULT_EXPIRY_TIME, Invoice, InvoiceBuilder, SignOrCreationError, RawInvoice};
use payment::{Payer, Router};

use bech32::ToBase32;
use bitcoin_hashes::Hash;
use bitcoin_hashes::sha256::Hash as Sha256;
use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::keysinterface::{Sign, KeysInterface};
use lightning::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::ln::channelmanager::{ChannelDetails, ChannelManager, PaymentId, PaymentSendFailure, MIN_FINAL_CLTV_EXPIRY, MIN_CLTV_EXPIRY_DELTA};
use lightning::ln::msgs::LightningError;
use lightning::routing::scoring::Score;
use lightning::routing::network_graph::{NetworkGraph, RoutingFees};
use lightning::routing::router::{Route, RouteHint, RouteHintHop, RouteParameters, find_route};
use lightning::util::logger::Logger;
use secp256k1::Secp256k1;
use secp256k1::key::PublicKey;
use std::convert::TryInto;
use std::ops::Deref;

/// Utility to create an invoice that can be paid to one of multiple nodes, or a "phantom invoice."
/// This works because the invoice officially pays to a fake node (the "phantom"). Useful for
/// load-balancing payments between multiple nodes.
///
/// `channels` contains a list of tuples of `(phantom_node_scid, real_node_pubkey,
/// real_channel_details)`, where `phantom_node_scid` is unique to each `channels` entry and should
/// be retrieved freshly for each new invoice from [`ChannelManager::get_phantom_scid`].
/// `real_channel_details` comes from [`ChannelManager::list_channels`].
///
/// `payment_hash` and `payment_secret` come from [`ChannelManager::create_inbound_payment`] or
/// [`ChannelManager::create_inbound_payment_for_hash`].
///
/// See [`KeysInterface::get_phantom_secret`] for more requirements on supporting phantom node
/// payments.
///
/// [`KeysInterface::get_phantom_secret`]: lightning::chain::keysinterface::KeysInterface::get_phantom_secret
pub fn create_phantom_invoice<Signer: Sign, K: Deref>(
	amt_msat: Option<u64>, description: String, payment_hash: PaymentHash, payment_secret:
	PaymentSecret, channels: &[(u64, PublicKey, &ChannelDetails)], keys_manager: K, network: Currency
) -> Result<Invoice, SignOrCreationError<()>> where K::Target: KeysInterface {
	if channels.len() == 0 {
		return Err(SignOrCreationError::CreationError(CreationError::MissingRouteHints))
	}
	let phantom_secret = match keys_manager.get_phantom_secret(channels[0].0) {
		Ok(s) => s,
		Err(()) => return Err(SignOrCreationError::CreationError(CreationError::InvalidPhantomScid))
	};
	let mut route_hints = vec![];
	for (phantom_scid, real_node_pubkey, channel) in channels {
		let short_channel_id = match channel.short_channel_id {
			Some(id) => id,
			None => continue,
		};
		let forwarding_info = match &channel.counterparty.forwarding_info {
			Some(info) => info.clone(),
			None => continue,
		};
		route_hints.push(RouteHint(vec![
			RouteHintHop {
				src_node_id: channel.counterparty.node_id,
				short_channel_id,
				fees: RoutingFees {
					base_msat: forwarding_info.fee_base_msat,
					proportional_millionths: forwarding_info.fee_proportional_millionths,
				},
				cltv_expiry_delta: forwarding_info.cltv_expiry_delta,
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,
			},
			RouteHintHop {
				src_node_id: *real_node_pubkey,
				short_channel_id: *phantom_scid,
				fees: RoutingFees {
					base_msat: 0,
					proportional_millionths: 0,
				},
				cltv_expiry_delta: MIN_CLTV_EXPIRY_DELTA,
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,
			}])
		);
	}
	let phantom_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &phantom_secret);
	let mut invoice = InvoiceBuilder::new(network)
		.description(description)
		.current_timestamp()
		.payee_pub_key(phantom_pubkey)
		.payment_hash(Hash::from_slice(&payment_hash.0).unwrap())
		.payment_secret(payment_secret)
		.min_final_cltv_expiry(MIN_FINAL_CLTV_EXPIRY.into());
	if let Some(amt) = amt_msat {
		invoice = invoice.amount_milli_satoshis(amt);
	}
	for hint in route_hints {
		invoice = invoice.private_route(hint);
	}

	let raw_invoice = match invoice.build_raw() {
		Ok(inv) => inv,
		Err(e) => return Err(SignOrCreationError::CreationError(e))
	};
	let hrp_str = raw_invoice.hrp.to_string();
	let hrp_bytes = hrp_str.as_bytes();
	let data_without_signature = raw_invoice.data.to_base32();
	let invoice_preimage = RawInvoice::construct_invoice_preimage(hrp_bytes, &data_without_signature);
	let secp_ctx = Secp256k1::new();
	let invoice_preimage_msg = secp256k1::Message::from_slice(&Sha256::hash(&invoice_preimage)).unwrap();
	let signed_raw_invoice = raw_invoice.sign(|_| Ok(secp_ctx.sign_recoverable(&invoice_preimage_msg, &phantom_secret)));
	match signed_raw_invoice {
		Ok(inv) => Ok(Invoice::from_signed(inv).unwrap()),
		Err(e) => Err(SignOrCreationError::SignError(e))
	}
}

/// Utility to construct an invoice. Generally, unless you want to do something like a custom
/// cltv_expiry, this is what you should be using to create an invoice. The reason being, this
/// method stores the invoice's payment secret and preimage in `ChannelManager`, so (a) the user
/// doesn't have to store preimage/payment secret information and (b) `ChannelManager` can verify
/// that the payment secret is valid when the invoice is paid.
pub fn create_invoice_from_channelmanager<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref>(
	channelmanager: &ChannelManager<Signer, M, T, K, F, L>, keys_manager: K, network: Currency,
	amt_msat: Option<u64>, description: String
) -> Result<Invoice, SignOrCreationError<()>>
where
	M::Target: chain::Watch<Signer>,
	T::Target: BroadcasterInterface,
	K::Target: KeysInterface<Signer = Signer>,
	F::Target: FeeEstimator,
	L::Target: Logger,
{
	// Marshall route hints.
	let our_channels = channelmanager.list_usable_channels();
	let mut route_hints = vec![];
	for channel in our_channels {
		let short_channel_id = match channel.short_channel_id {
			Some(id) => id,
			None => continue,
		};
		let forwarding_info = match channel.counterparty.forwarding_info {
			Some(info) => info,
			None => continue,
		};
		route_hints.push(RouteHint(vec![RouteHintHop {
			src_node_id: channel.counterparty.node_id,
			short_channel_id,
			fees: RoutingFees {
				base_msat: forwarding_info.fee_base_msat,
				proportional_millionths: forwarding_info.fee_proportional_millionths,
			},
			cltv_expiry_delta: forwarding_info.cltv_expiry_delta,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]));
	}

	// `create_inbound_payment` only returns an error if the amount is greater than the total bitcoin
	// supply.
	let (payment_hash, payment_secret) = channelmanager.create_inbound_payment(
		amt_msat, DEFAULT_EXPIRY_TIME.try_into().unwrap())
		.map_err(|()| SignOrCreationError::CreationError(CreationError::InvalidAmount))?;
	let our_node_pubkey = channelmanager.get_our_node_id();
	let mut invoice = InvoiceBuilder::new(network)
		.description(description)
		.current_timestamp()
		.payee_pub_key(our_node_pubkey)
		.payment_hash(Hash::from_slice(&payment_hash.0).unwrap())
		.payment_secret(payment_secret)
		.basic_mpp()
		.min_final_cltv_expiry(MIN_FINAL_CLTV_EXPIRY.into());
	if let Some(amt) = amt_msat {
		invoice = invoice.amount_milli_satoshis(amt);
	}
	for hint in route_hints {
		invoice = invoice.private_route(hint);
	}

	let raw_invoice = match invoice.build_raw() {
		Ok(inv) => inv,
		Err(e) => return Err(SignOrCreationError::CreationError(e))
	};
	let hrp_str = raw_invoice.hrp.to_string();
	let hrp_bytes = hrp_str.as_bytes();
	let data_without_signature = raw_invoice.data.to_base32();
	let invoice_preimage = RawInvoice::construct_invoice_preimage(hrp_bytes, &data_without_signature);
	let signed_raw_invoice = raw_invoice.sign(|_| keys_manager.sign_invoice(invoice_preimage));
	match signed_raw_invoice {
		Ok(inv) => Ok(Invoice::from_signed(inv).unwrap()),
		Err(e) => Err(SignOrCreationError::SignError(e))
	}
}

/// A [`Router`] implemented using [`find_route`].
pub struct DefaultRouter<G: Deref<Target = NetworkGraph>, L: Deref> where L::Target: Logger {
	network_graph: G,
	logger: L,
}

impl<G: Deref<Target = NetworkGraph>, L: Deref> DefaultRouter<G, L> where L::Target: Logger {
	/// Creates a new router using the given [`NetworkGraph`] and  [`Logger`].
	pub fn new(network_graph: G, logger: L) -> Self {
		Self { network_graph, logger }
	}
}

impl<G: Deref<Target = NetworkGraph>, L: Deref, S: Score> Router<S> for DefaultRouter<G, L>
where L::Target: Logger {
	fn find_route(
		&self, payer: &PublicKey, params: &RouteParameters, _payment_hash: &PaymentHash,
		first_hops: Option<&[&ChannelDetails]>, scorer: &S
	) -> Result<Route, LightningError> {
		find_route(payer, params, &*self.network_graph, first_hops, &*self.logger, scorer)
	}
}

impl<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref> Payer for ChannelManager<Signer, M, T, K, F, L>
where
	M::Target: chain::Watch<Signer>,
	T::Target: BroadcasterInterface,
	K::Target: KeysInterface<Signer = Signer>,
	F::Target: FeeEstimator,
	L::Target: Logger,
{
	fn node_id(&self) -> PublicKey {
		self.get_our_node_id()
	}

	fn first_hops(&self) -> Vec<ChannelDetails> {
		self.list_usable_channels()
	}

	fn send_payment(
		&self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>
	) -> Result<PaymentId, PaymentSendFailure> {
		self.send_payment(route, payment_hash, payment_secret)
	}

	fn send_spontaneous_payment(
		&self, route: &Route, payment_preimage: PaymentPreimage,
	) -> Result<PaymentId, PaymentSendFailure> {
		self.send_spontaneous_payment(route, Some(payment_preimage))
			.map(|(_, payment_id)| payment_id)
	}

	fn retry_payment(
		&self, route: &Route, payment_id: PaymentId
	) -> Result<(), PaymentSendFailure> {
		self.retry_payment(route, payment_id)
	}

	fn abandon_payment(&self, payment_id: PaymentId) {
		self.abandon_payment(payment_id)
	}
}

#[cfg(test)]
mod tests {
	use {Currency, Description, InvoiceDescription};
	use bitcoin_hashes::Hash;
	use bitcoin_hashes::sha256::Hash as Sha256;
	use lightning::chain::keysinterface::{KeysInterface, KeysManager};
	use lightning::ln::{PaymentPreimage, PaymentHash};
	use lightning::ln::channelmanager::{ChannelDetails, MIN_FINAL_CLTV_EXPIRY};
	use lightning::ln::functional_test_utils::*;
	use lightning::ln::features::InitFeatures;
	use lightning::ln::msgs::ChannelMessageHandler;
	use lightning::routing::router::{Payee, RouteParameters, find_route};
	use lightning::util::enforcing_trait_impls::EnforcingSigner;
	use lightning::util::events::{MessageSendEvent, MessageSendEventsProvider, Event};
	use lightning::util::test_utils;
	use secp256k1::PublicKey;

	#[test]
	fn test_from_channelmanager() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let _chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
		let invoice = ::utils::create_invoice_from_channelmanager(&nodes[1].node, nodes[1].keys_manager, Currency::BitcoinTestnet, Some(10_000), "test".to_string()).unwrap();
		assert_eq!(invoice.amount_pico_btc(), Some(100_000));
		assert_eq!(invoice.min_final_cltv_expiry(), MIN_FINAL_CLTV_EXPIRY as u64);
		assert_eq!(invoice.description(), InvoiceDescription::Direct(&Description("test".to_string())));

		let payee = Payee::from_node_id(invoice.recover_payee_pub_key())
			.with_features(invoice.features().unwrap().clone())
			.with_route_hints(invoice.route_hints());
		let params = RouteParameters {
			payee,
			final_value_msat: invoice.amount_milli_satoshis().unwrap(),
			final_cltv_expiry_delta: invoice.min_final_cltv_expiry() as u32,
		};
		let first_hops = nodes[0].node.list_usable_channels();
		let network_graph = node_cfgs[0].network_graph;
		let logger = test_utils::TestLogger::new();
		let scorer = test_utils::TestScorer::with_fixed_penalty(0);
		let route = find_route(
			&nodes[0].node.get_our_node_id(), &params, network_graph,
			Some(&first_hops.iter().collect::<Vec<_>>()), &logger, &scorer,
		).unwrap();

		let payment_event = {
			let mut payment_hash = PaymentHash([0; 32]);
			payment_hash.0.copy_from_slice(&invoice.payment_hash().as_ref()[0..32]);
			nodes[0].node.send_payment(&route, payment_hash, &Some(invoice.payment_secret().clone())).unwrap();
			let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();

			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))

		};
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		added_monitors.clear();
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 2);
	}

	#[test]
	fn test_multi_node_receive() {
		do_test_multi_node_receive(true);
		do_test_multi_node_receive(false);
	}

	fn do_test_multi_node_receive(user_generated_pmt_hash: bool) {
		let mut chanmon_cfgs = create_chanmon_cfgs(3);
		let seed = [42 as u8; 32];
		chanmon_cfgs[2].keys_manager.backing = KeysManager::new_multi_receive(&seed, 43, 44, chanmon_cfgs[1].keys_manager.get_inbound_payment_key_material());
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
		let chan_0_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001, InitFeatures::known(), InitFeatures::known());
		nodes[0].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &chan_0_1.1);
		nodes[1].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &chan_0_1.0);
		let chan_0_2 = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100000, 10001, InitFeatures::known(), InitFeatures::known());
		nodes[0].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan_0_2.1);
		nodes[2].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &chan_0_2.0);

		let payment_amt = 10_000;
		let (payment_preimage, payment_hash, payment_secret) = {
			if user_generated_pmt_hash {
				let payment_preimage = PaymentPreimage([1; 32]);
				let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0[..]).into_inner());
				let payment_secret = nodes[1].node.create_inbound_payment_for_hash(payment_hash, Some(payment_amt), 3600).unwrap();
				(payment_preimage, payment_hash, payment_secret)
			} else {
				let (payment_hash, payment_secret) = nodes[1].node.create_inbound_payment(Some(payment_amt), 3600).unwrap();
				let payment_preimage = nodes[1].node.get_payment_preimage(payment_hash, payment_secret).unwrap();
				(payment_preimage, payment_hash, payment_secret)
			}
		};
		let channels_1 = nodes[1].node.list_channels();
		let channels_2 = nodes[2].node.list_channels();
		let mut route_hints = channels_1.iter().map(|e| (nodes[1].node.get_phantom_scid(), nodes[1].node.get_our_node_id(), e)).collect::<Vec<(u64, PublicKey, &ChannelDetails)>>();
		for channel in channels_2.iter() {
			route_hints.push((nodes[2].node.get_phantom_scid(), nodes[2].node.get_our_node_id(), &channel));
		}
		let invoice = ::utils::create_phantom_invoice::<EnforcingSigner, &test_utils::TestKeysInterface>(Some(payment_amt), "test".to_string(), payment_hash, payment_secret, &route_hints, &nodes[1].keys_manager, Currency::BitcoinTestnet).unwrap();

		assert_eq!(invoice.min_final_cltv_expiry(), MIN_FINAL_CLTV_EXPIRY as u64);
		assert_eq!(invoice.description(), InvoiceDescription::Direct(&Description("test".to_string())));
		assert_eq!(invoice.route_hints().len(), 2);
		assert!(!invoice.features().unwrap().supports_basic_mpp());

		let payee = Payee::from_node_id(invoice.recover_payee_pub_key())
			.with_features(invoice.features().unwrap().clone())
			.with_route_hints(invoice.route_hints());
		let params = RouteParameters {
			payee,
			final_value_msat: invoice.amount_milli_satoshis().unwrap(),
			final_cltv_expiry_delta: invoice.min_final_cltv_expiry() as u32,
		};
		let first_hops = nodes[0].node.list_usable_channels();
		let network_graph = node_cfgs[0].network_graph;
		let logger = test_utils::TestLogger::new();
		let scorer = test_utils::TestScorer::with_fixed_penalty(0);
		let route = find_route(
			&nodes[0].node.get_our_node_id(), &params, network_graph,
			Some(&first_hops.iter().collect::<Vec<_>>()), &logger, &scorer,
		).unwrap();
		let payment_event = {
			let mut payment_hash = PaymentHash([0; 32]);
			payment_hash.0.copy_from_slice(&invoice.payment_hash().as_ref()[0..32]);
			nodes[0].node.send_payment(&route, payment_hash, &Some(invoice.payment_secret().clone())).unwrap();
			let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();

			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))
		};
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		commitment_signed_dance!(nodes[1], nodes[0], &payment_event.commitment_msg, false, true);
		expect_pending_htlcs_forwardable!(nodes[1]);
		let payment_preimage_opt = if user_generated_pmt_hash { None } else { Some(payment_preimage) };
		expect_payment_received!(nodes[1], payment_hash, payment_secret, payment_amt, payment_preimage_opt);
		do_claim_payment_along_route(&nodes[0], &vec!(&vec!(&nodes[1])[..]), false, payment_preimage);
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 2);
		match events[0] {
			Event::PaymentSent { payment_preimage: ref ev_preimage, payment_hash: ref ev_hash, ref fee_paid_msat, .. } => {
				assert_eq!(payment_preimage, *ev_preimage);
				assert_eq!(payment_hash, *ev_hash);
				assert_eq!(fee_paid_msat, &Some(0));
			},
			_ => panic!("Unexpected event")
		}
		match events[1] {
			Event::PaymentPathSuccessful { payment_hash: hash, .. } => {
				assert_eq!(hash, Some(payment_hash));
			},
			_ => panic!("Unexpected event")
		}
	}
}
