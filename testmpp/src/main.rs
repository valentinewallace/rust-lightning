use lightning::ln::msgs::{ChannelMessageHandler, RoutingMessageHandler, ErrorAction};
use lightning::routing::network_graph::{NetGraphMsgHandler, NetworkGraph};
use bitcoin::secp256k1::{Secp256k1, All};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use lightning::chain;
use lightning::chain::transaction::OutPoint;
use bitcoin::hash_types::{BlockHash, Txid};
use std::collections::{HashMap, HashSet};
use bitcoin::network::constants::Network;
use lightning::util::logger::{Logger, Record};
use lightning::ln::msgs;
use lightning::ln::channelmanager::ChannelDetails;
use lightning::routing::router::get_route;
use lightning::ln::features::{ChannelFeatures, InitFeatures};
use lightning::util::events;
use lightning::ln::peer_handler;
use lightning::util::ser::Readable;
use lightning_net_tokio::*;
use std::sync::{Arc, Mutex};
use bitcoin::secp256k1::key::{PublicKey,SecretKey};
use std::{cmp, mem};
use time::OffsetDateTime;
use rand::{thread_rng, Rng};
use tokio::sync::mpsc;
use bitcoin::blockdata::opcodes;
use std::time::{Duration, SystemTime};
use std::io::{BufWriter, Cursor, Write};
use std::fs;
use lightning::util::ser::Writeable;

#[tokio::main]
async fn main() {
	let genesis_hash = genesis_block(Network::Bitcoin).header.block_hash();
	let logger = Arc::new(LogPrinter{});
	let channel_msg_handler = Arc::new(TestChannelMessageHandler::new());
	// let routing_msg_handler = Arc::new(TestRoutingMessageHandler::new());
	// let routing_msg_handler = Arc::new(NetGraphMsgHandler::new(genesis_hash, None, Arc::clone(&logger)));
	let routing_msg_handler = if let Ok(mut f) = fs::File::open("router_data") {
		let graph = NetworkGraph::read(&mut f).unwrap();
		Arc::new(NetGraphMsgHandler::from_net_graph(None, logger.clone(), graph))
	} else {
		Arc::new(NetGraphMsgHandler::new(genesis_hash, None, Arc::clone(&logger)))
	};

	let node_secret = SecretKey::from_slice(&[42; 32]).unwrap();
	let mut ephemeral_data = [0; 32];
	rand::thread_rng().fill_bytes(&mut ephemeral_data);
	let peer_manager: Arc<peer_handler::PeerManager<lightning_net_tokio::SocketDescriptor, std::sync::Arc<TestChannelMessageHandler>, std::sync::Arc<NetGraphMsgHandler<Arc<TestChainSource>, Arc<LogPrinter>>>, std::sync::Arc<LogPrinter>>> = Arc::new(peer_handler::PeerManager::new(peer_handler::MessageHandler{
		chan_handler: channel_msg_handler.clone(),
		route_handler: routing_msg_handler.clone(),
	}, node_secret, &ephemeral_data, logger.clone()));

	let (mut io_wake, mut io_receiver): (mpsc::Sender<()>, mpsc::Receiver<()>) = mpsc::channel(2);
	let (sender, mut receiver): (mpsc::Sender<()>, mpsc::Receiver<()>) = mpsc::channel(2);
	let mut self_sender = sender.clone();

	// Persist data
	let persisted_graph = routing_msg_handler.clone();
	tokio::spawn(async move {
		loop {
			io_receiver.recv().await.unwrap();
			let persisted_graph = persisted_graph.clone();

			let router_filename = "router_data".to_string();
			let router_tmp_filename = router_filename.clone() + ".tmp";

			{
				let f = fs::File::create(&router_tmp_filename).unwrap();
				let mut writer = BufWriter::new(f);
				let locked_netgraph = persisted_graph.read_locked_graph();
				let graph = locked_netgraph.graph();
				graph.write(&mut writer).unwrap();
				writer.flush().unwrap();
			}
			fs::rename(&router_tmp_filename, &router_filename).unwrap();
		}
	});

	// let us_events = Arc::clone(&us);
	let peer_manager_2 = peer_manager.clone();
	tokio::spawn(async move {
		loop {
			receiver.recv().await.unwrap();
			peer_manager_2.process_events();
			let _ = io_wake.try_send(());
		}
	});
	let mut listener = tokio::net::TcpListener::bind(("::".parse::<std::net::Ipv6Addr>().unwrap(), 9735)).await.unwrap();

	let peer_manager_listener = peer_manager.clone();
	let event_listener = sender.clone();
	tokio::spawn(async move {
		loop {
			let sock = listener.accept().await.unwrap().0;
			println!("Got new inbound connection, waiting on them to start handshake...");
			let peer_manager_listener = peer_manager_listener.clone();
			let event_listener = event_listener.clone();
			tokio::spawn(async move {
				setup_inbound(peer_manager_listener, event_listener, sock).await;
			});
		}
	});
	let peer_manager_timer = peer_manager.clone();
	tokio::spawn(async move {
		let mut intvl = tokio::time::interval(Duration::from_secs(60));
		loop {
			intvl.tick().await;
			peer_manager_timer.timer_tick_occured();
		}
	});
	println!("VMW: about to loop...");
	let addrs = [
		("03a042a5166017a87efa4bcd530dc4b695ed201722e99279ab68a1077cdd182728", "51.159.94.209:4041"), // good one (from lnd?)
		("02bb24da3d0fb0793f4918c7599f973cc402f0912ec3fb530470f1fc08bdd6ecb5", "46.229.165.147:9735"), // good one, lnbig
		("03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f", "34.239.230.56:9735"), // good one // acinq
		("0200a7f20e51049363cb7f2a0865fe072464d469dca0ac34c954bb3d4b552b6e95", "80.253.94.252:9736"),

		("0381fff6deaba9928c82c18305c108d3c99d53a19f404f1db79cb68905fec15262", "77.185.109.127:9735"),
		("02e624ada98431468dbab3fc78e7c38cf6f4b881fbdcf63098f887e9cba91d4b60", "128.65.201.215:9735"),
		("0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7", "88.99.209.230:9735"),
		("03b05b2b15cad59018428d6088dc12ee6ea9758d6743eeace71a19b65f5e05b457", "128.16.7.139:9735"),
		("030f375d8aecdddc852309c15c3b67c2934de0de4d31e1e04a03d656ca0a78d008", "104.131.26.124:9735"),
		("03ee83ec25fc43cf1d683be47fd5e2ac39713a489b03fed4350d9623be1ff0d817", "203.86.204.88:9745"),
		("027455aef8453d92f4706b560b61527cc217ddf14da41770e8ed6607190a1851b8", "3.13.29.161:9735"), // claims to be testnet yalls
		("03d5e17a3c213fe490e1b0c389f8cfcfcea08a29717d50a9f453735e0ab2a7c003", "3.16.119.191:9735"), // ion.radar.tech
		("022e56667f395bb7c119f5b301fd6bfa801b2247f9da3dbd74db67f6d07c608d29", "51.158.31.0:4046"), // nodl-lnd-s003-046
		("0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3", "3.124.63.44:9735"), // coingate
		("0331f80652fb840239df8dc99205792bba2e559a05469915804c08420230e23c7c", "34.200.181.109:9735"), // LightningPowerUsers.com
		// ("02004c625d622245606a1ea2c1c69cfb4516b703b47945a3647713c05fe4aaeb1c", "172.81.178.151:9735"), // WalletOfSatoshi
		("03bb88ccc444534da7b5b64b4f7b15e1eccb18e102db0e400d4b9cfe93763aa26d", "138.68.14.104:9735"), // LightningTo.me
		("02ad6fb8d693dc1e4569bcedefadf5f72a931ae027dc0f0c544b34c1c6f3b9a02b", "167.99.50.31:9735"), // rompert
		("03cde60a6323f7122d5178255766e38114b4722ede08f7c9e0c5df9b912cc201d6", "34.65.85.39:9745"), // btx-lnd1
		("0217890e3aad8d35bc054f43acc00084b25229ecff0ab68debd82883ad65ee8266", "23.237.77.11:9735"), // 1ML.com
		("0260fab633066ed7b1d9b9b8a0fac87e1579d1709e874d28a0d171a1f5c43bb877", "54.184.240.102:9735"), // southxexchange
		("030c3f19d742ca294a55c00376b3b355c3c90d61c6b6b39554dbc7ac19b141c14f", "52.50.244.44:9735"), // bitrefill
		("0390b5d4492dc2f5318e5233ab2cebf6d48914881a33ef6a9c6bcdbb433ad986d0", "46.229.165.136:9735"), // more lnbig lnd-01
		("02c91d6aa51aa940608b497b6beebcb1aec05be3c47704b682b3889424679ca490", "213.174.156.65:9735"), // more lnbig
		("032679fec1213e5b0a23e066c019d7b991b95c6e4d28806b9ebd1362f9e32775cf", "46.229.165.139:9735"), // more lnbig
		("03790e10c296b12535baf03738765163dadf91ae1f48a6a6d074a6cf910d26d8c4", "95.90.25.239:9735"), // le-bolt
		("028331898ddfd97c3579f313458c26f495cfc0c0e1dc762b710a5c4f82192a16b1", "51.15.21.116:9735"), // random
		("0247719ca61fa34ce383634a30b9cde6a2b396a8a6e2974dbbd4ebbe93e093ad2c", "189.39.6.82:9735"),
		("03757b80302c8dfe38a127c252700ec3052e5168a7ec6ba183cdab2ac7adad3910", "178.128.97.48:11000"),
		("023d70f2f76d283c6c4e58109ee3a2816eb9d8feb40b23d62469060a2b2867b77f", "54.159.193.149:9735"),
	];
	let num_active_nodes = 8;
	let mut channel_details = Vec::new();
	let payment_amt_msat = 12_000_000;
	let necessary_outbound_cap_msat_float = 1.2 * payment_amt_msat as f64;
	let necessary_outbound_cap_msat = necessary_outbound_cap_msat_float as usize;
	for i in 0..addrs.len() {
		let addr = addrs[i].1;
		let pk_str = addrs[i].0;
		let parse_res: Result<std::net::SocketAddr, _> = addr.parse();
		let pk = hex_to_compressed_pubkey(pk_str).unwrap();
		if let Ok(addr) = parse_res {
			print!("Attempting to connect to {}...", addr);
			match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
				Ok(stream) => {
					println!("connected, initiating handshake!");
					let peer_manager = peer_manager.clone();
					let event_notify = sender.clone();
					tokio::spawn(async move {
						setup_outbound(peer_manager, event_notify, pk,
													 tokio::net::TcpStream::from_std(stream).unwrap()).await;
					});
				},
				Err(e) => {
					println!("connection failed {:?}!", e);
				}
			}
		} else {
			println!("VMW: failed to parse peer");
		}

		let mut channel_id = [0; 32];
		rand::thread_rng().fill_bytes(&mut channel_id);
		let mut sid = [0; 1];
		rand::thread_rng().fill_bytes(&mut sid);

		let outbound_pk = PublicKey::from_slice(&::hex::decode(pk_str).unwrap()).unwrap();
		let chan_amt = 70000;
		let outbound_cap = necessary_outbound_cap_msat / num_active_nodes;
		let first_hops = ChannelDetails {
			channel_id,
			short_channel_id: Some(sid[0] as u64),
			remote_network_id: outbound_pk,
			counterparty_features: InitFeatures::known(),
			channel_value_satoshis: chan_amt,
			user_id: 0,
			outbound_capacity_msat: outbound_cap as u64,
			inbound_capacity_msat: (chan_amt * 1000) - outbound_cap as u64,
			is_live: true
		};
		channel_details.push(first_hops);
	}
	tokio::spawn(async move {
	let mut intvl = tokio::time::interval(Duration::from_secs(5));
	loop {
		let peerman = peer_manager.clone();
		// let dest_pk = PublicKey::from_slice(&::hex::decode("031015a7839468a3c266d662d5bb21ea4cea24226936e2864a7ca4f2c3939836e0").unwrap()).unwrap();
		let dest_pk = PublicKey::from_slice(&::hex::decode("02004c625d622245606a1ea2c1c69cfb4516b703b47945a3647713c05fe4aaeb1c").unwrap()).unwrap();
		const TEST_FINAL_CLTV: u32 = 32;
		let our_pk = PublicKey::from_secret_key(&Secp256k1::new(), &node_secret);
		println!("VMW: getting route, num_peers: {}", peerman.get_peer_node_ids().len());
		let route = get_route(&our_pk, &routing_msg_handler.network_graph.read().unwrap(), &dest_pk, Some(&channel_details.iter().collect::<Vec<_>>()), &vec![], payment_amt_msat as u64, TEST_FINAL_CLTV, logger.clone());
		match route {
			Ok(_route) => {}
			Err(e) => println!("VMW: errored in get_route: {:?}", e)
		}
		intvl.tick().await;
	}
	});
	loop {}
}

	pub fn hex_to_vec(hex: &str) -> Option<Vec<u8>> {
		let mut out = Vec::with_capacity(hex.len() / 2);

		let mut b = 0;
		for (idx, c) in hex.as_bytes().iter().enumerate() {
			b <<= 4;
			match *c {
				b'A'..=b'F' => b |= c - b'A' + 10,
				b'a'..=b'f' => b |= c - b'a' + 10,
				b'0'..=b'9' => b |= c - b'0',
				_ => return None,
			}
			if (idx & 1) == 1 {
				out.push(b);
				b = 0;
			}
		}

		Some(out)
	}
	pub fn hex_to_compressed_pubkey(hex: &str) -> Option<PublicKey> {
		let data = match hex_to_vec(&hex[0..33*2]) {
			Some(bytes) => bytes,
			None => return None
		};
		match PublicKey::from_slice(&data) {
			Ok(pk) => Some(pk),
			Err(_) => None,
		}
	}

pub struct TestChannelMessageHandler {
	pub pending_events: Mutex<Vec<events::MessageSendEvent>>,
}

impl TestChannelMessageHandler {
	pub fn new() -> Self {
		TestChannelMessageHandler {
			pending_events: Mutex::new(Vec::new()),
		}
	}
}

struct LogPrinter {}
impl Logger for LogPrinter {
	fn log(&self, record: &Record) {
		let log = record.args.to_string();
		if !log.contains("Received message of type 258") && !log.contains("Received message of type 256") && !log.contains("Received message of type 257") {
			println!("{} {:<5} [{}:{}] {}", OffsetDateTime::now_utc().format("%F %T"), record.level.to_string(), record.module_path, record.line, log);
		}
	}
}


impl msgs::ChannelMessageHandler for TestChannelMessageHandler {
	fn handle_open_channel(&self, _their_node_id: &PublicKey, _their_features: InitFeatures, _msg: &msgs::OpenChannel) {}
	fn handle_accept_channel(&self, _their_node_id: &PublicKey, _their_features: InitFeatures, _msg: &msgs::AcceptChannel) {}
	fn handle_funding_created(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingCreated) {}
	fn handle_funding_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingSigned) {}
	fn handle_funding_locked(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingLocked) {}
	fn handle_shutdown(&self, _their_node_id: &PublicKey, _msg: &msgs::Shutdown) {}
	fn handle_closing_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::ClosingSigned) {}
	fn handle_update_add_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateAddHTLC) {}
	fn handle_update_fulfill_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFulfillHTLC) {}
	fn handle_update_fail_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFailHTLC) {}
	fn handle_update_fail_malformed_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFailMalformedHTLC) {}
	fn handle_commitment_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::CommitmentSigned) {}
	fn handle_revoke_and_ack(&self, _their_node_id: &PublicKey, _msg: &msgs::RevokeAndACK) {}
	fn handle_update_fee(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFee) {}
	fn handle_announcement_signatures(&self, _their_node_id: &PublicKey, _msg: &msgs::AnnouncementSignatures) {}
	fn handle_channel_reestablish(&self, _their_node_id: &PublicKey, _msg: &msgs::ChannelReestablish) {}
	fn peer_disconnected(&self, _their_node_id: &PublicKey, _no_connection_possible: bool) {}
	fn peer_connected(&self, _their_node_id: &PublicKey, _msg: &msgs::Init) {}
	fn handle_error(&self, _their_node_id: &PublicKey, _msg: &msgs::ErrorMessage) {}
}

impl events::MessageSendEventsProvider for TestChannelMessageHandler {
	fn get_and_clear_pending_msg_events(&self) -> Vec<events::MessageSendEvent> {
		let mut pending_events = self.pending_events.lock().unwrap();
		let mut ret = Vec::new();
		mem::swap(&mut ret, &mut *pending_events);
		ret
	}
}

pub struct TestRoutingMessageHandler {
	// pub chan_upds_recvd: AtomicUsize,
	// pub chan_anns_recvd: AtomicUsize,
	// pub chan_anns_sent: AtomicUsize,
	// pub request_full_sync: AtomicBool,
}

impl TestRoutingMessageHandler {
	pub fn new() -> Self {
		TestRoutingMessageHandler {
			// chan_upds_recvd: AtomicUsize::new(0),
			// chan_anns_recvd: AtomicUsize::new(0),
			// chan_anns_sent: AtomicUsize::new(0),
			// request_full_sync: AtomicBool::new(false),
		}
	}
}
impl msgs::RoutingMessageHandler for TestRoutingMessageHandler {
	fn handle_node_announcement(&self, _msg: &msgs::NodeAnnouncement) -> Result<bool, msgs::LightningError> {
		Err(msgs::LightningError { err: "".to_owned(), action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_channel_announcement(&self, _msg: &msgs::ChannelAnnouncement) -> Result<bool, msgs::LightningError> {
		// self.chan_anns_recvd.fetch_add(1, Ordering::AcqRel);
		Err(msgs::LightningError { err: "".to_owned(), action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_channel_update(&self, _msg: &msgs::ChannelUpdate) -> Result<bool, msgs::LightningError> {
		// self.chan_upds_recvd.fetch_add(1, Ordering::AcqRel);
		Err(msgs::LightningError { err: "".to_owned(), action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_htlc_fail_channel_update(&self, _update: &msgs::HTLCFailChannelUpdate) {}
	fn get_next_channel_announcements(&self, starting_point: u64, batch_amount: u8) -> Vec<(msgs::ChannelAnnouncement, Option<msgs::ChannelUpdate>, Option<msgs::ChannelUpdate>)> {
		// let mut chan_anns = Vec::new();
		// const TOTAL_UPDS: u64 = 100;
		// let end: u64 = cmp::min(starting_point + batch_amount as u64, TOTAL_UPDS - self.chan_anns_sent.load(Ordering::Acquire) as u64);
		// for i in starting_point..end {
		// 	let chan_upd_1 = get_dummy_channel_update(i);
		// 	let chan_upd_2 = get_dummy_channel_update(i);
		// 	let chan_ann = get_dummy_channel_announcement(i);

		// 	chan_anns.push((chan_ann, Some(chan_upd_1), Some(chan_upd_2)));
		// }

		// self.chan_anns_sent.fetch_add(chan_anns.len(), Ordering::AcqRel);
		// chan_anns
		Vec::new()
	}

	fn get_next_node_announcements(&self, _starting_point: Option<&PublicKey>, _batch_amount: u8) -> Vec<msgs::NodeAnnouncement> {
		Vec::new()
	}

	fn sync_routing_table(&self, _their_node_id: &PublicKey, _init_msg: &msgs::Init) {}

	fn handle_reply_channel_range(&self, _their_node_id: &PublicKey, _msg: msgs::ReplyChannelRange) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn handle_reply_short_channel_ids_end(&self, _their_node_id: &PublicKey, _msg: msgs::ReplyShortChannelIdsEnd) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn handle_query_channel_range(&self, _their_node_id: &PublicKey, _msg: msgs::QueryChannelRange) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn handle_query_short_channel_ids(&self, _their_node_id: &PublicKey, _msg: msgs::QueryShortChannelIds) -> Result<(), msgs::LightningError> {
		Ok(())
	}
}

impl events::MessageSendEventsProvider for TestRoutingMessageHandler {
	fn get_and_clear_pending_msg_events(&self) -> Vec<events::MessageSendEvent> {
		vec![]
	}
}

pub struct TestChainSource {
	pub genesis_hash: BlockHash,
	pub utxo_ret: Mutex<Result<TxOut, chain::AccessError>>,
	pub watched_txn: Mutex<HashSet<(Txid, Script)>>,
	pub watched_outputs: Mutex<HashSet<(OutPoint, Script)>>,
}

impl TestChainSource {
	pub fn new(network: Network) -> Self {
		let script_pubkey = Builder::new().push_opcode(opcodes::OP_TRUE).into_script();
		Self {
			genesis_hash: genesis_block(network).block_hash(),
			utxo_ret: Mutex::new(Ok(TxOut { value: u64::max_value(), script_pubkey })),
			watched_txn: Mutex::new(HashSet::new()),
			watched_outputs: Mutex::new(HashSet::new()),
		}
	}
}

impl chain::Access for TestChainSource {
	fn get_utxo(&self, genesis_hash: &BlockHash, _short_channel_id: u64) -> Result<TxOut, chain::AccessError> {
		if self.genesis_hash != *genesis_hash {
			return Err(chain::AccessError::UnknownChain);
		}

		self.utxo_ret.lock().unwrap().clone()
	}
}

impl chain::Filter for TestChainSource {
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.watched_txn.lock().unwrap().insert((*txid, script_pubkey.clone()));
	}

	fn register_output(&self, outpoint: &OutPoint, script_pubkey: &Script) {
		self.watched_outputs.lock().unwrap().insert((*outpoint, script_pubkey.clone()));
	}
}
