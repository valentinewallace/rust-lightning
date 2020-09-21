extern crate lightning;
extern crate bitcoin;
extern crate libc;

use lightning::ln::data_persister::ChannelDataPersister;
use lightning::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateErr};
use lightning::chain::keysinterface::ChannelKeys;
use lightning::chain::transaction::OutPoint;
use lightning::util::ser::{Writeable, Readable};
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::hashes::hex::{ToHex, FromHex};
use std::fs;
use std::path::Path;
use std::io::{Error, ErrorKind, Cursor};
use std::collections::HashMap;
use std::marker::PhantomData;

#[cfg(not(target_os = "windows"))]
use std::os::unix::io::AsRawFd;

/// FilesystemPersister can persist channel data on disk on Linux machines, where
/// each channel's data is stored in a file named after its funding outpoint.
///
/// Warning: this module does the best it can with calls to persist data, but it
/// can only guarantee that the data is passed to the drive. It is up to the
/// drive manufacturers to do the actual persistence properly, which they often
/// don't (especially on consumer-grade hardware). Therefore, it is up to the
/// user to validate their entire storage stack, to ensure the writes are
/// persistent.
/// Corollary: especially when dealing with larger amounts of money, it is best
/// practice to have multiple channel data backups and not rely only on the
/// FilesystemPersister.
pub struct FilesystemPersister<ChanSigner: ChannelKeys + Readable + Writeable> {
	path_to_channel_data: String,
	phantom: PhantomData<ChanSigner>, // TODO: is there a way around this?
}

impl<ChanSigner: ChannelKeys + Readable + Writeable> FilesystemPersister<ChanSigner> {
	/// Initialize a new FilesystemPersister and set the path to the individual channels'
	/// files.
	pub fn new(path_to_channel_data: String) -> Self {
		return Self {
			path_to_channel_data,
			phantom: PhantomData,
		}
	}

	fn get_full_filepath(&self, funding_txo: OutPoint) -> String {
		let dir_path = Path::new(&self.path_to_channel_data);
		let mut path_buf = dir_path.to_path_buf();
		path_buf.push(format!("{}_{}", funding_txo.txid.to_hex(), funding_txo.index));
		path_buf.to_str().unwrap().to_string()
	}

	// Utility to write a file to disk.
	// Note: we may eventually want to change this model to a queue-based system, such that
	// writes are queued to a separate writer thread. This would improve performance
	// since syncing to disk can sometimes take 100s of milliseconds.
	fn write_channel_data(&self, funding_txo: OutPoint, monitor: &ChannelMonitor<ChanSigner>) -> std::io::Result<()> {
		// Do a crazy dance with lots of fsync()s to be overly cautious here...
		// We never want to end up in a state where we've lost the old data, or end up using the
		// old data on power loss after we've returned.
		// The way to atomically write a file on Unix platforms is:
		// open(tmpname), write(tmpfile), fsync(tmpfile), close(tmpfile), fsync(dir), rename(), fsync(dir)
		let filename = self.get_full_filepath(funding_txo);
		let tmp_filename = filename.clone() + ".tmp";

		{
			let mut f = fs::File::create(&tmp_filename)?;
			monitor.write_for_disk(&mut f)?;
			f.sync_all()?;
		}
		// We don't need to create a backup if didn't already have the file, but in any other case
		// try to create the backup and expect failure on fs::copy() if eg there's a perms issue.
		let need_bk = match fs::metadata(&filename) {
			Ok(data) => {
				if !data.is_file() { return Err(Error::new(ErrorKind::InvalidInput, "Filename given was not a file")); }
				true
			},
			Err(e) => match e.kind() {
				std::io::ErrorKind::NotFound => false,
				_ => true,
			}
		};
		let bk_filename = filename.clone() + ".bk";
		if need_bk {
			fs::copy(&filename, &bk_filename)?;
			{
				let f = fs::OpenOptions::new().write(true).open(&bk_filename)?;
				f.sync_all()?;
			}
		}
		fs::rename(&tmp_filename, &filename)?;
		if need_bk {
			fs::remove_file(&bk_filename)?;
		}

		// Fsync the parent directory on Unix.
		#[cfg(not(target_os = "windows"))]
		{
			println!("VMW: about to open path");
			println!("VMW: at the end, about to get path");
			let path_str = filename.clone();
			let path = Path::new(&path_str).parent().unwrap();
			// let dir_file = fs::File::open(path)?;
			let dir_file = fs::OpenOptions::new().read(true).open(path)?;
			unsafe { libc::fsync(dir_file.as_raw_fd()); }
		}
		Ok(())
	}
}

impl<ChanSigner: ChannelKeys + Readable + Writeable + Send + Sync> ChannelDataPersister for FilesystemPersister<ChanSigner> {
	type Keys = ChanSigner;

	fn persist_channel_data(&self, funding_txo: OutPoint, monitor: &ChannelMonitor<Self::Keys>) -> Result<(), ChannelMonitorUpdateErr> {
		match self.write_channel_data(funding_txo, monitor) {
			Ok(_) => Ok(()),
			Err(e) => {
				println!("VMW: err: {}", e);
				return Err(ChannelMonitorUpdateErr::TemporaryFailure); }
		}
	}

	fn update_channel_data(&self, funding_txo: OutPoint, _update: &ChannelMonitorUpdate, monitor: &ChannelMonitor<ChanSigner>) -> Result<(), ChannelMonitorUpdateErr> {
		match self.write_channel_data(funding_txo, monitor) {
			Ok(_) => Ok(()),
			Err(_) => Err(ChannelMonitorUpdateErr::TemporaryFailure)
		}
	}

	fn load_channel_data(&self) -> Result<HashMap<OutPoint, ChannelMonitor<ChanSigner>>, ChannelMonitorUpdateErr> {
		if let Err(_) = fs::create_dir_all(&self.path_to_channel_data) {
			return Err(ChannelMonitorUpdateErr::TemporaryFailure);
		}
		let mut res = HashMap::new();
		for file_option in fs::read_dir(&self.path_to_channel_data).unwrap() {
			let mut loaded = false;
			let file = file_option.unwrap();
			if let Some(filename) = file.file_name().to_str() {
				if filename.is_ascii() && filename.len() > 65 {
					if let Ok(txid) = Txid::from_hex(filename.split_at(64).0) {
						if let Ok(index) = filename.split_at(65).1.split('.').next().unwrap().parse() {
							if let Ok(contents) = fs::read(&file.path()) {
								if let Ok((_, loaded_monitor)) = <(BlockHash, ChannelMonitor<ChanSigner>)>::read(&mut Cursor::new(&contents)) {
									res.insert(OutPoint { txid, index }, loaded_monitor);
									loaded = true;
								}
							}
						}
					}
				}
			}
			if !loaded {
				// TODO(val): this should prob error not just print something
				println!("WARNING: Failed to read one of the channel monitor storage files! Check perms!");
			}
		}
		Ok(res)
	}
}

#[cfg(test)]
mod tests {
	extern crate lightning;
	extern crate bitcoin;
	use crate::FilesystemPersister;
	use lightning::ln::features::InitFeatures;
	use lightning::ln::data_persister::ChannelDataPersister;
	use lightning::ln::functional_test_utils::*;
	use lightning::ln::msgs::ErrorAction;
	use lightning::{check_closed_broadcast, check_added_monitors};
	use lightning::util::enforcing_trait_impls::EnforcingChannelKeys;
	use lightning::util::events::{MessageSendEventsProvider, MessageSendEvent};
	use lightning::util::test_utils;
	use bitcoin::blockdata::block::{Block, BlockHeader};
	use std::fs;

	#[test]
	fn test_filesystem_data_persister() {
		// Create the nodes, giving them FilesystemPersisters for data persisters.
		let data_persister_0: FilesystemPersister<EnforcingChannelKeys> = FilesystemPersister::new("persister0".to_string());
		let data_persister_1: FilesystemPersister<EnforcingChannelKeys> = FilesystemPersister::new("persister1".to_string());
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let chain_mon_0 = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[0].chain_source), &chanmon_cfgs[0].tx_broadcaster, &chanmon_cfgs[0].logger, &chanmon_cfgs[0].fee_estimator, &data_persister_0);
		let chain_mon_1 = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[1].chain_source), &chanmon_cfgs[1].tx_broadcaster, &chanmon_cfgs[1].logger, &chanmon_cfgs[1].fee_estimator, &data_persister_1);
		node_cfgs[0].chain_monitor = chain_mon_0;
		node_cfgs[1].chain_monitor = chain_mon_1;
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		// Check that the persisted channel data is empty before any channels are
		// open.
		let mut persisted_chan_data_0 = data_persister_0.load_channel_data().unwrap();
		assert_eq!(persisted_chan_data_0.keys().len(), 0);
		let mut persisted_chan_data_1 = data_persister_1.load_channel_data().unwrap();
		assert_eq!(persisted_chan_data_1.keys().len(), 0);

		// Helper to make sure the channel is on the expected update ID.
		macro_rules! check_persisted_data {
			($expected_update_id: expr) => {
				persisted_chan_data_0 = data_persister_0.load_channel_data().unwrap();
				assert_eq!(persisted_chan_data_0.keys().len(), 1);
				for mon in persisted_chan_data_0.values() {
					assert_eq!(mon.get_latest_update_id(), $expected_update_id);
				}
				persisted_chan_data_1 = data_persister_1.load_channel_data().unwrap();
				assert_eq!(persisted_chan_data_1.keys().len(), 1);
				for mon in persisted_chan_data_1.values() {
					assert_eq!(mon.get_latest_update_id(), $expected_update_id);
				}
			}
		}

		// Create some initial channel and check that a channel was persisted.
		let _ = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
		check_persisted_data!(0);

		// Send a few payments and make sure the monitors are updated to the latest.
		send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000, 8_000_000);
		check_persisted_data!(5);
		send_payment(&nodes[1], &vec!(&nodes[0])[..], 4000000, 4_000_000);
		check_persisted_data!(10);

		// Close the channel and make sure everything is persisted as expected.
		// Force close because cooperative close doesn't result in any persisted
		// updates.
		nodes[0].node.force_close_channel(&nodes[0].node.list_channels()[0].channel_id);
		check_closed_broadcast!(nodes[0], false);
		check_added_monitors!(nodes[0], 1);

		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);

		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		connect_block(&nodes[1], &Block { header, txdata: vec![node_txn[0].clone(), node_txn[0].clone()]}, 1);
		check_closed_broadcast!(nodes[1], false);
		check_added_monitors!(nodes[1], 1);
		check_persisted_data!(11);

		fs::remove_dir_all("./persister0").unwrap();
		fs::remove_dir_all("./persister1").unwrap();
	}
}
