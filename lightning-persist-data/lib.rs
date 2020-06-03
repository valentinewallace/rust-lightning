use lightning::chain;
use lightning::chain::chaininterface;
use lightning::chain::keysinterface::{KeysInterface, KeysManager, SpendableOutputDescriptor, InMemoryChannelKeys};
use lightning::ln::{peer_handler, router, channelmanager, channelmonitor, msgs};
use lightning::ln::channelmonitor::ManyChannelMonitor;
use lightning::ln::channelmanager::{PaymentHash, PaymentPreimage};
use lightning::util::events::{Event, EventsProvider};
use lightning::util::ser::{ReadableArgs, Writeable};
use lightning::util::config;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::hex::{ToHex, FromHex};

/// LinuxPersister can persist channel data on disk on Linux machines, where
/// each channel's data is stored in a file named after its outpoint.
pub struct LinuxPersister {
	path_to_channel_data: String,
}

impl LinuxPersister {
	/// Initialize a new LinuxPersister and set the path to the individual channels'
	/// files.
	pub fn new(path_to_channel_data: String) -> Self {
		return Self {
			path_to_channel_data,
		}
	}

	fn get_full_filepath(&self, funding_txo: OutPoint) -> String {
		format!("{}/{}_{}", self.path_to_channel_data, funding_txo.txid.to_hex(), funding_txo.index)
	}
}

impl ChannelDataPersister for LinuxPersister {
	fn save_single_channel_data<ChanSigner: ChannelKeys + Writeable>(&self, funding_txo: OutPoint, monitor: &ChannelMonitor<ChanSigner>) -> Result<(), Error> {
		// Do a crazy dance with lots of fsync()s to be overly cautious here...
		// We never want to end up in a state where we've lost the old data, or end up using the
		// old data on power loss after we've returned
		// Note that this actually *isn't* enough (at least on Linux)! We need to fsync an fd with
		// the containing dir, but Rust doesn't let us do that directly, sadly. TODO: Fix this with
		// the libc crate!
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
				if !data.is_file() { return Err(Error::new(ErrorKind::Other, "Backup filename was not a file")); }
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
				let f = fs::File::open(&bk_filename)?;
				f.sync_all()?;
			}
		}
		fs::rename(&tmp_filename, &filename)?;
		{
			let f = fs::File::open(&filename)?;
			f.sync_all()?;
		}
		if need_bk {
			fs::remove_file(&bk_filename)?;
		}
		Ok(())
	}

	fn fetch_all_channel_data(&self) -> Result<Vec<(OutPoint, Vec<u8>)>, ()> {
		let mut res = Vec::new();
		for file_option in fs::read_dir(&self.path_to_channel_data).unwrap() {
			let loaded = false;
			let file = file_option.unwrap();
			if let Some(filename) = file.file_name().to_str() {
				if filename.is_ascii() && filename.len() > 65 {
					if let Ok(txid) = Txid::from_hex(filename.split_at(64).0) {
						if let Ok(index) = filename.split_at(65).1.split('.').next().unwrap().parse() {
							if let Ok(channel_data) = fs::read(&file.path()) {
								res.push((OutPoint { txid, index }, channel_data));
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
