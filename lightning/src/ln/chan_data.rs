//! Logic for persisting data from ChannelMonitors on-disk. Per-platform data
//! persisters are separated into the lightning-persist-data crate.
//! These objects mainly interface with the SimpleManyChannelMonitor when a
//! channel monitor is added or updated, and when they are all synced on startup.
use ln::channelmonitor::ChannelMonitor;
use chain::keysinterface::ChannelKeys;
use chain::transaction::OutPoint;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::hex::{ToHex, FromHex};
use util::ser::Writeable;

use std::fs;
use std::io::{Error, ErrorKind};

/// ChannelDataPersister is responsible for persisting channel data: this could
/// mean writing once to disk, and/or uploading to several backup services.
pub trait ChannelDataPersister {
	/// Persist one channel's data. All backups should agree on a channel's state.
	/// The data can be stored with any file name/path, but the identifier provided
	/// is the channel's outpoint.
	fn save_single_channel_data<ChanSigner: ChannelKeys + Writeable>(&self, funding_txo: OutPoint, data: &ChannelMonitor<ChanSigner>) -> Result<(), Error>;

	/// Fetch the data for all channels. Generally only called on startup.
	fn fetch_all_channel_data(&self) -> Result<Vec<(OutPoint, Vec<u8>)>, ()>;
}
