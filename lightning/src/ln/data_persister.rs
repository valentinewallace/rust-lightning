//! Logic for persisting data from ChannelMonitors on-disk. Sample data
//! persisters are separated into the lightning-persist-data crate. These
//! objects mainly interface with the ChainMonitor when a channel monitor is
//! added or updated, and when they are all synced on startup.
use chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateErr};
use chain::keysinterface::ChannelKeys;
use chain::transaction::OutPoint;
use std::collections::HashMap;

/// ChannelDataPersister is responsible for persisting channel data: this could
/// mean writing once to disk, and/or uploading to one or more backup services.
///
/// Note that for every new monitor, you **must** persist the new ChannelMonitor
/// to disk/backups. And, on every update, you **must** persist either the
/// ChannelMonitorUpdate or the updated monitor itself. Otherwise, there is risk
/// of situations such as revoking a transaction, then crashing before this
/// revocation can be persisted, then unintentionally broadcasting a revoked
/// transaction and losing money. This is a risk because previous channel states
/// are toxic, so it's important that whatever channel state is persisted is
/// kept up-to-date.
///
/// Given multiple backups, situations may arise where one or more backup sources
/// have fallen behind or disagree on the current state. Because these backup
/// sources don't have any transaction signing/broadcasting duties and are only
/// supposed to be persisting bytes of data, backup sources may be considered
/// "in consensus" if a majority of them agree on the current state and are on
/// the highest known commitment number.
pub trait ChannelDataPersister: Send + Sync {
	/// The concrete type which signs for transactions and provides access to our channel public
	/// keys.
	type Keys: ChannelKeys;

	/// Persist a new channel's data. The data can be stored with any file
	/// name/path, but the identifier provided is the channel's outpoint.
	/// Note that you **must** persist every new monitor to disk. See the
	/// ChannelDataPersister trait documentation for more details, and for
	/// information on consensus between backups.
	///
	/// See [`ChannelMonitor::write_for_disk`] for writing out a ChannelMonitor.
	///
	/// [`update_id`]: struct.ChannelMonitorUpdate.html#structfield.update_id
	/// [`ChannelMonitor::write_for_disk`]: ../../chain/channelmonitor/struct.ChannelMonitor.html#method.write_for_disk
	fn persist_channel_data(&self, id: OutPoint, data: &ChannelMonitor<Self::Keys>) -> Result<(), ChannelMonitorUpdateErr>;

	/// Update one channel's data. The provided ChannelMonitor has already
	/// applied the given update.
	///
	/// Note that on every update, you **must** persist either the
	/// ChannelMonitorUpdate or the updated monitor itself to disk/backups.
	/// See the ChannelDataPersister trait documentation for more details, and
	/// for information on consensus between backups.
	///
	/// If an implementer chooses to persist the updates only, they need to make
	/// sure that all the updates are applied to the ChannelMonitors *before* the
	/// set of channel monitors is given to the ChainMonitor at startup time
	/// (e.g., all monitors returned by [`load_channel_data`] must be up-to-date).
	/// If full ChannelMonitors are persisted, then there is no need to persist
	/// individual updates.
	///
	/// Note that there could be a performance tradeoff between persisting complete
	/// channel monitors on every update vs. persisting only updates and applying
	/// them in batches.
	///
	/// See [`ChannelMonitor::write_for_disk`] for writing out a ChannelMonitor
	/// and [`ChannelMonitorUpdate::write`] for writing out an update.
	///
	/// [`load_channel_data`]: trait.ChannelDataPersister.html#tymethod.load_channel_data
	/// [`ChannelMonitor::write_for_disk`]: struct.ChannelMonitor.html#method.write_for_disk
	/// [`ChannelMonitorUpdate::write`]: struct.ChannelMonitorUpdate.html#method.write
	fn update_channel_data(&self, id: OutPoint, update: &ChannelMonitorUpdate, data: &ChannelMonitor<Self::Keys>) -> Result<(), ChannelMonitorUpdateErr>;

	/// Load the data for all channels. Generally only called on startup. You must
	/// ensure that the ChannelMonitors returned are on the latest [`update_id`],
	/// with all of the updates given in [`update_channel_data`] applied.
	///
	/// See the ChannelDataPersister trait documentation for more details, and
	/// for information on consensus between backups.
	///
	/// See [`ChannelMonitor::read`] for deserializing a ChannelMonitor.
	///
	/// [`update_id`]: struct.ChannelMonitorUpdate.html#structfield.update_id
	/// [`update_channel_data`]: trait.ChannelDataPersister.html#tymethod.update_channel_data
	/// [`ChannelMonitor::read`]: trait.Readable.html
	fn load_channel_data(&self) -> Result<HashMap<OutPoint, ChannelMonitor<Self::Keys>>, ChannelMonitorUpdateErr>;
}
