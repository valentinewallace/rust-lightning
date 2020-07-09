//! placeholder

use chain::transaction::OutPoint;
use bitcoin::blockdata::transaction::Transaction;
use ln::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateErr};
use chain::keysinterface::ChannelKeys;

// #[cfg(test)]
use std::collections::{HashMap, hash_map};

/// placeholder
pub trait ChannelDataPersister {
    /// placeholder
	type ChanTxSigner: ChannelKeys;
    /// placeholder
    fn persist_chan_data(&self, funding_txo: OutPoint, data: ChannelMonitor<Self::ChanTxSigner>) -> Result<(), ChannelMonitorUpdateErr>;
    /// placeholder
    fn update_chan_data(&self, funding_txo: OutPoint, update: ChannelMonitorUpdate) -> Result<Vec<Transaction>, ChannelMonitorUpdateErr>;
}

// #[cfg(test)]
pub struct TestChanDataPersister<ChanSigner: ChannelKeys> {
    pub channel_data: HashMap<OutPoint, ChannelMonitor<ChanSigner>>
}

// #[cfg(test)]
impl<ChanSigner: ChannelKeys> ChannelDataPersister for TestChanDataPersister<ChanSigner> {
    fn persist_chan_data(&self, funding_txo: OutPoint, data: ChannelMonitor<ChanSigner>) -> Result<(), ChannelMonitorUpdateErr> {
        let entry = match self.channel_data.entry(funding_txo) {
            hash_map::Entry::Occupied(_) => return Err(ChannelMonitorUpdateErr::PermanentFailure),
            hash_map::Entry::Vacant(e) => e,
        };
        entry.insert(data);
        Ok(())
    }

    fn update_chan_data(&self, funding_txo: OutPoint, update: ChannelMonitorUpdate) -> Result<Vec<Transaction>, ChannelMonitorUpdateErr> {
        let txs_to_broadcast = match self.channel_data.get_mut(&funding_txo) {
            Some(data) => {
                data.update_monitor(update)
            },
            None => return Err(ChannelMonitorUpdateErr::PermanentFailure)
        };
        Ok(txs_to_broadcast)
    }
}