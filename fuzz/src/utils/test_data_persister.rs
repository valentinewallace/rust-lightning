use lightning::ln::data_persister::ChannelDataPersister;
use lightning::chain::channelmonitor;
use lightning::chain::transaction::OutPoint;
use lightning::util::enforcing_trait_impls::EnforcingChannelKeys;

use std::collections::HashMap;

pub struct TestChanDataPersister {}
impl ChannelDataPersister for TestChanDataPersister {
	type Keys = EnforcingChannelKeys;

	fn persist_channel_data(&self, _funding_txo: OutPoint, _data: &channelmonitor::ChannelMonitor<EnforcingChannelKeys>) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		Ok(())
	}

	fn update_channel_data(&self, _funding_txo: OutPoint, _update: &channelmonitor::ChannelMonitorUpdate, _data: &channelmonitor::ChannelMonitor<EnforcingChannelKeys>) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		Ok(())
	}

	fn load_channel_data(&self) -> Result<HashMap<OutPoint, channelmonitor::ChannelMonitor<EnforcingChannelKeys>>, channelmonitor::ChannelMonitorUpdateErr> {
		Ok(HashMap::new())
	}
}
