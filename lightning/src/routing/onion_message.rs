use bitcoin::secp256k1::{self, PublicKey};

use routing::gossip::{NetworkGraph, NodeId};
use util::logger::Logger;

use alloc::collections::BinaryHeap;
use core::cmp;
use core::ops::Deref;
use prelude::*;

/// Find a path for sending an onion message.
pub fn find_path<L: Deref, GL: Deref>(
	our_node_pubkey: &PublicKey, destination: &PublicKey, network_graph: &NetworkGraph<GL>, first_hops: Option<&[&PublicKey]>, logger: L
) -> Result<Vec<PublicKey>, Error> where L::Target: Logger, GL::Target: Logger
{
	log_trace!(logger, "Searching for an onion message path from origin {} to destination {} and {} first hops {}overriding the network graph", our_node_pubkey, destination, first_hops.map(|hops| hops.len()).unwrap_or(0), if first_hops.is_some() { "" } else { "not " });
	let graph_lock = network_graph.read_only();
	let network_channels = graph_lock.channels();
	let network_nodes = graph_lock.nodes();
	let our_node_id = NodeId::from_pubkey(our_node_pubkey);
	let dest_node_id = NodeId::from_pubkey(destination);

	// Add our start and first-hops to `frontier`.
	let start = NodeId::from_pubkey(&our_node_pubkey);
	let mut frontier = BinaryHeap::new();
	frontier.push(PathBuildingHop { cost: 0, node_id: start, parent_node_id: start });
	if let Some(first_hops) = first_hops {
		for hop in first_hops {
			let node_id = NodeId::from_pubkey(&hop);
			frontier.push(PathBuildingHop { cost: 1, node_id, parent_node_id: start });
		}
	}

	let mut visited = HashMap::new();
	while !frontier.is_empty() {
		let PathBuildingHop { cost, node_id, parent_node_id } = frontier.pop().unwrap();
		if visited.contains_key(&node_id) { continue; }
		visited.insert(node_id, parent_node_id);
		if node_id == dest_node_id {
			return Ok(reverse_path(visited, our_node_id, dest_node_id, logger)?)
		}
		if let Some(node_info) = network_nodes.get(&node_id) {
			for scid in &node_info.channels {
				if let Some(chan_info) = network_channels.get(&scid) {
					if let Some((_, successor)) = chan_info.as_directed_from(&node_id) {
						// We may push a given successor multiple times, but the heap should sort its best entry
						// to the top. We do this because there is no way to adjust the priority of an existing
						// entry in `BinaryHeap`.
						frontier.push(PathBuildingHop {
							cost: cost + 1,
							node_id: *successor,
							parent_node_id: node_id,
						});
					}
				}
			}
		}
	}

	Err(Error::PathNotFound)
}

#[derive(Debug, PartialEq)]
/// Errored running [`find_path`].
pub enum Error {
	/// No path exists to the destination.
	PathNotFound,
	/// We failed to convert this node id into a [`PublicKey`].
	InvalidNodeId(secp256k1::Error),
}

#[derive(Eq, PartialEq)]
struct PathBuildingHop {
	cost: u64,
	node_id: NodeId,
	parent_node_id: NodeId,
}

impl PartialOrd for PathBuildingHop {
	fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
		// We need a min-heap, whereas `BinaryHeap`s are a max-heap, so compare the costs in reverse.
		other.cost.partial_cmp(&self.cost)
	}
}

impl Ord for PathBuildingHop {
	fn cmp(&self, other: &Self) -> cmp::Ordering {
		self.partial_cmp(other).unwrap()
	}
}

fn reverse_path<L: Deref>(
	parents: HashMap<NodeId, NodeId>, our_node_id: NodeId, destination: NodeId, logger: L
)-> Result<Vec<PublicKey>, Error> where L::Target: Logger
{
	let mut path = Vec::new();
	let mut curr = destination;
	loop {
		match PublicKey::from_slice(curr.as_slice()) {
			Ok(pk) => path.push(pk),
			Err(e) => return Err(Error::InvalidNodeId(e))
		}
		match parents.get(&curr) {
			None => return Err(Error::PathNotFound),
			Some(parent) => {
				if *parent == our_node_id { break; }
				curr = *parent;
			}
		}
	}

	path.reverse();
	log_info!(logger, "Got route to {:?}: {:?}", destination, path);
	Ok(path)
}

#[cfg(test)]
mod tests {
	use routing::test_utils;

	use sync::Arc;

	#[test]
	fn one_hop() {
		let (secp_ctx, network_graph, _, _, logger) = test_utils::build_graph();
		let (_, our_id, _, node_pks) = test_utils::get_nodes(&secp_ctx);

		let path = super::find_path(&our_id, &node_pks[0], &network_graph, None, Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 1);
		assert!(path[0] == node_pks[0]);
	}

	#[test]
	fn two_hops() {
		let (secp_ctx, network_graph, _, _, logger) = test_utils::build_graph();
		let (_, our_id, _, node_pks) = test_utils::get_nodes(&secp_ctx);

		let path = super::find_path(&our_id, &node_pks[2], &network_graph, None, Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 2);
		// See test_utils::build_graph ASCII graph, the first hop can be any of these
		assert!(path[0] == node_pks[1] || path[0] == node_pks[7] || path[0] == node_pks[0]);
		assert_eq!(path[1], node_pks[2]);
	}

	#[test]
	fn three_hops() {
		let (secp_ctx, network_graph, _, _, logger) = test_utils::build_graph();
		let (_, our_id, _, node_pks) = test_utils::get_nodes(&secp_ctx);

		let mut path = super::find_path(&our_id, &node_pks[5], &network_graph, None, Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 3);
		assert!(path[0] == node_pks[1] || path[0] == node_pks[7] || path[0] == node_pks[0]);
		path.remove(0);
		assert_eq!(path, vec![node_pks[2], node_pks[5]]);
	}

	#[test]
	fn long_path() {
		let (secp_ctx, network_graph, _, _, logger) = test_utils::build_line_graph();
		let (_, our_id, _, node_pks) = test_utils::get_nodes(&secp_ctx);

		let path = super::find_path(&our_id, &node_pks[18], &network_graph, None, Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 19);
	}
}
