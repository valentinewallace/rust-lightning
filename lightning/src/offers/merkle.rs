// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tagged hashes for use in signature calculation and verification.

use bitcoin::hashes::{Hash, HashEngine, sha256};
use util::ser::{BigSize, Readable};

const SIGNATURE_TYPES: core::ops::RangeInclusive<u64> = 240..=1000;

pub(super) fn root_hash(data: &[u8]) -> sha256::Hash {
	let mut engine = sha256::Hash::engine();
	engine.input("LnAll".as_bytes());
	for record in TlvStream::new(&data[..]) {
		if !SIGNATURE_TYPES.contains(&record.r#type.0) {
			engine.input(record.as_ref());
		}
	}
	let nonce_tag = sha256::Hash::from_engine(engine);
	let leaf_tag = sha256::Hash::hash("LnLeaf".as_bytes());
	let branch_tag = sha256::Hash::hash("LnBranch".as_bytes());

	let mut leaves = Vec::new();
	for record in TlvStream::new(&data[..]) {
		if !SIGNATURE_TYPES.contains(&record.r#type.0) {
			leaves.push(tagged_hash(leaf_tag, &record));
			leaves.push(tagged_hash(nonce_tag, &record));
		}
	}

	let num_leaves = leaves.len();
	for level in 0.. {
		let step = 2 << level;
		let offset = step / 2;
		if offset >= num_leaves {
			break;
		}

		for (i, j) in (0..num_leaves).step_by(step).zip((offset..num_leaves).step_by(step)) {
			leaves[i] = tagged_branch_hash(branch_tag, leaves[i], leaves[j]);
		}
	}

	// TODO: Can we ever have zero leaves?
	*leaves.first().unwrap()
}

pub(super) fn tagged_hash<T: AsRef<[u8]>>(tag: sha256::Hash, msg: T) -> sha256::Hash {
	let mut engine = sha256::Hash::engine();
	engine.input(tag.as_ref());
	engine.input(tag.as_ref());
	engine.input(msg.as_ref());
	sha256::Hash::from_engine(engine)
}

fn tagged_branch_hash(tag: sha256::Hash, leaf1: sha256::Hash, leaf2: sha256::Hash) -> sha256::Hash {
	let mut engine = sha256::Hash::engine();
	engine.input(tag.as_ref());
	engine.input(tag.as_ref());
	if leaf1 < leaf2 {
		engine.input(leaf1.as_ref());
		engine.input(leaf2.as_ref());
	} else {
		engine.input(leaf2.as_ref());
		engine.input(leaf1.as_ref());
	};
	sha256::Hash::from_engine(engine)
}

struct TlvStream<'a> {
	data: ::io::Cursor<&'a [u8]>,
}

impl<'a> TlvStream<'a> {
	fn new(data: &'a [u8]) -> Self {
		Self {
			data: ::io::Cursor::new(data),
		}
	}
}

struct TlvRecord<'a> {
	r#type: BigSize,
	_length: BigSize,
	_value: &'a [u8],
	data: &'a [u8],
}

impl AsRef<[u8]> for TlvRecord<'_> {
	fn as_ref(&self) -> &[u8] { &self.data }
}

impl<'a> Iterator for TlvStream<'a> {
	type Item = TlvRecord<'a>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.data.position() < self.data.get_ref().len() as u64 {
			let start = self.data.position();

			let r#type: BigSize = Readable::read(&mut self.data).unwrap();
			let length: BigSize = Readable::read(&mut self.data).unwrap();

			let offset = self.data.position();
			let end = offset + length.0;

			let value = &self.data.get_ref()[offset as usize..end as usize];
			let data = &self.data.get_ref()[start as usize..end as usize];

			self.data.set_position(end);

			Some(TlvRecord { r#type, _length: length, _value: value, data })
		} else {
			None
		}
	}
}
