// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Structs and enums useful for constructing and reading an onion message packet.

use bitcoin::secp256k1::PublicKey;

use ln::msgs::DecodeError;
use util::ser::{LengthRead, LengthReadable, Readable, Writeable, Writer};

use io;
use prelude::*;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Packet {
	pub(crate) version: u8,
	pub(crate) public_key: PublicKey,
	// Unlike the onion packets used for payments, onion message packets can have payloads greater
	// than 1300 bytes.
	pub(crate) hop_data: Vec<u8>,
	pub(crate) hmac: [u8; 32],
}

impl Writeable for Packet {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.version.write(w)?;
		self.public_key.write(w)?;
		w.write_all(&self.hop_data)?;
		self.hmac.write(w)?;
		Ok(())
	}
}

impl LengthReadable for Packet {
	fn read<R: LengthRead>(r: &mut R) -> Result<Self, DecodeError> {
		if r.total_bytes() < 66 {
			return Err(DecodeError::InvalidValue)
		}
		let version = Readable::read(r)?;
		let public_key = {
			let mut buf = [0u8;33];
			r.read_exact(&mut buf)?;
			PublicKey::from_slice(&buf).map_err(|_| DecodeError::InvalidValue)?
		};
		// 1 (version) + 33 (pubkey) + 32 (HMAC) = 66
		let mut hop_data = vec![0; r.total_bytes() as usize - 66];
		for i in 0..r.total_bytes() - 66 {
			let byte: u8 = Readable::read(r)?;
			hop_data[i as usize] = byte;
		}
		let hmac = Readable::read(r)?;
		Ok(Packet {
			version,
			public_key,
			hop_data,
			hmac,
		})
	}
}
