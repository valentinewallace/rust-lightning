// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Some utility modules live here. See individual sub-modules for more info.

#[macro_use]
pub(crate) mod fuzz_wrappers;

#[macro_use]
pub(crate) mod ser_macros;

pub mod events;
pub mod errors;
pub mod ser;
pub mod message_signing;

pub(crate) mod atomic_counter;
pub(crate) mod byte_utils;
pub(crate) mod chacha20;
#[cfg(feature = "fuzztarget")]
pub mod zbase32;
#[cfg(not(feature = "fuzztarget"))]
pub(crate) mod zbase32;
#[cfg(not(feature = "fuzztarget"))]
pub(crate) mod poly1305;
pub(crate) mod chacha20poly1305rfc;
pub(crate) mod transaction_utils;
pub(crate) mod scid_utils;

/// Logging macro utilities.
#[macro_use]
pub(crate) mod macro_logger;

// These have to come after macro_logger to build
pub mod logger;
pub mod config;

#[cfg(any(test, feature = "fuzztarget", feature = "_test_utils"))]
pub mod test_utils;

/// impls of traits that add exra enforcement on the way they're called. Useful for detecting state
/// machine errors and used in fuzz targets and tests.
#[cfg(any(test, feature = "fuzztarget", feature = "_test_utils"))]
pub mod enforcing_trait_impls;

pub(crate) mod crypto {
	use bitcoin::hashes::{Hash, HashEngine};
	use bitcoin::hashes::hmac::{Hmac, HmacEngine};
	use bitcoin::hashes::sha256::Hash as Sha256;
	use prelude::*;

	pub fn hkdf_extract_expand(salt: &[u8], ikm: &[u8], num_keys: u8) -> Vec<[u8; 32]> {
		let mut keys_res: Vec<[u8; 32]> = Vec::new();
		let mut hmac = HmacEngine::<Sha256>::new(salt);
		hmac.input(ikm);
		let prk = Hmac::from_engine(hmac).into_inner();
		for i in 0..num_keys {
			let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
			if i != 0 {
				hmac.input(&keys_res[keys_res.len() - 1]);
			}
			hmac.input(&[i + 1; 1]);
			keys_res.push(Hmac::from_engine(hmac).into_inner());
		}
		keys_res
	}
}
