// ring has a garbage API so its use is avoided, but rust-crypto doesn't have RFC-variant poly1305
// Instead, we steal rust-crypto's implementation and tweak it to match the RFC.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.
//
// This is a port of Andrew Moons poly1305-donna
// https://github.com/floodyberry/poly1305-donna

use util::ser::{Writeable, Writer};
use io;

#[cfg(not(fuzzing))]
mod real_chachapoly {
	use ln::onion_messages;
	use util::chacha20::{BLOCK_SIZE, ChaCha20};
	use util::poly1305::Poly1305;
	use util::ser::{Writeable, Writer};
	use bitcoin::hashes::cmp::fixed_time_eq;

	// use io;
	use io::{self, Write};

	#[derive(Clone, Copy)]
	pub struct ChaCha20Poly1305RFC {
		cipher: ChaCha20,
		mac: Poly1305,
		finished: bool,
		data_len: usize,
		aad_len: u64,
	}

	impl ChaCha20Poly1305RFC {
		#[inline]
		fn pad_mac_16(mac: &mut Poly1305, len: usize) {
			if len % 16 != 0 {
				mac.input(&[0; 16][0..16 - (len % 16)]);
			}
		}
		pub fn new(key: &[u8], nonce: &[u8], aad: &[u8]) -> ChaCha20Poly1305RFC {
			assert!(key.len() == 16 || key.len() == 32);
			assert!(nonce.len() == 12);

			// Ehh, I'm too lazy to *also* tweak ChaCha20 to make it RFC-compliant
			assert!(nonce[0] == 0 && nonce[1] == 0 && nonce[2] == 0 && nonce[3] == 0);

			let mut cipher = ChaCha20::new(key, &nonce[4..]);
			let mut mac_key = [0u8; 64];
			let zero_key = [0u8; 64];
			cipher.process(&zero_key, &mut mac_key);

			let mut mac = Poly1305::new(&mac_key[..32]);
			mac.input(aad);
			ChaCha20Poly1305RFC::pad_mac_16(&mut mac, aad.len());

			ChaCha20Poly1305RFC {
				cipher,
				mac,
				finished: false,
				data_len: 0,
				aad_len: aad.len() as u64,
			}
		}

		pub fn encrypt(&mut self, input: &[u8], output: &mut [u8], out_tag: &mut [u8]) {
			assert!(input.len() == output.len());
			assert!(self.finished == false);
			self.cipher.process(input, output);
			self.data_len += input.len();
			self.mac.input(output);
			ChaCha20Poly1305RFC::pad_mac_16(&mut self.mac, self.data_len);
			self.finished = true;
			self.mac.input(&self.aad_len.to_le_bytes());
			self.mac.input(&(self.data_len as u64).to_le_bytes());
			self.mac.raw_result(out_tag);
		}

		pub fn encrypt_in_place(&mut self, input_output: &mut [u8], out_tag: Option<&mut [u8]>) {
			assert!(self.finished == false);
			self.cipher.process_in_place(input_output);
			self.data_len += input_output.len();
			self.mac.input(input_output);
			if let Some(tag) = out_tag {
				self.get_tag(tag);
			}
		}

		pub fn get_tag(&mut self, out_tag: &mut [u8]) {
			self.finished = true;
			ChaCha20Poly1305RFC::pad_mac_16(&mut self.mac, self.data_len);
			self.mac.input(&self.aad_len.to_le_bytes());
			self.mac.input(&(self.data_len as u64).to_le_bytes());
			self.mac.raw_result(out_tag);
		}

		pub fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> bool {
			if self.decrypt_inner(input, Some(output), Some(tag)) {
				self.cipher.process(input, output);
				return true
			}
			false
		}

		pub fn decrypt_in_place(&mut self, input: &mut [u8], tag: Option<&[u8]>) -> bool {
			if self.decrypt_inner(input, None, tag) {
				self.cipher.process_in_place(input);
				return true
			}
			false
		}


		fn decrypt_inner(&mut self, input: &[u8], output: Option<&mut [u8]>, tag: Option<&[u8]>) -> bool {
			if let Some(output) = output {
				assert!(input.len() == output.len());
			}
			assert!(self.finished == false);


			self.mac.input(input);

			self.data_len += input.len();

			if let Some(tag) = tag {
				return self.finish_and_check_tag(tag)
			}
			true
		}

		pub fn finish_and_check_tag(&mut self, tag: &[u8]) -> bool {
			self.finished = true;
			ChaCha20Poly1305RFC::pad_mac_16(&mut self.mac, self.data_len);
			self.mac.input(&self.aad_len.to_le_bytes());
			self.mac.input(&(self.data_len as u64).to_le_bytes());
			let mut calc_tag =  [0u8; 16];
			self.mac.raw_result(&mut calc_tag);
			// println!("VMW: in check_tag, expected_tag: {:02x?}, actual tag: {:02x?}", tag, calc_tag);
			if fixed_time_eq(&calc_tag, tag) {
				// if let Some(output) = output {
				//   self.cipher.process(input, output);
				// } else {
				//   self.cipher.process_in_place(input);
				// }
				true
			} else {
				false
			}
		}
	}
}
#[cfg(not(fuzzing))]
pub use self::real_chachapoly::ChaCha20Poly1305RFC;

pub(crate) struct ChaChaPoly1305Reader<'a, R: io::Read> {
	pub chacha: &'a mut ChaCha20Poly1305RFC,
	pub read: R,
}

impl<'a, R: io::Read> io::Read for ChaChaPoly1305Reader<'a, R> {
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		let res = self.read.read(dest)?;
		if res > 0 {
			self.chacha.decrypt_in_place(&mut dest[0..res], None);
		}
		Ok(res)
	}
}

pub(crate) struct ChaChaPoly1305Writer<'a, W: Writer> {
	pub chacha: &'a mut ChaCha20Poly1305RFC,
	pub write: &'a mut W,
}

impl<'a, W: Writer> Writer for ChaChaPoly1305Writer<'a, W> {
	fn write_all(&mut self, src: &[u8]) -> Result<(), io::Error> {
		println!("VMW: writing to chachapoly, src: {:02x?}", src);
		for byte in src.iter() {
			let mut encrypted_byte = [*byte];
			self.chacha.encrypt_in_place(&mut encrypted_byte, None);
			encrypted_byte.write(self.write)?;
		}
		Ok(())
	}
}

#[cfg(fuzzing)]
mod fuzzy_chachapoly {
	#[derive(Clone, Copy)]
	pub struct ChaCha20Poly1305RFC {
		tag: [u8; 16],
		finished: bool,
	}
	impl ChaCha20Poly1305RFC {
		pub fn new(key: &[u8], nonce: &[u8], _aad: &[u8]) -> ChaCha20Poly1305RFC {
			assert!(key.len() == 16 || key.len() == 32);
			assert!(nonce.len() == 12);

			// Ehh, I'm too lazy to *also* tweak ChaCha20 to make it RFC-compliant
			assert!(nonce[0] == 0 && nonce[1] == 0 && nonce[2] == 0 && nonce[3] == 0);

			let mut tag = [0; 16];
			tag.copy_from_slice(&key[0..16]);

			ChaCha20Poly1305RFC {
				tag,
				finished: false,
			}
		}

		pub fn encrypt(&mut self, input: &[u8], output: &mut [u8], out_tag: &mut [u8]) {
			assert!(input.len() == output.len());
			assert!(self.finished == false);

			output.copy_from_slice(&input);
			out_tag.copy_from_slice(&self.tag);
			self.finished = true;
		}

		pub fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> bool {
			assert!(input.len() == output.len());
			assert!(self.finished == false);

			if tag[..] != self.tag[..] { return false; }
			output.copy_from_slice(input);
			self.finished = true;
			true
		}
	}
}
#[cfg(fuzzing)]
pub use self::fuzzy_chachapoly::ChaCha20Poly1305RFC;
