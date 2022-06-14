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

use ln::msgs::DecodeError;
use util::ser::{self, Readable, ReadableArgs, Writeable, Writer};
use io::{self, Read, Write};

#[cfg(not(fuzzing))]
mod real_chachapoly {
	use util::chacha20::ChaCha20;
	use util::poly1305::Poly1305;
	use bitcoin::hashes::cmp::fixed_time_eq;

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
			self.cipher.process(input, output);
			self.encrypt_inner(input, Some(output), Some(out_tag));
		}

		pub fn encrypt_in_place(&mut self, input_output: &mut [u8], out_tag: Option<&mut [u8]>) {
			self.cipher.process_in_place(input_output);
			self.encrypt_inner(input_output, None, out_tag);
		}

		// Encrypt in place, and fill in the tag if it's provided. If the tag is not provided, then
		// `finish_and_get_tag` may be called to check it later.
		fn encrypt_inner(&mut self, input: &[u8], output: Option<&mut [u8]>, out_tag: Option<&mut [u8]>) {
			assert!(self.finished == false);
			if let Some(output) = output {
				assert!(input.len() == output.len());
				self.mac.input(output);
			} else {
				self.mac.input(input);
			}
			self.data_len += input.len();
			if let Some(tag) = out_tag {
				self.finish_and_get_tag(tag);
			}
		}

		pub fn finish_and_get_tag(&mut self, out_tag: &mut [u8]) {
			ChaCha20Poly1305RFC::pad_mac_16(&mut self.mac, self.data_len);
			self.finished = true;
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

		// Decrypt in place, and check the tag if it's provided. If the tag is not provided, then
		// `finish_and_check_tag` may be called to check it later.
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
			if fixed_time_eq(&calc_tag, tag) {
				true
			} else {
				false
			}
		}
	}
}
#[cfg(not(fuzzing))]
pub use self::real_chachapoly::ChaCha20Poly1305RFC;

pub(crate) struct ChaChaPolyReader<'a, R: Read> {
	pub chacha: &'a mut ChaCha20Poly1305RFC,
	pub read: R,
}

impl<'a, R: Read> Read for ChaChaPolyReader<'a, R> {
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		let res = self.read.read(dest)?;
		if res > 0 {
			self.chacha.decrypt_in_place(&mut dest[0..res], None);
		}
		Ok(res)
	}
}

pub(crate) struct ChaChaPolyWriter<'a, W: Writer> {
	pub chacha: &'a mut ChaCha20Poly1305RFC,
	pub write: &'a mut W,
}

impl<'a, W: Writer> Writer for ChaChaPolyWriter<'a, W> {
	fn write_all(&mut self, src: &[u8]) -> Result<(), io::Error> {
		let num_writes = (src.len() + (8192 - 1)) / 8192;
		for i in 0..num_writes {
			let mut write_buffer = [0; 8192];
			let bytes_written = (&mut write_buffer[..]).write(&src[i * 8192..])?;
			self.chacha.encrypt_in_place(&mut write_buffer[..bytes_written], None);
			self.write.write_all(&write_buffer[..bytes_written])?;
		}
		Ok(())
	}
}

pub(crate) struct ChaChaPolyWriteAdapter<'a, W: Writeable> {
	pub rho: [u8; 32],
	pub writeable: &'a W,
}

impl<'a, W: Writeable> ChaChaPolyWriteAdapter<'a, W> {
	pub fn new(rho: [u8; 32], writeable: &'a W) -> ChaChaPolyWriteAdapter<'a, W> {
		Self { rho, writeable }
	}
}

impl<'a, T: Writeable> Writeable for ChaChaPolyWriteAdapter<'a, T> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		let mut chacha = ChaCha20Poly1305RFC::new(&self.rho, &[0; 12], &[]);
		let mut chacha_stream = ChaChaPolyWriter { chacha: &mut chacha, write: w };
		self.writeable.write(&mut chacha_stream)?;
		let mut tag = [0 as u8; 16];
		chacha.finish_and_get_tag(&mut tag);
		tag.write(w)?;

		Ok(())
	}
}

pub(crate) struct ChaChaPolyReadAdapter<R: Readable> {
	pub readable: R,
}

impl<T: Readable> ReadableArgs<([u8; 32], u64)> for ChaChaPolyReadAdapter<T> {
	fn read<R: Read>(mut r: &mut R, secret_and_len: ([u8; 32], u64)) -> Result<Self, DecodeError> {
		let (secret, total_len) = (secret_and_len.0, secret_and_len.1);
		if total_len < 16 { return Err(DecodeError::InvalidValue) }

		let mut chacha = ChaCha20Poly1305RFC::new(&secret, &[0; 12], &[]);
		let decrypted_len = total_len - 16;
		let s = ser::FixedLengthReader::new(&mut r, decrypted_len);
		let mut chacha_stream = ChaChaPolyReader { chacha: &mut chacha, read: s };
		let readable: T = ser::Readable::read(&mut chacha_stream)?;

		let mut tag = [0 as u8; 16];
		r.read_exact(&mut tag)?;
		if !chacha.finish_and_check_tag(&tag) {
			return Err(DecodeError::InvalidValue)
		}

		Ok(Self { readable })
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

		pub fn encrypt_in_place(&mut self, _input_output: &mut [u8], out_tag: Option<&mut [u8]>) {
			assert!(self.finished == false);
			if let Some(tag) = out_tag {
				tag.copy_from_slice(&self.tag);
				self.finished = true;
			}
		}

		pub fn finish_and_get_tag(&mut self, out_tag: &mut [u8]) {
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


		pub fn decrypt_in_place(&mut self, _input: &mut [u8], tag: Option<&[u8]>) -> bool {
			assert!(self.finished == false);
			if let Some(tag) = tag {
				if tag[..] != self.tag[..] { return false; }
			}
			self.finished = true;
			true
		}


		pub fn finish_and_check_tag(&mut self, tag: &[u8]) -> bool {
			if tag[..] != self.tag[..] { return false; }
			self.finished = true;
			true
		}
	}
}
#[cfg(fuzzing)]
pub use self::fuzzy_chachapoly::ChaCha20Poly1305RFC;
