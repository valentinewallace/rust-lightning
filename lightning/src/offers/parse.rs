// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Parsing and formatting for bech32 message encoding.

use bitcoin::bech32;
use bitcoin::bech32::{FromBase32, ToBase32};
use bitcoin::secp256k1;
use core::fmt;
use ln::msgs::DecodeError;
use util::ser::Readable;

/// Indicates a message can be encoded using bech32.
pub(crate) trait Bech32Encode: AsRef<[u8]> {
	/// TLV stream that a bech32-encoded message is parsed into.
	type TlvStream: Readable;

	/// Human readable part of the message's bech32 encoding.
	const BECH32_HRP: &'static str;

	/// Parses a bech32-encoded message into a TLV stream.
	fn from_bech32_str(s: &str) -> Result<(Self::TlvStream, Vec<u8>), ParseError> {
		// Offer encoding may be split by '+' followed by optional whitespace.
		for chunk in s.split('+') {
			let chunk = chunk.trim_start();
			if chunk.is_empty() || chunk.contains(char::is_whitespace) {
				return Err(ParseError::InvalidContinuation);
			}
		}

		let s = s.chars().filter(|c| *c != '+' && !c.is_whitespace()).collect::<String>();
		let (hrp, data) = bech32::decode_without_checksum(&s)?;

		if hrp != Self::BECH32_HRP {
			return Err(ParseError::InvalidBech32Hrp);
		}

		let data = Vec::<u8>::from_base32(&data)?;
		Ok((Readable::read(&mut &data[..])?, data))
	}

	/// Formats the message using bech32-encoding.
	fn fmt_bech32_str(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		bech32::encode_without_checksum_to_fmt(f, Self::BECH32_HRP, self.as_ref().to_base32())
			.expect("HRP is valid").unwrap();

		Ok(())
	}
}

/// Error when parsing a bech32 encoded message using [`str::parse`].
#[derive(Debug, PartialEq)]
pub enum ParseError {
	/// The bech32 encoding does not conform to the BOLT 12 requirements for continuing messages
	/// across multiple parts (i.e., '+' followed by whitespace).
	InvalidContinuation,
	/// The bech32 encoding's human-readable part does not match what was expected for the message
	/// being parsed.
	InvalidBech32Hrp,
	/// The string could not be bech32 decoded.
	Bech32(bech32::Error),
	/// The bech32 decoded string could not be decoded as the expected message type.
	Decode(DecodeError),
	/// The parsed message has invalid semantics.
	InvalidSemantics(SemanticError),
	/// The parsed message has an invalid signature.
	InvalidSignature(secp256k1::Error),
}

/// Error when interpreting a TLV stream as a specific type.
#[derive(Debug, PartialEq)]
pub enum SemanticError {
	/// The provided block hash does not correspond to a supported chain.
	UnsupportedChain,
	/// A currency was provided without an amount.
	UnexpectedCurrency,
	///
	MissingAmount,
	///
	InsufficientAmount,
	///
	UnknownRequiredFeatures,
	/// A required description was not provided.
	MissingDescription,
	/// A node id was not provided.
	MissingNodeId,
	/// An empty set of blinded paths was provided.
	MissingPaths,
	/// A quantity representing an empty range or that was outside of a valid range was provided.
	InvalidQuantity,
	///
	MissingPayerId,
}

impl From<bech32::Error> for ParseError {
	fn from(error: bech32::Error) -> Self {
		Self::Bech32(error)
	}
}

impl From<DecodeError> for ParseError {
	fn from(error: DecodeError) -> Self {
		Self::Decode(error)
	}
}

impl From<SemanticError> for ParseError {
	fn from(error: SemanticError) -> Self {
		Self::InvalidSemantics(error)
	}
}

impl From<secp256k1::Error> for ParseError {
	fn from(error: secp256k1::Error) -> Self {
		Self::InvalidSignature(error)
	}
}
