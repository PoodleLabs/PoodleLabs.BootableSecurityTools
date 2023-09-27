// Poodle Labs' Bootable Security Tools (BST)
// Copyright (C) 2023 Isaac Beizsley (isaac@poodlelabs.com)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use super::ceil;
use crate::integers::BigInteger;
use alloc::boxed::Box;
use core::mem;
use macros::log2_range;

const BASE_BITS_PER_ROUND: [f64; 254] = log2_range!(256);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct CollectedNumericData<T> {
    trimmed_byte_count: usize,
    padded_byte_count: usize,
    bit_count: f64,
    data: T,
}

impl<T> CollectedNumericData<T> {
    pub const fn trimmed_byte_count(&self) -> usize {
        self.trimmed_byte_count
    }

    pub const fn padded_byte_count(&self) -> usize {
        self.padded_byte_count
    }

    pub const fn bit_count(&self) -> f64 {
        self.bit_count
    }

    pub const fn data(&self) -> &T {
        &self.data
    }

    pub fn take_data_ownership(self) -> T {
        self.data
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum NumericCollectorRoundBase {
    SubByte(u8),
    WholeByte,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum NumericCollectorRoundError {
    ValueGreaterThanOrEqualToBase(u8, u8),
    BaseLessThan2(u8),
}

#[derive(Debug, Clone, PartialEq)]
pub struct NumericCollector {
    big_integer: BigInteger,
    bit_counter: f64,
}

#[allow(dead_code)]
impl NumericCollector {
    pub fn with_byte_capacity(capacity: usize) -> Self {
        Self {
            big_integer: BigInteger::with_capacity(capacity),
            bit_counter: 0f64,
        }
    }

    pub fn new() -> Self {
        Self {
            big_integer: BigInteger::with_capacity(8),
            bit_counter: 0f64,
        }
    }

    pub const fn bit_counter(&self) -> f64 {
        self.bit_counter
    }

    pub fn try_add_round(
        &mut self,
        round_value: u8,
        round_base: NumericCollectorRoundBase,
    ) -> Result<(f64, f64), NumericCollectorRoundError> {
        match round_base {
            NumericCollectorRoundBase::SubByte(round_base) => {
                if round_value >= round_base {
                    // The round value is too big for the specified base.
                    Err(NumericCollectorRoundError::ValueGreaterThanOrEqualToBase(
                        round_value,
                        round_base,
                    ))
                } else if round_base < 2 {
                    // The specified base is invalid; 0 and 1 aren't supported (0 is nonsensical, 1 is impractical).
                    Err(NumericCollectorRoundError::BaseLessThan2(round_base))
                } else {
                    // Push a digit to the end of the integer.
                    let bits = BASE_BITS_PER_ROUND[(round_base - 2) as usize];
                    self.bit_counter += bits;
                    self.big_integer.multiply(round_base);
                    self.big_integer.add(round_value);
                    Ok((bits, self.bit_counter))
                }
            }
            NumericCollectorRoundBase::WholeByte => {
                // Push a digit to the end of the integer.
                self.bit_counter += 8f64;
                self.big_integer.multiply(128);
                self.big_integer.multiply(2);
                self.big_integer.add(round_value);
                Ok((8f64, self.bit_counter))
            }
        }
    }

    pub fn extract_trimmed_bytes(&mut self) -> CollectedNumericData<Box<[u8]>> {
        let r = CollectedNumericData {
            trimmed_byte_count: self.trimmed_byte_count(),
            padded_byte_count: self.padded_byte_count(),
            data: self.big_integer.to_be_bytes(),
            bit_count: self.bit_counter,
        };

        self.bit_counter = 0f64;
        // We can zero out the internal bytes by just multiplying by zero,
        // so we don't leave any potentially sensitive info hanging about.
        self.big_integer.multiply(0);
        r
    }

    pub fn extract_big_integer(
        &mut self,
        new_capacity: Option<usize>,
    ) -> CollectedNumericData<BigInteger> {
        // The capacity for the new underlying big integer.
        let capacity = match new_capacity {
            None => self.trimmed_byte_count(),
            Some(v) => v,
        };

        let r = CollectedNumericData {
            // Swap out the current underlying big integer with a new one, and return the old one.
            data: mem::replace(&mut self.big_integer, BigInteger::with_capacity(capacity)),
            trimmed_byte_count: self.trimmed_byte_count(),
            padded_byte_count: self.padded_byte_count(),
            bit_count: self.bit_counter,
        };

        // Reset the bit counter.
        self.bit_counter = 0f64;
        r
    }

    pub fn copy_trimmed_bytes_to(&self, buffer: &mut [u8]) {
        self.big_integer.copy_bytes_to(buffer);
    }

    pub fn copy_padded_bytes_to(&self, buffer: &mut [u8]) {
        let padding = self.padded_byte_count() - self.trimmed_byte_count();
        self.big_integer.copy_bytes_to(&mut buffer[padding..]);
        // Make sure our leading zeroes are actually zeroes.
        buffer[..padding].fill(0);
    }

    pub fn set_content_to(&mut self, bytes: &[u8]) {
        // We assume all the bits had a chance at being a 1.
        self.bit_counter += bytes.len() as f64 * 8f64;
        self.big_integer.copy_bytes_from(bytes);
    }

    pub fn trimmed_byte_count(&self) -> usize {
        self.big_integer.byte_count()
    }

    pub fn padded_byte_count(&self) -> usize {
        // We often need to know how many leading zeros we should have.
        // If we've got even a tiny bit of a bit more than a multiple of 8, we need a whole extra byte.
        ceil(self.bit_counter / 8f64)
    }
}
