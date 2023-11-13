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

use super::{ceil, Digit};
use crate::integers::BigUnsigned;
use core::mem::size_of;
use macros::log2_range;

const WHOLE_BYTE_MULTIPLIER: &[Digit] = if size_of::<Digit>() == 1 {
    &[1, 0]
} else {
    &[255 + 1]
};

const BASE_BITS_PER_ROUND: [f64; 254] = log2_range!(256);

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
    big_unsigned: BigUnsigned,
    bit_counter: f64,
}

impl NumericCollector {
    pub fn with_byte_capacity(capacity: usize) -> Self {
        Self {
            big_unsigned: BigUnsigned::with_capacity(capacity / size_of::<Digit>()),
            bit_counter: 0f64,
        }
    }

    pub fn new() -> Self {
        Self {
            big_unsigned: BigUnsigned::with_capacity(1),
            bit_counter: 0f64,
        }
    }

    pub fn extract_big_unsigned(self) -> BigUnsigned {
        self.big_unsigned
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
                    // Push a digit to the end of the unsigned integer.
                    let bits = BASE_BITS_PER_ROUND[(round_base - 2) as usize];
                    self.bit_counter += bits;
                    self.big_unsigned.multiply(&[round_base as Digit]);
                    self.big_unsigned.add(&[round_value as Digit]);
                    Ok((bits, self.bit_counter))
                }
            }
            NumericCollectorRoundBase::WholeByte => {
                // Push a digit to the end of the unsigned integer.
                self.bit_counter += 8f64;
                self.big_unsigned.multiply(WHOLE_BYTE_MULTIPLIER);
                self.big_unsigned.add(&[round_value as Digit]);
                Ok((8f64, self.bit_counter))
            }
        }
    }

    pub fn copy_padded_bytes_to(&self, buffer: &mut [u8]) {
        let padding = self.padded_byte_count() - self.trimmed_byte_count();
        self.big_unsigned.copy_be_bytes_to(&mut buffer[padding..]);
        // Make sure our leading zeroes are actually zeroes.
        buffer[..padding].fill(0);
    }

    pub fn trimmed_byte_count(&self) -> usize {
        self.big_unsigned.byte_count()
    }

    pub fn padded_byte_count(&self) -> usize {
        // We often need to know how many leading zeros we should have.
        // If we've got even a tiny bit of a bit more than a multiple of 8, we need a whole extra byte.
        ceil(self.bit_counter / 8f64)
    }
}
