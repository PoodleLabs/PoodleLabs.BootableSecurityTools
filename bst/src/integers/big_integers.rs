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

use alloc::{boxed::Box, vec::Vec};
use core::{cmp::Ordering, num::Wrapping};

#[derive(Debug, Clone)]
pub struct BigInteger {
    // We store bytes in big-endian format.
    bytes: Vec<u8>,
}

impl PartialEq for BigInteger {
    fn eq(&self, other: &Self) -> bool {
        let self_is_shorter = self.bytes.len() < other.bytes.len();
        let (longer, shorter) = if self_is_shorter {
            (&other.bytes[..], &self.bytes[..])
        } else {
            (&self.bytes[..], &other.bytes[..])
        };

        let required_leading_zeroes = longer.len() - shorter.len();
        longer[..required_leading_zeroes].iter().all(|b| *b == 0)
            && &longer[required_leading_zeroes..] == shorter
    }
}

impl Eq for BigInteger {}

impl PartialOrd for BigInteger {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let self_is_shorter = self.bytes.len() <= other.bytes.len();
        let (longer, shorter) = if self_is_shorter {
            (&other.bytes[..], &self.bytes[..])
        } else {
            (&self.bytes[..], &other.bytes[..])
        };

        let required_leading_zeroes = longer.len() - shorter.len();
        if required_leading_zeroes > 0 && longer[..required_leading_zeroes].iter().any(|b| *b != 0)
        {
            return Some(if self_is_shorter {
                Ordering::Less
            } else {
                Ordering::Greater
            });
        }

        Some(if self_is_shorter {
            shorter.cmp(&longer[required_leading_zeroes..])
        } else {
            longer[required_leading_zeroes..].cmp(shorter)
        })
    }
}

impl Ord for BigInteger {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

#[allow(dead_code)]
impl BigInteger {
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: Vec::from(bytes),
        }
    }

    pub fn copy_bytes_from(&mut self, bytes: &[u8]) {
        // Match the internal buffer's length to the length of the provided bytes.
        if self.bytes.len() < bytes.len() {
            // Expand the internal byte buffer to the input bytes' length.
            self.bytes.reserve(bytes.len() - self.bytes.len());
            while self.bytes.len() < bytes.len() {
                self.bytes.push(0);
            }
        } else {
            // Truncate the internal byte buffer to the input bytes' length.
            self.bytes.truncate(bytes.len());
        }

        // Copy the provided bytes to the internal buffer.
        self.bytes.copy_from_slice(bytes);
    }

    pub fn take_ownership_of_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn copy_bytes_to(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.bytes);
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    pub fn to_be_bytes(&self) -> Box<[u8]> {
        Box::from(&self.bytes[..])
    }

    pub fn byte_count(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_non_zero(&self) -> bool {
        for i in 0..self.bytes.len() {
            if self.bytes[i] != 0 {
                return true;
            }
        }

        false
    }

    pub fn add(&mut self, value: u8) {
        if value == 0 {
            return;
        }

        let mut carry = value as u32;
        // Start at the least significant bit and work backwards.
        for i in (0..self.bytes.len()).rev() {
            // Add the current bytes to the carry.
            carry += self.bytes[i] as u32;

            // This byte becomes the least significant byte of the carry.
            self.bytes[i] = carry as u8;

            // Drop the least significant byte of the carry for the next step.
            carry >>= 8;

            if carry == 0 {
                // There's nothing left to add; we can return now.
                return;
            }
        }

        // We have overflow! Add the remaining bytes to the start.
        while carry > 0 {
            self.bytes.insert(0, carry as u8);
            carry >>= 8;
        }
    }

    pub fn multiply(&mut self, value: u8) {
        if value == 0 {
            // Anything multiplied by zero is zero, so just... zero it all.
            self.bytes.fill(0);
            return;
        } else if value == 1 {
            return;
        }

        // Overflow will cause the byte array to grow underneath us.
        // We track an offset & original length so we don't multiply the same bytes twice.
        let mut offset = 0usize;
        let len = self.bytes.len();
        for i in 0..len {
            let j = i + offset;
            // Multiply the current byte with the multiplier in a bigger integer format, so we can track overflow.
            let mut carry = self.bytes[j] as u32 * value as u32;
            // The current byte just becomes the least significant byte of the multiplication.
            self.bytes[j] = carry as u8;
            // Drop that least significant byte now we've written it.
            carry >>= 8;

            // Back-track to add any remaining carry.
            for k in 1..j + 1 {
                let l = j - k;
                carry += self.bytes[l] as u32;
                self.bytes[l] = carry as u8;
                carry >>= 8;

                if carry == 0 {
                    break;
                }
            }

            // If we've still got a carry, we can grow our integer.
            while carry > 0 {
                self.bytes.insert(0, carry as u8);
                carry >>= 8;
                offset += 1;
            }
        }
    }

    pub fn divide(&mut self, value: u8) -> Option<u8> {
        if value == 0 {
            // Bad. Don't do it.
            return None;
        }

        if value == 1 {
            // No mutation needed, and the remainder is always zero. Nice.
            return Some(0);
        }

        // Track remainder in a bigger integer format.
        let mut remainder = 0u32;
        for i in 0..self.bytes.len() {
            // Any previous remainder becomes the higher-order byte. The current byte is the lower order.
            let dividend = (remainder << 8) | (self.bytes[i] as u32);
            // The lower order bytes of this divided value are our new byte for this index.
            self.bytes[i] = (dividend / (value as u32)) as u8;
            // The remainder carries down into the next byte; 169 / 3 = 100 / 3 + 60 / 3 + 9 / 3
            remainder = dividend % (value as u32);
        }

        Some(remainder as u8)
    }

    pub fn subtract(&mut self, value: u8) {
        if value == 0 || self.bytes.len() == 0 {
            // Subtracting 0 obviously does nothing, but we also don't want to underflow.
            // Any underflow behaviour would be weird, given the integer isn't a fixed size.
            return;
        }

        // If the last byte is bigger than our subtracted value, all we need to do is subtract the value from that last byte.
        let last_byte_index = self.bytes.len() - 1;
        if self.bytes[last_byte_index] >= value {
            self.bytes[last_byte_index] -= value;
            return;
        }

        // We have to wrap the last byte. The byte above will subtract 1. If it's 0, the byte above that. So on.
        self.bytes[last_byte_index] = (Wrapping(self.bytes[last_byte_index]) - Wrapping(value)).0;
        for i in (0..self.bytes.len() - 1).rev() {
            if self.bytes[i] == 0 {
                self.bytes[i] = u8::MAX;
            } else {
                self.bytes[i] -= 1;
                return;
            }
        }

        // We ran out of bytes to subtract 1 from. Don't underflow, just go to zero.
        self.bytes.fill(0);
    }

    pub fn and(&mut self, value: &Self) {
        let (self_slice, value_slice) = self.binary_conditional_op_slices(value, true);
        for i in 0..self_slice.len() {
            self_slice[i] &= value_slice[i]
        }
    }

    pub fn xor(&mut self, value: &Self) {
        let (self_slice, value_slice) = self.binary_conditional_op_slices(value, false);
        for i in 0..self_slice.len() {
            self_slice[i] ^= value_slice[i]
        }
    }

    pub fn or(&mut self, value: &Self) {
        let (self_slice, value_slice) = self.binary_conditional_op_slices(value, false);
        for i in 0..self_slice.len() {
            self_slice[i] |= value_slice[i]
        }
    }

    fn binary_conditional_op_slices<'a>(
        &'a mut self,
        value: &'a Self,
        is_and: bool,
    ) -> (&mut [u8], &[u8]) {
        if self.bytes.len() > value.bytes.len() {
            // Our bytes are bigger than their bytes. Only operate on the shared length.
            let self_leading = self.bytes.len() - value.bytes.len();
            if is_and {
                // If we're doing an and, all our leading bytes go to zero; their 'virtual' bytes in this range were all zero, afterall.
                self.bytes[..self_leading].fill(0);
            } // If we're doing an or or xor, same logic, but we don't need to do anything to those bytes. Sweet.

            (&mut self.bytes[self_leading..], &value.bytes[..])
        } else if self.bytes.len() < value.bytes.len() {
            // Our bytes are smaller than their bytes. Again, only operate on the shared length.
            let other_leading = value.bytes.len() - self.bytes.len();
            if is_and {
                // If we're doing an and, all of our virtual bytes are zero, so they'd stay zero. Easy.
                (&mut self.bytes[..], &value.bytes[other_leading..])
            } else {
                // Oh no, it's a xor or or, which are functionally the same thing for our leading bytes.
                // We add leading bytes to match their byte length, so any 1 bits can be written to our integer.
                self.bytes.reserve(other_leading);
                for i in 0..other_leading {
                    self.bytes.insert(i, 0);
                }

                (&mut self.bytes[..], &value.bytes[..])
            }
        } else {
            (&mut self.bytes[..], &value.bytes[..])
        }
    }
}
