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

use core::mem::size_of;

pub trait BitTarget: Sized + Eq + Copy {
    fn bits_per_digit() -> usize {
        size_of::<Self>() * 8
    }

    fn right_shift(self, by: usize) -> Self;

    fn and(self, value: Self) -> Self;

    fn or(self, value: Self) -> Self;

    fn complement(self) -> Self;

    fn shift_start() -> Self;

    fn zero() -> Self;
}

impl BitTarget for u8 {
    fn right_shift(self, by: usize) -> Self {
        self >> by
    }

    fn and(self, value: Self) -> Self {
        self & value
    }

    fn or(self, value: Self) -> Self {
        self | value
    }

    fn complement(self) -> Self {
        !self
    }

    fn shift_start() -> Self {
        1u8 << 7
    }

    fn zero() -> Self {
        0
    }
}

impl BitTarget for u64 {
    fn right_shift(self, by: usize) -> Self {
        self >> by
    }

    fn and(self, value: Self) -> Self {
        self & value
    }

    fn or(self, value: Self) -> Self {
        self | value
    }

    fn complement(self) -> Self {
        !self
    }

    fn shift_start() -> Self {
        1u64 << 63
    }

    fn zero() -> Self {
        0
    }
}

pub const fn try_get_bit_start_offset(bit_count: usize, byte_count: usize) -> Option<usize> {
    let available_bits = byte_count * 8;
    if available_bits < bit_count {
        None
    } else {
        // Read the trailing bits if we have more than we need.
        Some(available_bits - bit_count)
    }
}

pub fn try_get_bit_at_index<T: BitTarget>(bit_index: usize, digits: &[T]) -> Option<bool> {
    let byte_index = bit_index / T::bits_per_digit();
    if byte_index >= digits.len() {
        return None;
    }

    let digit = digits[byte_index];
    let bit_index = bit_index % T::bits_per_digit();
    let bit_mask = T::shift_start().right_shift(bit_index);
    Some(digit.and(bit_mask) != T::zero())
}

pub fn try_set_bit_at_index<T: BitTarget>(bit_index: usize, value: bool, bytes: &mut [T]) -> bool {
    let byte_index = bit_index / T::bits_per_digit();
    if byte_index >= bytes.len() {
        return false;
    }

    let byte = bytes[byte_index];
    let bit_index = bit_index % T::bits_per_digit();
    let bit_mask = T::shift_start().right_shift(bit_index);
    bytes[byte_index] = if value {
        byte.or(bit_mask)
    } else {
        byte.and(bit_mask.complement())
    };

    true
}
