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

    fn left_shift(self, by: usize) -> Self;

    fn and(self, value: Self) -> Self;

    fn or(self, value: Self) -> Self;

    fn complement(self) -> Self;

    fn shift_start() -> Self;

    fn zero() -> Self;

    fn one() -> Self;
}

macro_rules! bit_target_integer {
    ($($integer:ident $shift_start_offset:ident,)*) => {
        $(
            impl BitTarget for $integer {
                fn right_shift(self, by: usize) -> Self {
                    self >> by
                }

                fn left_shift(self, by: usize) -> Self {
                    self << by
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
                    1 << $shift_start_offset
                }

                fn zero() -> Self {
                    0
                }

                fn one() -> Self {
                    1
                }
            }

        )*
    };
}

const fn shift_offset<T: Sized>() -> usize {
    (size_of::<T>() * 8) - 1
}

const U8_SHIFT_OFFSET: usize = shift_offset::<u8>();
const U16_SHIFT_OFFSET: usize = shift_offset::<u16>();
const U32_SHIFT_OFFSET: usize = shift_offset::<u32>();
const USIZE_SHIFT_OFFSET: usize = shift_offset::<usize>();
const U64_SHIFT_OFFSET: usize = shift_offset::<u64>();

bit_target_integer!(
    u8 U8_SHIFT_OFFSET,
    u16 U16_SHIFT_OFFSET,
    u32 U32_SHIFT_OFFSET,
    usize USIZE_SHIFT_OFFSET,
    u64 U64_SHIFT_OFFSET,
);

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

pub fn first_high_bit_index<T: BitTarget>(digit: T) -> usize {
    let mut first_high_bit_index = T::bits_per_digit() - 1;
    for i in 0..first_high_bit_index {
        if (digit.and(T::shift_start().right_shift(i))) != T::zero() {
            first_high_bit_index = i;
            break;
        }
    }

    first_high_bit_index
}

macro_rules! bit_field {
    ($t:ident) => {
        use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};
        impl $t {
            #[allow(dead_code)]
            pub const fn overlaps(self, other: Self) -> bool {
                (self.0 & other.0) != 0
            }

            #[allow(dead_code)]
            pub const fn encompasses(self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }
        }

        impl BitAnd for $t {
            type Output = Self;

            fn bitand(self, rhs: Self) -> Self::Output {
                Self(self.0 & rhs.0)
            }
        }

        impl BitAndAssign for $t {
            fn bitand_assign(&mut self, rhs: Self) {
                *self = Self(self.0 & rhs.0)
            }
        }

        impl BitOr for $t {
            type Output = Self;

            fn bitor(self, rhs: Self) -> Self::Output {
                Self(self.0 | rhs.0)
            }
        }

        impl BitOrAssign for $t {
            fn bitor_assign(&mut self, rhs: Self) {
                *self = Self(self.0 | rhs.0)
            }
        }

        impl BitXor for $t {
            type Output = Self;

            fn bitxor(self, rhs: Self) -> Self::Output {
                Self(self.0 ^ rhs.0)
            }
        }

        impl BitXorAssign for $t {
            fn bitxor_assign(&mut self, rhs: Self) {
                *self = Self(self.0 ^ rhs.0)
            }
        }

        impl Not for $t {
            type Output = Self;

            fn not(self) -> Self::Output {
                Self(!self.0)
            }
        }
    };
}

pub(crate) use bit_field;
