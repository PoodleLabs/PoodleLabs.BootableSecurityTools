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

use core::{
    mem::size_of,
    ops::{
        BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Shl, ShlAssign, Shr,
        ShrAssign,
    },
};

pub trait BitTarget:
    Sized
    + Copy
    + Clone
    + PartialEq<Self>
    + Eq
    + PartialOrd<Self>
    + Ord
    + BitAnd<Self, Output = Self>
    + BitAndAssign<Self>
    + BitXor<Self, Output = Self>
    + BitXorAssign<Self>
    + BitOr<Self, Output = Self>
    + BitOrAssign<Self>
    + Not<Output = Self>
    + Shl<usize, Output = Self>
    + ShlAssign<usize>
    + Shr<usize, Output = Self>
    + ShrAssign<usize>
    + Shl<Self, Output = Self>
    + ShlAssign<Self>
    + Shr<Self, Output = Self>
    + ShrAssign<Self>
{
    fn bits_per_digit() -> usize {
        size_of::<Self>() * 8
    }

    fn shift_start() -> Self;

    fn zero() -> Self;

    fn one() -> Self;
}

macro_rules! bit_target_integer {
    ($($integer:ident $shift_start_offset:ident,)*) => {
        $(
            impl BitTarget for $integer {
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

pub const fn try_get_bit_start_offset(bit_count: usize, digit_count: usize) -> Option<usize> {
    let available_bits = digit_count * 8;
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
    let bit_mask = T::shift_start() >> bit_index;
    Some((digit & bit_mask) != T::zero())
}

pub fn try_set_bit_at_index<T: BitTarget>(bit_index: usize, value: bool, digits: &mut [T]) -> bool {
    let byte_index = bit_index / T::bits_per_digit();
    if byte_index >= digits.len() {
        return false;
    }

    let byte = digits[byte_index];
    let bit_index = bit_index % T::bits_per_digit();
    let bit_mask = T::shift_start() >> bit_index;
    digits[byte_index] = if value {
        byte | bit_mask
    } else {
        byte & !bit_mask
    };

    true
}

pub fn first_high_bit_index<T: BitTarget>(digit: T) -> usize {
    let mut first_high_bit_index = T::bits_per_digit() - 1;
    for i in 0..first_high_bit_index {
        if (digit & (T::shift_start() >> i)) != T::zero() {
            first_high_bit_index = i;
            break;
        }
    }

    first_high_bit_index
}

pub fn try_copy<TSource: BitTarget, TDestination: BitTarget>(
    source: &[TSource],
    source_index: usize,
    destination: &mut [TDestination],
    destination_index: usize,
    count: usize,
) -> bool {
    if count == 0
        || source_index + count > source.len() * TSource::bits_per_digit()
        || destination_index + count > destination.len() * TDestination::bits_per_digit()
    {
        return false;
    }

    for i in 0..count {
        assert!(try_set_bit_at_index(
            destination_index + i,
            try_get_bit_at_index(source_index + i, source).unwrap(),
            destination
        ));
    }

    true
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
