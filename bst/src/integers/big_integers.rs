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
use core::{cmp::Ordering, mem::size_of};

#[derive(Debug, Clone, Eq)]
pub struct BigUnsigned {
    // We store digits in big-endian format, in base-256.
    digits: Vec<u8>,
}

impl PartialEq for BigUnsigned {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl PartialOrd for BigUnsigned {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigUnsigned {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp(&self.digits, &other.digits)
    }
}

#[derive(Debug, Clone, Eq)]
pub struct BigSigned {
    big_unsigned: BigUnsigned,
    is_negative: bool,
}

impl PartialEq for BigSigned {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl PartialOrd for BigSigned {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigSigned {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.is_negative {
            if other.is_negative {
                // Both are negative; the larger unsigned value is smaller.
                other.big_unsigned.cmp(&self.big_unsigned)
            } else {
                // The operand is negative, and the operator is positive. The operand must be smaller.
                Ordering::Less
            }
        } else if other.is_negative {
            // The operand is positive, and the operator is negative. The operand must be larger.
            Ordering::Greater
        } else {
            // Both are positive; the smaller unsigned value is smaller.
            self.big_unsigned.cmp(&other.big_unsigned)
        }
    }
}

//\/\/\/\/\/\/\///
// Construction //
//\/\/\/\/\/\/\///

impl BigUnsigned {
    pub fn from_be_bytes(be_bytes: &[u8]) -> Self {
        Self {
            digits: match Self::first_non_zero_digit_index(&be_bytes) {
                // Trim any leading zero digits.
                Some(i) => Vec::from(&be_bytes[i..]),
                // There are no non-zero digits. Initialize with a single zero digit.
                None => Vec::from([0]),
            },
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut bytes = Vec::with_capacity(capacity);
        // We always need at least one digit; initialize as zero.
        bytes.push(0);
        Self { digits: bytes }
    }

    pub fn from_vec(digits: Vec<u8>) -> Self {
        let mut value = Self { digits };
        if value.digit_count() == 0 {
            value.digits.push(0);
        } else {
            value.trim_leading_zeroes();
        }

        value
    }
}

impl BigSigned {
    pub fn from_unsigned(is_negative: bool, big_unsigned: BigUnsigned) -> Self {
        Self {
            is_negative: is_negative && big_unsigned.is_non_zero(),
            big_unsigned,
        }
    }

    pub fn from_be_bytes(is_negative: bool, be_bytes: &[u8]) -> Self {
        Self::from_unsigned(is_negative, BigUnsigned::from_be_bytes(be_bytes))
    }

    #[allow(dead_code)]
    pub fn from_vec(is_negative: bool, digits: Vec<u8>) -> Self {
        Self::from_unsigned(is_negative, BigUnsigned::from_vec(digits))
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self::from_unsigned(false, BigUnsigned::with_capacity(capacity))
    }
}

//\/\/\/\/\/\/\/\//
// Introspection //
//\/\/\/\/\/\/\/\//

impl BigUnsigned {
    pub fn extract_be_bytes(self) -> Vec<u8> {
        self.digits
    }

    pub fn copy_digits_to(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.digits)
    }

    pub fn clone_be_bytes(&self) -> Box<[u8]> {
        (&self.digits[..]).into()
    }

    pub fn borrow_digits(&self) -> &[u8] {
        &self.digits
    }

    pub fn digit_count(&self) -> usize {
        self.digits.len()
    }

    pub fn is_non_zero(&self) -> bool {
        // The internal digits are always trimmed of leading zeroes, and we guarantee at least one digit.
        self.digits.len() > 1 || self.digits[0] != 0
    }

    pub fn is_zero(&self) -> bool {
        !self.is_non_zero()
    }

    pub fn is_not_one(&self) -> bool {
        // The internal digits are always trimmed of leading zeroes, and we guarantee at least one digit.
        self.digits.len() > 1 || self.digits[0] != 1
    }

    pub fn is_one(&self) -> bool {
        !self.is_not_one()
    }

    pub fn is_even(&self) -> bool {
        // We guarantee at least one digit. The final digit's final bit is all we need to check.
        self.digits[self.digits.len() - 1] & 1 == 0
    }

    #[allow(dead_code)]
    pub fn is_odd(&self) -> bool {
        !self.is_even()
    }
}

impl BigSigned {
    #[allow(dead_code)]
    pub fn extract_be_bytes(self) -> Vec<u8> {
        self.big_unsigned.extract_be_bytes()
    }

    pub fn borrow_unsigned_mut(&mut self) -> &mut BigUnsigned {
        &mut self.big_unsigned
    }

    pub fn copy_digits_to(&self, buffer: &mut [u8]) {
        self.big_unsigned.copy_digits_to(buffer)
    }

    #[allow(dead_code)]
    pub fn borrow_unsigned(&self) -> &BigUnsigned {
        &self.big_unsigned
    }

    pub fn clone_be_bytes(&self) -> Box<[u8]> {
        self.big_unsigned.clone_be_bytes()
    }

    #[allow(dead_code)]
    pub fn borrow_digits(&self) -> &[u8] {
        self.big_unsigned.borrow_digits()
    }

    pub fn digit_count(&self) -> usize {
        self.big_unsigned.digit_count()
    }

    pub fn is_non_zero(&self) -> bool {
        self.big_unsigned.is_non_zero()
    }

    pub fn is_zero(&self) -> bool {
        !self.is_non_zero()
    }

    pub fn is_negative(&self) -> bool {
        self.is_negative
    }

    #[allow(dead_code)]
    pub fn is_positive(&self) -> bool {
        !self.is_negative
    }

    pub fn is_even(&self) -> bool {
        self.big_unsigned.is_even()
    }

    #[allow(dead_code)]
    pub fn is_odd(&self) -> bool {
        !self.is_even()
    }
}

//\/\/\/\/\/\/\/\///
// Basic Mutation //
//\/\/\/\/\/\/\/\///

impl BigUnsigned {
    pub fn copy_digits_from(&mut self, digits: &[u8]) {
        let digits = match Self::first_non_zero_digit_index(digits) {
            Some(i) => &digits[i..],
            None => {
                self.zero();
                return;
            }
        };

        if self.digits.len() > digits.len() {
            let original_length = self.digits.len();
            self.digits[0..original_length - digits.len()].fill(0);
            self.digits.truncate(digits.len());
            self.digits.copy_from_slice(digits);
        } else if self.digits.len() == digits.len() {
            self.digits.copy_from_slice(digits);
        } else {
            let original_length = self.digits.len();
            self.digits.copy_from_slice(&digits[..original_length]);
            self.digits.extend_from_slice(&digits[original_length..]);
        }
    }

    pub fn set_equal_to(&mut self, value: &Self) {
        self.digits.truncate(0);
        self.digits.extend(&value.digits);
    }

    pub fn zero(&mut self) {
        self.digits.fill(0);
        self.digits.truncate(1);
    }

    pub fn one(&mut self) {
        self.digits.fill(1);
        self.digits.truncate(1);
    }
}

impl BigSigned {
    pub fn copy_digits_from(&mut self, digits: &[u8], is_negative: bool) {
        self.big_unsigned.copy_digits_from(digits);
        self.is_negative = is_negative;
    }

    pub fn set_equal_to_unsigned(&mut self, value: &BigUnsigned, is_negative: bool) {
        self.big_unsigned.set_equal_to(&value);
        self.is_negative = is_negative;
    }

    pub fn set_sign(&mut self, is_negative: bool) {
        self.is_negative = is_negative;
    }

    pub fn set_equal_to(&mut self, value: &Self) {
        self.big_unsigned.set_equal_to(&value.big_unsigned);
        self.is_negative = value.is_negative;
    }

    pub fn zero(&mut self) {
        self.is_negative = false;
        self.big_unsigned.zero();
    }

    pub fn negate(&mut self) {
        self.is_negative = !self.is_negative;
    }
}

//\/\/\/\///
// Macros //
//\/\/\/\///

macro_rules! simple_operation_implement_unsigned_type {
    ($(($digits_name:ident, $operation_name:ident): $operator_type:ty,)*) => {
        $(
            #[allow(dead_code)]
            pub fn $operation_name(&mut self, operator: $operator_type) {
                self.$digits_name(&operator.to_be_bytes())
            }
        )*
    };
}

macro_rules! simple_operation_implement_unsigned_types {
    ($($digits_name:ident: $u8_name:ident, $u16_name:ident, $u32_name:ident, $usize_name:ident, $u64_name:ident, $u128_name:ident, $big_unsigned_name:ident,)*) => {
    $(
        simple_operation_implement_unsigned_type!(
            ($digits_name, $u8_name): u8,
            ($digits_name, $u16_name): u16,
            ($digits_name, $u32_name): u32,
            ($digits_name, $usize_name): usize,
            ($digits_name, $u64_name): u64,
            ($digits_name, $u128_name): u128,
        );

        #[allow(dead_code)]
        pub fn $big_unsigned_name(&mut self, value: &BigUnsigned) {
            self.$digits_name(&value.digits)
        }
    )*
    }
}

macro_rules! simple_operation_implement_signed_type {
    ($(($digits_name:ident, $operation_name:ident): $operator_type:ty,)*) => {
        $(
            #[allow(dead_code)]
            pub fn $operation_name(&mut self, operator: $operator_type) {
                self.$digits_name(&operator.unsigned_abs().to_be_bytes(), operator < 0)
            }
        )*
    };
}

macro_rules! simple_operation_implement_signed_types {
    ($($digits_name:ident: $i8_name:ident, $i16_name:ident, $i32_name:ident, $isize_name:ident, $i64_name:ident, $i128_name:ident, $big_unsigned_name:ident,)*) => {
    $(
        simple_operation_implement_signed_type!(
            ($digits_name, $i8_name): i8,
            ($digits_name, $i16_name): i16,
            ($digits_name, $i32_name): i32,
            ($digits_name, $isize_name): isize,
            ($digits_name, $i64_name): i64,
            ($digits_name, $i128_name): i128,
        );

        #[allow(dead_code)]
        pub fn $big_unsigned_name(&mut self, value: &BigSigned) {
            self.$digits_name(&value.big_unsigned.digits, value.is_negative)
        }
    )*
    }
}

macro_rules! big_unsigned_division_implementation {
    ($($division_name:ident: $division_type:ident, $remainder_buffer_size:expr,)*) => {
    $(
        #[allow(dead_code)]
        pub fn $division_name(&mut self, divisor: $division_type, remainder_buffer: &mut $division_type) -> bool {
            let mut remainder_bytes = [0u8; $remainder_buffer_size];
            match self.divide_be_bytes_with_remainder(&divisor.to_be_bytes(), &mut remainder_bytes) {
                true => {
                    *remainder_buffer = $division_type::from_be_bytes(remainder_bytes);
                    true
                }
                false => false,
            }
        }
    )*
    }
}

macro_rules! big_signed_division_implementation_for_unsigned_with_remainder {
    ($($division_name:ident: $divisor_type:ty, $remainder_type:ty,)*) => {
        $(
            #[allow(dead_code)]
            pub fn $division_name(
                &mut self,
                divisor: $divisor_type,
                remainder_buffer: $remainder_type,
                remainder_is_negative: &mut bool,
            ) -> bool {
                if self
                    .big_unsigned
                    .$division_name(divisor, remainder_buffer)
                {
                    *remainder_is_negative = self.is_negative;
                    self.is_negative = self.is_negative && !self.is_zero();
                    true
                } else {
                    false
                }
            }
        )*
        }
}

macro_rules! big_signed_division_implementation_for_signed_with_remainder {
    ($(($division_name:ident, $unsigned_division_name:ident): $divisor_type:ty, $remainder_type:ty,)*) => {
        $(
            #[allow(dead_code)]
            pub fn $division_name(&mut self, divisor: $divisor_type, remainder_buffer: $remainder_type) -> bool {
                let mut unsigned_remainder = 0;
                if self
                    .big_unsigned
                    .$unsigned_division_name(divisor.unsigned_abs(), &mut unsigned_remainder)
                {
                    *remainder_buffer = if self.is_negative {
                        -(unsigned_remainder as $divisor_type)
                    } else {
                        unsigned_remainder as $divisor_type
                    };

                    self.is_negative = self.is_negative != (divisor < 0) && !self.is_zero();
                    true
                } else {
                    false
                }
            }
        )*
        }
}

//\/\/\/\/\/\/\/\/\/\///
// Logical Operations //
//\/\/\/\/\/\/\/\/\/\///

impl BigUnsigned {
    simple_operation_implement_unsigned_types!(
        and_be_bytes: and_u8, and_u16, and_u32, and_usize, and_u64, and_u128, and_big_unsigned,
    );

    pub fn and_be_bytes(&mut self, operator_digits: &[u8]) {
        let operator_digits = match Self::first_non_zero_digit_index(operator_digits) {
            Some(i) => &operator_digits[i..],
            None => {
                // The operator has no non-zero digits. We end up with zero as X & 0 = 0.
                self.zero();
                return;
            }
        };

        let operand_digit_count = self.digit_count();
        let (operand_digits, operator_digits) = if operator_digits.len() >= operand_digit_count {
            // The operator has a digit length greater than or equal to the operand's digit length. We can ignore leading digits, as X & 0 = 0.
            (
                &mut self.digits[..],
                &operator_digits[operator_digits.len() - operand_digit_count..],
            )
        } else {
            // The operator has a digit length less than the operand's digit length. X & 0 = 0, so zero out the operand's leading digits.
            let offset = operand_digit_count - operator_digits.len();
            self.digits[..offset].fill(0);
            (&mut self.digits[offset..], &operator_digits[..])
        };

        for i in 0..operator_digits.len() {
            // Perform the AND on each overlapping digit.
            operand_digits[i] &= operator_digits[i];
        }

        self.trim_leading_zeroes();
    }

    simple_operation_implement_unsigned_types!(
        xor_be_bytes: xor_u8, xor_u16, xor_u32, xor_usize, xor_u64, xor_u128, xor_big_unsigned,
    );

    pub fn xor_be_bytes(&mut self, operator_digits: &[u8]) {
        let (operand_digits, operator_digits) = match self.prepare_or_or_xor(operator_digits) {
            Some(d) => d,
            None => return,
        };

        for i in 0..operator_digits.len() {
            // Perform the XOR on each overlapping digit.
            operand_digits[i] ^= operator_digits[i];
        }

        self.trim_leading_zeroes();
    }

    simple_operation_implement_unsigned_types!(
        or_be_bytes: or_u8, or_u16, or_u32, or_usize, or_u64, or_u128, or_big_unsigned,
    );

    pub fn or_be_bytes(&mut self, operator_digits: &[u8]) {
        let (operand_digits, operator_digits) = match self.prepare_or_or_xor(operator_digits) {
            Some(d) => d,
            None => return,
        };

        for i in 0..operator_digits.len() {
            // Perform the OR on each overlapping digit.
            operand_digits[i] |= operator_digits[i];
        } // OR can't zero out any digits, so there's no need to trim.
    }
}

impl BigSigned {
    simple_operation_implement_unsigned_types!(
        and_be_bytes_unsigned: and_u8, and_u16, and_u32, and_usize, and_u64, and_u128, and_big_unsigned,
    );

    pub fn and_be_bytes_unsigned(&mut self, operator_digits: &[u8]) {
        self.and_be_bytes_signed(operator_digits, false)
    }

    simple_operation_implement_signed_types!(
        and_be_bytes_signed: and_i8, and_i16, and_i32, and_isize, and_i64, and_i128, and_big_signed,
    );

    pub fn and_be_bytes_signed(&mut self, operator_digits: &[u8], is_negative: bool) {
        self.big_unsigned.and_be_bytes(operator_digits);
        self.is_negative &= is_negative;
    }

    simple_operation_implement_unsigned_types!(
        xor_be_bytes_unsigned: xor_u8, xor_u16, xor_u32, xor_usize, xor_u64, xor_u128, xor_big_unsigned,
    );

    pub fn xor_be_bytes_unsigned(&mut self, operator_digits: &[u8]) {
        self.xor_be_bytes_signed(operator_digits, false)
    }

    simple_operation_implement_signed_types!(
        xor_be_bytes_signed: xor_i8, xor_i16, xor_i32, xor_isize, xor_i64, xor_i128, xor_big_signed,
    );

    pub fn xor_be_bytes_signed(&mut self, operator_digits: &[u8], is_negative: bool) {
        self.big_unsigned.xor_be_bytes(operator_digits);
        self.is_negative ^= is_negative;
    }

    simple_operation_implement_unsigned_types!(
        or_be_bytes_unsigned: or_u8, or_u16, or_u32, or_usize, or_u64, or_u128, or_big_unsigned,
    );

    pub fn or_be_bytes_unsigned(&mut self, operator_digits: &[u8]) {
        self.or_be_bytes_signed(operator_digits, false)
    }

    simple_operation_implement_signed_types!(
        or_be_bytes_signed: or_i8, or_i16, or_i32, or_isize, or_i64, or_i128, or_big_signed,
    );

    pub fn or_be_bytes_signed(&mut self, operator_digits: &[u8], is_negative: bool) {
        self.big_unsigned.or_be_bytes(operator_digits);
        self.is_negative |= is_negative;
    }
}

//\/\/\/\/\/\///
// Arithmetic //
//\/\/\/\/\/\///

impl BigUnsigned {
    simple_operation_implement_unsigned_types!(
        add_be_bytes: add_u8, add_u16, add_u32, add_usize, add_u64, add_u128, add_big_unsigned,
    );

    pub fn add_be_bytes(&mut self, addend_digits: &[u8]) {
        let addend_digits = match Self::first_non_zero_digit_index(addend_digits) {
            // Skip any leading zero digits in the addend.
            Some(i) => &addend_digits[i..],
            // The addend is zero; X + 0 = X, so we can just return.
            None => return,
        };

        let (self_is_smaller, min_len) = if self.digits.len() < addend_digits.len() {
            // The addend has more digts than the augend, so the augend is definitely going to grow. Reserve space ahead of time.
            self.digits.reserve(addend_digits.len() - self.digits.len());

            // The overlapping digit range is equal to the length of the shorter value which, in this case, is the augend.
            (true, self.digits.len())
        } else {
            // The overlapping digit range is equal to the length of the shorter value which, in this case, is the addend.
            (false, addend_digits.len())
        };

        let mut carry = 0u32;
        // Iterate over the overlapping digits, from least to most significant.
        for i in 1..(min_len + 1) {
            let augend_index = self.digits.len() - i;
            let augend = self.digits[augend_index] as u32;
            let addend = addend_digits[addend_digits.len() - i] as u32;

            // Sum the digit in this position from the augend and addend with any existing carry.
            let sum = augend + addend + carry;

            // Set the digit in the current position.
            self.digits[augend_index] = sum as u8;

            // Carry over any overflow for the next iteration.
            carry = sum >> 8;
        }

        if self_is_smaller {
            // We need to add digits (and any remaining carry) to the start of our augend.
            for i in (0..addend_digits.len() - min_len).rev() {
                let sum = carry + (addend_digits[i] as u32);
                self.digits.insert(0, sum as u8);
                carry = sum >> 8;
            }
        } else {
            // We need to add any remaining carry to the leading digits of of our augend.
            for i in (0..self.digits.len() - min_len).rev() {
                let sum = carry + (self.digits[i] as u32);
                self.digits[i] = sum as u8;
                carry = sum >> 8;
            }
        }

        // Add any remaining carry to our augend.
        while carry > 0 {
            self.digits.insert(0, carry as u8);
            carry >>= 8;
        } // Adding can't result in leading zeroes where there were none, so there's no need to trim.
    }

    simple_operation_implement_unsigned_types!(
        subtract_be_bytes: subtract_u8, subtract_u16, subtract_u32, subtract_usize, subtract_u64, subtract_u128, subtract_big_unsigned,
    );

    pub fn subtract_be_bytes(&mut self, subtrahend_digits: &[u8]) {
        if self.is_zero() {
            // If the minuend is already zero, as we don't wrap, we can just return.
            return;
        }

        let subtrahend_digits = match Self::first_non_zero_digit_index(subtrahend_digits) {
            // Skip any leading zero digits in the subtrahend.
            Some(i) => &subtrahend_digits[i..],
            // The subtrahend is zero; X - 0 = X, so we can just return.
            None => return,
        };

        match cmp(&self.digits, subtrahend_digits) {
            Ordering::Greater => {
                Self::subtract_internal(&mut self.digits, subtrahend_digits);
                self.trim_leading_zeroes();
            }
            _ => {
                // The minuend is less than or equal to the subtrahend. We don't wrap, so we can just zero out the minuend.
                self.zero();
            }
        }
    }

    simple_operation_implement_unsigned_types!(
        difference_be_bytes: difference_u8, difference_u16, difference_u32, difference_usize, difference_u64, difference_u128, difference_big_unsigned,
    );

    pub fn difference_be_bytes(&mut self, operator_digits: &[u8]) {
        let operator_digits = match Self::first_non_zero_digit_index(operator_digits) {
            // The operator is non-zero; trim any leading zero digits.
            Some(i) => &operator_digits[i..],
            // The operator is zero; the operand is already the difference, and we can just return.
            None => return,
        };

        // Compare the operand and operator.
        match cmp(&self.digits, operator_digits) {
            Ordering::Equal => {
                // The operand and operator are equal. The difference is zero.
                self.zero();
            }
            Ordering::Greater => {
                // The operand is larger than the operator. The difference is operand - operator.
                Self::subtract_internal(&mut self.digits, operator_digits);
                self.trim_leading_zeroes();
            }
            Ordering::Less => {
                // The operand is less than the operator. The difference is operator - operand, but we want to minimize allocations.
                // Store the original length of the operand.
                let operand_original_len = self.digits.len();

                // Pre-pend the operand with any leading digits in the operator.
                self.digits.splice(
                    0..0,
                    operator_digits[..operator_digits.len() - self.digits.len()]
                        .iter()
                        .cloned(),
                );

                // Iterate over the unchanged digits in the operand from most to least significant.
                for i in (operator_digits.len() - operand_original_len)..operator_digits.len() {
                    let operator_digit = operator_digits[i];
                    let operand_digit = self.digits[i];

                    // Compare the operand digit to the operator digit at this location.
                    // Remember: we are effectively performing operator - operand.
                    match operator_digit.cmp(&operand_digit) {
                        // The operator's digit at this position is larger than the operand's digit at this position.
                        // The digit in the difference is operator_digit - operand_digit
                        Ordering::Greater => self.digits[i] = operator_digit - operand_digit,
                        // The digits at this position were the same; the digit in the difference is zero.
                        Ordering::Equal => self.digits[i] = 0,
                        Ordering::Less => {
                            // The operator's digit at this position was smaller than the operand's digit at this position.
                            // The digit in the difference becomes the wrapped subtraction of operator_digit - operand_digit.
                            self.digits[i] = operator_digit.wrapping_sub(operand_digit);

                            // Subtraction would have wrapped here. We need to propagate backwards until we've subtracted
                            // 1 from a more digificant digit.
                            let mut j = i - 1;
                            loop {
                                if self.digits[j] == 0 {
                                    self.digits[j] = u8::MAX;
                                } else {
                                    self.digits[j] -= 1;
                                    break;
                                }

                                j -= 1;
                            }
                        }
                    }
                }

                self.trim_leading_zeroes();
            }
        }
    }

    simple_operation_implement_unsigned_types!(
        multiply_be_bytes: multiply_u8, multiply_u16, multiply_u32, multiply_usize, multiply_u64, multiply_u128, multiply_big_unsigned,
    );

    pub fn multiply_be_bytes(&mut self, multiplier_digits: &[u8]) {
        let multiplier_digits = match Self::first_non_zero_digit_index(multiplier_digits) {
            // Skip any leading zero digits in the multiplier.
            Some(i) => &multiplier_digits[i..],
            None => {
                // The multiplier is zero. X * 0 = 0, so just zero the multiplicand and return.
                self.zero();
                return;
            }
        };

        if multiplier_digits.len() == 1 && multiplier_digits[0] == 1 {
            // The multiplier is 1; X * 1 = X, so we can just return.
            return;
        }

        // Multiplication is likely to overflow the current bounds of a trimmed big unsigned. Pre-emptively grow to the
        // maximum size we'll need, which is the sum of the number of digits in the multiplier and the multiplicand.
        self.digits
            .splice(0..0, (0..multiplier_digits.len()).into_iter().map(|_| 0));

        // We want to multiply in place. When multiplying a digit in a number, the less signifcant digits in the multiplicand do not change,
        // but digits of equal or higher significance can change. This means we need to iterate over multiplicand's digits from
        // most to least significant, so we can always multiply the original value of that digit.
        for i in 0..self.digits.len() - multiplier_digits.len() {
            // We padded the multiplicand with leading zeroes to accomodate overflow; none of those digits are relevant to the actual
            // multiplication, only for carry handling; we can just skip them.
            let multiplicand_index = i + multiplier_digits.len();

            // Get the multiplicand digit at this index. We need to multiply it by all the digits in the multiplier, summing all the products,
            // so we need to store its original value as this digit will be mutated during each multiplication.
            let multiplicand = self.digits[multiplicand_index] as u32;

            // Zero out this digit, otherwise we end up with X + (X * Y).
            self.digits[multiplicand_index] = 0;

            // Iterate over the multiplier's digits from least to most significant.
            for j in (0..multiplier_digits.len()).rev() {
                // Calculate the position (or magnitude) of the least significant digit for the product of this multiplication.
                // Consider 21 * 36.
                // This is equivalent to:
                // (20 * 30) + (20 * 6) + (1 * 30) + (1 * 6).
                // The digits 6 and 1 have magnitude 1. The digits 2 and 3 have magnitudes 2.
                // 20 * 30 = 600. The least significant digit which can be non-zero is magnitude 3.
                // 20 * 6 = 120. The least significant digit which can be non-zero is magnitude 2.
                // 1 * 30 = 30. The least significant digit which can be non-zero is magnitude 2.
                // 1 * 6 = 6. The least significant digit which can be non-zero is magnitude 1.
                // Note: any multiplication may overflow into one more-significant digit.
                let mut k = multiplicand_index - (multiplier_digits.len() - (j + 1));

                // Calculate the product for this digit's multiplication.
                // This is the value we need to insert at magnitude K.
                let mut value_at_magnitude = multiplicand * (multiplier_digits[j] as u32);
                loop {
                    // We can't discard any existing digit at magnitude K.
                    value_at_magnitude += self.digits[k] as u32;

                    // K becomes the least-significant digit of our calculated value ending at this digit.
                    self.digits[k] = value_at_magnitude as u8;

                    // Discard the least significant digit.
                    value_at_magnitude >>= 8;
                    if value_at_magnitude == 0 {
                        // Once there's nothing left to insert, we can break.
                        break;
                    }

                    // Move to the next magnitude up, and repeat.
                    k -= 1;
                }
            }
        }

        self.trim_leading_zeroes()
    }

    pub fn divide_u8_with_remainder(&mut self, divisor: u8, remainder_buffer: &mut u8) -> bool {
        if divisor == 0 {
            // The divisor is zero; we can't divide by zero, so return None.
            return false;
        }

        if divisor == 1 {
            // The divisor is one; X / 1 = X r0, so the remainder is 0.
            *remainder_buffer = 0;
            return true;
        }

        if self.is_zero() {
            // The dividend is zero; 0 / X = 0 r0, the remainder is 0.
            *remainder_buffer = 0;
            return true;
        }

        // Track the remainder in a bigger integer format.
        let mut remainder = 0u32;
        // Iterate over the digits in the dividend from most to least significant.
        for i in 0..self.digits.len() {
            // Any previous remainder becomes the more significant digit. The current digit is the less significant digit.
            let dividend = (remainder << 8) | (self.digits[i] as u32);

            // The less significant digit of this round of division's quotient is our new digit for this index.
            self.digits[i] = (dividend / (divisor as u32)) as u8;

            // The remainder carries down into the next digit; 169 / 3 = 100 / 3 + 60 / 3 + 9 / 3
            remainder = dividend % (divisor as u32);
        }

        self.trim_leading_zeroes();
        *remainder_buffer = remainder as u8;
        return true;
    }

    big_unsigned_division_implementation!(
        divide_u16_with_remainder: u16, 2,
        divide_u32_with_remainder: u32, 4,
        divide_usize_with_remainder: usize, size_of::<usize>(),
        divide_u64_with_remainder: u64, 8,
        divide_u128_with_remainder: u128, 16,
    );

    pub fn divide_big_unsigned_with_remainder(
        &mut self,
        divisor: &BigUnsigned,
        remainder_buffer: &mut BigUnsigned,
    ) -> bool {
        remainder_buffer.zero();
        remainder_buffer
            .digits
            .extend((0..divisor.digit_count() - 1).into_iter().map(|_| 0));

        match self.divide_be_bytes_with_remainder(&divisor.digits, &mut remainder_buffer.digits) {
            true => {
                remainder_buffer.trim_leading_zeroes();
                true
            }
            false => false,
        }
    }

    pub fn divide_be_bytes_with_remainder(
        &mut self,
        divisor_digits: &[u8],
        remainder_buffer: &mut [u8],
    ) -> bool {
        let divisor_digits = match Self::first_non_zero_digit_index(divisor_digits) {
            // Skip any leading zero digits in the divisor.
            Some(i) => &divisor_digits[i..],
            // The divisor is zero; we can't divide by zero, so return false.
            None => return false,
        };

        if remainder_buffer.len() < divisor_digits.len() {
            // The remainder buffer must have a length which can fit the divisor in it.
            return false;
        }

        // We can definitely perform the division at this point, so ensure the remainder buffer is zeroed out.
        remainder_buffer.fill(0);

        // Get a window into the remainder buffer which can be written to without worrying about leading zero digits.
        let remainder_buffer_length = remainder_buffer.len();
        let remainder_digits =
            &mut remainder_buffer[remainder_buffer_length - divisor_digits.len()..];
        let remainder_digit_count = remainder_digits.len();

        if divisor_digits.len() == 1 {
            // The divisor has a single digit; we can use the simple division algorithm.
            let mut remainder = 0u8;
            assert!(self.divide_u8_with_remainder(divisor_digits[0], &mut remainder));

            // This is guaranteed to succeed as we already checked the divisor is non-zero.
            // Write the remainder to the remainder buffer, and return true.
            remainder_digits[0] = remainder;
            return true;
        }

        if self.is_zero() {
            // The dividend is zero; 0 / X = 0 r0, and we already zeroed out the remainder buffer, so we can just return.
            return true;
        }

        match cmp(&self.digits, divisor_digits) {
            Ordering::Less => {
                // The dividend is less than the divisor. Where X < Y, X / Y = 0, and X % Y = X.
                // We can just move the dividend into the remainder buffer, then zero the dividend.
                remainder_digits[remainder_digit_count - self.digits.len()..]
                    .copy_from_slice(&self.digits);
                self.zero();
            }
            Ordering::Equal => {
                // The dividend is equal to the divisor. Where X == Y, X / Y = 1, and X % Y = 0.
                // We can just mutate the dividend to equal one, and return.
                self.digits.truncate(1);
                self.digits[0] = 1;
            }
            Ordering::Greater => {
                // Add a leading zero to the dividend to ensure we have space to fit both the quotient and the remainder.
                self.digits.insert(0, 0);

                // Track the length of the working quotient and remainder; we will overwrite the dividend
                // using subtraction over a shifting window of digits.
                let mut quotient_len = 0;

                // We added a leading zero; we can skip that for iterative division.
                let mut remainder_off = 1;

                // Start with a window with a length equal to the divisor length; we can't do anything while the working remainder
                // is less than the divisor, and with fewer digits, it is guaranteed to be less.
                let mut remainder_len = divisor_digits.len();
                loop {
                    let mut remainder = if remainder_off + remainder_len > self.digits.len() {
                        // We've reached the end of the dividend.
                        match Self::first_non_zero_digit_index(&self.digits[remainder_off..]) {
                            Some(i) => {
                                // There are non-zero digits remaining in the working remainder. Extract them.
                                let remainder = &mut self.digits[remainder_off + i..];
                                match cmp(remainder, divisor_digits) {
                                    Ordering::Less => {
                                        // The remaining digits are the remainder.
                                        remainder_digits[remainder_digit_count - remainder.len()..]
                                            .copy_from_slice(&remainder);

                                        // Break to extract the quotient.
                                        break;
                                    }
                                    Ordering::Equal => {
                                        // The remainder's digits are equal to the divisor.
                                        self.append_quotient_digit(1, &mut quotient_len);
                                        // The remainder should be zero, and can just be truncated away. Break to extract the quotient.
                                        break;
                                    }
                                    // There is more division to perform; pass the working remainder digits out.
                                    Ordering::Greater => remainder,
                                }
                            }
                            None => {
                                // There are no non-zero digits remaining in the working remainder. The remainder is zero.
                                // Break to extract the quotient.
                                break;
                            }
                        }
                    } else {
                        // We're still within the bounds of the dividend. Extract the working remainder digits.
                        let remainder =
                            &mut self.digits[remainder_off..remainder_off + remainder_len];
                        match Self::first_non_zero_digit_index(&remainder) {
                            Some(i) => {
                                // The working remainder has non-zero digits.
                                // Truncate any zero digits from the working remainder window.
                                remainder_off += i;
                                remainder_len -= i;

                                // Pass out the working remainder digits.
                                &mut remainder[i..]
                            }
                            None => {
                                // The working remainder contains no non-zero digits.
                                self.append_quotient_digit(0, &mut quotient_len);

                                // Expand the working remainder to include the next digit, and go back to the start of the loop.
                                remainder_len += 1;
                                continue;
                            }
                        }
                    };

                    // Compare the working remainder with the divisor.
                    match cmp(&remainder, divisor_digits) {
                        Ordering::Greater => {
                            // The working remainder is larger than the divisor.
                            // We will perform division-by-subtraction on it.
                            let mut subtraction_counter = 0u8;
                            loop {
                                // Subtract the divisor from the working remainder.
                                Self::subtract_internal(remainder, divisor_digits);
                                subtraction_counter += 1;

                                // Trim any new leading zero digits.
                                let offset = Self::first_non_zero_digit_index(&remainder).unwrap();
                                remainder_off += offset;
                                remainder_len -= offset;
                                remainder =
                                    &mut self.digits[remainder_off..remainder_off + remainder_len];

                                // Compare the new working remainder to the divisor post-subtraction.
                                match cmp(&remainder, divisor_digits) {
                                    Ordering::Less => {
                                        // The working remainder is smaller than the divisor. Carry the remainder over into the next
                                        // iteration of the main loop, expanding to include the next digit.
                                        remainder_len += 1;

                                        self.append_quotient_digit(
                                            subtraction_counter,
                                            &mut quotient_len,
                                        );

                                        // Go back to the main loop.
                                        break;
                                    }
                                    Ordering::Equal => {
                                        // The working remainder's digits are equal to the divisor.
                                        self.handle_remainder_equals_divisor(
                                            subtraction_counter + 1,
                                            remainder_off,
                                            remainder_len,
                                            &mut quotient_len,
                                        );

                                        // Start over with a new working remainder window for the next iteration.
                                        remainder_off += remainder_len;
                                        remainder_len = 1;

                                        // Go back to the main loop.
                                        break;
                                    }
                                    Ordering::Greater => {}
                                }
                            }
                        }
                        Ordering::Equal => {
                            // The working remainder's digits are equal to the divisor.
                            self.handle_remainder_equals_divisor(
                                1,
                                remainder_off,
                                remainder_len,
                                &mut quotient_len,
                            );

                            // Start over with a new working remainder window for the next iteration.
                            remainder_off += remainder_len;
                            remainder_len = 1;
                        }
                        Ordering::Less => {
                            // The working remainder is smaller than the divisor. Expand the working remainder to include the next digit.
                            remainder_len += 1;
                            self.append_quotient_digit(0, &mut quotient_len);
                        }
                    }
                }

                // Truncate the dividend to yield the quotient.
                self.digits.truncate(quotient_len);
            }
        }

        true
    }
}

impl BigSigned {
    simple_operation_implement_unsigned_types!(
        add_be_bytes_unsigned: add_u8, add_u16, add_u32, add_usize, add_u64, add_u128, add_big_unsigned,
    );

    pub fn add_be_bytes_unsigned(&mut self, addend_digits: &[u8]) {
        self.add_be_bytes_signed(addend_digits, false)
    }

    simple_operation_implement_signed_types!(
        add_be_bytes_signed: add_i8, add_i16, add_i32, add_isize, add_i64, add_i128, add_big_signed,
    );

    pub fn add_be_bytes_signed(&mut self, addend_digits: &[u8], is_negative: bool) {
        if is_negative == self.is_negative {
            // Sign is the same; we're moving away from zero, and can just perform an unsigned add.
            self.big_unsigned.add_be_bytes(addend_digits)
        } else {
            // Sign is different; we're moving toward zero. The result is the difference between the two values, with a sign based on which is larger.
            self.is_negative = Ordering::Greater
                == (if self.is_negative {
                    // Augend is negative, addend is positive. If augend > addend, sum < 0, and we are negative.
                    cmp(&self.big_unsigned.digits, addend_digits)
                } else {
                    // Augend is positive, addend is negative. If addend > augend, sum < 0, and we are negative.
                    cmp(addend_digits, &self.big_unsigned.digits)
                });

            self.big_unsigned.difference_be_bytes(addend_digits)
        }
    }

    simple_operation_implement_unsigned_types!(
        subtract_be_bytes_unsigned: subtract_u8, subtract_u16, subtract_u32, subtract_usize, subtract_u64, subtract_u128, subtract_big_unsigned,
    );

    pub fn subtract_be_bytes_unsigned(&mut self, subtrahend_digits: &[u8]) {
        self.subtract_be_bytes_signed(subtrahend_digits, false)
    }

    simple_operation_implement_signed_types!(
        subtract_be_bytes_signed: subtract_i8, subtract_i16, subtract_i32, subtract_isize, subtract_i64, subtract_i128, subtract_big_signed,
    );

    pub fn subtract_be_bytes_signed(&mut self, subtrahend_digits: &[u8], is_negative: bool) {
        // Subtracting a negative is addition, and adding a negative is subtraction. We can invert the subtrahend's sign and add it.
        self.add_be_bytes_signed(subtrahend_digits, !is_negative)
    }

    simple_operation_implement_unsigned_types!(
        difference_be_bytes_unsigned: difference_u8, difference_u16, difference_u32, difference_usize, difference_u64, difference_u128, difference_big_unsigned,
    );

    pub fn difference_be_bytes_unsigned(&mut self, operator_digits: &[u8]) {
        self.difference_be_bytes_signed(operator_digits, false)
    }

    simple_operation_implement_signed_types!(
        difference_be_bytes_signed: difference_i8, difference_i16, difference_i32, difference_isize, difference_i64, difference_i128, difference_big_signed,
    );

    pub fn difference_be_bytes_signed(&mut self, operator_digits: &[u8], is_negative: bool) {
        if self.is_negative == is_negative {
            // If the values have the same sign, the difference is the unsigned difference.
            self.big_unsigned.difference_be_bytes(operator_digits)
        } else {
            // If the values have a different sign, the difference is the sum of the unsigned values.
            self.big_unsigned.add_be_bytes(operator_digits)
        }

        // Differences are an absolute value.
        self.is_negative = false;
    }

    simple_operation_implement_unsigned_types!(
        multiply_be_bytes_unsigned: multiply_u8, multiply_u16, multiply_u32, multiply_usize, multiply_u64, multiply_u128, multiply_big_unsigned,
    );

    pub fn multiply_be_bytes_unsigned(&mut self, multiplier_digits: &[u8]) {
        self.multiply_be_bytes_signed(multiplier_digits, false)
    }

    simple_operation_implement_signed_types!(
        multiply_be_bytes_signed: multiply_i8, multiply_i16, multiply_i32, multiply_isize, multiply_i64, multiply_i128, multiply_big_signed,
    );

    pub fn multiply_be_bytes_signed(&mut self, multiplier_digits: &[u8], is_negative: bool) {
        // The unsigned value will always just be the product.
        self.big_unsigned.multiply_be_bytes(multiplier_digits);

        // A negative multiplied by a negative is positive, and a positive multiplied by a positive is negative.
        // A negative multiplied by a positive is negative, unless the positive value is zero, in which case, the product is zero.
        self.is_negative = self.is_negative != is_negative && !self.is_zero()
    }

    big_signed_division_implementation_for_unsigned_with_remainder!(
        divide_u8_with_remainder: u8, &mut u8,
        divide_u16_with_remainder: u16, &mut u16,
        divide_u32_with_remainder: u32, &mut u32,
        divide_usize_with_remainder: usize, &mut usize,
        divide_u64_with_remainder: u64, &mut u64,
        divide_u128_with_remainder: u128, &mut u128,
        divide_big_unsigned_with_remainder: &BigUnsigned, &mut BigUnsigned,
        divide_be_bytes_with_remainder: &[u8], &mut [u8],
    );

    big_signed_division_implementation_for_signed_with_remainder!(
        (divide_i8_with_remainder, divide_u8_with_remainder): i8, &mut i8,
        (divide_i16_with_remainder, divide_u16_with_remainder): i16, &mut i16,
        (divide_i32_with_remainder, divide_u32_with_remainder): i32, &mut i32,
        (divide_isize_with_remainder, divide_usize_with_remainder): isize, &mut isize,
        (divide_i64_with_remainder, divide_u64_with_remainder): i64, &mut i64,
        (divide_i128_with_remainder, divide_u128_with_remainder): i128, &mut i128,
    );

    pub fn divide_big_signed_with_remainder(
        &mut self,
        divisor: &BigSigned,
        remainder_buffer: &mut BigSigned,
    ) -> bool {
        if self.big_unsigned.divide_big_unsigned_with_remainder(
            &divisor.big_unsigned,
            &mut remainder_buffer.big_unsigned,
        ) {
            remainder_buffer.is_negative = self.is_negative && !remainder_buffer.is_zero();
            self.is_negative = self.is_negative != divisor.is_negative && !self.is_zero();
            true
        } else {
            false
        }
    }

    pub fn divide_big_signed_with_modulus(
        &mut self,
        divisor: &BigSigned,
        modulus_buffer: &mut BigSigned,
    ) -> bool {
        let dividend_was_negative = self.is_negative;
        if self.divide_big_signed_with_remainder(divisor, modulus_buffer) {
            if modulus_buffer.is_non_zero() {
                if dividend_was_negative != divisor.is_negative {
                    modulus_buffer
                        .big_unsigned
                        .difference_big_unsigned(&divisor.big_unsigned);
                }

                modulus_buffer.is_negative = divisor.is_negative;
            }

            true
        } else {
            false
        }
    }

    pub fn divide_big_unsigned_with_modulus(
        &mut self,
        divisor: &BigUnsigned,
        modulus_buffer: &mut BigUnsigned,
    ) -> bool {
        let dividend_was_negative = self.is_negative;
        let mut remainder_is_negative = false;
        if self.divide_big_unsigned_with_remainder(
            divisor,
            modulus_buffer,
            &mut remainder_is_negative,
        ) {
            if modulus_buffer.is_non_zero() {
                if dividend_was_negative {
                    modulus_buffer.difference_big_unsigned(&divisor);
                }
            }

            true
        } else {
            false
        }
    }

    pub fn divide_big_unsigned_with_signed_modulus(
        &mut self,
        divisor: &BigUnsigned,
        modulus_buffer: &mut BigSigned,
    ) -> bool {
        let dividend_was_negative = self.is_negative;
        let mut remainder_is_negative = false;
        if self.divide_big_unsigned_with_remainder(
            divisor,
            &mut modulus_buffer.big_unsigned,
            &mut remainder_is_negative,
        ) {
            modulus_buffer.is_negative = false;
            if modulus_buffer.is_non_zero() {
                if dividend_was_negative {
                    modulus_buffer.difference_big_unsigned(&divisor);
                }
            }

            true
        } else {
            false
        }
    }
}

//\/\/\/\/\/\/\/\/\///
// Internal Helpers //
//\/\/\/\/\/\/\/\/\///

impl BigUnsigned {
    //\/\/\/\/\/\/\/\/\/\/\/\//
    // STATIC HELPER METHODS //
    //\/\/\/\/\/\/\/\/\/\/\/\//

    fn subtract_internal(minuend_digits: &mut [u8], subtrahend_digits: &[u8]) {
        // This is called with a subtrahend guaranteed to be smaller than the minuend, though they may have the same number of digits.
        // Calculate the number of overlapping digits. The minuend is guaranteed to have as many or more digits.
        let overlapping_digit_count = minuend_digits.len().min(subtrahend_digits.len());

        // If the minuend has more digits, those more significant digits can only be mutated via a carry. For the core subtraction loop, we only need
        // to worry about the overlapping digits, so we need to know at which offset in the minuend that overlap starts.
        let minuend_digit_offset = minuend_digits.len() - overlapping_digit_count;

        // Iterate over the overlapping digits from least to most significant.
        for i in (0..overlapping_digit_count).rev() {
            let minuend_digit_index = minuend_digit_offset + i;
            // Get the minuend and subtrahend for the current magnitude.
            let minuend = minuend_digits[minuend_digit_index];
            let subtrahend = subtrahend_digits[i];

            // Subtract the subtrahend from the minuend. This may wrap.
            minuend_digits[minuend_digit_index] = minuend.wrapping_sub(subtrahend);
            if minuend < subtrahend {
                // The subtrahend was larger than the minuend. This digit wrapped, so we need to subtract 1 from the first more-significant digit
                // whose value is non-zero, wrapping any intermediate zeroes.
                let mut j = minuend_digit_index - 1;
                loop {
                    if minuend_digits[j] == 0 {
                        // The next more significant digit is zero. We need to keep wrapping.
                        minuend_digits[j] = u8::MAX;
                        j -= 1;
                    } else {
                        // The next more significant digit is non-zero. We can subtract 1 and stop.
                        minuend_digits[j] -= 1;
                        break;
                    } // As we already guaranteed the minuend is greater than the subtrahend, j will never wrap.
                }
            }
        }
    }

    fn first_non_zero_digit_index(digits: &[u8]) -> Option<usize> {
        match digits.iter().enumerate().find(|(_, x)| **x != 0) {
            Some((i, _)) => Some(i),
            None => None,
        }
    }

    //\/\/\/\/\/\/\/\/\/\/\/\/\//
    // INSTANCE HELPER METHODS //
    //\/\/\/\/\/\/\/\/\/\/\/\/\//

    fn prepare_or_or_xor<'a>(
        &'a mut self,
        operator_digits: &'a [u8],
    ) -> Option<(&'a mut [u8], &'a [u8])> {
        let operator_digits = match Self::first_non_zero_digit_index(operator_digits) {
            Some(i) => &operator_digits[i..],
            None => {
                // The operator has no non-zero digits. This is a no-op as X | 0 = X, and X ^ 0 = X.
                return None;
            }
        };

        Some(if operator_digits.len() >= self.digits.len() {
            // The operator has a digit length greater than or equal to the operand's digit length.
            // Pre-pend the operand with the operator's leading digits as X | 0 = X, and X ^ 0 = X.
            let offset = operator_digits.len() - self.digits.len();
            self.digits
                .splice(0..0, operator_digits[..offset].iter().cloned());

            (&mut self.digits[offset..], &operator_digits[offset..])
        } else {
            // The operator has a digit length less than the operand's digit length. X | 0 = X, and X ^ 0 = X, so skip the operand's leading digits.
            let digit_count = self.digit_count();
            (
                &mut self.digits[digit_count - operator_digits.len()..],
                operator_digits,
            )
        })
    }

    fn handle_remainder_equals_divisor(
        &mut self,
        quotient_digit: u8,
        remainder_off: usize,
        remainder_len: usize,
        quotient_len: &mut usize,
    ) {
        // The remainder is equal to the divisor. Zero the remainder digits.
        self.digits[remainder_off..remainder_off + remainder_len].fill(0);
        self.append_quotient_digit(quotient_digit, quotient_len);
    }

    fn append_quotient_digit(&mut self, quotient_digit: u8, quotient_len: &mut usize) {
        // Add the digit to the end of the quotient.
        self.digits[*quotient_len] = quotient_digit;
        *quotient_len += 1;
    }

    fn trim_leading_zeroes(&mut self) {
        match Self::first_non_zero_digit_index(&self.digits) {
            // There are non-zero digits; remove any leading zeroes.
            Some(i) => {
                self.digits.drain(0..i);
            }
            // There are no non-zero digits.
            None => {
                if self.digits.len() != 1 {
                    // All of the digits are zero; if there's more than one digit, truncate.
                    self.digits.truncate(1);
                }
            }
        }
    }
}

fn cmp(left: &[u8], right: &[u8]) -> Ordering {
    // Compares two big-endian unsigned integers with no leading zero digits.
    match left.len().cmp(&right.len()) {
        // Left and right have the same number of digits. We need to look for any differing digits.
        Ordering::Equal => match left.iter().enumerate().find(|(i, d)| **d != right[*i]) {
            Some((i, left_digit)) => {
                // There is a differing digit; we just need to compare the first differing digit to get the comparison result.
                if *left_digit < right[i] {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            // There are no differing digits; left and right are equal.
            None => Ordering::Equal,
        },
        // Left has more digits than right; it's larger.
        Ordering::Greater => Ordering::Greater,
        // Left has fewer digits than right; it's smaller.
        Ordering::Less => Ordering::Less,
    }
}
