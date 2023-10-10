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

#![allow(dead_code)]

use alloc::{boxed::Box, vec, vec::Vec};
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
        Self::cmp(&self.digits, &other.digits)
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

    fn from_vec(digits: Vec<u8>) -> Self {
        let mut value = Self { digits };
        value.trim_leading_zeroes();
        value
    }
}

impl BigSigned {
    fn from_unsigned(is_negative: bool, big_unsigned: BigUnsigned) -> Self {
        Self {
            is_negative: is_negative && big_unsigned.is_non_zero(),
            big_unsigned,
        }
    }

    pub fn from_be_bytes(is_negative: bool, be_bytes: &[u8]) -> Self {
        Self::from_unsigned(is_negative, BigUnsigned::from_be_bytes(be_bytes))
    }

    fn from_vec(is_negative: bool, digits: Vec<u8>) -> Self {
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

    pub fn is_odd(&self) -> bool {
        !self.is_even()
    }
}

impl BigSigned {
    pub fn extract_be_bytes(self) -> Vec<u8> {
        self.big_unsigned.extract_be_bytes()
    }

    pub fn copy_digits_to(&self, buffer: &mut [u8]) {
        self.big_unsigned.copy_digits_to(buffer)
    }

    pub fn clone_be_bytes(&self) -> Box<[u8]> {
        self.big_unsigned.clone_be_bytes()
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

    pub fn is_not_one(&self) -> bool {
        self.big_unsigned.is_not_one() || self.is_negative
    }

    pub fn is_one(&self) -> bool {
        !self.is_not_one()
    }

    pub fn is_not_negative_one(&self) -> bool {
        self.big_unsigned.is_not_one() || !self.is_negative
    }

    pub fn is_negative_one(&self) -> bool {
        !self.is_not_one()
    }

    pub fn is_negative(&self) -> bool {
        self.is_negative
    }

    pub fn is_positive(&self) -> bool {
        !self.is_negative
    }

    pub fn is_even(&self) -> bool {
        self.big_unsigned.is_even()
    }

    pub fn is_odd(&self) -> bool {
        !self.is_even()
    }
}

//\/\/\/\/\/\/\/\///
// Basic Mutation //
//\/\/\/\/\/\/\/\///

impl BigUnsigned {
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
    pub fn set_equal_to(&mut self, value: &Self) {
        self.big_unsigned.set_equal_to(&value.big_unsigned);
        self.is_negative = value.is_negative;
    }

    pub fn zero(&mut self) {
        self.is_negative = false;
        self.big_unsigned.zero();
    }

    pub fn one(&mut self) {
        self.is_negative = false;
        self.big_unsigned.one();
    }

    pub fn negative_one(&mut self) {
        self.is_negative = true;
        self.big_unsigned.one();
    }

    pub fn negate(&mut self) {
        self.is_negative = !self.is_negative;
    }
}

//\/\/\/\///
// Macros //
//\/\/\/\///

// TODO: Macros for division operations, and signed types.
macro_rules! simple_operation_implement_unsigned_types {
    ($($digits_name:ident: $byte_name:ident, $short_name:ident, $int_name:ident, $size_name:ident, $long_name:ident, $big_unsigned_name:ident,)*) => {
    $(
        pub fn $byte_name(&mut self, value: u8) {
            self.$digits_name(&[value])
        }

        pub fn $short_name(&mut self, value: u16) {
            self.$digits_name(&value.to_be_bytes())
        }

        pub fn $int_name(&mut self, value: u32) {
            self.$digits_name(&value.to_be_bytes())
        }

        pub fn $size_name(&mut self, value: usize) {
            self.$digits_name(&value.to_be_bytes())
        }

        pub fn $long_name(&mut self, value: u64) {
            self.$digits_name(&value.to_be_bytes())
        }

        pub fn $big_unsigned_name(&mut self, value: &BigUnsigned) {
            self.$digits_name(&value.digits)
        }
    )*
    }
}

//\/\/\/\/\/\/\/\/\/\///
// Logical Operations //
//\/\/\/\/\/\/\/\/\/\///

impl BigUnsigned {
    simple_operation_implement_unsigned_types!(
        and_be_bytes: and_byte, and_short, and_int, and_size, and_long, and_big_unsigned,
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
        xor_be_bytes: xor_byte, xor_short, xor_int, xor_size, xor_long, xor_big_unsigned,
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
        or_be_bytes: or_byte, or_short, or_int, or_size, or_long, or_big_unsigned,
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
        and_be_bytes_unsigned: and_byte, and_short, and_int, and_size, and_long, and_big_unsigned,
    );

    pub fn and_be_bytes_unsigned(&mut self, operator_digits: &[u8]) {
        self.and_be_bytes_signed(operator_digits, false)
    }

    pub fn and_be_bytes_signed(&mut self, _operator_digits: &[u8], _is_negative: bool) {
        todo!()
    }

    simple_operation_implement_unsigned_types!(
        xor_be_bytes_unsigned: xor_byte, xor_short, xor_int, xor_size, xor_long, xor_big_unsigned,
    );

    pub fn xor_be_bytes_unsigned(&mut self, operator_digits: &[u8]) {
        self.xor_be_bytes_signed(operator_digits, false)
    }

    pub fn xor_be_bytes_signed(&mut self, _operator_digits: &[u8], _is_negative: bool) {
        todo!()
    }

    simple_operation_implement_unsigned_types!(
        or_be_bytes_unsigned: or_byte, or_short, or_int, or_size, or_long, or_big_unsigned,
    );

    pub fn or_be_bytes_unsigned(&mut self, operator_digits: &[u8]) {
        self.or_be_bytes_signed(operator_digits, false)
    }

    pub fn or_be_bytes_signed(&mut self, _operator_digits: &[u8], _is_negative: bool) {
        todo!()
    }
}

//\/\/\/\/\/\///
// Arithmetic //
//\/\/\/\/\/\///

impl BigUnsigned {
    simple_operation_implement_unsigned_types!(
        add_be_bytes: add_byte, add_short, add_int, add_size, add_long, add_big_unsigned,
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
        subtract_be_bytes: subtract_byte, subtract_short, subtract_int, subtract_size, subtract_long, subtract_big_unsigned,
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

        match Self::cmp(&self.digits, subtrahend_digits) {
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
        difference_be_bytes: difference_byte, difference_short, difference_int, difference_size, difference_long, difference_big_unsigned,
    );

    pub fn difference_be_bytes(&mut self, operator_digits: &[u8]) {
        let operator_digits = match Self::first_non_zero_digit_index(operator_digits) {
            // The operator is non-zero; trim any leading zero digits.
            Some(i) => &operator_digits[i..],
            // The operator is zero; the operand is already the difference, and we can just return.
            None => return,
        };

        // Compare the operand and operator.
        match Self::cmp(&self.digits, operator_digits) {
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
        multiply_be_bytes: multiply_byte, multiply_short, multiply_int, multiply_size, multiply_long, multiply_big_unsigned,
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

    pub fn divide_byte(&mut self, value: u8) -> Option<u8> {
        if value == 0 {
            // The divisor is zero; we can't divide by zero, so return None.
            return None;
        }

        if value == 1 {
            // The divisor is one; X / 1 = X r0, so we can just return a remainder of zero.
            return Some(0);
        }

        if self.is_zero() {
            // The dividend is zero; 0 / X = 0 r0, so we can just return a remainder of zero.
            return Some(0);
        }

        // Track the remainder in a bigger integer format.
        let mut remainder = 0u32;

        // Iterate over the digits in the dividend from most to least significant.
        for i in 0..self.digits.len() {
            // Any previous remainder becomes the more significant digit. The current digit is the less significant digit.
            let dividend = (remainder << 8) | (self.digits[i] as u32);

            // The less significant digit of this round of division's quotient is our new digit for this index.
            self.digits[i] = (dividend / (value as u32)) as u8;

            // The remainder carries down into the next digit; 169 / 3 = 100 / 3 + 60 / 3 + 9 / 3
            remainder = dividend % (value as u32);
        }

        self.trim_leading_zeroes();
        Some(remainder as u8)
    }

    pub fn divide_short(&mut self, value: u16) -> Option<u16> {
        let mut remainder_buffer = [0u8; 2];
        match self.divide_be_bytes(&value.to_be_bytes(), &mut remainder_buffer) {
            true => Some(u16::from_be_bytes(remainder_buffer)),
            false => None,
        }
    }

    pub fn divide_int(&mut self, value: u32) -> Option<u32> {
        let mut remainder_buffer = [0u8; 4];
        match self.divide_be_bytes(&value.to_be_bytes(), &mut remainder_buffer) {
            true => Some(u32::from_be_bytes(remainder_buffer)),
            false => None,
        }
    }

    pub fn divide_size(&mut self, value: usize) -> Option<usize> {
        let mut remainder_buffer = [0u8; size_of::<usize>()];
        match self.divide_be_bytes(&value.to_be_bytes(), &mut remainder_buffer) {
            true => Some(usize::from_be_bytes(remainder_buffer)),
            false => None,
        }
    }

    pub fn divide_long(&mut self, value: u64) -> Option<u64> {
        let mut remainder_buffer = [0u8; 8];
        match self.divide_be_bytes(&value.to_be_bytes(), &mut remainder_buffer) {
            true => Some(u64::from_be_bytes(remainder_buffer)),
            false => None,
        }
    }

    pub fn divide_big_unsigned(&mut self, value: &Self) -> Option<BigUnsigned> {
        let mut remainder_buffer = vec![0u8; value.digit_count()];
        match self.divide_be_bytes(&value.digits, &mut remainder_buffer) {
            true => Some(BigUnsigned::from_vec(remainder_buffer)),
            false => None,
        }
    }

    pub fn divide_big_unsigned_with_remainder_buffer(
        &mut self,
        value: &Self,
        remainder_buffer: &mut Self,
    ) -> bool {
        // Grow the remainder buffer's internal digits to be able to use it as a buffer safely.
        if value.digits.len() > remainder_buffer.digits.len() {
            remainder_buffer.digits.splice(
                0..0,
                (0..value.digits.len() - remainder_buffer.digits.len())
                    .into_iter()
                    .map(|_| 0),
            );
        }

        // Perform the division.
        let result = self.divide_be_bytes(&value.digits, &mut remainder_buffer.digits);
        // Trim any leading zeroes from the remainder buffer.
        remainder_buffer.trim_leading_zeroes();
        return result;
    }

    pub fn divide_be_bytes(&mut self, divisor_digits: &[u8], remainder_buffer: &mut [u8]) -> bool {
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
            let remainder = self.divide_byte(divisor_digits[0]);

            // This is guaranteed to succeed as we already checked the divisor is non-zero.
            // Write the remainder to the remainder buffer, and return true.
            remainder_digits[0] = remainder.unwrap();
            return true;
        }

        if self.is_zero() {
            // The dividend is zero; 0 / X = 0 r0, and we already zeroed out the remainder buffer, so we can just return.
            return true;
        }

        match Self::cmp(&self.digits, divisor_digits) {
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
                                match Self::cmp(remainder, divisor_digits) {
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
                    match Self::cmp(&remainder, divisor_digits) {
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
                                match Self::cmp(&remainder, divisor_digits) {
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
        add_be_bytes_unsigned: add_byte, add_short, add_int, add_size, add_long, add_big_unsigned,
    );

    pub fn add_be_bytes_unsigned(&mut self, addend_digits: &[u8]) {
        self.add_be_bytes_signed(addend_digits, false)
    }

    pub fn add_be_bytes_signed(&mut self, _addend_digits: &[u8], _is_negative: bool) {
        todo!()
    }

    simple_operation_implement_unsigned_types!(
        subtract_be_bytes_unsigned: subtract_byte, subtract_short, subtract_int, subtract_size, subtract_long, subtract_big_unsigned,
    );

    pub fn subtract_be_bytes_unsigned(&mut self, subtrahend_digits: &[u8]) {
        self.subtract_be_bytes_signed(subtrahend_digits, false)
    }

    pub fn subtract_be_bytes_signed(&mut self, _subtrahend_digits: &[u8], _is_negative: bool) {
        todo!()
    }

    simple_operation_implement_unsigned_types!(
        difference_be_bytes_unsigned: difference_byte, difference_short, difference_int, difference_size, difference_long, difference_big_unsigned,
    );

    pub fn difference_be_bytes_unsigned(&mut self, operator_digits: &[u8]) {
        self.difference_be_bytes_signed(operator_digits, false)
    }

    pub fn difference_be_bytes_signed(&mut self, _operator_digits: &[u8], _is_negative: bool) {
        todo!()
    }

    simple_operation_implement_unsigned_types!(
        multiply_be_bytes_unsigned: multiply_byte, multiply_short, multiply_int, multiply_size, multiply_long, multiply_big_unsigned,
    );

    pub fn multiply_be_bytes_unsigned(&mut self, multiplier_digits: &[u8]) {
        self.multiply_be_bytes_signed(multiplier_digits, false)
    }

    pub fn multiply_be_bytes_signed(&mut self, _multiplier_digits: &[u8], _is_negative: bool) {
        todo!()
    }

    // TODO: Division
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
