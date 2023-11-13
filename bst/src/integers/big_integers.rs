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

use alloc::{vec, vec::Vec};
use core::{cmp::Ordering, mem::size_of};

pub const DIGIT_SHIFT: usize = size_of::<Digit>() * 8;
pub type Digit = u8;

type Carry = u16;

#[derive(Debug, Clone, Eq)]
pub struct BigUnsigned {
    // We store digits in big-endian format, in base-2^64.
    digits: Vec<Digit>,
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

impl PartialEq<[Digit]> for BigUnsigned {
    fn eq(&self, other: &[Digit]) -> bool {
        cmp(&self.digits, other) == Ordering::Equal
    }
}

impl PartialOrd<[Digit]> for BigUnsigned {
    fn partial_cmp(&self, other: &[Digit]) -> Option<Ordering> {
        Some(cmp(&self.digits, other))
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
        // Calculate the number of required digits, and trim leading zeroes from the input bytes.
        let (digit_count, be_bytes) = Self::calculate_required_digits_for_bytes(be_bytes);

        // Prepare a buffer for the digits.
        let mut digits = vec![0; digit_count];

        // Copy in the bytes.
        Self::copy_bytes_to_digit_buffer(&mut digits, be_bytes);
        Self { digits }
    }

    pub fn from_digits(digits: &[Digit]) -> Self {
        Self {
            digits: match Self::first_non_zero_digit_index(digits) {
                // Trim any leading zero digits.
                Some(i) => Vec::from(&digits[i..]),
                // There are no non-zero digits. Initialize with a single zero digit.
                None => Vec::from([0]),
            },
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut digits = Vec::with_capacity(capacity);
        // We always need at least one digit; initialize as zero.
        digits.push(0);
        Self { digits }
    }

    pub fn from_vec(digits: Vec<Digit>) -> Self {
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

    pub fn with_capacity(capacity: usize) -> Self {
        Self::from_unsigned(false, BigUnsigned::with_capacity(capacity))
    }
}

//\/\/\/\/\/\/\/\//
// Introspection //
//\/\/\/\/\/\/\/\//

impl BigUnsigned {
    pub fn copy_be_bytes_to(&self, buffer: &mut [u8]) {
        let byte_count = self.byte_count();
        if buffer.len() < byte_count {
            panic!("Tried to copy big-endian bytes out of a BigUnsigned to a buffer whose length was too short.");
        }

        // Zero out the buffer.
        buffer.fill(0);

        // Trim any leading bytes from the output buffer.
        let original_buffer_length = buffer.len();
        let buffer = &mut buffer[original_buffer_length - byte_count..];

        // Track the buffer index and digit indexes separately.
        let mut buffer_index = 0;
        let mut digit_index = 0;

        let partial_digit_bytes = byte_count % size_of::<Digit>();
        if partial_digit_bytes != 0 {
            // The first digit has leading zero bytes; write that first.
            let first_digit_bytes = self.digits[0].to_be_bytes();
            for i in size_of::<Digit>() - partial_digit_bytes..size_of::<Digit>() {
                buffer[buffer_index] = first_digit_bytes[i];
                buffer_index += 1;
            }

            digit_index += 1;
        }

        // Write all whole digits to the buffer.
        while digit_index < self.digits.len() {
            let digit_bytes = self.digits[digit_index].to_be_bytes();
            for i in 0..digit_bytes.len() {
                buffer[buffer_index] = digit_bytes[i];
                buffer_index += 1;
            }

            digit_index += 1;
        }
    }

    pub fn borrow_digits(&self) -> &[Digit] {
        &self.digits
    }

    pub fn digit_count(&self) -> usize {
        self.digits.len()
    }

    pub fn byte_count(&self) -> usize {
        ((self.digits.len() * size_of::<Digit>())
            - (match Self::first_non_zero_byte_index(&self.digits[0].to_be_bytes()) {
                Some(i) => i,
                None => size_of::<Digit>(),
            }))
        .max(1)
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
}

impl BigSigned {
    pub fn borrow_unsigned_mut(&mut self) -> &mut BigUnsigned {
        &mut self.big_unsigned
    }

    pub fn copy_be_bytes_to(&self, buffer: &mut [u8]) {
        self.big_unsigned.copy_be_bytes_to(buffer)
    }

    pub fn borrow_unsigned(&self) -> &BigUnsigned {
        &self.big_unsigned
    }

    pub fn byte_count(&self) -> usize {
        self.big_unsigned.byte_count()
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

    pub fn is_even(&self) -> bool {
        self.big_unsigned.is_even()
    }
}

//\/\/\/\/\/\/\/\///
// Basic Mutation //
//\/\/\/\/\/\/\/\///

impl BigUnsigned {
    pub fn copy_be_bytes_from(&mut self, be_bytes: &[u8]) {
        // Calculate the number of required digits, and trim leading zeroes from the input bytes.
        let (digit_count, be_bytes) = Self::calculate_required_digits_for_bytes(be_bytes);

        // Zero existing digits.
        self.digits.fill(0);

        // Match the internal digit buffer to the required digit length.
        if self.digits.len() < digit_count {
            self.digits
                .extend((0..digit_count - self.digits.len()).into_iter().map(|_| 0));
        } else {
            self.digits.truncate(digit_count);
        }

        // Copy in the bytes.
        Self::copy_bytes_to_digit_buffer(&mut self.digits, be_bytes)
    }

    pub fn copy_digits_from(&mut self, digits: &[Digit]) {
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
    pub fn copy_be_bytes_from(&mut self, be_bytes: &[u8], is_negative: bool) {
        self.big_unsigned.copy_be_bytes_from(be_bytes);
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

//\/\/\/\/\/\///
// Arithmetic //
//\/\/\/\/\/\///

impl BigUnsigned {
    pub fn add_big_unsigned(&mut self, addend: &BigUnsigned) {
        self.add(&addend.digits)
    }

    pub fn add(&mut self, addend_digits: &[Digit]) {
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

        let mut carry: Carry = 0;
        // Iterate over the overlapping digits, from least to most significant.
        for i in 1..(min_len + 1) {
            let augend_index = self.digits.len() - i;
            let augend = self.digits[augend_index] as Carry;
            let addend = addend_digits[addend_digits.len() - i] as Carry;

            // Sum the digit in this position from the augend and addend with any existing carry.
            let sum = augend + addend + carry;

            // Set the digit in the current position.
            self.digits[augend_index] = sum as Digit;

            // Carry over any overflow for the next iteration.
            carry = sum >> DIGIT_SHIFT;
        }

        if self_is_smaller {
            // We need to add digits (and any remaining carry) to the start of our augend.
            for i in (0..addend_digits.len() - min_len).rev() {
                let sum = carry + (addend_digits[i] as Carry);
                self.digits.insert(0, sum as Digit);
                carry = sum >> DIGIT_SHIFT;
            }
        } else {
            // We need to add any remaining carry to the leading digits of of our augend.
            for i in (0..self.digits.len() - min_len).rev() {
                let sum = carry + (self.digits[i] as Carry);
                self.digits[i] = sum as Digit;
                carry = sum >> DIGIT_SHIFT;
            }
        }

        // Add any remaining carry to our augend.
        while carry > 0 {
            self.digits.insert(0, carry as Digit);
            carry >>= DIGIT_SHIFT;
        } // Adding can't result in leading zeroes where there were none, so there's no need to trim.
    }

    pub fn subtract_big_unsigned(&mut self, subtrahend: &BigUnsigned) {
        self.subtract(&subtrahend.digits)
    }

    pub fn subtract(&mut self, subtrahend_digits: &[Digit]) {
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

    pub fn difference_big_unsigned(&mut self, operator: &BigUnsigned) {
        self.difference(&operator.digits)
    }

    pub fn difference(&mut self, operator_digits: &[Digit]) {
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
                                    self.digits[j] = Digit::MAX;
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

    pub fn multiply_big_unsigned(&mut self, multiplier: &BigUnsigned) {
        self.multiply(&multiplier.digits)
    }

    pub fn multiply(&mut self, multiplier_digits: &[Digit]) {
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
            let multiplicand = self.digits[multiplicand_index] as Carry;

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
                let mut value_at_magnitude = multiplicand * (multiplier_digits[j] as Carry);
                loop {
                    // We can't discard any existing digit at magnitude K.
                    value_at_magnitude += self.digits[k] as Carry;

                    // K becomes the least-significant digit of our calculated value ending at this digit.
                    self.digits[k] = value_at_magnitude as Digit;

                    // Discard the least significant digit.
                    value_at_magnitude >>= DIGIT_SHIFT;
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

    pub fn divide_by_single_digit_with_remainder(
        &mut self,
        divisor: Digit,
        remainder_buffer: &mut Digit,
    ) -> bool {
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
        let mut remainder: Carry = 0;
        // Iterate over the digits in the dividend from most to least significant.
        for i in 0..self.digits.len() {
            // Any previous remainder becomes the more significant digit. The current digit is the less significant digit.
            let dividend = (remainder << DIGIT_SHIFT) | (self.digits[i] as Carry);

            // The less significant digit of this round of division's quotient is our new digit for this index.
            self.digits[i] = (dividend / (divisor as Carry)) as Digit;

            // The remainder carries down into the next digit; 169 / 3 = 100 / 3 + 60 / 3 + 9 / 3
            remainder = dividend % (divisor as Carry);
        }

        self.trim_leading_zeroes();
        *remainder_buffer = remainder as Digit;
        return true;
    }

    pub fn divide_big_unsigned_with_remainder(
        &mut self,
        divisor: &BigUnsigned,
        remainder_buffer: &mut BigUnsigned,
    ) -> bool {
        remainder_buffer.zero();
        remainder_buffer
            .digits
            .extend((0..divisor.digit_count() - 1).into_iter().map(|_| 0));

        match self.divide_with_remainder(&divisor.digits, &mut remainder_buffer.digits) {
            true => {
                remainder_buffer.trim_leading_zeroes();
                true
            }
            false => false,
        }
    }

    pub fn divide_with_remainder(
        &mut self,
        divisor_digits: &[Digit],
        remainder_buffer: &mut [Digit],
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

        if self.is_zero() {
            // The dividend is zero; 0 / X = 0 r0, and we already zeroed out the remainder buffer, so we can just return.
            return true;
        }

        // Get a window into the remainder buffer which can be written to without worrying about leading zero digits.
        let remainder_buffer_length = remainder_buffer.len();
        let remainder_digits =
            &mut remainder_buffer[remainder_buffer_length - divisor_digits.len()..];
        let remainder_digit_count = remainder_digits.len();

        if divisor_digits.len() == 1 {
            // The divisor has a single digit; we can use the simple division algorithm.
            let mut remainder: Digit = 0;
            assert!(self.divide_by_single_digit_with_remainder(divisor_digits[0], &mut remainder));

            // This is guaranteed to succeed as we already checked the divisor is non-zero.
            // Write the remainder to the remainder buffer, and return true.
            remainder_digits[0] = remainder;
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
                self.one();
            }
            Ordering::Greater => {
                // The internal divide method returns two values; the number of digits in the quotient, and the start
                // offset for the remainder's digits. This resutls in two values:
                // q = digits[..quotient_length]
                // r = digits[remainder_start..]

                let (quotient_length, remainder_start) = self.internal_divide(divisor_digits);

                // Copy out the remainder digits.
                let remainder = &self.digits[remainder_start..];
                remainder_digits[remainder_digit_count - remainder.len()..]
                    .copy_from_slice(&remainder);

                // Truncate the dividend to yield the quotient.
                self.digits.truncate(quotient_length);

                // Trim any leading zeroes (and ensure there's at least one digit).
                self.trim_leading_zeroes();
            }
        }

        true
    }

    pub fn modulo_big_unsigned(&mut self, modulus: &BigUnsigned) -> bool {
        self.modulo(&modulus.digits)
    }

    pub fn modulo(&mut self, modulus_digits: &[Digit]) -> bool {
        let divisor_digits = match Self::first_non_zero_digit_index(modulus_digits) {
            // Skip any leading zero digits in the divisor.
            Some(i) => &modulus_digits[i..],
            // The divisor is zero; we can't divide by zero, so return false.
            None => return false,
        };

        if self.is_zero() {
            // The dividend is zero; 0 % X = 0, so we can just return.
            return true;
        }

        if modulus_digits.len() == 1 {
            // The divisor has a single digit; we can use the simple division algorithm.
            let mut remainder: Digit = 0;
            assert!(self.divide_by_single_digit_with_remainder(divisor_digits[0], &mut remainder));

            // Overwrite the quotient with the remainder.
            self.copy_digits_from(&[remainder]);
            return true;
        }

        match cmp(&self.digits, divisor_digits) {
            Ordering::Less => {
                // The dividend is less than the divisor. Where X < Y, X / Y = 0, and X % Y = X.
                // We don't need to do anything.
            }
            Ordering::Equal => {
                // The dividend is equal to the divisor. Where X == Y, X / Y = 1, and X % Y = 0.
                // We can just zero out the divisor.
                self.zero()
            }
            Ordering::Greater => {
                // The internal divide method returns two values; the number of digits in the quotient, and the start
                // offset for the remainder's digits. This resutls in two values:
                // q = digits[..quotient_length]
                // r = digits[remainder_start..]
                // We only want the remainder.

                let (_, remainder_start) = self.internal_divide(divisor_digits);

                // Truncate the quotient from the divisor.
                self.digits.drain(0..remainder_start);

                // Trim any leading zeroes (and ensure there's at least one digit).
                self.trim_leading_zeroes();
            }
        }

        true
    }
}

impl BigSigned {
    pub fn add_big_unsigned(&mut self, addend: &BigUnsigned) {
        self.add_unsigned(&addend.digits)
    }

    pub fn add_unsigned(&mut self, addend_digits: &[Digit]) {
        self.add_signed(addend_digits, false)
    }

    pub fn add_signed(&mut self, addend_digits: &[Digit], is_negative: bool) {
        if is_negative == self.is_negative {
            // Sign is the same; we're moving away from zero, and can just perform an unsigned add.
            self.big_unsigned.add(addend_digits)
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

            self.big_unsigned.difference(addend_digits)
        }
    }

    pub fn subtract_big_signed(&mut self, subtrahend: &BigSigned) {
        self.subtract_signed(&subtrahend.big_unsigned.digits, subtrahend.is_negative)
    }

    pub fn subtract_signed(&mut self, subtrahend_digits: &[Digit], is_negative: bool) {
        // Subtracting a negative is addition, and adding a negative is subtraction. We can invert the subtrahend's sign and add it.
        self.add_signed(subtrahend_digits, !is_negative)
    }

    pub fn difference_big_unsigned(&mut self, operator: &BigUnsigned) {
        self.difference_unsigned(&operator.digits)
    }

    pub fn difference_unsigned(&mut self, operator_digits: &[Digit]) {
        self.difference_signed(operator_digits, false)
    }

    pub fn difference_signed(&mut self, operator_digits: &[Digit], is_negative: bool) {
        if self.is_negative == is_negative {
            // If the values have the same sign, the difference is the unsigned difference.
            self.big_unsigned.difference(operator_digits)
        } else {
            // If the values have a different sign, the difference is the sum of the unsigned values.
            self.big_unsigned.add(operator_digits)
        }

        // Differences are an absolute value.
        self.is_negative = false;
    }

    pub fn multiply_unsigned(&mut self, multiplier_digits: &[Digit]) {
        self.multiply_signed(multiplier_digits, false)
    }

    pub fn multiply_big_signed(&mut self, multiplier: &BigSigned) {
        self.multiply_signed(&multiplier.big_unsigned.digits, multiplier.is_negative)
    }

    pub fn multiply_signed(&mut self, multiplier_digits: &[Digit], is_negative: bool) {
        // The unsigned value will always just be the product.
        self.big_unsigned.multiply(multiplier_digits);

        // A negative multiplied by a negative is positive, and a positive multiplied by a positive is negative.
        // A negative multiplied by a positive is negative, unless the positive value is zero, in which case, the product is zero.
        self.is_negative = self.is_negative != is_negative && !self.is_zero()
    }

    pub fn divide_big_unsigned_with_remainder(
        &mut self,
        divisor: &BigUnsigned,
        remainder_buffer: &mut BigUnsigned,
        remainder_is_negative: &mut bool,
    ) -> bool {
        if self
            .big_unsigned
            .divide_big_unsigned_with_remainder(divisor, remainder_buffer)
        {
            *remainder_is_negative = self.is_negative;
            self.is_negative = self.is_negative && !self.is_zero();
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
                    modulus_buffer.difference_big_unsigned(divisor);
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

    fn calculate_required_digits_for_bytes(be_bytes: &[u8]) -> (usize, &[u8]) {
        if be_bytes.len() == 0 {
            return (1, be_bytes);
        }

        // Trim any leading zeroes.
        let first_non_zero_byte_index = match Self::first_non_zero_byte_index(be_bytes) {
            Some(i) => i,
            None => return (1, &be_bytes[be_bytes.len()..]),
        };

        // Calculate the number of digits we need.
        let byte_count = be_bytes.len() - first_non_zero_byte_index;
        let mut digit_count = byte_count / size_of::<Digit>();
        if digit_count * size_of::<Digit>() < byte_count {
            digit_count += 1;
        }

        return (digit_count, &be_bytes[first_non_zero_byte_index..]);
    }

    fn copy_bytes_to_digit_buffer(digits: &mut [Digit], be_bytes: &[u8]) {
        // Iterate over the bytes from least to most significant and write into the digit buffer.
        let mut current_byte_index = 0;
        let mut current_digit_index = digits.len() - 1;
        for i in (0..be_bytes.len()).rev() {
            // Write the current byte to the correct spot in the digit buffer.
            digits[current_digit_index] |= (be_bytes[i] as Digit) << (current_byte_index * 8);

            // Increment the current byte index.
            current_byte_index += 1;
            if current_byte_index == size_of::<Digit>() && i != 0 {
                // If we've written a whole digit, move to the next digit and reset the byte index.
                current_digit_index -= 1;
                current_byte_index = 0;
            }
        }
    }

    fn subtract_internal(minuend_digits: &mut [Digit], subtrahend_digits: &[Digit]) {
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
                        minuend_digits[j] = Digit::MAX;
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

    fn first_non_zero_digit_index(digits: &[Digit]) -> Option<usize> {
        match digits.iter().enumerate().find(|(_, x)| **x != 0) {
            Some((i, _)) => Some(i),
            None => None,
        }
    }

    fn first_non_zero_byte_index(be_bytes: &[u8]) -> Option<usize> {
        match be_bytes.iter().enumerate().find(|(_, x)| **x != 0) {
            Some((i, _)) => Some(i),
            None => None,
        }
    }

    //\/\/\/\/\/\/\/\/\/\/\/\/\//
    // INSTANCE HELPER METHODS //
    //\/\/\/\/\/\/\/\/\/\/\/\/\//
    fn handle_remainder_equals_divisor(
        &mut self,
        quotient_digit: Digit,
        remainder_off: usize,
        remainder_len: usize,
        quotient_len: &mut usize,
    ) {
        // The remainder is equal to the divisor. Zero the remainder digits.
        self.digits[remainder_off..remainder_off + remainder_len].fill(0);
        self.append_quotient_digit(quotient_digit, quotient_len);
    }

    fn append_quotient_digit(&mut self, quotient_digit: Digit, quotient_len: &mut usize) {
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
                match self.digits.len().cmp(&1) {
                    Ordering::Less => {
                        // There are no digits; we should add a zero.
                        self.digits.push(0);
                    }
                    Ordering::Equal => {
                        // There is only a single digit; we don't need to do anything.
                    }
                    Ordering::Greater => {
                        // Tere are no non-zero digits; we should have exactly one digit.
                        self.digits.truncate(1);
                    }
                }
            }
        }
    }

    fn internal_divide(&mut self, divisor_digits: &[Digit]) -> (usize, usize) {
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
                                return (quotient_len, remainder_off + i);
                            }
                            Ordering::Equal => {
                                // The remainder's digits are equal to the divisor.
                                self.append_quotient_digit(1, &mut quotient_len);
                                // The remainder should be zero, and can just be truncated away. Break to extract the quotient.
                                return (quotient_len, self.digits.len());
                            }
                            // There is more division to perform; pass the working remainder digits out.
                            Ordering::Greater => remainder,
                        }
                    }
                    None => {
                        // There are no non-zero digits remaining in the working remainder. The remainder is zero.
                        // Return the quotient length.
                        return (quotient_len, self.digits.len());
                    }
                }
            } else {
                // We're still within the bounds of the dividend. Extract the working remainder digits.
                let remainder = &mut self.digits[remainder_off..remainder_off + remainder_len];
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
                    let mut subtraction_counter: Digit = 0;
                    loop {
                        // Subtract the divisor from the working remainder.
                        Self::subtract_internal(remainder, divisor_digits);
                        subtraction_counter += 1;

                        // Trim any new leading zero digits.
                        let offset = Self::first_non_zero_digit_index(&remainder).unwrap();
                        remainder_off += offset;
                        remainder_len -= offset;
                        remainder = &mut self.digits[remainder_off..remainder_off + remainder_len];

                        // Compare the new working remainder to the divisor post-subtraction.
                        match cmp(&remainder, divisor_digits) {
                            Ordering::Less => {
                                // The working remainder is smaller than the divisor. Carry the remainder over into the next
                                // iteration of the main loop, expanding to include the next digit.
                                remainder_len += 1;

                                self.append_quotient_digit(subtraction_counter, &mut quotient_len);

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
    }
}

fn cmp(left: &[Digit], right: &[Digit]) -> Ordering {
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
