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

pub mod secp256k1;

mod point;

pub use point::{EllipticCurvePoint, COMPRESSED_Y_IS_EVEN_IDENTIFIER};

use crate::{
    bits::{try_get_bit_at_index, try_set_bit_at_index},
    global_runtime_immutable::GlobalRuntimeImmutable,
    integers::{BigSigned, BigUnsigned, BigUnsignedCalculator, Digit, BITS_PER_DIGIT},
};
use alloc::{boxed::Box, vec, vec::Vec};
use core::cmp::Ordering;

const PRIVATE_KEY_PREFIX: u8 = 0x00;

static mut CUBE: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| BigUnsigned::from_digits(&[3]));

pub struct EllipticCurvePointAdditionContext {
    unsigned_calculator: BigUnsignedCalculator,
    augend: EllipticCurvePoint,
    p: &'static BigUnsigned,
    a: &'static BigUnsigned,
    slope: BigSigned,
}

impl EllipticCurvePointAdditionContext {
    pub fn from(p: &'static BigUnsigned, a: &'static BigUnsigned, integer_capacity: usize) -> Self {
        Self {
            unsigned_calculator: BigUnsignedCalculator::new(integer_capacity),
            slope: BigSigned::with_capacity(integer_capacity),
            augend: EllipticCurvePoint::infinity(integer_capacity),
            p,
            a,
        }
    }

    pub fn store_augend(&mut self, augend: &EllipticCurvePoint) {
        self.augend.set_equal_to(augend);
    }

    pub fn zero(&mut self) {
        self.augend.set_infinity();
        self.slope.zero();
    }

    pub fn mod_inverse(&mut self, value: &mut BigSigned) -> bool {
        let is_negative = value.is_negative();
        let success = self.unsigned_calculator.calculate_mod_inverse(
            &mut value.borrow_unsigned_mut(),
            is_negative,
            self.p,
        );

        if success && is_negative {
            value.negate();
        }

        success
    }
}

pub struct EllipticCurvePointMultiplicationContext {
    addition_context: EllipticCurvePointAdditionContext,
    side_channel_mitigation_point: EllipticCurvePoint,
    comparison_box: Box<Option<Ordering>>,
    working_point: EllipticCurvePoint,
    i: &'static BigUnsigned,
    b: &'static BigUnsigned,
    n: &'static BigUnsigned,
    bit_buffer: Vec<Digit>,
}

impl EllipticCurvePointMultiplicationContext {
    pub fn new(
        n: &'static BigUnsigned,
        p: &'static BigUnsigned,
        i: &'static BigUnsigned,
        a: &'static BigUnsigned,
        b: &'static BigUnsigned,
        integer_capacity: usize,
    ) -> Self {
        if n.digit_count() == 0 {
            panic!("Zero-length N for Elliptic Curve Point Multiplication Context.");
        }

        Self {
            addition_context: EllipticCurvePointAdditionContext::from(p, a, integer_capacity),
            side_channel_mitigation_point: EllipticCurvePoint::infinity(integer_capacity),
            working_point: EllipticCurvePoint::infinity(integer_capacity),
            bit_buffer: vec![0; n.digit_count()],
            comparison_box: Box::from(None),
            i,
            b,
            n,
        }
    }

    pub fn multiply_point(
        &mut self,
        x: &BigUnsigned,
        y: &BigUnsigned,
        multiplier: &BigUnsigned,
    ) -> Option<EllipticCurvePoint> {
        // This method uses the double and add algorithm for multiplying a point by an integer.
        //
        // Multiplication is repeated additions:
        // X * 3 = X + X + X
        //
        // But in the case of ECC point multiplication, the multiplier could be absolutely massive,
        // and a simple for loop here could take a very, very long time.
        //
        // To achieve point multiplication, we can take advantage of binary.
        //
        // Consider that 'X * 151' can also be written as '(X * 100) + (X * 50) + (X * 1)'.
        // That's base-10. What we're actually doing is (X * 1 * 10^2) + (X * 5 * 10^1) + (X * 1 * 10^0).
        //
        // Written in binary, 151 is:
        // 10010111
        //
        // The equivalent multiplication in base-2 is:
        // (X * 1 * 2^7)
        //   + (X * 0 * 2^6)
        //   + (X * 0 * 2^5)
        //   + (X * 1 * 2^4)
        //   + (X * 0 * 2^3)
        //   + (X * 1 * 2^2)
        //   + (X * 1 * 2^1)
        //   + (X * 1 * 2^0)
        //
        // Which can be simplified, given 'X * 0 = 0', to:
        // (X * 1 * 2^7)
        //   + (X * 1 * 2^4)
        //   + (X * 1 * 2^2)
        //   + (X * 1 * 2^1)
        //   + (X * 1 * 2^0)
        //
        // To perform this (relatively) efficienctly, we track two values: the product, and the addend.
        // We start at the least significant bit, with an addend equal to our value; that's 'X * 1 * 2^0'.
        //
        // If the least significant bit is 1, we add the addend to our product; we add 'X * 1 * 2^0'
        // If the least significant bit is 0, we don't add the addend; we add 'X * 0 * 2^0', which is the same as adding nothing.
        //
        // Then we double our addend, which becomes 'X * 1 * 2^1', and repeat the process for all the bits.
        //
        // We always double the addend, but we only add it to our product where the bit is high,
        // which yields the product in ceil(log2(n)) iterations, rather than n iterations.
        //
        // That is to say that multiplication by, for example:
        // 42,399,223,942,308,432,984,098,502,903,482,309,425,270,475,893,475
        // Would take that many iterations of simple addition to multiply a point, but only 165 iterations of double and add:
        // log2(42,399,223,942,308,432,984,098,502,903,482,309,425,270,475,893,475) = 164.85...
        //
        // Given the above value written in binary is:
        // 11101000000101011111011110100111011101001010011100011111011000000100000110111100101
        // 0100010000011010011110000100101000111101001010101011011001111001101010101011100011
        // Which contains 165 bits, 84 of which are high, and 81 of which are low. To be exact, the double and add multiplication
        // algorithm would require only 165 double operations, and 84 addition operations, which is... a few fewer operations than
        // the number of addition operations required for the simple repeated addition algorithm.

        if multiplier.digit_count() > self.n.digit_count() {
            // The multiplier has more digits than N. It's definitely too large, and therefore is invalid, and we can't derive a public key.
            return None;
        }

        let multiplier_digits = multiplier.borrow_digits();

        // Constant-time zero check on the multiplier.
        let zero_check = multiplier_digits[multiplier_digits.len() - 1] as u16
            | if multiplier_digits.len() > 1 {
                0xFF00
            } else {
                0x0000
            };

        if zero_check == 0x0000 {
            // The multiplier is 0; it's invalid, and we can't derive a public key.
            return None;
        }

        // Constant-time comparison between the multiplier and N.
        let m_is_less_than_n = {
            let mut throwaway_comparison = Some(Ordering::Less);
            let mut first_differing_comparison = None;
            let n_digits = self.n.borrow_digits();

            // We have already guaranteed that M has as many or fewer digits than N.
            // If it has fewer, it is definitely smaller, so we will compare to a zeroed out buffer with length equal to N's length.
            // If it has the same number of digits, we will perform an actual comparison.
            let m_digits = if n_digits.len() > multiplier_digits.len() {
                &self.bit_buffer[..]
            } else {
                multiplier_digits
            };

            for i in 0..n_digits.len() {
                match m_digits[i].cmp(&n_digits[i]) {
                    Ordering::Greater => {
                        if first_differing_comparison == None {
                            first_differing_comparison = Some(Ordering::Greater);
                        } else {
                            throwaway_comparison = Some(Ordering::Greater);
                        }
                    }
                    Ordering::Equal => {
                        if first_differing_comparison == None {
                            throwaway_comparison = Some(Ordering::Greater);
                        } else {
                            throwaway_comparison = Some(Ordering::Less);
                        }
                    }
                    Ordering::Less => {
                        if first_differing_comparison == None {
                            first_differing_comparison = Some(Ordering::Less);
                        } else {
                            throwaway_comparison = Some(Ordering::Less);
                        }
                    }
                }
            }

            // Do something with the throwaway comparison to avoid it being optimized away.
            *self.comparison_box = throwaway_comparison;

            // M is less than N only if there was a differing digit, and the first differing digit was smaller.
            first_differing_comparison.is_some_and(|o| o == Ordering::Less)
        };

        if !m_is_less_than_n {
            // The multiplier is >= N; it's invalid, and we can't derive a public key.
            return None;
        }

        // Constant-time copy of the bits from the multiplier into our local bit buffer with a fixed length.
        for i in 0..self.bit_buffer.len() {
            let j = multiplier_digits
                .len()
                .wrapping_sub(self.bit_buffer.len() - i);

            let digit = if j >= multiplier_digits.len() {
                self.bit_buffer[i]
            } else {
                multiplier_digits[j]
            };

            for j in 0..BITS_PER_DIGIT {
                assert!(try_set_bit_at_index(
                    i * BITS_PER_DIGIT + j,
                    try_get_bit_at_index(j, &[digit]).unwrap(),
                    &mut self.bit_buffer
                ));
            }
        }

        // Prepare a zero product (in an elliptic curve, 'infinity' is a neutral element where X + Infinity = X).
        let mut product = EllipticCurvePoint::infinity(self.addition_context.p.digit_count());

        // Prepare our addend to equal the value we're multiplying.
        self.working_point.set_equal_to_unsigned(x, y);

        // Iterate over the bits in the multiplier from least to most significant.
        for i in (0..self.bit_buffer.len() * BITS_PER_DIGIT).rev() {
            if try_get_bit_at_index(i, &self.bit_buffer).unwrap() {
                // The bit at the current index is high; we should add to our product.
                product.add(&self.working_point, &mut self.addition_context);
            } else {
                // The bit at the current index is low; we should add to our throwaway value.
                // This results in the number of operations always being the same.
                self.side_channel_mitigation_point
                    .add(&self.working_point, &mut self.addition_context)
            }

            // We always double the addend before moving to the next bit.
            self.working_point.double(&mut self.addition_context);
        }

        // Zero out our working values; they could otherwise leak sensitive information.
        self.zero();

        // Return our product, which is guaranteed to be non-infinity.
        Some(product)
    }

    pub fn calculate_y_from_x(
        &mut self,
        y_is_even: bool,
        x: &BigUnsigned,
        y_out: &mut BigUnsigned,
    ) {
        // y_out = x
        y_out.set_equal_to(x);

        // y_out = x^3 mod p
        self.addition_context
            .unsigned_calculator
            .modpow(y_out, cube(), self.addition_context.p);

        if self.addition_context.a.is_non_zero() {
            // Borrow the addition context's slope buffer for a working value.
            let temp = self.addition_context.slope.borrow_unsigned_mut();

            // t = a
            temp.set_equal_to(self.addition_context.a);

            // t = a * x
            temp.multiply_big_unsigned(x);

            // t = a * x (mod p)
            temp.modulo_big_unsigned(self.addition_context.p);

            // y_out = (x^3 mod p) + ((a * x) mod p)
            y_out.add_big_unsigned(temp);

            // Zero out temp; we're done with it.
            temp.zero();

            // y_out = x^3 + ax (mod p)
            y_out.modulo_big_unsigned(self.addition_context.p);
        }

        if self.b.is_non_zero() {
            // y_out = (x^3 + ax (mod p)) + b
            y_out.add_big_unsigned(self.b);

            // y_out = x^3 + ax + b (mod p)
            y_out.modulo_big_unsigned(self.addition_context.p);
        }

        // sqrt shortcut for curve where p mod 3 = 1
        self.addition_context
            .unsigned_calculator
            .modpow(y_out, self.i, self.addition_context.p);

        if y_is_even != y_out.is_even() {
            // Y has two possible values given an X coordinate; if the calculated Y's evenness does not match
            // the desired evenness from the compressed coordinate flag, we just subtract it from P.
            // This is equivalent to calculating the difference, as P will always be larger.
            y_out.difference_big_unsigned(self.addition_context.p);
        }

        self.working_point.set_infinity();
    }

    pub fn borrow_addition_context(&mut self) -> &mut EllipticCurvePointAdditionContext {
        &mut self.addition_context
    }

    fn zero(&mut self) {
        self.bit_buffer.fill(0);
        *self.comparison_box = None;
        self.addition_context.zero();
        self.working_point.set_infinity();
        self.side_channel_mitigation_point.set_infinity();
    }
}

fn cube() -> &'static BigUnsigned {
    unsafe { CUBE.value() }
}
