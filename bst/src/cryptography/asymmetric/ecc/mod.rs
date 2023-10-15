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

mod point;

pub use point::EccPoint;

use crate::{
    bits::{get_first_high_bit_index, try_get_bit_at_index},
    integers::{BigSigned, BigUnsigned, BigUnsignedModInverseCalculator},
};

pub struct EllipticCurvePointAdditionContext {
    mod_inverse_calculator: BigUnsignedModInverseCalculator,
    p: &'static BigUnsigned,
    a: &'static BigUnsigned,
    slope: BigSigned,
    augend: EccPoint,
}

impl EllipticCurvePointAdditionContext {
    pub fn from(p: &'static BigUnsigned, a: &'static BigUnsigned, integer_capacity: usize) -> Self {
        Self {
            mod_inverse_calculator: BigUnsignedModInverseCalculator::new(integer_capacity),
            slope: BigSigned::with_capacity(integer_capacity),
            augend: EccPoint::infinity(integer_capacity),
            p,
            a,
        }
    }

    pub fn slope(&self) -> &BigSigned {
        &self.slope
    }

    pub fn p(&self) -> &BigUnsigned {
        self.p
    }

    pub fn a(&self) -> &BigUnsigned {
        self.a
    }

    pub fn augend(&self) -> &EccPoint {
        &self.augend
    }

    pub fn store_augend(&mut self, augend: &EccPoint) {
        self.augend.set_equal_to(augend);
    }

    pub fn slope_mut(&mut self) -> &mut BigSigned {
        &mut self.slope
    }

    pub fn zero(&mut self) {
        self.augend.set_infinity();
        self.slope.zero();
    }

    pub fn mod_inverse(&mut self, value: &mut BigSigned) -> bool {
        let is_negative = value.is_negative();
        let success = self.mod_inverse_calculator.calculate_mod_inverse(
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
    working_point: EccPoint,
}

impl EllipticCurvePointMultiplicationContext {
    pub fn new(p: &'static BigUnsigned, a: &'static BigUnsigned, integer_capacity: usize) -> Self {
        Self {
            addition_context: EllipticCurvePointAdditionContext::from(p, a, integer_capacity),
            working_point: EccPoint::infinity(integer_capacity),
        }
    }

    pub fn multiply_point(
        &mut self,
        x: &BigUnsigned,
        y: &BigUnsigned,
        multiplier: &BigUnsigned,
    ) -> Option<EccPoint> {
        let multiplier_bytes = multiplier.borrow_digits();
        let multiplier_bit_count = multiplier.digit_count() * 8;
        let multiplier_bit_start = match get_first_high_bit_index(0, multiplier_bytes) {
            Some(start) => start,
            // There are no high bits in the multiplier; that means it's zero.
            // A multiplier of 0 just yields infinity; there's no point in constructing a new point for that.
            None => return None,
        };

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

        // Prepare a zero product (in an elliptic curve, 'infinity' is a neutral element where X + Infinity = X).
        let mut product = EccPoint::infinity(self.addition_context.p.digit_count());

        // Prepare our addend to equal the value we're multiplying.
        self.working_point.set_equal_to_unsigned(x, y);

        // Iterate over the bits in the multiplier from least to most significant.
        for i in (multiplier_bit_start..multiplier_bit_count).rev() {
            if try_get_bit_at_index(i, multiplier_bytes).unwrap() {
                // The bit at the current index is high; we should add.
                product.add(&self.working_point, &mut self.addition_context);
            }

            // We always double the addend before moving to the next bit.
            self.working_point.double(&mut self.addition_context);
        }

        self.zero();
        Some(product)
    }

    fn zero(&mut self) {
        self.addition_context.zero();
        self.working_point.set_infinity();
    }
}
