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

use super::{BigUnsigned, BITS_PER_DIGIT};
use crate::bits::{first_high_bit_index, try_get_bit_at_index};

pub struct BigUnsignedCalculator {
    a: BigUnsigned,
    m: BigUnsigned,
    x: BigUnsigned,
    y: BigUnsigned,
    q: BigUnsigned,
    r: BigUnsigned,
}

impl BigUnsignedCalculator {
    pub fn new(integer_byte_capacity: usize) -> Self {
        Self {
            a: BigUnsigned::with_byte_capacity(integer_byte_capacity),
            m: BigUnsigned::with_byte_capacity(integer_byte_capacity),
            x: BigUnsigned::with_byte_capacity(integer_byte_capacity),
            y: BigUnsigned::with_byte_capacity(integer_byte_capacity),
            q: BigUnsigned::with_byte_capacity(integer_byte_capacity),
            r: BigUnsigned::with_byte_capacity(integer_byte_capacity),
        }
    }

    pub fn calculate_mod_inverse(
        &mut self,
        value: &mut BigUnsigned,
        value_is_negative: bool,
        modulus: &BigUnsigned,
    ) -> bool {
        if modulus.is_zero() {
            return false;
        }

        if modulus.is_one() {
            value.zero();
            return true;
        }

        let mut x_negative = false;
        let mut y_negative = false;
        self.m.set_equal_to(modulus);
        self.a.set_equal_to(value);
        self.q.zero();
        self.r.zero();
        self.y.zero();
        self.x.one();

        // While a > 1
        while self.m.is_non_zero() {
            // We need a / m and a % m. a / m will live in q, and a % m will live in r.
            self.q.set_equal_to(&self.a);

            // Perform a / m. q is now a / m, and r is a % m.
            assert!(self
                .q
                .divide_big_unsigned_with_remainder(&self.m, &mut self.r));

            // Set a = m, and m = a % m.
            self.a.set_equal_to(&self.m);
            self.m.set_equal_to(&self.r);
            // a % m, currently stored in r, is no longer needed.

            // Store x's current value, as we'll be setting y = x - q * y, and we're about to mutate x.
            self.r.set_equal_to(&self.x);
            let old_x_negative = x_negative;

            // Set x to y's old value.
            self.x.set_equal_to(&self.y);
            x_negative = y_negative;

            // q is (a / m). We will need (a / m) * y, so multiply it.
            self.q.multiply_big_unsigned(&self.y);

            // r stored x's previous value. Set y to r.
            self.y.set_equal_to(&self.r);

            // Final step of setting y = x - ((a / m) * y).
            // y is currently set to x, and q is set to ((a / m) * y).
            // y's current value has the sign old_x_negative.
            // q's current value has the sign y_negative, because it's a multiple of y's old value.
            // The final step is to perform:
            // y -= q
            if old_x_negative == y_negative {
                y_negative = if old_x_negative {
                    // Both values are negative
                    // If q is less than y:                y will remain negative.
                    // If q is greater than or equal to y: y will become positive.
                    self.q < self.y
                } else {
                    // Both values are positive:
                    // If q is greater than y:          y will become negative.
                    // If q is less than or equal to y: y will remain positive.
                    self.q > self.y
                };

                // abs(x - y) == abs(y - x). abs(x - y) == diff(x, y), so we can set y to its difference from q.
                self.y.difference_big_unsigned(&self.q);
            } else {
                y_negative = if old_x_negative {
                    // y's current value is negative, and q is positive. We're subtracting a positive number from a negative number.
                    // The result will get more negative.
                    true
                } else {
                    // y's current value is positive, and q is negative. We're subtracting a negative number from a positive number.
                    // Subtraction with a negative subtrahend is the same as addition of abs(subtrahend). The number will get more positive.
                    false
                };

                // We've already handled the sign; either way, we just need to add q.
                self.y.add_big_unsigned(&self.q);
            }
        }

        if self.a.is_one() {
            // The value and the modulus were coprime, and have a mod inverse value.
            if x_negative != value_is_negative {
                // The inverse was negative; with signed arithmetic, we'd return inv + modulus.
                // This is unsigned arithmetic, so: -x + y == y - x
                value.set_equal_to(modulus);
                value.subtract_big_unsigned(&self.x);
            } else {
                // The inverse was not negative. We can return it as-is.
                value.set_equal_to(&self.x);
            }

            true
        } else {
            // The value and the modulus were not coprime, and do not have a mod inverse value.
            false
        }
    }

    pub fn modpow(
        &mut self,
        value: &mut BigUnsigned,
        exponent: &BigUnsigned,
        modulus: &BigUnsigned,
    ) {
        // Modular exponentiation via the square-and-multiply binary algorithm. This is conceptually identical to the double
        // and add algorithm used in ecc::EllipticCurvePointMultiplicationContext::multiply_point; see comments there.
        value.modulo_big_unsigned(modulus);
        self.x.one();

        let e = exponent.borrow_digits();
        let bit_count = e.len() * BITS_PER_DIGIT;
        let first_high_bit = first_high_bit_index(e[0]);
        for i in (first_high_bit..bit_count).rev() {
            if try_get_bit_at_index(i, e).unwrap() {
                self.x.multiply_big_unsigned(&value);
                self.x.modulo_big_unsigned(modulus);
            }

            self.y.set_equal_to(value);
            value.multiply_big_unsigned(&self.y);
            value.modulo_big_unsigned(modulus);
        }

        value.set_equal_to(&self.x);
        self.x.zero();
        self.y.zero();
    }
}
