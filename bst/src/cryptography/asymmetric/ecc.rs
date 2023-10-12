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

use crate::integers::{BigSigned, BigUnsigned};

pub struct Point {
    x: BigSigned,
    y: BigSigned,
}

impl Point {
    pub fn from(x: BigSigned, y: BigSigned) -> Self {
        Self { x, y }
    }

    pub fn is_infinity(&self) -> bool {
        // The identity point of the curve; (X, Y) + -(X, Y) = Infinity.
        // Where I is Infinity, and P is another point:
        // I + I = I
        // I + P = P
        self.x.is_zero() && self.y.is_zero()
    }

    pub fn negate(&mut self) {
        // A negated point means that P + -P = Infinity
        // (x, y) + -(x, y) = I
        // (x, y) + (x, -y) = I
        // (x, -y) = -(x, y)
        self.y.negate()
    }

    pub fn double(&mut self, context: &mut PointMultiplicationContext) {
        if self.is_infinity() {
            // I + I = I
            return;
        }

        // Store X and Y's original values. X and Y can now be used as temporary value buffers.
        context.prepare_doubling(&self);

        // Point addition and doubling both consist of two steps: calculating a lambda value λ, then applying it.
        // The application of λ is the same for doubling and addition, but the calculation of λ is different.
        // Where p is the point to double, for doubling, the calculation is:
        // λ = (3 * (Xp^2) + a) / (2 * Yp)

        // λ = Xp
        context.lambda.set_equal_to(&self.x);

        // λ = Xp * Xp = Xp^2
        context.lambda.multiply_big_signed(&context.x_augend);

        // λ = 3 * Xp^2
        context.lambda.multiply_u8(3);

        // λ = 3 * Xp^2 + a
        context.lambda.add_big_unsigned(context.a);

        // Y = 2 * Yp
        self.y.multiply_u8(2);

        // λ = (3 * Xp^2 + a) / (2 * Yp)
        context
            .lambda
            .divide_big_signed_with_remainder(&self.y, &mut self.x);

        self.update_with_lambda(context, None);
    }

    pub fn add(&mut self, addend: &Point, context: &mut PointMultiplicationContext) {
        if self.is_infinity() {
            // I + P = P
            self.x.set_equal_to(&addend.x);
            self.y.set_equal_to(&addend.y);
            return;
        }

        if addend.is_infinity() {
            // P + I = P
            return;
        }

        if addend.x == self.x {
            if addend.y != self.y {
                // The points are mutual inverses; the result is infinity.
                self.x.zero();
                self.y.zero();
                return;
            }

            // Where added points are coincident (the same), we need to use the doubling algorithm instead.
            self.double(context);
            return;
        }

        // Store the original X and Y values of the augend. X and Y can now be used as temporary value buffers.
        context.prepare_addition(&self);

        // Point addition and doubling both consist of two steps: calculating a lambda value λ, then applying it.
        // The application of λ is the same for doubling and addition, but the calculation of λ is different.
        // Where p = augend, q = addend, for addition, the calculation is:
        // λ = (Yq - Yp) / (Xq - Xp)

        // λ = Yq
        context.lambda.set_equal_to(&addend.y);

        // λ = Yq - Yp
        context.lambda.subtract_big_signed(&self.y);

        // Y = Xq
        self.y.set_equal_to(&addend.x);

        // Y = Xq - Xp
        self.y.subtract_big_signed(&self.x);

        // λ = (Yq - Yp) / (Xq - Xp)
        context
            .lambda
            .divide_big_signed_with_remainder(&self.y, &mut self.x);

        self.update_with_lambda(context, Some(&addend.x));
    }

    fn update_with_lambda(
        &mut self,
        context: &mut PointMultiplicationContext,
        x_addend: Option<&BigSigned>,
    ) {
        // Where p = augend, q = addend, r is the result, and λ is the temporary field from point addition or doubling:
        // Xr = λ^2 - Xp - Xq
        // Yr = (λ * (Xp - Xr)) - Yp

        // Xr = λ
        self.x.set_equal_to(&context.lambda);

        // Xr = λ * λ = λ^2
        self.x.multiply_big_signed(&context.lambda);

        // Xr = λ^2 - Xp
        self.x.subtract_big_signed(&context.x_augend);

        // Xr = λ^2 - Xp - Xq
        self.x.subtract_big_signed(match x_addend {
            // We passed in the addend's X value from addition.
            Some(x) => x,
            // We didn't pass in an addend X value; we're doubling, and Xq = Xp
            None => &context.x_augend,
        });

        // Yr = Xp
        self.y.set_equal_to(&context.x_augend);

        // Yr = Xp - Xr
        self.y.subtract_big_signed(&self.x);

        // Yr = λ * (Xp - Xr)
        self.y.multiply_big_signed(&context.lambda);

        // Yr = (λ * (Xp - Xr)) - Yp
        self.y.subtract_big_signed(&context.y_augend);
    }

    fn zero(&mut self) {
        self.x.zero();
        self.y.zero();
    }
}

pub struct PointMultiplicationContext {
    integer_byte_capacity: usize,
    a: &'static BigUnsigned,
    x_augend: BigSigned,
    y_augend: BigSigned,
    lambda: BigSigned,
}

impl PointMultiplicationContext {
    pub fn new(a: &'static BigUnsigned, integer_byte_capacity: usize) -> Self {
        Self {
            x_augend: BigSigned::with_capacity(integer_byte_capacity),
            y_augend: BigSigned::with_capacity(integer_byte_capacity),
            lambda: BigSigned::with_capacity(integer_byte_capacity),
            integer_byte_capacity,
            a,
        }
    }

    pub fn multiply(
        &mut self,
        x: &BigUnsigned,
        y: &BigUnsigned,
        mut multiplier: BigUnsigned,
    ) -> Point {
        let mut aggregate = Point::from(
            BigSigned::with_capacity(self.integer_byte_capacity),
            BigSigned::with_capacity(self.integer_byte_capacity),
        );

        let mut working_point = Point::from(
            BigSigned::from_unsigned(false, x.clone()),
            BigSigned::from_unsigned(false, y.clone()),
        );

        let mut remainder = 0u8;
        while multiplier.is_non_zero() {
            if multiplier.is_even() {
                working_point.double(self);
            } else {
                aggregate.add(&working_point, self)
            }

            multiplier.divide_u8_with_remainder(2, &mut remainder);
        }

        self.zero();
        aggregate
    }

    fn prepare_doubling(&mut self, point: &Point) {
        self.x_augend.set_equal_to(&point.x);
        self.y_augend.set_equal_to(&point.y);
    }

    fn prepare_addition(&mut self, augend: &Point) {
        self.x_augend.set_equal_to(&augend.x);
        self.y_augend.set_equal_to(&augend.y);
    }

    fn zero(&mut self) {
        self.x_augend.zero();
        self.y_augend.zero();
        self.lambda.zero()
    }
}
