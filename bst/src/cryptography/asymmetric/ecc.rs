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

use crate::integers::BigSigned;

struct Point {
    x: BigSigned,
    y: BigSigned,
}

impl Point {
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

        context.prepare_doubling(&self);

        // Point addition and doubling both consist of two steps: calculating a lambda value λ, then applying it.
        // The application of λ is the same for doubling and addition, but the calculation of λ is different.
        // Where p is the point to double, for doubling, the calculation is:
        // λ = (3 * (Xp * Xp) + a) / (2 * Yp)
        // TODO

        self.update_With_lambda(context);
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

        context.prepare_addition(&self, addend);

        // Point addition and doubling both consist of two steps: calculating a lambda value λ, then applying it.
        // The application of λ is the same for doubling and addition, but the calculation of λ is different.
        // Where p = augend, q = addend, for addition, the calculation is:
        // λ = (Yq - Yp) / (Xq - Xp)
        // TODO

        self.update_With_lambda(context);
    }

    fn update_With_lambda(&mut self, context: &mut PointMultiplicationContext) {
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
        self.x.subtract_big_signed(&context.x_addend);

        // Yr = Xp
        self.y.set_equal_to(&context.x_augend);

        // Yr = Xp - Xr
        self.y.subtract_big_signed(&self.x);

        // Yr = λ * (Xp - Xr)
        self.y.multiply_big_signed(&context.lambda);

        // Yr = (λ * (Xp - Xr)) - Yp
        self.y.subtract_big_signed(&context.y_augend);
    }
}

struct PointMultiplicationContext {
    x_augend: BigSigned,
    y_augend: BigSigned,
    x_addend: BigSigned,
    lambda: BigSigned,
}

impl PointMultiplicationContext {
    fn prepare_doubling(&mut self, point: &Point) {
        self.x_addend.set_equal_to(&point.x);
        self.x_augend.set_equal_to(&point.x);
        self.y_augend.set_equal_to(&point.y);
    }

    fn prepare_addition(&mut self, augend: &Point, addend: &Point) {
        self.x_addend.set_equal_to(&addend.x);
        self.x_augend.set_equal_to(&augend.x);
        self.y_augend.set_equal_to(&augend.y);
    }
}
