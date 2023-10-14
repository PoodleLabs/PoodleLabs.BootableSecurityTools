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

use super::EllipticCurvePointAdditionContext;
use crate::integers::{BigSigned, BigUnsigned};

#[derive(Debug, Clone)]
pub struct Point {
    is_infinity: bool,
    x: BigSigned,
    y: BigSigned,
}

impl Point {
    pub fn infinity(integer_capacity: usize) -> Self {
        Self {
            x: BigSigned::with_capacity(integer_capacity),
            y: BigSigned::with_capacity(integer_capacity),
            is_infinity: true,
        }
    }

    pub fn from(x: BigSigned, y: BigSigned) -> Self {
        Self {
            is_infinity: x.is_zero() && y.is_zero(),
            x,
            y,
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.is_infinity
    }

    pub fn x(&self) -> &BigSigned {
        &self.x
    }

    pub fn y(&self) -> &BigSigned {
        &self.y
    }

    pub fn add(
        &mut self,
        addend: &Point,
        addition_context: &mut EllipticCurvePointAdditionContext,
    ) {
        todo!()
    }

    pub fn double(&mut self, addition_context: &mut EllipticCurvePointAdditionContext) {
        todo!()
    }

    pub fn set_equal_to_unsigned(&mut self, x: &BigUnsigned, y: &BigUnsigned) {
        self.x.set_equal_to_unsigned(x, false);
        self.y.set_equal_to_unsigned(y, false);
        self.is_infinity = x.is_zero() && y.is_zero();
    }

    pub fn set_equal_to(&mut self, other: &Point) {
        self.is_infinity = other.is_infinity;
        self.x.set_equal_to(&other.x);
        self.y.set_equal_to(&other.y);
    }

    pub fn zero(&mut self) {
        self.is_infinity = true;
        self.x.zero();
        self.y.zero();
    }
}
