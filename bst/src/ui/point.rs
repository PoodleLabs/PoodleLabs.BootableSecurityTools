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

use core::ops::{Add, Sub};

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct Point {
    x: usize,
    y: usize,
}

impl Point {
    pub const ZERO: Self = Self::from_single(0);

    pub const fn from(x: usize, y: usize) -> Self {
        Self { x, y }
    }

    pub const fn from_single(value: usize) -> Self {
        Self::from(value, value)
    }

    pub const fn height(&self) -> usize {
        self.y
    }

    pub const fn width(&self) -> usize {
        self.x
    }

    pub const fn area(&self) -> usize {
        self.x * self.y
    }

    pub const fn x(&self) -> usize {
        self.x
    }

    pub const fn y(&self) -> usize {
        self.y
    }

    pub fn clamp_inclusive(&self, within: Point) -> Self {
        Self::from(self.x.min(within.x), self.y.min(within.y))
    }

    pub fn clamp_exclusive(&self, within: Point) -> Self {
        self.clamp_inclusive(Self::from(
            Self::max_or_plus_1(within.x),
            Self::max_or_plus_1(within.y),
        ))
    }

    const fn max_or_plus_1(value: usize) -> usize {
        if value == usize::MAX {
            value
        } else {
            value + 1
        }
    }

    const fn no_underflow_subtract(a: usize, b: usize) -> usize {
        if a < b {
            0
        } else {
            a - b
        }
    }
}

impl Add for Point {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::from(self.x + rhs.x, self.y + rhs.y)
    }
}

impl Sub for Point {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::from(
            Self::no_underflow_subtract(self.x, rhs.x),
            Self::no_underflow_subtract(self.y, rhs.y),
        )
    }
}
