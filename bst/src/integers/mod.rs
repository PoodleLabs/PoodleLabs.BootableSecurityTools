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

mod big_integers;
mod numeric_base;
mod numeric_collector;

pub use big_integers::BigInteger;
pub use numeric_base::{NumericBase, NumericBaseWithCharacterPredicate, NumericBases};
pub use numeric_collector::{
    NumericCollector, NumericCollectorRoundBase, NumericCollectorRoundError,
};

pub fn ceil(value: f64) -> usize {
    let floored = value as usize;
    if (floored as f64) < value {
        floored + 1
    } else {
        floored
    }
}
