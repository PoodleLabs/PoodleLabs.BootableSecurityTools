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

// If a point in a derivation path is >= 2^31, we should derive a hardened key. If it's < 2^31, we should derive a normal key.
// Hardened children can only be derived from the parent private key; this is desirable as the compromise of both an extended public key parent and
// and non-hardened child private key descending from it is equivalent to knowing the parent extended private key, compromising the entire branch.
const HARDENED_CHILD_DERIVATION_THRESHOLD: u32 = 0b10000000000000000000000000000000;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct DerivationPathPoint(u32);

impl DerivationPathPoint {
    pub const fn is_for_hardened_key(&self) -> bool {
        self.0 >= HARDENED_CHILD_DERIVATION_THRESHOLD
    }
}

impl From<u32> for DerivationPathPoint {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl Into<u32> for DerivationPathPoint {
    fn into(self) -> u32 {
        self.0
    }
}
