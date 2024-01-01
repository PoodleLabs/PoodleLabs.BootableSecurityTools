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

use crate::bits::bit_field;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ToggleKeys(u8);

#[allow(dead_code)]
impl ToggleKeys {
    pub const NONE: Self = Self(0);
    pub const NUM_LOCK: Self = Self(1);
    pub const CAPS_LOCK: Self = Self(2);
    pub const SCROLL_LOCK: Self = Self(4);

    pub const fn num_lock(self) -> bool {
        self.overlaps(Self::NUM_LOCK)
    }

    pub const fn caps_lock(self) -> bool {
        self.overlaps(Self::CAPS_LOCK)
    }

    pub const fn scroll_lock(self) -> bool {
        self.overlaps(Self::SCROLL_LOCK)
    }
}

bit_field!(ToggleKeys);
