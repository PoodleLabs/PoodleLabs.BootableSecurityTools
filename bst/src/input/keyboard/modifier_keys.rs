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
pub struct ModifierKeys(u16);

#[allow(dead_code)]
impl ModifierKeys {
    pub const NONE: Self = Self(0);
    pub const RIGHT_SHIFT: Self = Self(1);
    pub const LEFT_SHIFT: Self = Self(2);
    pub const RIGHT_CONTROL: Self = Self(4);
    pub const LEFT_CONTROL: Self = Self(8);
    pub const RIGHT_ALT: Self = Self(16);
    pub const LEFT_ALT: Self = Self(32);
    pub const RIGHT_LOGO: Self = Self(64);
    pub const LEFT_LOGO: Self = Self(128);
    pub const MENU: Self = Self(256);
    pub const SYSTEM_REQUEST: Self = Self(512);

    pub const CONTROL: Self = Self(Self::LEFT_CONTROL.0 | Self::RIGHT_CONTROL.0);
    pub const SHIFT: Self = Self(Self::LEFT_SHIFT.0 | Self::RIGHT_SHIFT.0);
    pub const LOGO: Self = Self(Self::LEFT_LOGO.0 | Self::RIGHT_LOGO.0);
    pub const ALT: Self = Self(Self::LEFT_ALT.0 | Self::RIGHT_ALT.0);

    pub const fn control(self) -> bool {
        self.overlaps(Self::CONTROL)
    }

    pub const fn shift(self) -> bool {
        self.overlaps(Self::SHIFT)
    }

    pub const fn logo(self) -> bool {
        self.overlaps(Self::LOGO)
    }

    pub const fn alt(self) -> bool {
        self.overlaps(Self::ALT)
    }

    pub const fn right_shift(self) -> bool {
        self.overlaps(Self::RIGHT_SHIFT)
    }

    pub const fn left_shift(self) -> bool {
        self.overlaps(Self::LEFT_SHIFT)
    }

    pub const fn right_control(self) -> bool {
        self.overlaps(Self::RIGHT_CONTROL)
    }

    pub const fn left_control(self) -> bool {
        self.overlaps(Self::LEFT_CONTROL)
    }

    pub const fn right_alt(self) -> bool {
        self.overlaps(Self::RIGHT_ALT)
    }

    pub const fn left_alt(self) -> bool {
        self.overlaps(Self::LEFT_ALT)
    }

    pub const fn right_logo(self) -> bool {
        self.overlaps(Self::RIGHT_LOGO)
    }

    pub const fn left_logo(self) -> bool {
        self.overlaps(Self::LEFT_LOGO)
    }

    pub const fn menu(self) -> bool {
        self.overlaps(Self::MENU)
    }

    pub const fn system_request(self) -> bool {
        self.overlaps(Self::SYSTEM_REQUEST)
    }
}

bit_field!(ModifierKeys);
