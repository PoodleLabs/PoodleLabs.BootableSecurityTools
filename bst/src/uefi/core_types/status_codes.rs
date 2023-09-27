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

use core::{fmt::Display, mem::size_of};

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiStatusCode(usize);

impl UefiStatusCode {
    pub const SUCCESS: Self = Self(0);
    pub const ABORTED: Self = Self(21 & Self::ERROR_BIT);

    const ERROR_BIT: usize = 1usize << ((size_of::<usize>() * 8) - 1);

    pub const fn is_warning_or_success(self) -> bool {
        (self.0 & Self::ERROR_BIT) == 0
    }

    pub const fn is_success(self) -> bool {
        self.0 == Self::SUCCESS.0
    }
}

impl Into<Result<UefiStatusCode, UefiStatusCode>> for UefiStatusCode {
    fn into(self) -> Result<UefiStatusCode, UefiStatusCode> {
        if self.is_warning_or_success() {
            Ok(self)
        } else {
            Err(self)
        }
    }
}

impl Display for UefiStatusCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}
