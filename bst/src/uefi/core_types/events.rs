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

use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign};

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiEventHandle(usize);

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiTaskPriorityLevel(usize);

#[repr(u32)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) enum UefiTimerType {
    Cancel,
    Periodic,
    Relative,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiEventTypeFlags(u32);

impl UefiEventTypeFlags {
    pub const TIMER: Self = Self(0x80000000);
    pub const RUNTIME: Self = Self(0x40000000);
    pub const NOTIFY_WAIT: Self = Self(0x00000100);
    pub const NOTIFY_SIGNAL: Self = Self(0x00000200);
    pub const SIGNAL_EXIT_BOOT_SERVICES: Self = Self(0x00000201);
    pub const SIGNAL_VIRTUAL_ADDRESS_CHANGE: Self = Self(0x60000202);
}

impl BitAnd for UefiEventTypeFlags {
    type Output = UefiEventTypeFlags;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for UefiEventTypeFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = Self(rhs.0 & self.0)
    }
}

impl BitOr for UefiEventTypeFlags {
    type Output = UefiEventTypeFlags;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for UefiEventTypeFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = Self(rhs.0 | self.0)
    }
}

impl BitXor for UefiEventTypeFlags {
    type Output = UefiEventTypeFlags;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for UefiEventTypeFlags {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = Self(rhs.0 ^ self.0)
    }
}
