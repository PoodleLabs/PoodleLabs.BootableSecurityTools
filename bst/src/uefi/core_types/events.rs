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

bit_field!(UefiEventTypeFlags);
