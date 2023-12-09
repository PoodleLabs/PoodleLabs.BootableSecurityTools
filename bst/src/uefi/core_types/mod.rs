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

mod events;
mod guids;
mod memory_descriptions;
mod status_codes;
mod table_headers;
mod time;

pub(in crate::uefi) use events::{
    UefiEventHandle, UefiEventTypeFlags, UefiTaskPriorityLevel, UefiTimerType,
};
pub(in crate::uefi) use guids::UefiGuid;
pub(in crate::uefi) use memory_descriptions::{
    UefiAllocateType, UefiMemoryDescriptor, UefiMemoryType, UefiPhysicalAddress,
};
pub(in crate::uefi) use status_codes::UefiStatusCode;
pub(in crate::uefi) use table_headers::UefiTableHeader;
pub(in crate::uefi) use time::{UefiTime, UefiTimeCapabilities};

use crate::bits::bit_field;
use alloc::sync::Arc;
use core::slice;
use macros::c16;

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiHandle(usize);

impl UefiHandle {
    pub const NULL: Self = Self(0);
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiString(*const u16);

impl UefiString {
    pub const fn content_length(&self) -> usize {
        let mut len = 0usize;
        while unsafe { *self.0.add(len) } != c16!("\0") {
            len += 1;
        }

        len
    }
}

impl From<*const u16> for UefiString {
    fn from(value: *const u16) -> Self {
        Self(value)
    }
}

impl Into<Arc<[u16]>> for UefiString {
    fn into(self) -> Arc<[u16]> {
        Arc::from_iter(
            unsafe { slice::from_raw_parts(self.0, self.content_length()) }
                .iter()
                .cloned(),
        )
    }
}

impl Into<*const u16> for UefiString {
    fn into(self) -> *const u16 {
        self.0
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) enum UefiResetType {
    Cold,
    Warm,
    Shutdown,
    PlatformSpecific,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiVariableAttributes(u32);

impl UefiVariableAttributes {
    pub const NONE: Self = Self(0x00000000);
    pub const NON_VOLATILE: Self = Self(0x00000001);
    pub const BOOTSERVICE_ACCESS: Self = Self(0x00000002);
    pub const RUNTIME_ACCESS: Self = Self(0x00000004);
    pub const HARDWARE_ERROR_RECORD: Self = Self(0x00000008);
    pub const AUTHENTICATED_WRITE_ACCESS: Self = Self(0x00000010);
    pub const TIME_BASED_AUTHENTICATED_WRITE_ACCESS: Self = Self(0x00000020);
    pub const APPEND_WRITE: Self = Self(0x00000040);
    pub const ENHANCED_AUTHENTICATED_ACCESS: Self = Self(0x00000080);
}

bit_field!(UefiVariableAttributes);
