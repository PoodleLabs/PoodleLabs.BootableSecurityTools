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

use super::{
    boot_services::UefiBootServices,
    core_types::{UefiGuid, UefiString, UefiTableHeader},
    protocols::{
        text::{UefiSimpleTextInput, UefiSimpleTextOutput},
        UefiProtocolHandle,
    },
    runtime_services::UefiRuntimeServices,
};
use core::{ffi::c_void, slice};

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiConfigurationTableRow {
    vendor_guid: UefiGuid,
    vendor_table: *const c_void,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiConfigurationTable {
    length: usize,
    rows: *const UefiConfigurationTableRow,
}

impl UefiConfigurationTable {
    pub const fn rows(&self) -> &[UefiConfigurationTableRow] {
        &unsafe { slice::from_raw_parts(self.rows, self.length) }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiSystemTable {
    header: UefiTableHeader,
    firmware_vendor: UefiString,
    firmware_revision: u32,
    console_in: UefiProtocolHandle<&'static UefiSimpleTextInput>,
    console_out: UefiProtocolHandle<&'static UefiSimpleTextOutput>,
    error_out: UefiProtocolHandle<&'static UefiSimpleTextOutput>,
    runtime_services: &'static UefiRuntimeServices,
    boot_services: &'static UefiBootServices,
    configuration_table: UefiConfigurationTable,
}

impl UefiSystemTable {
    pub const fn console_out(&self) -> UefiProtocolHandle<&'static UefiSimpleTextOutput> {
        self.console_out
    }

    pub const fn error_out(&self) -> UefiProtocolHandle<&'static UefiSimpleTextOutput> {
        self.error_out
    }

    pub const fn console_in(&self) -> UefiProtocolHandle<&'static UefiSimpleTextInput> {
        self.console_in
    }

    pub const fn runtime_services(&self) -> &'static UefiRuntimeServices {
        self.runtime_services
    }

    pub const fn boot_services(&self) -> &'static UefiBootServices {
        self.boot_services
    }
}
