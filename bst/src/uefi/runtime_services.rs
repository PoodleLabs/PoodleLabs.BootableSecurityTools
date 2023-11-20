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

use super::core_types::{
    UefiGuid, UefiMemoryDescriptor, UefiResetType, UefiStatusCode, UefiTableHeader, UefiTime,
    UefiTimeCapabilities, UefiVariableAttributes,
};
use crate::String16;
use alloc::boxed::Box;
use core::{ffi::c_void, ptr};

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiRuntimeServices {
    header: UefiTableHeader,

    // Time Services
    get_time: extern "efiapi" fn(
        time: &mut UefiTime,                     /* OUT */
        capabilities: &mut UefiTimeCapabilities, /* OUT */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    set_time: extern "efiapi" fn(time: &UefiTime) -> UefiStatusCode, /* EFI 1.0+ */
    get_wakeup_time: extern "efiapi" fn(
        enabled: &mut bool,  /* OUT */
        pending: &mut bool,  /* OUT */
        time: &mut UefiTime, /* OUT */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    set_wakeup_time: extern "efiapi" fn(enable: bool, time: &UefiTime) -> UefiStatusCode, /* EFI 1.0+ */

    // Virtual Memory Services
    set_virtual_address_map: extern "efiapi" fn(
        memory_map_size: usize,
        descriptor_size: usize,
        descriptor_version: u32,
        virtual_map: *const UefiMemoryDescriptor, /* Array with length memory_map_size */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    convert_pointer: extern "efiapi" fn(
        debug_disposition: usize, /* EFI_OPTIONAL_PTR = 0x00000001; allows the pointer to be null */
        address: &mut *const u8,  /* IN/OUT */
    ) -> UefiStatusCode, /* EFI 1.0+ */

    // Variable Services
    get_variable: extern "efiapi" fn(
        variable_name: *const u16,
        vendor_guid: &UefiGuid,
        attributes: &mut UefiVariableAttributes, /* OUT */
        data_length: &mut usize,                 /* IN/OUT */
        data: *mut u8, /* OUT OPTIONAL Mutable buffer for data with length data_length */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    get_next_variable_name: extern "efiapi" fn(
        variable_name_length: &mut usize, /* IN/OUT */
        variable_name: *mut u16, /* IN/OUT Mutable buffer with length variable_name_length for both input and output of a null terminated string */
        vendor_guid: &mut UefiGuid, /* IN/OUT */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    set_variable: extern "efiapi" fn(
        variable_name: *const u16,
        vendor_guid: &UefiGuid,
        attributes: UefiVariableAttributes,
        data_length: usize,
        data: *const u8, /* Array/bytes of length >= data_length */
    ) -> UefiStatusCode, /* EFI 1.0+ */

    // Misc Services
    get_next_high_monotonic_count:
        extern "efiapi" fn(high_count: &mut u32 /* OUT */) -> UefiStatusCode, /* EFI 1.0+ */
    reset_system: extern "efiapi" fn(
        reset_type: UefiResetType,
        reset_status: UefiStatusCode,
        data_length: usize,
        data: *const u8, /* OUT OPTIONAL Null Terminated String (u16) followed by optional bytes of total byte length data_length.*/
    ), /* EFI 1.0+ */

    // Capsule Services
    update_capsule: *const c_void,             /* EFI 2.0+ */
    query_capsule_capabilities: *const c_void, /* EFI 2.0+ */

    // Variable Query Services
    query_variable_info: *const c_void, /* EFI 2.0+ */
}

impl UefiRuntimeServices {
    pub fn reset(
        &self,
        status_code: UefiStatusCode,
        reset_type: UefiResetType,
        data: Option<Box<[u8]>>,
    ) {
        match data {
            Some(b) => (self.reset_system)(reset_type, status_code, b.len(), b.as_ptr()),
            None => (self.reset_system)(reset_type, status_code, 0, ptr::null()),
        }
    }

    pub fn get_variable(
        &self,
        variable_name: String16<'static>,
        vendor_guid: &UefiGuid,
        buffer: Option<&mut Box<[u8]>>,
    ) -> Result<(UefiVariableAttributes, usize), (UefiStatusCode, usize)> {
        let mut attributes = UefiVariableAttributes::NONE;
        let (mut buffer_length, buffer) = match buffer {
            Some(b) => (b.len(), b.as_mut_ptr()),
            None => (0, ptr::null_mut()),
        };

        let result = (self.get_variable)(
            unsafe { variable_name.get_underlying_slice().as_ptr() },
            vendor_guid,
            &mut attributes,
            &mut buffer_length,
            buffer,
        );

        if result.is_success() {
            Ok((attributes, buffer_length))
        } else {
            Err((result, buffer_length))
        }
    }

    pub fn set_variable(
        &self,
        variable_name: String16<'static>,
        vendor_guid: &UefiGuid,
        attributes: UefiVariableAttributes,
        data: Option<Box<[u8]>>,
    ) -> UefiStatusCode {
        let (buffer_length, buffer) = match data {
            Some(b) => (b.len(), b.as_ptr()),
            None => (0, ptr::null()),
        };

        (self.set_variable)(
            unsafe { variable_name.get_underlying_slice().as_ptr() },
            vendor_guid,
            attributes,
            buffer_length,
            buffer,
        )
    }
}
