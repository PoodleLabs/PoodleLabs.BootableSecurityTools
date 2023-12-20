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
    core_types::{
        UefiAllocateType, UefiEventHandle, UefiEventTypeFlags, UefiGuid, UefiHandle,
        UefiMemoryDescriptor, UefiMemoryType, UefiPhysicalAddress, UefiStatusCode, UefiTableHeader,
        UefiTaskPriorityLevel, UefiTimerType,
    },
    protocols::{
        device_paths::UefiDevicePathProtocol, scoped_protocol::UefiScopedProtocol,
        UefiInterfaceType, UefiLocateSearchType, UefiOpenProtocolInformation, UefiProtocol,
        UefiProtocolAttributes, UefiProtocolRegistrationHandle,
    },
};
use core::{ffi::c_void, ptr, slice, time::Duration};

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiBootServices {
    header: UefiTableHeader,

    // Task Priority Services
    raise_task_priority_level:
        extern "efiapi" fn(task_priority_level: UefiTaskPriorityLevel) -> UefiTaskPriorityLevel, /* EFI 1.0+ */
    restore_task_priority_level: extern "efiapi" fn(old_task_priority_level: UefiTaskPriorityLevel), /* EFI 1.0+ */

    // Memory Services
    allocate_pages: extern "efiapi" fn(
        allocation_type: UefiAllocateType,
        memory_type: UefiMemoryType,
        page_count: usize,
        memory: &mut UefiPhysicalAddress, /* IN/OUT */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    free_pages:
        extern "efiapi" fn(address: UefiPhysicalAddress, page_count: usize) -> UefiStatusCode, /* EFI 1.0+ */
    get_memory_map: extern "efiapi" fn(
        memory_map_size: &mut usize,           /* IN/OUT */
        memory_map: *mut UefiMemoryDescriptor, /* Array of length memory_map_size to write to */
        map_key: &mut usize,                   /* OUT */
        descriptor_size: &mut usize,           /* OUT */
        descriptor_version: &mut u32,          /* OUT */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    allocate_pool: extern "efiapi" fn(
        memory_type: UefiMemoryType,
        size: usize,
        buffer: &mut *mut u8, /* OUT */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    free_pool: extern "efiapi" fn(buffer: *const u8) -> UefiStatusCode, /* EFI 1.0+ */

    // Event & Timer Services
    create_event: extern "efiapi" fn(
        event_type: UefiEventTypeFlags,
        notify_task_priority_level: UefiTaskPriorityLevel,
        notify_function: fn(event: UefiEventHandle, context: *const u8), /* OPTIONAL */
        notify_context: *const u8,                                       /* OPTIONAL */
        event: &mut UefiEventHandle,                                     /* OUT */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    set_timer: extern "efiapi" fn(
        event: UefiEventHandle,
        timer_type: UefiTimerType,
        trigger_time: u64, /* 100ns increments */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    wait_for_event: extern "efiapi" fn(
        events_count: usize,
        events: *const UefiEventHandle, /* Array of length events_count */
        triggered_event_index: &mut usize, /* OUT */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    signal_event: extern "efiapi" fn(event: UefiEventHandle) -> UefiStatusCode, /* EFI 1.0+ */
    close_event: extern "efiapi" fn(event: UefiEventHandle) -> UefiStatusCode,  /* EFI 1.0+ */
    check_event: extern "efiapi" fn(event: UefiEventHandle) -> UefiStatusCode,  /* EFI 1.0+ */

    // Protocol Handler Services
    install_protocol_interface: extern "efiapi" fn(
        handle: &mut UefiHandle, /* IN/OUT */
        protocol_guid: &UefiGuid,
        interface_type: UefiInterfaceType,
        interface: *const u8,
    ) -> UefiStatusCode, /* EFI 1.0+ */
    reinstall_protocol_interface: extern "efiapi" fn(
        handle: UefiHandle,
        protocol_guid: &UefiGuid,
        old_interface: *const u8,
        new_interface: *const u8,
    ) -> UefiStatusCode, /* EFI 1.0+ */
    uninstall_protocol_interface: extern "efiapi" fn(
        handle: UefiHandle,
        protocol_guid: &UefiGuid,
        interface: *const u8,
    ) -> UefiStatusCode, /* EFI 1.0+ */
    handle_protocol: extern "efiapi" fn(
        handle: UefiHandle,
        protocol_guid: &UefiGuid,
        interface: &mut *const u8, /* OUT */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    reserved: *const c_void, /* EFI 1.0+ */
    register_protocol_notify: extern "efiapi" fn(
        protocol_guid: &UefiGuid,
        event: UefiEventHandle,
        registration: &mut UefiProtocolRegistrationHandle, /* OUT */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    locate_handle: extern "efiapi" fn(
        search_type: UefiLocateSearchType,
        protocol_guid: &UefiGuid,                   /* Optional */
        search_key: UefiProtocolRegistrationHandle, /* Optional */
        handle_count: &mut usize,                   /* IN/OUT */
        handles: &mut *const UefiHandle,            /* OUT Array of length handle_count */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    locate_device_path: extern "efiapi" fn(
        protocol_guid: &UefiGuid,
        device_path: &mut &UefiDevicePathProtocol, /* IN/OUT */
        device: &mut UefiHandle,                   /* OUT */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    install_configuration_table:
        extern "efiapi" fn(guid: &UefiGuid, table: UefiHandle) -> UefiStatusCode, /* EFI 1.0+ */

    // Image Services
    load_image: extern "efiapi" fn(
        boot_policy: bool,
        parent_image_handle: UefiHandle,
        device_path: &UefiDevicePathProtocol, /* OPTIONAL */
        source_buffer: *const u8,             /* OPTIONAL Array/bytes of length source_length */
        source_length: usize,
        image_handle: &mut UefiHandle, /* OUT */
    ) -> UefiStatusCode, /* EFI 1.0+ */
    start_image: extern "efiapi" fn(
        image_handle: UefiHandle,
        exit_data_length: &mut usize, /* OUT */
        exit_data: &mut *const u8, /* OUT OPTIONAL Null Terminated String (u16) followed by optional bytes.*/
    ) -> UefiStatusCode, /* EFI 1.0+ */
    exit_image: extern "efiapi" fn(
        image_handle: UefiHandle,
        exit_status: UefiStatusCode,
        exit_data_length: usize,
        exit_data: *const u8, /* OUT OPTIONAL Null Terminated String (u16) followed by optional bytes.*/
    ) -> UefiStatusCode, /* EFI 1.0+ */
    unload_image: extern "efiapi" fn(image_handle: UefiHandle) -> UefiStatusCode, /* EFI 1.0+ */
    exit_boot_services:
        extern "efiapi" fn(image_handle: UefiHandle, map_key: usize) -> UefiStatusCode, /* EFI 1.0+ */

    // Misc Services
    get_next_monotonic_count: extern "efiapi" fn(count: &mut u64 /* OUT */) -> UefiStatusCode, /* EFI 1.0+ */
    stall: extern "efiapi" fn(microseconds: usize) -> UefiStatusCode, /* EFI 1.0+ */
    set_watchdog_timer: extern "efiapi" fn(
        timeout: usize,
        watchdog_code: u64,
        watchdog_data_length: usize,
        watchdog_data: *const u8, /* IN OPTIONAL Null Terminated String (u16) followed by optional bytes.*/
    ) -> UefiStatusCode, /* EFI 1.0+ */

    // DriverSupport Services
    connect_controller: extern "efiapi" fn(
        controller_handle: UefiHandle,
        driver_image_handle: &UefiHandle, /* OPTIONAL */
        remaining_device_path: &UefiDevicePathProtocol, /* OPTIONAL */
        recursive: bool,
    ) -> UefiStatusCode, /* EFI 1.1+ */
    disconnect_controller: extern "efiapi" fn(
        controller_handle: UefiHandle,
        driver_image_handle: UefiHandle, /* OPTIONAL */
        child_handle: UefiHandle,        /* OPTIONAL */
    ) -> UefiStatusCode, /* EFI 1.1+ */

    // Open and Close Protocol Services
    open_protocol: extern "efiapi" fn(
        handle: UefiHandle,
        protocol_guid: &UefiGuid,
        interface: &mut *mut u8, /* OUT OPTIONAL */
        agent_handle: UefiHandle,
        controller_handle: UefiHandle,
        attributes: UefiProtocolAttributes,
    ) -> UefiStatusCode, /* EFI 1.1+ */
    close_protocol: extern "efiapi" fn(
        handle: UefiHandle,
        protocol_guid: &UefiGuid,
        agent_handle: UefiHandle,
        controller_handle: UefiHandle,
    ) -> UefiStatusCode, /* EFI 1.1+ */
    open_protocol_information: extern "efiapi" fn(
        handle: UefiHandle,
        protocol_guid: &UefiGuid,
        entries: &mut *const UefiOpenProtocolInformation, /* OUT Array of size entry_count */
        entry_count: &mut usize,                          /* OUT */
    ) -> UefiStatusCode, /* EFI 1.1+ */

    // Library Services
    protocols_per_handle: extern "efiapi" fn(
        handle: UefiHandle,
        protocol_guids: &mut *const &UefiGuid, /* OUT Array of size protocol_guids_count */
        protocol_guids_count: &mut usize,      /* OUT */
    ) -> UefiStatusCode, /* EFI 1.1+ */
    locate_handle_buffer: extern "efiapi" fn(
        search_type: UefiLocateSearchType,
        protocol_guid: &UefiGuid,                   /* OPTIONAL */
        search_key: UefiProtocolRegistrationHandle, /* OPTIONAL */
        handle_count: &mut usize,                   /* OUT */
        handles: &mut *const UefiHandle,            /* OUT Array of size handle_count */
    ) -> UefiStatusCode, /* EFI 1.1+ */
    locate_protocol: extern "efiapi" fn(
        protocol_guid: &UefiGuid,
        registration: UefiProtocolRegistrationHandle, /* OPTIONAL */
        interface: &mut *const u8,                    /* OUT */
    ) -> UefiStatusCode, /* EFI 1.1+ */
    install_multiple_protocol_interfaces: *const c_void, /* EFI 1.1+ */
    uninstall_multiple_protocol_interfaces: *const c_void, /* EFI 1.1+ */

    // 32-bit CRC Services
    calculate_crc32: extern "efiapi" fn(
        data: *const u8, /* Array/bytes of length data_length */
        data_length: usize,
        crc32: &mut u32, /* OUT */
    ) -> UefiStatusCode, /* EFI 1.1+ */

    // Memory Utilities
    copy_memory: extern "efiapi" fn(
        destination: *mut u8, /* Array/bytes of length >= length  */
        source: *const u8,    /* Array/bytes of length >= length */
        length: usize,
    ), /* EFI 1.1+ */
    set_memory: extern "efiapi" fn(
        buffer: *mut u8, /* Array/bytes of length >= length */
        length: usize,
        value: u8,
    ), /* EFI 1.1+ */

    // Extended Events
    create_event_extended: *const c_void, /* EFI 2.0+ */
}

impl UefiBootServices {
    pub fn disable_watchdog_timer(&self) -> UefiStatusCode {
        (self.set_watchdog_timer)(0, 999999999, 0, ptr::null())
    }

    pub fn wait_for_event(&self, event: UefiEventHandle) -> UefiStatusCode {
        let events = [event];
        let mut triggered_index = 0usize;
        (self.wait_for_event)(1, events.as_ptr(), &mut triggered_index)
    }

    pub fn allocate_pool(
        &self,
        memory_type: UefiMemoryType,
        size: usize,
    ) -> Result<*mut u8, UefiStatusCode> {
        let mut ptr = ptr::null_mut();
        let result = (self.allocate_pool)(memory_type, size, &mut ptr);
        match result.into() {
            Ok(_) => Ok(ptr),
            Err(c) => Err(c),
        }
    }

    pub fn free_pool(&self, ptr: *mut u8) {
        (self.free_pool)(ptr);
    }

    pub fn stall(&self, time_span: Duration) -> UefiStatusCode {
        (self.stall)(time_span.as_micros().min(usize::MAX as u128) as usize)
    }

    pub fn get_protocol_handles<T: UefiProtocol>(&self) -> Result<&[UefiHandle], UefiStatusCode> {
        let mut count = 0usize;
        let mut handles = 0usize as *const UefiHandle;
        match (self.locate_handle_buffer)(
            UefiLocateSearchType::ByProtocol,
            &T::guid(),
            UefiProtocolRegistrationHandle::NULL,
            &mut count,
            &mut handles,
        )
        .into()
        {
            Ok(_) => Ok(unsafe { slice::from_raw_parts(handles, count) }),
            Err(c) => Err(c),
        }
    }

    pub fn open_scoped_protocol<T: UefiProtocol>(
        &self,
        handle: UefiHandle,
        agent_handle: UefiHandle,
        controller_handle: Option<UefiHandle>,
    ) -> Result<UefiScopedProtocol<T>, UefiStatusCode> {
        UefiScopedProtocol::open_on(handle, agent_handle, self, controller_handle)
    }

    pub fn open_protocol<T: UefiProtocol>(
        &self,
        handle: UefiHandle,
        agent_handle: UefiHandle,
        controller_handle: UefiHandle,
        attributes: UefiProtocolAttributes,
    ) -> Result<*mut T, UefiStatusCode> {
        let mut protocol_pointer = 0usize as *mut u8;
        match (self.open_protocol)(
            handle,
            &T::guid(),
            &mut protocol_pointer,
            agent_handle,
            controller_handle,
            attributes,
        )
        .into()
        {
            Ok(_) => Ok(protocol_pointer as *mut T),
            Err(c) => Err(c),
        }
    }

    pub fn close_protocol(
        &self,
        handle: UefiHandle,
        protocol_guid: &UefiGuid,
        agent: UefiHandle,
        controller: UefiHandle,
    ) -> UefiStatusCode {
        (self.close_protocol)(handle, protocol_guid, agent, controller)
    }
}
