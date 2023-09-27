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

#![allow(dead_code)]

mod boot_services;
mod console_out;
mod core_types;
mod keyboard_in;
mod protocols;
mod runtime_services;
mod system_services;
mod system_table;

use self::{
    core_types::{UefiEventHandle, UefiHandle, UefiStatusCode},
    system_table::UefiSystemTable,
};
use crate::system_services::SystemServicesAllocator;
use core::panic::PanicInfo;
use system_services::UefiSystemServices;

static mut SYSTEM_SERVICES: Option<UefiSystemServices> = None;

fn get_system_services() -> UefiSystemServices {
    match unsafe { SYSTEM_SERVICES } {
        Some(s) => s,
        None => panic!("Tried to access system services prior to their initialization."),
    }
}

fn wait_for_event(event: UefiEventHandle) -> UefiStatusCode {
    get_system_services()
        .system_table()
        .boot_services()
        .wait_for_event(event)
}

#[no_mangle]
fn efi_main(image_handle: UefiHandle, system_table: &'static UefiSystemTable) -> usize {
    let system_services = UefiSystemServices::from(system_table, image_handle);
    unsafe { SYSTEM_SERVICES = Some(system_services) }

    // Disable the watchdog timer; (most) computers will time out in a UEFI
    // application after 5 minutes without this and just reset.
    system_table.boot_services().disable_watchdog_timer();
    crate::run_console_ui(system_services);
    0
}

#[cfg_attr(test, allow(dead_code))]
#[cfg_attr(not(test), panic_handler)]
fn panic_handler(panic_info: &PanicInfo) -> ! {
    crate::system_services::panic_handler(get_system_services(), panic_info)
}

#[cfg_attr(test, allow(dead_code))]
#[cfg_attr(not(test), global_allocator)]
static ALLOCATOR: SystemServicesAllocator<UefiSystemServices, fn() -> UefiSystemServices> =
    SystemServicesAllocator::from(get_system_services);
