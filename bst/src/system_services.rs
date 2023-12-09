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

use crate::{
    clipboard::Clipboard, console_out::ConsoleOut, constants, initialize_console,
    input::keyboard::KeyboardIn, string16::String16,
};
use alloc::{boxed::Box, format};
use core::{
    alloc::{GlobalAlloc, Layout},
    panic::PanicInfo,
    slice,
    time::Duration,
};
use macros::s16;

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum PowerAction {
    FailureReset(Option<Box<[u8]>>),
    Off,
    Reboot,
    Reset,
}

static mut CLIPBOARD: Option<Clipboard> = None;

pub trait SystemServices: Clone + 'static {
    type TVariableIdentifier: Copy;
    type TConsoleOut: ConsoleOut + Clone;
    type TKeyboardIn: KeyboardIn + Clone;

    unsafe fn allocate(&self, byte_count: usize) -> *mut u8;

    unsafe fn free(&self, pointer: *mut u8);

    fn try_get_variable(&self, identifier: Self::TVariableIdentifier) -> Option<Box<[u8]>>;

    fn try_set_variable(&self, identifier: Self::TVariableIdentifier, data: &[u8]) -> bool;

    fn try_clear_variable(&self, identifier: Self::TVariableIdentifier) -> bool;

    fn console_resolution_variable_name() -> Self::TVariableIdentifier;

    fn execute_power_action(&self, power_action: PowerAction);

    fn get_keyboard_in(&self) -> Self::TKeyboardIn;

    fn get_console_out(&self) -> Self::TConsoleOut;

    fn get_error_out(&self) -> Self::TConsoleOut;

    fn stall(&self, duration: Duration);

    fn clipboard_mut(&self) -> &mut Clipboard {
        match unsafe { CLIPBOARD.as_mut() } {
            Some(c) => c,
            None => {
                let c = Clipboard::new();
                unsafe { CLIPBOARD = Some(c) };
                self.clipboard_mut()
            }
        }
    }

    fn clipboard(&self) -> &Clipboard {
        match unsafe { CLIPBOARD.as_ref() } {
            Some(c) => c,
            None => {
                let c = Clipboard::new();
                unsafe { CLIPBOARD = Some(c) };
                self.clipboard()
            }
        }
    }

    fn currently_allocated_bytes(&self) -> usize {
        self.total_bytes_allocated() - self.total_bytes_freed()
    }

    fn outstanding_allocations(&self) -> usize {
        self.allocation_call_count() - self.free_call_count()
    }

    fn allocation_call_count(&self) -> usize {
        unsafe { ALLOCATION_COUNT }
    }

    fn total_bytes_allocated(&self) -> usize {
        unsafe { TOTAL_ALLOCATED }
    }

    fn total_bytes_freed(&self) -> usize {
        unsafe { TOTAL_FREED }
    }

    fn free_call_count(&self) -> usize {
        unsafe { FREE_COUNT }
    }
}

static mut PANIC_COUNTER: usize = 0;

const PANIC_HEADER: String16 =
    s16!("[PANIC]: An unrecoverable error has occurred. Exiting BST in 60 seconds...\r\n\r\nPlease consider reporting this in an issue at:\r\nhttps://github.com/PoodleLabs/PoodleLabs.BootableSecurityTools\r\n\r\nInclude details of what you were doing, and the following message:");

const PANIC_RECURSE: String16 =
    s16!("Three panics occurred recursively; this is likely due to you running out of memory.");

pub fn panic_handler<T: SystemServices>(system_services: T, panic_info: &PanicInfo) -> ! {
    unsafe { PANIC_COUNTER += 1 };
    let panic_count = unsafe { PANIC_COUNTER };
    if panic_count >= 4 {
        loop {}
    }

    let console_out = initialize_console(&system_services, constants::ERROR_SCREEN_COLOURS);
    console_out.output_utf16_line(PANIC_HEADER);
    if panic_count == 3 {
        console_out.output_utf16_line(PANIC_RECURSE);
        system_services.stall(Duration::from_secs(60));
        system_services.execute_power_action(PowerAction::FailureReset(None));
        loop {}
    }

    let detail_lines = Box::from_iter(
        format!("{}\0", &panic_info)
            .replace("\n", "\r\n")
            .encode_utf16(),
    );

    console_out.output_utf16_line(String16::from(&detail_lines));
    let data = if detail_lines.len() > 0 {
        Some(Box::from(unsafe {
            slice::from_raw_parts(detail_lines.as_ptr() as *const u8, detail_lines.len() * 2)
        }))
    } else {
        None
    };

    system_services.stall(Duration::from_secs(60));
    system_services.execute_power_action(PowerAction::FailureReset(data));
    loop {}
}

static mut ALLOCATION_COUNT: usize = 0;
static mut TOTAL_ALLOCATED: usize = 0;
static mut TOTAL_FREED: usize = 0;
static mut FREE_COUNT: usize = 0;

pub struct SystemServicesAllocator<T: SystemServices, F: Fn() -> T> {
    system_services_provider: F,
}

impl<T: SystemServices, F: Fn() -> T> SystemServicesAllocator<T, F> {
    pub const fn from(system_services_provider: F) -> Self {
        Self {
            system_services_provider,
        }
    }

    fn system_services(&self) -> T {
        (self.system_services_provider)()
    }
}

unsafe impl<T: SystemServices, F: Fn() -> T> GlobalAlloc for SystemServicesAllocator<T, F> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();

        let (pointer, allocated_bytes) = if align > 8 {
            let ptr = self.system_services().allocate(size + align);
            let mut offset = ptr.align_offset(align);
            if offset == 0 {
                offset = align;
            }

            let aligned_ptr = ptr.add(offset);
            (aligned_ptr.cast::<*mut u8>()).sub(1).write(ptr);
            (aligned_ptr, size + align)
        } else {
            (self.system_services().allocate(size), size)
        };

        TOTAL_ALLOCATED += allocated_bytes;
        ALLOCATION_COUNT += 1;
        pointer
    }

    unsafe fn dealloc(&self, mut ptr: *mut u8, layout: Layout) {
        let align = layout.align();
        let size = if align > 8 {
            ptr = (ptr as *const *mut u8).sub(1).read();
            layout.size() + align
        } else {
            layout.size()
        };

        slice::from_raw_parts_mut(ptr, size).fill(0);
        self.system_services().free(ptr);
        TOTAL_FREED += size;
        FREE_COUNT += 1;
    }
}
