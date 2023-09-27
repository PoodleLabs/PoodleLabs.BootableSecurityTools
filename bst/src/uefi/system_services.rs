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
    console_out::UefiConsoleOut,
    core_types::{UefiHandle, UefiMemoryType, UefiResetType},
    keyboard_in::UefiKeyboardIn,
    system_table::UefiSystemTable,
};
use crate::{
    console_out::ConsoleOut, constants, system_services::PowerAction,
    uefi::core_types::UefiStatusCode, ui::Point, String16, SystemServices,
};
use core::time::Duration;
use macros::s16;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiSystemServices {
    system_table: &'static UefiSystemTable,
    image_handle: UefiHandle,
}

impl UefiSystemServices {
    pub const fn from(system_table: &'static UefiSystemTable, image_handle: UefiHandle) -> Self {
        Self {
            system_table: system_table,
            image_handle: image_handle,
        }
    }

    pub const fn system_table(&self) -> &UefiSystemTable {
        self.system_table
    }

    fn user_reset(&self, message: String16<'static>, reset_type: UefiResetType) {
        self.get_console_out()
            .set_cursor_position(Point::ZERO)
            .in_colours(constants::SHUTDOWN_MESSGE_COLOURS, |c| {
                c.output_utf16(message)
            });
        self.stall(Duration::from_secs(1));
        self.system_table
            .runtime_services()
            .reset(UefiStatusCode::SUCCESS, reset_type, None);
    }
}

impl SystemServices for UefiSystemServices {
    type TKeyboardIn = UefiKeyboardIn;
    type TConsoleOut = UefiConsoleOut;

    unsafe fn allocate(&self, byte_count: usize) -> *mut u8 {
        self.system_table
            .boot_services()
            .allocate_pool(UefiMemoryType::LoaderData, byte_count)
            .unwrap()
    }

    unsafe fn free(&self, pointer: *mut u8) {
        self.system_table.boot_services().free_pool(pointer)
    }

    fn get_keyboard_in(&self) -> Self::TKeyboardIn {
        UefiKeyboardIn::from(self.system_table, self.image_handle)
    }

    fn get_console_out(&self) -> Self::TConsoleOut {
        UefiConsoleOut::from(self.system_table.console_out())
    }

    fn get_error_out(&self) -> Self::TConsoleOut {
        UefiConsoleOut::from(self.system_table.error_out())
    }

    fn stall(&self, duration: Duration) {
        assert_eq!(
            self.system_table.boot_services().stall(duration),
            UefiStatusCode::SUCCESS
        )
    }

    fn execute_power_action(&self, power_action: PowerAction) {
        let rs = self.system_table.runtime_services();
        match power_action {
            PowerAction::FailureReset(data) => {
                rs.reset(UefiStatusCode::ABORTED, UefiResetType::Cold, data)
            }
            PowerAction::Off => {
                self.user_reset(s16!("User requested shutdown..."), UefiResetType::Shutdown)
            }
            PowerAction::Reboot => {
                self.user_reset(s16!("User requested reboot..."), UefiResetType::Cold)
            }
            PowerAction::Reset => {
                self.user_reset(s16!("User requested reset..."), UefiResetType::Warm)
            }
        }
    }
}
