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
    core_types::UefiHandle,
    protocols::{text::UefiSimpleTextInputExtended, UefiProtocolAttributes},
    system_table::UefiSystemTable,
};
use crate::input::keyboard::{KeyPress, KeyboardIn, ModifierKeys, ToggleKeys};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiKeyboardIn {
    system_table: &'static UefiSystemTable,
    image_handle: UefiHandle,
}

impl UefiKeyboardIn {
    pub const fn from(system_table: &'static UefiSystemTable, image_handle: UefiHandle) -> Self {
        Self {
            system_table,
            image_handle,
        }
    }
}

impl KeyboardIn for UefiKeyboardIn {
    fn read_key(&self) -> KeyPress {
        match self
            .system_table
            .boot_services()
            .open_protocol::<UefiSimpleTextInputExtended>(
                self.system_table.console_in().handle(),
                self.image_handle,
                UefiHandle::NULL,
                UefiProtocolAttributes::BY_HANDLE_PROTOCOL,
            ) {
            Ok(p) => {
                let protocol = unsafe { p.as_mut().unwrap() };
                protocol.read_key_stroke().unwrap().into()
            }
            Err(_) => {
                let protocol_handle = self.system_table.console_in();
                let protocol = protocol_handle.protocol();
                KeyPress::from(
                    protocol.read_key_stroke().unwrap().into(),
                    ToggleKeys::NONE,
                    ModifierKeys::NONE,
                )
            }
        }
    }
}
