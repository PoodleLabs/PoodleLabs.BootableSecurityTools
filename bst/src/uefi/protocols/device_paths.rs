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

use super::UefiProtocol;
use crate::uefi::core_types::{UefiGuid, UefiString};
use alloc::sync::Arc;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiDevicePath<'a> {
    device_path: &'a UefiDevicePathProtocol,
    text_protocol: &'a UefiDevicePathToTextProtocol,
}

impl<'a> UefiDevicePath<'a> {
    pub const fn from(
        device_path: &'a UefiDevicePathProtocol,
        text_protocol: &'a UefiDevicePathToTextProtocol,
    ) -> Self {
        Self {
            device_path,
            text_protocol,
        }
    }
}

impl<'a> Into<Arc<[u16]>> for UefiDevicePath<'a> {
    fn into(self) -> Arc<[u16]> {
        (self.text_protocol.convert_device_node_to_text)(self.device_path, true, true).into()
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiDevicePathProtocol {
    device_path_part_type: u8,
    device_path_part_sub_type: u8,
    length: [u8; 2],
    // Length - 4 bytes of content beyond this.
}

impl UefiDevicePathProtocol {
    pub const GUID: UefiGuid = UefiGuid::from(
        0x09576e91,
        0x6d3f,
        0x11d2,
        0x8e,
        0x39,
        [0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );

    pub const fn to_writeable<'a>(
        &'a self,
        to_text_protocol: &'a UefiDevicePathToTextProtocol,
    ) -> UefiDevicePath {
        UefiDevicePath::from(self, to_text_protocol)
    }
}

impl UefiProtocol for UefiDevicePathProtocol {
    fn guid() -> &'static UefiGuid {
        &Self::GUID
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiDevicePathToTextProtocol {
    convert_device_node_to_text: extern "efiapi" fn(
        device_node: &UefiDevicePathProtocol,
        allow_shortening: bool,
        allow_shortcuts: bool,
    ) -> UefiString,
    convert_device_path_to_text: extern "efiapi" fn(
        device_node: &UefiDevicePathProtocol,
        allow_shortening: bool,
        allow_shortcuts: bool,
    ) -> UefiString,
}

impl UefiDevicePathToTextProtocol {
    pub const GUID: UefiGuid = UefiGuid::from(
        0x8b843e20,
        0x8132,
        0x4852,
        0x90,
        0xcc,
        [0x55, 0x1a, 0x4e, 0x4a, 0x7f, 0x1c],
    );
}

impl UefiProtocol for UefiDevicePathToTextProtocol {
    fn guid() -> &'static UefiGuid {
        &Self::GUID
    }
}
