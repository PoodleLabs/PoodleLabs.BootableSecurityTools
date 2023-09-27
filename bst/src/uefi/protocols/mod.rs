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

pub(in crate::uefi) mod device_paths;
pub(in crate::uefi) mod text;

use super::core_types::{UefiGuid, UefiHandle};
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign};

pub(in crate::uefi) trait UefiProtocol {
    fn guid() -> &'static UefiGuid;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiProtocolHandle<T> {
    handle: UefiHandle,
    protocol: T,
}

impl<T> UefiProtocolHandle<T> {
    pub const fn protocol(&self) -> &T {
        &self.protocol
    }

    pub const fn handle(&self) -> UefiHandle {
        self.handle
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) enum UefiInterfaceType {
    NativeInterface,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiProtocolRegistrationHandle(usize);

impl UefiProtocolRegistrationHandle {
    pub const NULL: Self = Self(0);
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) enum UefiLocateSearchType {
    AllHandles,
    ByRegisterNotify,
    ByProtocol,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiProtocolAttributes(u32);

impl UefiProtocolAttributes {
    pub const BY_HANDLE_PROTOCOL: Self = Self(0x00000001);
    pub const GET_PROTOCOL: Self = Self(0x00000002);
    pub const TEST_PROTOCOL: Self = Self(0x00000004);
    pub const BY_CHILD_CONTROLLER: Self = Self(0x00000008);
    pub const BY_DRIVER: Self = Self(0x00000010);
    pub const EXCLUSIVE: Self = Self(0x00000020);
}

impl BitAnd for UefiProtocolAttributes {
    type Output = UefiProtocolAttributes;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for UefiProtocolAttributes {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = Self(rhs.0 & self.0)
    }
}

impl BitOr for UefiProtocolAttributes {
    type Output = UefiProtocolAttributes;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for UefiProtocolAttributes {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = Self(rhs.0 | self.0)
    }
}

impl BitXor for UefiProtocolAttributes {
    type Output = UefiProtocolAttributes;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for UefiProtocolAttributes {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = Self(rhs.0 ^ self.0)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiOpenProtocolInformation {
    agent_handle: UefiHandle,
    controller_handle: UefiHandle,
    attributes: UefiProtocolAttributes,
    open_count: u32,
}
