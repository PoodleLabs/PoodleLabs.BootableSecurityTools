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

use super::{UefiProtocol, UefiProtocolAttributes};
use crate::uefi::{
    boot_services::UefiBootServices,
    core_types::{UefiHandle, UefiStatusCode},
};
use core::ops::{Deref, DerefMut};

#[derive(Debug, Eq, PartialEq)]
pub(in crate::uefi) struct UefiScopedProtocol<'a, T: UefiProtocol> {
    protocol: &'a mut T,
    handle: UefiHandle,
    agent: UefiHandle,
    controller: UefiHandle,
    boot_services: &'a UefiBootServices,
}

impl<'a, T: UefiProtocol> UefiScopedProtocol<'a, T> {
    pub fn open_on(
        handle: UefiHandle,
        agent_handle: UefiHandle,
        boot_services: &'a UefiBootServices,
        controller_handle: Option<UefiHandle>,
    ) -> Result<Self, UefiStatusCode> {
        let controller_handle = match controller_handle {
            Some(h) => h,
            None => UefiHandle::NULL,
        };

        match boot_services.open_protocol::<T>(
            handle,
            agent_handle,
            controller_handle,
            UefiProtocolAttributes::EXCLUSIVE,
        ) {
            Ok(p) => Ok(Self {
                protocol: unsafe { p.as_mut().unwrap() },
                controller: controller_handle,
                agent: agent_handle,
                boot_services,
                handle,
            }),
            Err(c) => Err(c),
        }
    }

    pub fn protocol(&self) -> &T {
        &self.protocol
    }
}

impl<'a, T: UefiProtocol> Drop for UefiScopedProtocol<'a, T> {
    fn drop(&mut self) {
        assert_eq!(
            UefiStatusCode::SUCCESS,
            self.boot_services
                .close_protocol(self.handle, &T::guid(), self.agent, self.controller)
        )
    }
}

impl<'a, T: UefiProtocol> Deref for UefiScopedProtocol<'a, T> {
    type Target = T;

    #[track_caller]
    fn deref(&self) -> &Self::Target {
        self.protocol
    }
}

impl<'a, T: UefiProtocol> DerefMut for UefiScopedProtocol<'a, T> {
    #[track_caller]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.protocol
    }
}
