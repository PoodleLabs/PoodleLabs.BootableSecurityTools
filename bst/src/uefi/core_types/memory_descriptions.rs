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

use crate::bits::bit_field;

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiPhysicalAddress(u64);

impl Into<usize> for UefiPhysicalAddress {
    fn into(self) -> usize {
        self.0 as usize
    }
}

impl From<usize> for UefiPhysicalAddress {
    fn from(value: usize) -> Self {
        Self(value as u64)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiVirtualAddress(u64);

impl Into<usize> for UefiVirtualAddress {
    fn into(self) -> usize {
        self.0 as usize
    }
}

impl From<usize> for UefiVirtualAddress {
    fn from(value: usize) -> Self {
        Self(value as u64)
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) enum UefiAllocateType {
    AnyPages,
    MaxAddress,
    Address,
    Max,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) enum UefiMemoryType {
    Reserved,
    LoaderCode,
    LoaderData,
    BootServicesCode,
    BootServicesData,
    RuntimeServicesCode,
    RuntimeServicesData,
    Conventional,
    Unusable,
    ACPIReclaim,
    ACPIMemoryNVS,
    MemoryMappedIO,
    MemoryMappedIOPortSpace,
    PalCode,
    Persistent,
    Unaccepted,
    Max,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiMemoryAttributes(u64);

impl UefiMemoryAttributes {
    pub const UC_ATTRIBUTE_FLAG: Self = Self(0x0000000000000001);
    pub const WC_ATTRIBUTE_FLAG: Self = Self(0x0000000000000002);
    pub const WT_ATTRIBUTE_FLAG: Self = Self(0x0000000000000004);
    pub const WB_ATTRIBUTE_FLAG: Self = Self(0x0000000000000008);
    pub const UCE_ATTRIBUTE_FLAG: Self = Self(0x0000000000000010);
    pub const WP_ATTRIBUTE_FLAG: Self = Self(0x0000000000001000);
    pub const RP_ATTRIBUTE_FLAG: Self = Self(0x0000000000002000);
    pub const XP_ATTRIBUTE_FLAG: Self = Self(0x0000000000004000);
    pub const NV_ATTRIBUTE_FLAG: Self = Self(0x0000000000008000);
    pub const MORE_RELIABLE_ATTRIBUTE_FLAG: Self = Self(0x0000000000010000);
    pub const RO_ATTRIBUTE_FLAG: Self = Self(0x0000000000020000);
    pub const SP_ATTRIBUTE_FLAG: Self = Self(0x0000000000040000);
    pub const CPU_CRYPTO_ATTRIBUTE_FLAG: Self = Self(0x0000000000080000);
    pub const RUNTIME_ATTRIBUTE_FLAG: Self = Self(0x8000000000000000);
    pub const ISA_VALID_ATTRIBUTE_FLAG: Self = Self(0x4000000000000000);
    pub const ISA_MASK_ATTRIBUTE_FLAG: Self = Self(0x0FFFF00000000000);
}

bit_field!(UefiMemoryAttributes);

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiMemoryDescriptor {
    memory_type: UefiMemoryType,
    physical_start: UefiPhysicalAddress,
    virtual_address: UefiVirtualAddress,
    number_of_bages: u64,
    attributes: u64,
}
