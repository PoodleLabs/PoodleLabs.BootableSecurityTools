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

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExtendedBootSignatureIndicator {
    V4_0 = 0x28,
    V4_1 = 0x29,
    V8_0 = 0x80,
}

impl ExtendedBootSignatureIndicator {
    pub const fn has_extended_fields(&self) -> bool {
        *self as u8 >= 0x29
    }
}

#[repr(C)]
pub struct BootCode<const N: usize> {
    boot_code: [u8; N],
    boot_sign: [u8; 2],
}

impl<const N: usize> BootCode<N> {
    pub const fn boot_sign_is_valid(&self) -> bool {
        self.boot_sign() == 0xAA55
    }

    pub const fn clone_boot_code(&self) -> [u8; N] {
        self.boot_code
    }

    pub const fn boot_sign(&self) -> u16 {
        u16::from_le_bytes(self.boot_sign)
    }
}

#[repr(C)]
pub struct ExtendedBootSignature {
    volume_id: [u8; 4],
    volume_label: [u8; 11],
    file_system_type: [u8; 8],
}

impl ExtendedBootSignature {
    pub const NONDESCRIPT_FAT_FILE_SYSTEM_TYPE: &[u8; 8] = b"FAT     ";
    pub const FAT_12_FILE_SYSTEM_TYPE: &[u8; 8] = b"FAT12   ";
    pub const FAT_16_FILE_SYSTEM_TYPE: &[u8; 8] = b"FAT16   ";
    pub const FAT_32_FILE_SYSTEM_TYPE: &[u8; 8] = b"FAT32   ";
    pub const VOLUME_DEFAULT_LABEL: &[u8; 11] = b"NO NAME    ";

    pub const fn file_system_type(&self) -> &[u8; 8] {
        &self.file_system_type
    }

    pub const fn volume_label(&self) -> &[u8; 11] {
        &self.volume_label
    }

    pub const fn volume_id(&self) -> &[u8; 4] {
        &self.volume_id
    }
}

#[repr(C)]
pub struct Body<T: super::bios_parameters_blocks::BiosParameterBlock> {
    jump_boot: [u8; 3],
    oem_name: [u8; 8],
    bios_parameters_block: T,
    drive_number: u8,
    reserved: u8,
    extended_indicator: ExtendedBootSignatureIndicator,
}

impl<T: super::bios_parameters_blocks::BiosParameterBlock> Body<T> {
    pub const fn bios_parameters_block(&self) -> &T {
        &self.bios_parameters_block
    }

    pub const fn extended_indicator(&self) -> ExtendedBootSignatureIndicator {
        self.extended_indicator
    }
}

#[repr(C)]
pub struct ExtendedTail<const N: usize> {
    extended_boot_signature: ExtendedBootSignature,
    boot_code: BootCode<N>,
}

pub trait BootSector<const N: usize, T: super::bios_parameters_blocks::BiosParameterBlock> {
    fn body(&self) -> &Body<T>;

    fn boot_code(&self) -> &BootCode<N>;
}

pub trait ExtendedBootSector<const N: usize, T: super::bios_parameters_blocks::BiosParameterBlock>:
    BootSector<N, T>
{
    fn extended_boot_signature(&self) -> &ExtendedBootSignature;
}

#[repr(C)]
pub struct BootSector32 {
    start: Body<super::bios_parameters_blocks::Fat32BiosParameterBlock>,
    tail: ExtendedTail<420>,
}

impl BootSector<420, super::bios_parameters_blocks::Fat32BiosParameterBlock> for BootSector32 {
    fn body(&self) -> &Body<super::bios_parameters_blocks::Fat32BiosParameterBlock> {
        &self.start
    }

    fn boot_code(&self) -> &BootCode<420> {
        &self.tail.boot_code
    }
}

impl ExtendedBootSector<420, super::bios_parameters_blocks::Fat32BiosParameterBlock>
    for BootSector32
{
    fn extended_boot_signature(&self) -> &ExtendedBootSignature {
        &self.tail.extended_boot_signature
    }
}

#[repr(C)]
pub struct BootSectorSmall {
    start: Body<super::bios_parameters_blocks::FatBiosParameterBlockCommonFields>,
    tail: BootCode<471>,
}

impl BootSector<471, super::bios_parameters_blocks::FatBiosParameterBlockCommonFields>
    for BootSectorSmall
{
    fn body(&self) -> &Body<super::bios_parameters_blocks::FatBiosParameterBlockCommonFields> {
        &self.start
    }

    fn boot_code(&self) -> &BootCode<471> {
        &self.tail
    }
}

#[repr(C)]
pub struct BootSectorSmallExtended {
    start: Body<super::bios_parameters_blocks::FatBiosParameterBlockCommonFields>,
    tail: ExtendedTail<448>,
}

impl BootSector<448, super::bios_parameters_blocks::FatBiosParameterBlockCommonFields>
    for BootSectorSmallExtended
{
    fn body(&self) -> &Body<super::bios_parameters_blocks::FatBiosParameterBlockCommonFields> {
        &self.start
    }

    fn boot_code(&self) -> &BootCode<448> {
        &self.tail.boot_code
    }
}

impl ExtendedBootSector<448, super::bios_parameters_blocks::FatBiosParameterBlockCommonFields>
    for BootSectorSmallExtended
{
    fn extended_boot_signature(&self) -> &ExtendedBootSignature {
        &self.tail.extended_boot_signature
    }
}
