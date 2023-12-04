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

mod bios_parameters_blocks;

pub(in crate::filesystem) use bios_parameters_blocks::BiosParameterBlockFlags;

use self::bios_parameters_blocks::{
    Fat32BiosParameterBlock, FatBiosParameterBlock, FatBiosParameterBlockCommonFields,
};
use super::BootSectorExtendedBootSignature;
use core::mem::size_of;

pub trait FatBootSector<const N: usize, T: FatBiosParameterBlock> {
    fn boot_sector_body(&self) -> &FatBootSectorStart<T>;

    fn boot_code(&self) -> &FatBootCode<N>;
}

pub trait FatExtendedBootSector<const N: usize, T: FatBiosParameterBlock>:
    FatBootSector<N, T>
{
    fn extended_boot_signature(&self) -> &FatExtendedBootSignature;
}

struct Fat32BootSector {
    start: FatBootSectorStart<Fat32BiosParameterBlock>,
    tail: FatBootSectorExtendedTail<420>,
}

impl FatBootSector<420, Fat32BiosParameterBlock> for Fat32BootSector {
    fn boot_sector_body(&self) -> &FatBootSectorStart<Fat32BiosParameterBlock> {
        &self.start
    }

    fn boot_code(&self) -> &FatBootCode<420> {
        &self.tail.boot_code
    }
}

impl FatExtendedBootSector<420, Fat32BiosParameterBlock> for Fat32BootSector {
    fn extended_boot_signature(&self) -> &FatExtendedBootSignature {
        &self.tail.extended_boot_signature
    }
}

struct SmallFatNonExtendedBootSector {
    start: FatBootSectorStart<FatBiosParameterBlockCommonFields>,
    tail: FatBootCode<471>,
}

impl FatBootSector<471, FatBiosParameterBlockCommonFields> for SmallFatNonExtendedBootSector {
    fn boot_sector_body(&self) -> &FatBootSectorStart<FatBiosParameterBlockCommonFields> {
        &self.start
    }

    fn boot_code(&self) -> &FatBootCode<471> {
        &self.tail
    }
}

struct SmallFatExtendedBootSector {
    start: FatBootSectorStart<FatBiosParameterBlockCommonFields>,
    tail: FatBootSectorExtendedTail<448>,
}

impl FatBootSector<448, FatBiosParameterBlockCommonFields> for SmallFatExtendedBootSector {
    fn boot_sector_body(&self) -> &FatBootSectorStart<FatBiosParameterBlockCommonFields> {
        &self.start
    }

    fn boot_code(&self) -> &FatBootCode<448> {
        &self.tail.boot_code
    }
}

impl FatExtendedBootSector<448, FatBiosParameterBlockCommonFields> for SmallFatExtendedBootSector {
    fn extended_boot_signature(&self) -> &FatExtendedBootSignature {
        &self.tail.extended_boot_signature
    }
}

pub struct FatBootSectorStart<TBiosParametersBlock: FatBiosParameterBlock> {
    jump_boot: [u8; 3],
    oem_name: [u8; 8],
    bios_paramaters_block: TBiosParametersBlock,
    drive_number: u8,
    reserved: u8,
    extended_boot_signature: BootSectorExtendedBootSignature,
}

struct FatBootSectorExtendedTail<const N: usize> {
    extended_boot_signature: FatExtendedBootSignature,
    boot_code: FatBootCode<N>,
}

pub struct FatExtendedBootSignature {
    volume_id: [u8; 4],
    volume_label: [u8; 11],
    file_system_type: [u8; 8],
}

impl FatExtendedBootSignature {
    pub const NONDESCRIPT_FAT_FILE_SYSTEM_TYPE: &[u8; 8] = b"FAT     ";
    pub const FAT_12_FILE_SYSTEM_TYPE: &[u8; 8] = b"FAT12   ";
    pub const FAT_16_FILE_SYSTEM_TYPE: &[u8; 8] = b"FAT16   ";
    pub const FAT_32_FILE_SYSTEM_TYPE: &[u8; 8] = b"FAT32   ";
    pub const VOLUME_DEFAULT_LABEL: &[u8; 11] = b"NO NAME    ";

    pub fn file_system_type(&self) -> &[u8; 8] {
        &self.file_system_type
    }

    pub fn volume_label(&self) -> &[u8; 11] {
        &self.volume_label
    }

    pub fn volume_id(&self) -> &[u8; 4] {
        &self.volume_id
    }
}

pub struct FatBootCode<const N: usize> {
    boot_code: [u8; N],
    boot_sign: [u8; 2],
}

impl<const N: usize> FatBootCode<N> {
    fn boot_sign_is_valid(&self) -> bool {
        self.boot_sign() == 0xAA55
    }

    fn clone_boot_code(&self) -> [u8; N] {
        self.boot_code
    }

    fn boot_sign(&self) -> u16 {
        u16::from_le_bytes(self.boot_sign)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

fn get_fat_entry_byte_offset_and_sector<TEntry: Sized>(
    sector_size: usize,
    entry_index: usize,
) -> (usize, usize) {
    let entries_per_sector = sector_size / size_of::<TEntry>();
    let sector = entry_index / entries_per_sector;
    let offset = entry_index % entries_per_sector;
    ((sector_size * sector) + offset, sector)
}

fn try_read_fat_entry<TEntry: Sized + Clone + Copy, FPointerReader: Fn(usize) -> TEntry>(
    byte_reader: FPointerReader,
    fat_sector_count: usize,
    sector_size: usize,
    index: usize,
) -> Option<TEntry> {
    let (entry_byte_offset, sector) =
        get_fat_entry_byte_offset_and_sector::<TEntry>(sector_size, index);

    if sector >= fat_sector_count {
        None
    } else {
        Some((byte_reader)(entry_byte_offset))
    }
}

fn try_write_fat_entry<TEntry: Sized + Clone + Copy, FPointerWriter: Fn(usize, TEntry)>(
    byte_writer: FPointerWriter,
    fat_sector_count: usize,
    sector_size: usize,
    value: TEntry,
    index: usize,
) -> bool {
    let (entry_byte_offset, sector) =
        get_fat_entry_byte_offset_and_sector::<TEntry>(sector_size, index);

    if sector >= fat_sector_count {
        false
    } else {
        (byte_writer)(entry_byte_offset, value);
        true
    }
}
