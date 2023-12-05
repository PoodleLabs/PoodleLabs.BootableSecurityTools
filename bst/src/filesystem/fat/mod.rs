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

use crate::bits::{try_get_bit_at_index, BitTarget};

use self::bios_parameters_blocks::{
    Fat32BiosParameterBlock, FatBiosParameterBlock, FatBiosParameterBlockCommonFields,
};
use super::BootSectorExtendedBootSignature;
use core::{mem::size_of, slice};

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

    fn file_system_type(&self) -> &[u8; 8] {
        &self.file_system_type
    }

    fn volume_label(&self) -> &[u8; 11] {
        &self.volume_label
    }

    fn volume_id(&self) -> &[u8; 4] {
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

trait FatEntry: Sized + Copy + TryFrom<u32> + Into<u32> {
    fn try_read_from<
        const N: usize,
        TBiosParametersBlock: FatBiosParameterBlock,
        TBootSector: FatBootSector<N, TBiosParametersBlock>,
    >(
        index: usize,
        pointer: *const u8,
        boot_sector: &TBootSector,
    ) -> Option<Self>;

    fn try_write_to<
        const N: usize,
        TBiosParametersBlock: FatBiosParameterBlock,
        TBootSector: FatBootSector<N, TBiosParametersBlock>,
    >(
        &self,
        index: usize,
        pointer: *mut u8,
        boot_sector: &TBootSector,
    ) -> bool;
}

#[derive(Debug, Copy, Clone)]
struct FatEntryOutOfRangeError {
    value: u32,
    max: u32,
}

#[derive(Debug, Copy, Clone)]
struct Fat12Entry(u16);

impl Fat12Entry {
    const BIT_MASK: u32 = 0b111111111111;
}

impl TryFrom<u32> for Fat12Entry {
    type Error = FatEntryOutOfRangeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > Self::BIT_MASK {
            Err(FatEntryOutOfRangeError {
                max: Self::BIT_MASK,
                value,
            })
        } else {
            Ok(Self(value as u16))
        }
    }
}

impl Into<u32> for Fat12Entry {
    fn into(self) -> u32 {
        self.0 as u32
    }
}

impl FatEntry for Fat12Entry {
    fn try_read_from<
        const N: usize,
        TBiosParametersBlock: FatBiosParameterBlock,
        TBootSector: FatBootSector<N, TBiosParametersBlock>,
    >(
        index: usize,
        pointer: *const u8,
        boot_sector: &TBootSector,
    ) -> Option<Self> {
        let bpb = &boot_sector.boot_sector_body().bios_paramaters_block;
        let fat_byte_count = bpb.sectors_per_fat() as usize * bpb.bytes_per_sector() as usize;
        let fat_bit_count = fat_byte_count * 8;
        let fat_entry_count = fat_bit_count / 12;
        if index >= fat_entry_count {
            return None;
        }

        let mut aggregate = 0u16;
        let bit_index = index * 12;
        let shift_start = 1u16 << 11;
        let slice = unsafe { slice::from_raw_parts(pointer, fat_byte_count) };
        for i in bit_index..bit_index + 12 {
            if try_get_bit_at_index(i, slice).unwrap() {
                aggregate |= shift_start >> (i - bit_index);
            }
        }

        Some(Self(aggregate))
    }

    fn try_write_to<
        const N: usize,
        TBiosParametersBlock: FatBiosParameterBlock,
        TBootSector: FatBootSector<N, TBiosParametersBlock>,
    >(
        &self,
        index: usize,
        pointer: *mut u8,
        boot_sector: &TBootSector,
    ) -> bool {
        todo!()
    }
}

#[derive(Debug, Copy, Clone)]
struct Fat16Entry(u16);

impl Fat16Entry {
    const BIT_MASK: u32 = 0b1111111111111111;
}

impl TryFrom<u32> for Fat16Entry {
    type Error = FatEntryOutOfRangeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > Self::BIT_MASK {
            Err(FatEntryOutOfRangeError {
                max: Self::BIT_MASK,
                value,
            })
        } else {
            Ok(Self(value as u16))
        }
    }
}

impl Into<u32> for Fat16Entry {
    fn into(self) -> u32 {
        self.0 as u32
    }
}

fn get_byte_aligned_fat_entry_byte_offset_and_sector<TEntry: Sized>(
    sector_size: usize,
    entry_index: usize,
) -> (usize, usize) {
    let entries_per_sector = sector_size / size_of::<TEntry>();
    let sector = entry_index / entries_per_sector;
    let offset = entry_index % entries_per_sector;
    (
        (sector_size * sector) + (offset * size_of::<TEntry>()),
        sector,
    )
}

fn read_byte_aligned_fat_entry<
    const N: usize,
    TBiosParametersBlock: FatBiosParameterBlock,
    TBootSector: FatBootSector<N, TBiosParametersBlock>,
    TEntry: Sized + Copy,
>(
    index: usize,
    pointer: *const u8,
    boot_sector: &TBootSector,
) -> Option<TEntry> {
    let bpb = &boot_sector.boot_sector_body().bios_paramaters_block;
    let (byte_offset, sector) = get_byte_aligned_fat_entry_byte_offset_and_sector::<TEntry>(
        bpb.bytes_per_sector() as usize,
        index,
    );

    if sector >= bpb.sectors_per_fat() as usize {
        return None;
    }

    let byte_offset = byte_offset + bpb.fat_start_sector() as usize;
    Some(unsafe { *(pointer.add(byte_offset) as *const TEntry) })
}

impl FatEntry for Fat16Entry {
    fn try_read_from<
        const N: usize,
        TBiosParametersBlock: FatBiosParameterBlock,
        TBootSector: FatBootSector<N, TBiosParametersBlock>,
    >(
        index: usize,
        pointer: *const u8,
        boot_sector: &TBootSector,
    ) -> Option<Self> {
        match read_byte_aligned_fat_entry(index, pointer, boot_sector) {
            Some(e) => Some(e),
            None => None,
        }
    }

    fn try_write_to<
        const N: usize,
        TBiosParametersBlock: FatBiosParameterBlock,
        TBootSector: FatBootSector<N, TBiosParametersBlock>,
    >(
        &self,
        index: usize,
        pointer: *mut u8,
        boot_sector: &TBootSector,
    ) -> bool {
        todo!()
    }
}

#[derive(Debug, Copy, Clone)]
struct Fat32Entry(u32);

impl Fat32Entry {
    const BIT_MASK: u32 = 0b1111111111111111111111111111;
}

impl TryFrom<u32> for Fat32Entry {
    type Error = FatEntryOutOfRangeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > Self::BIT_MASK {
            Err(FatEntryOutOfRangeError {
                max: Self::BIT_MASK,
                value,
            })
        } else {
            Ok(Self(value))
        }
    }
}

impl Into<u32> for Fat32Entry {
    fn into(self) -> u32 {
        self.0 as u32
    }
}

impl FatEntry for Fat32Entry {
    fn try_read_from<
        const N: usize,
        TBiosParametersBlock: FatBiosParameterBlock,
        TBootSector: FatBootSector<N, TBiosParametersBlock>,
    >(
        index: usize,
        pointer: *const u8,
        boot_sector: &TBootSector,
    ) -> Option<Self> {
        match read_byte_aligned_fat_entry::<N, _, _, u32>(index, pointer, boot_sector) {
            Some(e) => Some(Self(e & Self::BIT_MASK)),
            None => None,
        }
    }

    fn try_write_to<
        const N: usize,
        TBiosParametersBlock: FatBiosParameterBlock,
        TBootSector: FatBootSector<N, TBiosParametersBlock>,
    >(
        &self,
        index: usize,
        pointer: *mut u8,
        boot_sector: &TBootSector,
    ) -> bool {
        todo!()
    }
}
