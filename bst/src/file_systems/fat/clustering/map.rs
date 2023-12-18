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
    bits::{try_copy, BitTarget},
    file_systems::{block_device::BlockDevice, fat},
};
use core::{
    marker::PhantomData,
    mem::size_of,
    ops::{
        BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Shl, ShlAssign, Shr,
        ShrAssign,
    },
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EntryType {
    Free,
    Reserved,
    Link,
    BadCluster,
    EndOfChain,
}

pub trait Entry: BitTarget + Into<usize> {
    fn volume_dirty_flag() -> Self;

    fn hard_error_flag() -> Self;

    fn end_of_chain() -> Self;

    fn bad_cluster() -> Self;

    fn reserved() -> Self;

    fn free() -> Self;

    fn try_read_from(map: &[u8], index: usize) -> Option<Self>;

    fn try_write_to(&self, map: &mut [u8], index: usize) -> bool;

    fn check_media_bits(&self, media_bits: u8) -> bool;

    fn check_error_bits(&self) -> fat::Errors;

    fn entry_type(&self) -> EntryType;
}

macro_rules! map_entry {
    ($($name:ident:$underlying:ident:$bit_count:literal;$reserved_bit_count:literal($free:literal, $reserved:literal, $bad_cluster:literal, $end_of_chain:literal, $mask:literal),)*) => {
        $(
            #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
            pub struct $name($underlying);

            impl $name {
                pub const RESERVED_BIT_COUNT: usize = $reserved_bit_count;
                pub const BIT_COUNT: usize = $bit_count;
                pub const MASK: $underlying = $mask;

                pub const END_OF_CHAIN: Self = Self($end_of_chain);
                pub const BAD_CLUSTER: Self = Self($bad_cluster);
                pub const RESERVED: Self = Self($reserved);
                pub const FREE: Self = Self($free);

                pub const VOLUME_DIRTY_FLAG: Self = Self(0b01);
                pub const HARD_ERROR_FLAG: Self = Self(0b10);

                // These values are used for reading/writing bits from/to disk.
                // We need to account reserved bits, as with the first 4 bits of FAT32 map entries, as well as
                // extra bits from the underlying storage type, as with the first 4 bits of FAT12 backed by u16s in memory.
                // These are handled differently; the former takes up space on disk, but the latter does not.
                const BIT_OFFSET: usize = Self::RESERVED_BIT_COUNT + ((size_of::<$underlying>() * 8) - Self::BIT_COUNT);
                const MUTABLE_BITS: usize = Self::BIT_COUNT - Self::RESERVED_BIT_COUNT;

                const ALWAYS_HIGH_ERROR_BITS: $underlying = Self::MASK ^ 0b11;
                const VOLUME_DIRTY_BIT: $underlying = 0b01;
                const HARD_ERROR_BIT: $underlying = 0b10;
            }

            impl BitAnd<Self> for $name {
                type Output = Self;

                fn bitand(self, rhs: Self) -> Self {
                    Self(self.0 & rhs.0)
                }
            }

            impl BitAndAssign<Self> for $name {
                fn bitand_assign(&mut self, rhs: Self) {
                    self.0 &= rhs.0
                }
            }

            impl BitXor<Self> for $name {
                type Output = Self;

                fn bitxor(self, rhs: Self) -> Self {
                    Self(self.0 ^ rhs.0)
                }
            }

            impl BitXorAssign<Self> for $name {
                fn bitxor_assign(&mut self, rhs: Self) {
                    self.0 ^= rhs.0
                }
            }

            impl BitOr<Self> for $name {
                type Output = Self;

                fn bitor(self, rhs: Self) -> Self {
                    Self(self.0 | rhs.0)
                }
            }

            impl BitOrAssign<Self> for $name {
                fn bitor_assign(&mut self, rhs: Self) {
                    self.0 |= rhs.0
                }
            }

            impl Not for $name {
                type Output = Self;

                fn not(self) -> Self {
                    Self(!self.0)
                }
            }

            impl Shl<usize> for $name {
                type Output = Self;

                fn shl(self, rhs: usize) -> Self {
                    Self(self.0 << rhs)
                }
            }

            impl ShlAssign<usize> for $name {
                fn shl_assign(&mut self, rhs: usize) {
                    self.0 <<= rhs
                }
            }

            impl Shr<usize> for $name {
                type Output = Self;

                fn shr(self, rhs: usize) -> Self {
                    Self(self.0 >> rhs)
                }
            }

            impl ShrAssign<usize> for $name {
                fn shr_assign(&mut self, rhs: usize) {
                    self.0 >>= rhs
                }
            }

            impl Shl<Self> for $name {
                type Output = Self;

                fn shl(self, rhs: Self) -> Self {
                    Self(self.0 << rhs.0)
                }
            }

            impl ShlAssign<Self> for $name {
                fn shl_assign(&mut self, rhs: Self) {
                    self.0 <<= rhs.0
                }
            }

            impl Shr<Self> for $name {
                type Output = Self;

                fn shr(self, rhs: Self) -> Self {
                    Self(self.0 >> rhs.0)
                }
            }

            impl ShrAssign<Self> for $name {
                fn shr_assign(&mut self, rhs: Self) {
                    self.0 >>= rhs.0
                }
            }

            impl BitTarget for $name {
                fn bits_per_digit() -> usize {
                    $bit_count
                }

                fn shift_start() -> Self {
                    Self(1 << ($bit_count - 1))
                }

                fn zero() -> Self {
                    Self(0)
                }

                fn one() -> Self {
                    Self(1)
                }
            }

            impl Into<usize> for $name {
                fn into(self) -> usize {
                    self.0 as usize
                }
            }

            impl Entry for $name {
                fn volume_dirty_flag() -> Self {
                    Self::VOLUME_DIRTY_FLAG
                }

                fn hard_error_flag() -> Self {
                    Self::HARD_ERROR_FLAG
                }

                fn end_of_chain() -> Self {
                    Self::END_OF_CHAIN
                }

                fn bad_cluster() -> Self {
                    Self::BAD_CLUSTER
                }

                fn reserved() -> Self {
                    Self::RESERVED
                }

                fn free() -> Self {
                    Self::FREE
                }

                fn try_read_from(map: &[u8], index: usize) -> Option<Self> {
                    // Prepare a buffer to read into.
                    let mut buffer: [$underlying; 1] = [0];
                    if try_copy(
                        map,
                        (index * Self::BIT_COUNT) + Self::RESERVED_BIT_COUNT,
                        &mut buffer,
                        Self::BIT_OFFSET,
                        Self::MUTABLE_BITS,
                    ) {
                        Some(Self(buffer[0]))
                    }
                    else {
                        None
                    }
                }

                fn try_write_to(&self, map: &mut [u8], index: usize) -> bool {
                    // Prepare a buffer to read form.
                    let buffer = [ self.0 ];
                    try_copy(
                        &buffer,
                        Self::BIT_OFFSET,
                        map,
                        (index * Self::BIT_COUNT) + Self::RESERVED_BIT_COUNT,
                        Self::MUTABLE_BITS,
                    )
                }

                fn check_media_bits(&self, media_bits: u8) -> bool {
                    self.0 == (Self::MASK & (media_bits as $underlying))
                }

                fn check_error_bits(&self) -> fat::Errors {
                    // Check all bits save the error bits are high.
                    if (self.0 & Self::ALWAYS_HIGH_ERROR_BITS) != Self::ALWAYS_HIGH_ERROR_BITS {
                        fat::Errors::InvalidErrorFatEntry
                    } else if (self.0 & Self::HARD_ERROR_BIT) != Self::HARD_ERROR_BIT
                    {
                        fat::Errors::HardError
                    } else if (self.0 & Self::VOLUME_DIRTY_BIT) != Self::VOLUME_DIRTY_BIT
                    {
                        fat::Errors::VolumeDirty
                    } else {
                        fat::Errors::None
                    }
                }

                fn entry_type(&self) -> EntryType {
                    match self.0 {
                        $free => EntryType::Free,
                        $reserved => EntryType::Reserved,
                        $bad_cluster => EntryType::BadCluster,
                        _ => {
                            if self.0 > $bad_cluster {
                                EntryType::EndOfChain
                            } else {
                                EntryType::Link
                            }
                        }
                    }
                }
            }
        )*
    };

}

map_entry!(
    Entry12:u16:12;0(0, 1, 0x0FF7, 0x0FFF, 0x0FFF),
    Entry16:u16:16;0(0, 1, 0xFFF7, 0xFFFF, 0xFFFF),
    Entry32:u32:32;4(0, 1, 0x0FFFFFF7, 0x0FFFFFFF, 0x0FFFFFFF),
);

pub struct LinearIterator<'a, TBlockDevice: BlockDevice, TEntry: Entry> {
    volume_parameters: &'a fat::clustering::VolumeParameters<'a, TBlockDevice>,
    phantom_data: PhantomData<TEntry>,
    next_index: usize,
}

impl<'a, TBlockDevice: BlockDevice, TEntry: Entry> LinearIterator<'a, TBlockDevice, TEntry> {
    pub const fn from(
        volume_parameters: &'a fat::clustering::VolumeParameters<'a, TBlockDevice>,
        next_index: usize,
    ) -> Self {
        Self {
            phantom_data: PhantomData,
            volume_parameters,
            next_index,
        }
    }
}

impl<'a, TBlockDevice: BlockDevice, TEntry: Entry> Iterator
    for LinearIterator<'a, TBlockDevice, TEntry>
{
    type Item = TEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let entry =
            match TEntry::try_read_from(self.volume_parameters.active_map_bytes(), self.next_index)
            {
                Some(e) => e,
                None => return None,
            };

        self.next_index += 1;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let entries = (self.volume_parameters.map_size() * 8) / TEntry::bits_per_digit();
        (entries, Some(entries))
    }
}

pub struct ChainIterator<'a, TBlockDevice: BlockDevice, TEntry: Entry> {
    volume_parameters: &'a fat::clustering::VolumeParameters<'a, TBlockDevice>,
    phantom_data: PhantomData<TEntry>,
    next_index: usize,
}

impl<'a, TBlockDevice: BlockDevice, TEntry: Entry> ChainIterator<'a, TBlockDevice, TEntry> {
    pub const fn from(
        volume_parameters: &'a fat::clustering::VolumeParameters<'a, TBlockDevice>,
        next_index: usize,
    ) -> Self {
        Self {
            phantom_data: PhantomData,
            volume_parameters,
            next_index,
        }
    }
}

impl<'a, TBlockDevice: BlockDevice, TEntry: Entry> Iterator
    for ChainIterator<'a, TBlockDevice, TEntry>
{
    type Item = TEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let entry =
            match TEntry::try_read_from(self.volume_parameters.active_map_bytes(), self.next_index)
            {
                Some(e) => e,
                None => return None,
            };

        self.next_index = entry.into();
        Some(entry)
    }
}
