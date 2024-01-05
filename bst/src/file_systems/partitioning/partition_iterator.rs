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
    gpt::GptPartitionDescriptor,
    mbr::{MasterBootRecord, MbrPartitionTableEntry},
    Partition,
};
use crate::{
    file_systems::{
        block_device::BlockDevice,
        partitioning::{gpt::GptHeader, mbr::MbrPartitionType},
    },
    integers,
};
use alloc::{vec, vec::Vec};
use core::mem::size_of;

enum PartitionArrayType {
    Mbr,
    Gpt(u64),
}

pub enum PartitionDescription<'a> {
    MbrPartition(&'a MbrPartitionTableEntry),
    GptPartition(&'a GptPartitionDescriptor),
}

pub struct PartitionIterator<'a> {
    iterator_method: fn(&mut Self) -> Option<PartitionDescription<'a>>,
    partition_array_bytes: Vec<u8>,
    entry_size: usize,
    next_index: usize,
}

impl<'a> PartitionIterator<'a> {
    pub fn try_from<TBlockDevice: BlockDevice>(block_device: &'a mut TBlockDevice) -> Option<Self> {
        // Calculations for reading the MBR.
        let description = block_device.description();
        let mbr_size = size_of::<MasterBootRecord>();
        let block_size = description.block_size();

        let mbr_block_count = integers::ceil_div(mbr_size, block_size);
        let buffer_size = mbr_block_count * block_size;
        let mut buffer = vec![0; buffer_size];

        // Read however many blocks we need for the MBR.
        if !block_device.read_blocks(description.media_id(), 0, &mut buffer) {
            // If reading fails, return nothing.
            return None;
        }

        // Extract the MBR from the read blocks.
        let mbr_offset = buffer_size - mbr_size;
        let master_boot_record = unsafe {
            (buffer.as_ptr().add(mbr_offset) as *const MasterBootRecord)
                .as_ref()
                .unwrap()
        };

        // Check the MBR is a valid MBR.
        if !master_boot_record.signature_is_valid() {
            return None;
        }

        let mut partition_type = None;
        for partition in master_boot_record.partitions() {
            if partition.is_empty() {
                // Skip empty partitions.
                continue;
            }

            // Base the partition type on the first non-empty partition.
            partition_type = Some(
                if partition.partition_type() == MbrPartitionType::GPT_PROTECTIVE {
                    PartitionArrayType::Gpt(partition.first_block())
                } else {
                    PartitionArrayType::Mbr
                },
            );

            break;
        }

        match partition_type {
            Some(t) => match t {
                PartitionArrayType::Mbr => {
                    // Remove the leading bytes from the buffer.
                    buffer.splice(0..mbr_offset, (0..1).into_iter().map(|_| 0));

                    // Trim the MBR signature off the end of the buffer.
                    buffer.resize(size_of::<MbrPartitionTableEntry>() * 4, 0);
                    Some(Self::from(t, buffer, size_of::<MbrPartitionTableEntry>()))
                }
                PartitionArrayType::Gpt(partition_table_header_block) => {
                    // Resize the buffer to read the GPT header table.
                    buffer.fill(0);
                    buffer.resize(
                        integers::ceil_div(size_of::<GptHeader>(), block_size) * block_size,
                        0,
                    );

                    // Read the GPT header blocks.
                    if !block_device.read_blocks(
                        description.media_id(),
                        partition_table_header_block,
                        &mut buffer,
                    ) {
                        // If reading fails, return nothing.
                        return None;
                    }

                    // Interpret the bytes at a GPT header.
                    let gpt_header =
                        unsafe { (buffer.as_ptr() as *const GptHeader).as_ref().unwrap() };

                    if !gpt_header.signature_is_valid() {
                        // If the signautre of the partition table header is invalid, return nothing.
                        return None;
                    }

                    // Resize the buffer for reading the partition table.
                    let partition_table_start_block = gpt_header.partition_table_start_block();
                    let partition_description_size = gpt_header.partition_description_size();
                    let partition_count = gpt_header.partition_count();

                    buffer.fill(0);
                    buffer.resize(
                        integers::ceil_div(
                            partition_description_size * partition_count,
                            block_size,
                        ) * block_size,
                        0,
                    );

                    // Read the partition table blocks.
                    if !block_device.read_blocks(
                        description.media_id(),
                        partition_table_start_block,
                        &mut buffer,
                    ) {
                        // If reading fails, return nothing.
                        return None;
                    }

                    Some(Self::from(t, buffer, partition_description_size))
                }
            },
            None => None,
        }
    }

    pub fn reset(&mut self) {
        self.next_index = 0;
    }

    fn from(
        partition_array_type: PartitionArrayType,
        partition_array_bytes: Vec<u8>,
        entry_size: usize,
    ) -> Self {
        // TODO: Select a function pointer to handle the partition table correctly based on the partition_array_bytes.
        Self {
            iterator_method: match partition_array_type {
                PartitionArrayType::Gpt(_) => Self::iter_gpt,
                PartitionArrayType::Mbr => Self::iter_mbr,
            },
            partition_array_bytes,
            next_index: 0,
            entry_size,
        }
    }

    fn iter_gpt(&mut self) -> Option<PartitionDescription<'a>> {
        let offset = self.next_index * self.entry_size;
        todo!()
    }

    fn iter_mbr(&mut self) -> Option<PartitionDescription<'a>> {
        let offset = self.next_index * self.entry_size;
        todo!()
    }
}

impl<'a> Iterator for PartitionIterator<'a> {
    type Item = PartitionDescription<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        (self.iterator_method)(self)
    }
}
