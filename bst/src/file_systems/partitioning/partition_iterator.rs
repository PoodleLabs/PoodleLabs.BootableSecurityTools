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
    file_systems::{block_device::BlockDevice, partitioning::mbr::MbrPartitionType},
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

pub struct PartitionIterator {
    partition_array_type: PartitionArrayType,
    partition_array_bytes: Vec<u8>,
    next_index: usize,
}

impl PartitionIterator {
    pub fn try_from<'a, TBlockDevice: BlockDevice>(
        block_device: &'a mut TBlockDevice,
    ) -> Option<Self> {
        // Calculations for reading the MBR.
        let description = block_device.description();
        let mbr_size = size_of::<MasterBootRecord>();
        let block_size = description.block_size();

        let mbr_block_count = integers::ceil_div(mbr_size, block_size);
        let buffer_size = mbr_block_count * description.block_size();
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
                    buffer.truncate(size_of::<MbrPartitionTableEntry>() * 4);
                    Some(Self {
                        partition_array_bytes: buffer,
                        partition_array_type: t,
                        next_index: 0,
                    })
                }
                PartitionArrayType::Gpt(partition_table_block) => todo!(),
            },
            None => None,
        }
    }

    pub fn reset(&mut self) {
        self.next_index = 0;
    }
}
