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
mod boot_sectors;

use crate::file_systems::{block_device::BlockDevice, fat};
use alloc::vec;
use bios_parameters_blocks::BiosParameterBlock;
use boot_sectors::BootSector;
use core::mem::size_of;

pub fn try_read_volume_cluster_parameters<'a, TBlockDevice: BlockDevice>(
    block_device: &'a mut TBlockDevice,
) -> Option<(
    fat::Variant,
    fat::clustering::VolumeParameters<'a, TBlockDevice>,
)> {
    // Ensure the media actually exists.
    if !block_device.description().media_present() {
        return None;
    }

    // Prepare a buffer to read the
    let mut buffer = vec![
        0u8;
        size_of::<boot_sectors::BootSectorSmall>().max(
            size_of::<boot_sectors::BootSectorSmallExtended>()
                .max(size_of::<boot_sectors::BootSector32>())
        )
    ];

    // Capture the media id.
    let media_id = block_device.description().media_id();

    // Read the head of the volume.
    if !block_device.read_bytes(media_id, 0, &mut buffer) {
        return None;
    }

    // First interpret the device as having a FAT12/16 non-extended layout.
    // The BPB should always line up if we're reading an actual FAT volume.
    // We can use this to determine the layout we need to read with.
    let small_fat_non_extended =
        unsafe { (buffer.as_ptr() as *const boot_sectors::BootSectorSmall).as_ref() }.unwrap();

    // Check whether the layout includes an extended boot signature.
    let extended = match small_fat_non_extended.body().extended_indicator() {
        boot_sectors::ExtendedBootSignatureIndicator::V4_0 => false,
        boot_sectors::ExtendedBootSignatureIndicator::V4_1 => true,
        boot_sectors::ExtendedBootSignatureIndicator::V8_0 => true,
        _ => {
            return None;
        }
    };

    // Work out the FAT variant to expect.
    let variant = small_fat_non_extended
        .body()
        .bios_parameters_block()
        .variant();

    match variant {
        fat::Variant::Fat12 => {
            match read_small_fat_volume_parameters(block_device, extended, media_id, &buffer) {
                Some(p) => Some((fat::Variant::Fat12, p)),
                None => None,
            }
        }
        fat::Variant::Fat16 => {
            match read_small_fat_volume_parameters(block_device, extended, media_id, &buffer) {
                Some(p) => Some((fat::Variant::Fat16, p)),
                None => None,
            }
        }
        fat::Variant::Fat32 => {
            if !extended {
                // A FAT32 volume must always have an extended boot signature; the volume is invalid or not FAT
                // at all, and incidentally got here.
                None
            } else {
                let boot_sector =
                    unsafe { (buffer.as_ptr() as *const boot_sectors::BootSector32).as_ref() }
                        .unwrap();

                match volume_parameters_from_boot_sector(
                    block_device,
                    boot_sector.body().bios_parameters_block().root_cluster() as usize,
                    boot_sector,
                    media_id,
                ) {
                    Some(p) => Some((fat::Variant::Fat32, p)),
                    None => None,
                }
            }
        }
    }
}

fn read_small_fat_volume_parameters<'a, TBlockDevice: BlockDevice>(
    block_device: &'a mut TBlockDevice,
    extended: bool,
    media_id: u32,
    buffer: &[u8],
) -> Option<fat::clustering::VolumeParameters<'a, TBlockDevice>> {
    if extended {
        let boot_sector =
            unsafe { (buffer.as_ptr() as *const boot_sectors::BootSectorSmallExtended).as_ref() }
                .unwrap();

        volume_parameters_from_boot_sector(
            block_device,
            boot_sector
                .body()
                .bios_parameters_block()
                .root_directory_entries() as usize,
            boot_sector,
            media_id,
        )
    } else {
        let boot_sector =
            unsafe { (buffer.as_ptr() as *const boot_sectors::BootSectorSmall).as_ref() }.unwrap();

        volume_parameters_from_boot_sector(
            block_device,
            boot_sector
                .body()
                .bios_parameters_block()
                .root_directory_entries() as usize,
            boot_sector,
            media_id,
        )
    }
}

fn volume_parameters_from_boot_sector<
    'a,
    const N: usize,
    TBlockDevice: BlockDevice,
    TBiosParameterBlock: bios_parameters_blocks::BiosParameterBlock,
    TBootSector: boot_sectors::BootSector<N, TBiosParameterBlock>,
>(
    block_device: &'a mut TBlockDevice,
    root_directory_value: usize,
    boot_sector: &TBootSector,
    media_id: u32,
) -> Option<fat::clustering::VolumeParameters<'a, TBlockDevice>> {
    if !boot_sector.boot_code().boot_sign_is_valid() {
        // Invalid boot sign; we can't read the parameters safely.
        return None;
    }

    let bpb = boot_sector.body().bios_parameters_block();
    Some(fat::clustering::VolumeParameters::from(
        block_device,
        root_directory_value,
        bpb.sectors_per_cluster() as usize,
        match bpb.active_map() {
            Some(m) => Some(m as usize),
            None => None,
        },
        bpb.bytes_per_sector() as usize,
        bpb.reserved_sectors() as usize,
        bpb.sectors_per_map() as usize,
        bpb.total_sectors() as usize,
        bpb.map_count() as usize,
        bpb.media_type(),
        media_id,
    ))
}
