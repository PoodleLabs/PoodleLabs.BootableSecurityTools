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

use crate::file_systems::fat;
use bios_parameters_blocks::BiosParameterBlock;
use boot_sectors::BootSector;

pub fn try_read_volume_cluster_parameters(
    volume_root: *const u8,
) -> Option<(fat::Variant, fat::clustering::VolumeParameters)> {
    // First interpret the volume root as a FAT12/16 non-extended layout.
    // The BPB should always line up if we're reading an actual FAT volume.
    // We can use this to determine the layout we need to read with.
    let small_fat_non_extended =
        unsafe { (volume_root as *const boot_sectors::BootSectorSmall).as_ref() }.unwrap();

    // Check whether the layout includes an extended boot signature.
    let extended = match small_fat_non_extended.body().extended_indicator() {
        boot_sectors::ExtendedBootSignatureIndicator::V4_0 => false,
        boot_sectors::ExtendedBootSignatureIndicator::V4_1 => true,
        _ => return None,
    };

    // Work out the FAT variant to expect.
    let variant = small_fat_non_extended
        .body()
        .bios_parameters_block()
        .variant();

    match variant {
        fat::Variant::Fat12 => match read_small_fat_volume_parameters(volume_root, extended) {
            Some(p) => Some((fat::Variant::Fat12, p)),
            None => None,
        },
        fat::Variant::Fat16 => match read_small_fat_volume_parameters(volume_root, extended) {
            Some(p) => Some((fat::Variant::Fat16, p)),
            None => None,
        },
        fat::Variant::Fat32 => {
            if !extended {
                // A FAT32 volume must always have an extended boot signature; the volume is invalid or not FAT
                // at all, and incidentally got here.
                None
            } else {
                let boot_sector =
                    unsafe { (volume_root as *const boot_sectors::BootSector32).as_ref() }.unwrap();

                match volume_parameters_from_boot_sector(
                    boot_sector.body().bios_parameters_block().root_cluster() as usize,
                    boot_sector,
                    volume_root,
                ) {
                    Some(p) => Some((fat::Variant::Fat32, p)),
                    None => None,
                }
            }
        }
    }
}

fn read_small_fat_volume_parameters(
    volume_root: *const u8,
    extended: bool,
) -> Option<fat::clustering::VolumeParameters> {
    if extended {
        let boot_sector =
            unsafe { (volume_root as *const boot_sectors::BootSectorSmallExtended).as_ref() }
                .unwrap();

        volume_parameters_from_boot_sector(
            boot_sector
                .body()
                .bios_parameters_block()
                .root_directory_entries() as usize,
            boot_sector,
            volume_root,
        )
    } else {
        let boot_sector =
            unsafe { (volume_root as *const boot_sectors::BootSectorSmall).as_ref() }.unwrap();

        volume_parameters_from_boot_sector(
            boot_sector
                .body()
                .bios_parameters_block()
                .root_directory_entries() as usize,
            boot_sector,
            volume_root,
        )
    }
}

fn volume_parameters_from_boot_sector<
    const N: usize,
    TBiosParameterBlock: bios_parameters_blocks::BiosParameterBlock,
    TBootSector: boot_sectors::BootSector<N, TBiosParameterBlock>,
>(
    root_directory_value: usize,
    boot_sector: &TBootSector,
    volume_root: *const u8,
) -> Option<fat::clustering::VolumeParameters> {
    if !boot_sector.boot_code().boot_sign_is_valid() {
        // Invalid boot sign; we can't read the parameters safely.
        return None;
    }

    let bpb = boot_sector.body().bios_parameters_block();
    Some(fat::clustering::VolumeParameters::from(
        root_directory_value,
        bpb.sectors_per_cluster() as usize,
        match bpb.active_map() {
            Some(m) => Some(m as usize),
            None => None,
        },
        bpb.bytes_per_sector() as usize,
        bpb.reserved_sectors() as usize,
        volume_root,
        bpb.sectors_per_map() as usize,
        bpb.total_sectors() as usize,
        bpb.map_count() as usize,
    ))
}

// TODO: Find new home for:
// fn error_check<TMapEntry: fat::clustering::map::Entry>(&self, root: *const u8) -> fat::Errors {
//     let active_fat_bytes = self.active_fat_bytes(root);
//     let first_entry = match TMapEntry::try_read_from(active_fat_bytes, 0) {
//         Some(e) => e,
//         None => return fat::Errors::Unreadable,
//     };

//     let second_entry = match TMapEntry::try_read_from(active_fat_bytes, 1) {
//         Some(e) => e,
//         None => return fat::Errors::Unreadable,
//     };

//     if !first_entry.check_media_bits(self.media_type()) {
//         return fat::Errors::InvalidMediaFatEntry;
//     }

//     return second_entry.check_error_bits();
// }
