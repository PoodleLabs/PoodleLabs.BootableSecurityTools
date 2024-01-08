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
    console_out::ConsoleOut,
    constants,
    file_systems::{
        block_device::{
            BlockDevice, BlockDeviceDescription, BlockDevicePartition, BlockDeviceType,
        },
        fat::{self, Fat12FileSystemReader, Fat16FileSystemReader, Fat32FileSystemReader},
        partitioning::partition_iterator::{PartitionDescription, PartitionIterator},
        FileSize,
    },
    programs::{Program, ProgramExitResult},
    system_services::SystemServices,
    ui::{
        console::{
            ConsoleUiConfirmationPrompt, ConsoleUiContinuePrompt, ConsoleUiList, ConsoleUiTitle,
            ConsoleWriteable,
        },
        ConfirmationPrompt, ContinuePrompt,
    },
    String16,
};
use alloc::{boxed::Box, format};
use macros::s16;

pub struct FileExplorerProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices> FileExplorerProgram<TSystemServices> {
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }

    fn select_partition<TBlockDevice: BlockDevice>(
        &self,
        partitions: Box<[PartitionDescription]>,
        block_device: &mut TBlockDevice,
    ) {
        if partitions.len() == 0 {
            self.system_services
                .get_console_out()
                .line_start()
                .new_line()
                .in_colours(constants::ERROR_COLOURS, |c| {
                    c.output_utf16_line(s16!("The selected device has no partitions."))
                });
        }

        let mut partition_list = ConsoleUiList::from(
            ConsoleUiTitle::from(s16!("Partitions"), constants::SMALL_TITLE),
            constants::SELECT_LIST,
            &partitions[..],
        );

        loop {
            match partition_list.prompt_for_selection(&self.system_services) {
                Some((p, _, _)) => {
                    self.open_block_device(&mut BlockDevicePartition::from(
                        block_device,
                        p.first_block(),
                        p.block_count(),
                    ));
                }
                None => todo!(),
            }
        }
    }

    fn open_block_device<TBlockDevice: BlockDevice>(&self, block_device: &mut TBlockDevice) {
        match fat::try_read_volume_cluster_parameters(block_device) {
            Some((fat_variant, volume_parameters)) => {
                let skip_hidden_files = ConsoleUiConfirmationPrompt::from(&self.system_services)
                    .prompt_for_confirmation(s16!("Skip hidden files while exploring?"));

                self.open_fat_filesystem(volume_parameters, fat_variant, skip_hidden_files);
            }
            None => {
                self.system_services
                    .get_console_out()
                    .in_colours(constants::ERROR_COLOURS, |c| {
                        c.line_start().new_line().output_utf16_line(s16!(
                            "The selected block device does not appear to have a FAT filesystem."
                        ))
                    });
            }
        };
    }

    fn open_fat_filesystem<TBlockDevice: BlockDevice>(
        &self,
        volume_parameters: fat::VolumeParameters<'_, TBlockDevice>,
        fat_variant: fat::Variant,
        skip_hidden_files: bool,
    ) {
        match fat_variant {
            fat::Variant::Fat12 => self.explore_fat_filesystem(&mut Fat12FileSystemReader::from(
                volume_parameters,
                skip_hidden_files,
            )),
            fat::Variant::Fat16 => self.explore_fat_filesystem(&mut Fat16FileSystemReader::from(
                volume_parameters,
                skip_hidden_files,
            )),
            fat::Variant::Fat32 => self.explore_fat_filesystem(&mut Fat32FileSystemReader::from(
                volume_parameters,
                skip_hidden_files,
            )),
        };
    }

    fn explore_fat_filesystem<
        'a,
        TBlockDevice: 'a + BlockDevice,
        TFileSystemReader: fat::FileSystemReader<'a, TBlockDevice>,
    >(
        &self,
        filesystem_reader: &'a mut TFileSystemReader,
    ) {
        self.explore_directory::<TFileSystemReader::FatEntry, TBlockDevice, _>(
            filesystem_reader.iter_root_directory_entries(),
        )
    }

    fn explore_directory<
        'a,
        TMapEntry: fat::clustering::map::Entry,
        TBlockDevice: 'a + BlockDevice,
        TChildIterator: fat::objects::directories::ChildIterator<'a>,
    >(
        &self,
        child_iterator: TChildIterator,
    ) {
        let console = &self.system_services.get_console_out();
        console
            .line_start()
            .new_line()
            .output_utf16_line(s16!("Exploration has not been implemented yet."));
        ConsoleUiContinuePrompt::from(&self.system_services).prompt_for_continue();
    }
}

impl<TSystemServices: SystemServices> Program for FileExplorerProgram<TSystemServices> {
    fn name(&self) -> String16<'static> {
        s16!("File Explorer")
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console.output_utf16_line(s16!("This program can be used to explore connected block devices, and their filesystems. Currently, only FAT filesystems are supported."));

        let block_devices = self.system_services.list_block_devices();
        let mut device_list = ConsoleUiList::from(
            ConsoleUiTitle::from(s16!("Block Devices"), constants::SMALL_TITLE),
            constants::SELECT_LIST,
            &block_devices[..],
        );

        loop {
            console.line_start().new_line();
            let selected_device = match device_list.prompt_for_selection(&self.system_services) {
                Some((d, _, _)) => d,
                None => {
                    if ConsoleUiConfirmationPrompt::from(&self.system_services)
                        .prompt_for_confirmation(s16!("Exit file explorer?"))
                    {
                        return ProgramExitResult::UserCancelled;
                    } else {
                        continue;
                    }
                }
            };

            let mut block_device = match self
                .system_services
                .open_block_device(selected_device.handle())
            {
                Some(d) => d,
                None => {
                    console
                        .line_start()
                        .new_line()
                        .in_colours(constants::ERROR_COLOURS, |c| {
                            c.output_utf16_line(s16!("Failed to open the selected block device."))
                        });
                    continue;
                }
            };

            if block_device.description().device_type() == BlockDeviceType::Hardware {
                // If the block device is a hardware block device, it may be partitioned.
                // Try to read the partitions on the disk.
                match PartitionIterator::try_from(&mut block_device) {
                    Some(p) => {
                        // We read a partition table; ask the user to select a partition.
                        self.select_partition(Box::from_iter(p), &mut block_device);
                        continue;
                    }
                    None => { /* It may be a SFD device; fall through.*/ }
                }
            }

            // Attempt to open the block device without any partitioning.
            self.open_block_device(&mut block_device)
        }
    }
}

impl<THandle: Copy> ConsoleWriteable for BlockDeviceDescription<THandle> {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        if !self.media_present() {
            console.output_utf16(s16!("Empty"));
            return;
        }

        if self.read_only() {
            console.output_utf16(s16!("Read-Only "));
        }

        FileSize::from_bytes(self.block_count() * self.block_size() as u64).write_to(console);
        console.output_utf16(s16!(" "));

        console.output_utf16(match self.device_type() {
            BlockDeviceType::FirmwarePartition => s16!("Partition"),
            BlockDeviceType::SoftwarePartition => s16!("Partition"),
            BlockDeviceType::Hardware => s16!("Device"),
        });
    }
}

impl ConsoleWriteable for PartitionDescription {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        let block_size = self.block_size();
        let partition_size = FileSize::from_bytes(self.block_count() * block_size);
        let partition_start = FileSize::from_bytes(self.first_block() * block_size);

        let preferred_unit = partition_size
            .preferred_unit()
            .min(partition_start.preferred_unit());
        let suffix = preferred_unit.suffix_32();
        console.output_utf32(&format!(
            "Partition {:.1}{}:+{:.1}{}\0",
            partition_start.in_units(preferred_unit),
            suffix,
            partition_start.in_units(preferred_unit),
            suffix,
        ));
    }
}

impl ConsoleWriteable for FileSize {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        let preferred_unit = self.preferred_unit();
        console.output_utf32(&format!(
            "{:.1}{}\0",
            self.in_units(preferred_unit),
            preferred_unit.suffix_32()
        ));
    }
}
