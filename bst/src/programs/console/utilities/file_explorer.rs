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
        block_device::{BlockDevice, BlockDeviceDescription, BlockDeviceType},
        fat::{self, Fat12FileSystemReader, Fat16FileSystemReader, Fat32FileSystemReader},
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
use alloc::format;
use macros::s16;

pub struct FileExplorerProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices> FileExplorerProgram<TSystemServices> {
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
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

            match fat::try_read_volume_cluster_parameters(&mut block_device) {
                Some((fat_variant, volume_parameters)) => {
                    let skip_hidden_files =
                        ConsoleUiConfirmationPrompt::from(&self.system_services)
                            .prompt_for_confirmation(s16!("Skip hidden files while exploring?"));

                    open_fat_filesystem(
                        volume_parameters,
                        &self.system_services,
                        fat_variant,
                        skip_hidden_files,
                    );

                    continue;
                }
                None => {
                    console.in_colours(constants::ERROR_COLOURS, |c| {
                        c.line_start().new_line().output_utf16_line(s16!(
                            "The selected block device does not appear to have a FAT filesystem."
                        ))
                    });
                }
            };
        }
    }
}

fn open_fat_filesystem<TBlockDevice: BlockDevice, TSystemServices: SystemServices>(
    volume_parameters: fat::VolumeParameters<'_, TBlockDevice>,
    system_services: &TSystemServices,
    fat_variant: fat::Variant,
    skip_hidden_files: bool,
) {
    match fat_variant {
        fat::Variant::Fat12 => explore_fat_filesystem(
            Fat12FileSystemReader::from(volume_parameters, skip_hidden_files),
            system_services,
        ),
        fat::Variant::Fat16 => explore_fat_filesystem(
            Fat16FileSystemReader::from(volume_parameters, skip_hidden_files),
            system_services,
        ),
        fat::Variant::Fat32 => explore_fat_filesystem(
            Fat32FileSystemReader::from(volume_parameters, skip_hidden_files),
            system_services,
        ),
    };
}

fn explore_fat_filesystem<
    'a,
    TBlockDevice: 'a + BlockDevice,
    TFileSystemReader: fat::FileSystemReader<'a, TBlockDevice>,
    TSystemServices: SystemServices,
>(
    _filesystem_reader: TFileSystemReader,
    system_services: &TSystemServices,
) {
    let console = system_services.get_console_out();
    console
        .line_start()
        .new_line()
        .output_utf16_line(s16!("Exploration has not been implemented yet."));
    ConsoleUiContinuePrompt::from(system_services).prompt_for_continue();
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

        let byte_count = self.block_count() * self.block_size() as u64;
        let (size, size_word) = if byte_count > 1000000000000 {
            (byte_count as f64 / 1000000000000f64, s16!("TB"))
        } else if byte_count > 1000000000 {
            (byte_count as f64 / 1000000000f64, s16!("GB"))
        } else if byte_count > 1000000 {
            (byte_count as f64 / 1000000f64, s16!("MB"))
        } else if byte_count > 1000 {
            (byte_count as f64 / 1000f64, s16!("KB"))
        } else {
            (byte_count as f64, s16!("B"))
        };

        console.output_utf32(&format!("{:.1}\0", size));
        console.output_utf16(size_word);
        console.output_utf16(s16!(" "));

        console.output_utf16(match self.device_type() {
            BlockDeviceType::FirmwarePartition => s16!("Partition"),
            BlockDeviceType::SoftwarePartition => s16!("Partition"),
            BlockDeviceType::Hardware => s16!("Device"),
        });
    }
}
