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
    file_systems::block_device::{BlockDeviceDescription, BlockDeviceType},
    integers::NumericBase,
    programs::{Program, ProgramExitResult},
    system_services::SystemServices,
    ui::console::{ConsoleUiList, ConsoleUiTitle, ConsoleWriteable},
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
        let block_devices = self.system_services.list_block_devices();
        ConsoleUiList::from(
            ConsoleUiTitle::from(s16!("Block Devices"), constants::SMALL_TITLE),
            constants::SELECT_LIST,
            &block_devices[..],
        )
        .prompt_for_selection(&self.system_services);

        ProgramExitResult::Success
    }
}

impl ConsoleWriteable for BlockDeviceDescription {
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
            BlockDeviceType::Partition => s16!("Partition"),
            BlockDeviceType::Hardware => s16!("Device"),
        });
    }
}
