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
    bitcoin::validate_checksum_in,
    console_out::ConsoleOut,
    constants,
    programs::{Program, ProgramExitResult},
    system_services::SystemServices,
    ui::{
        console::{
            prompt_for_data_input, ConsoleUiContinuePrompt, ConsoleUiTitle, ConsoleWriteable,
        },
        ContinuePrompt, DataInput, DataInputType,
    },
    String16,
};
use alloc::format;
use macros::s16;

pub struct ChecksumValidator<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices> ChecksumValidator<TSystemServices> {
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<TSystemServices: SystemServices> Program for ChecksumValidator<TSystemServices> {
    fn name(&self) -> String16<'static> {
        s16!("Checksum Validator")
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16_line(s16!("This program validates a 32 bit big-endian appended SHA256 double-hash of at least 5 bytes of input."))
            .output_utf16(s16!("This is the checksum format used with all Bitcoin-related base-58 encoded strings, but it can be applied elsewhere."));

        // Get the bytes to check the checksum for.
        let input = match prompt_for_data_input(
            None,
            &[DataInputType::Bytes],
            &self.system_services,
            s16!("Cancel checksum validation?"),
            s16!("Bytes to validate"),
        ) {
            DataInput::Bytes(b) => b,
            _ => return ProgramExitResult::UserCancelled,
        };

        console.line_start().new_line();
        if input.len() < 5 {
            // The checksum is 4 bytes long. We could checksum a single byte, so we should require at least 5 bytes of input; 1 byte of data,
            // and 4 bytes of checksum.
            console.in_colours(constants::ERROR_COLOURS, |c| c.output_utf16_line(
                s16!("Input less than 5 bytes; given the checksum is 4 bytes in length, this cannot be validated.")));
        } else {
            let (checksum_is_valid, checksum) = validate_checksum_in(&input);
            if checksum_is_valid {
                console.in_colours(constants::SUCCESS_COLOURS, |c| {
                    c.output_utf16_line(s16!("Checksum passed."))
                });
            } else {
                // If the checksum doesn't match the last 4 bytes of input, the checksum failed. It could be that the data has been changed,
                // and now fails its checksum, or it could be that there wasn't a checksum in the first place. If the user expected the
                // data to have a valid checksum, which one is the case doesn't really matter... The data is bad.
                console.in_colours(constants::ERROR_COLOURS, |c| {
                    c.output_utf16_line(s16!("Checksum failed:"))
                        .output_utf32(&format!(
                            "Expected: {:?}\r\nGot: {:?}\0",
                            checksum,
                            &input[input.len() - 4..]
                        ))
                });
            }
        }

        ConsoleUiContinuePrompt::from(&self.system_services).prompt_for_continue();
        ProgramExitResult::Success
    }
}
