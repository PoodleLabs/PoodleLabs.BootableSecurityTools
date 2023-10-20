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
    bitcoin::{calculate_checksum_for, validate_checksum_in},
    clipboard::ClipboardEntry,
    console_out::ConsoleOut,
    constants,
    programs::{console::write_bytes, Program, ProgramExitResult},
    system_services::SystemServices,
    ui::{
        console::{
            prompt_for_clipboard_write, prompt_for_data_input, ConsoleUiConfirmationPrompt,
            ConsoleUiTitle, ConsoleWriteable,
        },
        ConfirmationPrompt, DataInput, DataInputType,
    },
    String16,
};
use macros::s16;

pub struct ChecksumCalculator<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices> ChecksumCalculator<TSystemServices> {
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<TSystemServices: SystemServices> Program for ChecksumCalculator<TSystemServices> {
    fn name(&self) -> String16<'static> {
        s16!("Checksum Calculator")
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16_line(s16!("This program calculates a 32 bit big-endian SHA256 double-hash checksum of byte data."))
            .output_utf16(s16!("This is the checksum format used with all Bitcoin-related base-58 encoded strings, but it can be applied elsewhere."));

        // Get bytes to calculate a checksum for.
        let mut input = match prompt_for_data_input(
            None,
            &[DataInputType::Bytes],
            &self.system_services,
            s16!("Cancel checksum calculation?"),
            s16!("Bytes to checksum"),
        ) {
            DataInput::Bytes(b) => b,
            _ => return ProgramExitResult::UserCancelled,
        };

        if input.len() < 1 {
            // If there's no data, we can't calculate a (meaningful) checksum.
            console
                .line_start()
                .new_line()
                .in_colours(constants::ERROR_COLOURS, |c| {
                    c.output_utf16_line(s16!("No bytes input; cannot calculate a checksum."))
                });

            return ProgramExitResult::UserCancelled;
        }

        if input.len() > 4 {
            // Check whether the bytes already have a checksum. There's a 1/2^32 chance that some random data will have a checksum.
            // That's not really worth worrying about, but there's no harm in adding a checksum to a piece of data which already
            // has a checksum on it, as long as we let the user know that's probably what's happening.
            let (already_has_valid_checksum, _) = validate_checksum_in(&input);
            if already_has_valid_checksum {
                console
                    .line_start()
                    .new_line()
                    .in_colours(constants::WARNING_COLOURS, |c| {
                        c.output_utf16_line(s16!(
                            "The input appears to already contain a checksum."
                        ))
                    });

                if !ConsoleUiConfirmationPrompt::from(&self.system_services)
                    .prompt_for_confirmation(s16!("Append a checksum anyway?"))
                {
                    // If the user chooses not to checksum the already (seemingly) checksummed data, we just fill the input and return.
                    input.fill(0);
                    return ProgramExitResult::UserCancelled;
                }
            }
        }

        // Calculate the checksum for the input data, and append it.
        let checksum = calculate_checksum_for(&input);
        input.extend(checksum);

        write_bytes(&self.system_services, s16!("Checksummed Data"), &input);
        prompt_for_clipboard_write(
            &self.system_services,
            ClipboardEntry::Bytes(s16!("Manually Checksummed Bytes"), input.into()),
        );

        ProgramExitResult::Success
    }
}
