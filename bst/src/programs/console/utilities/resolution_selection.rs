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
    console_out::{ConsoleModeIdentifier, ConsoleModeInformation, ConsoleOut},
    constants,
    integers::{BigUnsigned, NumericBase},
    programs::{Program, ProgramExitResult},
    system_services::SystemServices,
    ui::{
        console::{
            ConsoleUiConfirmationPrompt, ConsoleUiContinuePrompt, ConsoleUiLabel, ConsoleUiList,
            ConsoleUiTitle, ConsoleWriteable,
        },
        ConfirmationPrompt, ContinuePrompt,
    },
    String16,
};
use core::mem::size_of;
use macros::s16;

pub struct ResolutionSelectionProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices> ResolutionSelectionProgram<TSystemServices> {
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<TSystemServices: SystemServices> Program for ResolutionSelectionProgram<TSystemServices> {
    fn name(&self) -> String16<'static> {
        s16!("Resolution Selection")
    }

    fn run(&self) -> ProgramExitResult {
        let mut console = self.system_services.get_console_out();
        let title = ConsoleUiTitle::from(self.name(), constants::BIG_TITLE);
        let available_resolutions = console.get_modes();

        let mut list = ConsoleUiList::from(
            ConsoleUiTitle::from(s16!("Available Resolutions"), constants::SMALL_TITLE),
            constants::SELECT_LIST,
            &available_resolutions[..],
        );

        loop {
            let mode_identifier = console.current_mode_identifier();
            let current_resolution = available_resolutions
                .iter()
                .find(|r| r.identifier().eq(&mode_identifier));

            console.clear();
            let output = |r: Option<&ConsoleModeInformation<_>>| {
                title.write_to(&console);
                console
                    .output_utf16_line(s16!(
                        "This program lists and allows the selection of available console resolutions, with the option to save the selection into NVRAM."
                    ));

                ConsoleUiLabel::from(s16!("Current Resolution")).write_to(&console);
                match r {
                    Some(r) => {
                        r.write_to(&console);
                    }
                    None => {
                        console.in_colours(constants::ERROR_COLOURS, |c| {
                            c.output_utf16_line(s16!("Unknown"))
                        });
                    }
                }
            };

            output(current_resolution);
            console.new_line().new_line();
            let selected_resolution = list.prompt_for_selection(&self.system_services);
            match selected_resolution {
                Some((r, _, _)) => {
                    self.system_services
                        .get_console_out()
                        .set_mode(*r.identifier());
                    output(Some(&r));

                    if !ConsoleUiConfirmationPrompt::from(&self.system_services)
                        .prompt_for_confirmation(s16!("Keep this resolution?"))
                    {
                        console.set_mode(mode_identifier);
                        continue;
                    }

                    if ConsoleUiConfirmationPrompt::from(&self.system_services)
                        .prompt_for_confirmation(s16!("Save selection to NVRAM for future boots?"))
                    {
                        if !self.system_services.try_set_variable(
                            TSystemServices::console_resolution_variable_name(),
                            &r.identifier().to_be_bytes(),
                        ) {
                            console.in_colours(constants::ERROR_COLOURS, |c| {
                                c.line_start()
                                    .new_line()
                                    .output_utf16_line(s16!("Failed to set NVRAM variable."))
                            });

                            ConsoleUiContinuePrompt::from(&self.system_services)
                                .prompt_for_continue();
                            continue;
                        }
                    }

                    return ProgramExitResult::Success;
                }
                None => {
                    if ConsoleUiConfirmationPrompt::from(&self.system_services)
                        .prompt_for_confirmation(s16!("Cancel resolution selection?"))
                    {
                        return ProgramExitResult::UserCancelled;
                    }
                }
            }
        }
    }
}

impl<TIdentifier: ConsoleModeIdentifier> ConsoleWriteable for ConsoleModeInformation<TIdentifier> {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        let mut bound_buffer = BigUnsigned::with_byte_capacity(size_of::<usize>());
        bound_buffer.copy_be_bytes_from(&self.size().x().to_be_bytes());
        console.output_utf16(String16::from(
            &NumericBase::BASE_10.build_string_from_big_unsigned(&mut bound_buffer, true, 0),
        ));

        console.output_utf16(s16!("x"));

        bound_buffer.copy_be_bytes_from(&self.size().y().to_be_bytes());
        console.output_utf16(String16::from(
            &NumericBase::BASE_10.build_string_from_big_unsigned(&mut bound_buffer, true, 0),
        ));
    }
}
