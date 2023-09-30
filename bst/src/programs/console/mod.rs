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

mod cryptography;
mod entropy;
mod hashing;
mod instructions;
mod utilities;

use super::{
    exit_result_handlers::ProgramExitResultHandler,
    power_option_programs,
    program_lists::{ProgramList, ProgramListProgram, ProgramSelector},
    Program,
};
use crate::{
    console_out::ConsoleOut,
    integers::NumericBase,
    system_services::SystemServices,
    ui::{
        console::{ConsoleUiContinuePrompt, ConsoleUiLabel, ConsoleWriteable},
        ContinuePrompt,
    },
    String16,
};
use alloc::sync::Arc;
use macros::s16;

pub fn get_programs_list<
    'a,
    TSystemServices: SystemServices,
    TProgramSelector: ProgramSelector + 'static,
    TProgramExitResultHandler: ProgramExitResultHandler + 'static,
>(
    system_services: &TSystemServices,
    program_selector: &TProgramSelector,
    exit_result_handler: &TProgramExitResultHandler,
) -> ProgramListProgram<TProgramSelector, TProgramExitResultHandler> {
    let programs: [Arc<dyn Program>; 6] = [
        Arc::from(instructions::get_instructional_programs_list(
            system_services,
            program_selector,
            exit_result_handler,
        )),
        Arc::from(utilities::get_utility_programs_list(
            system_services,
            program_selector,
            exit_result_handler,
        )),
        Arc::from(hashing::get_hashing_programs_list(
            system_services,
            program_selector,
            exit_result_handler,
        )),
        Arc::from(entropy::get_entropy_program_list(
            system_services,
            program_selector,
            exit_result_handler,
        )),
        Arc::from(cryptography::get_cryptography_program_list(
            system_services,
            program_selector,
            exit_result_handler,
        )),
        Arc::from(power_option_programs::get_power_options_list(
            system_services,
            program_selector,
            exit_result_handler,
        )),
    ];
    ProgramList::from(
        Arc::from(programs),
        s16!("Poodle Labs' Bootable Security Tools"),
    )
    .as_program(program_selector.clone(), exit_result_handler.clone())
}

fn write_bytes<TSystemServices: SystemServices>(
    system_services: &TSystemServices,
    label: String16,
    bytes: &[u8],
) {
    let string = NumericBase::BASE_16.build_string_from_bytes(&bytes, true);
    let console = system_services.get_console_out();
    ConsoleUiLabel::from(label).write_to(&console);
    console.output_utf16_line(String16::from(&string));
    ConsoleUiContinuePrompt::from(system_services).prompt_for_continue();
}
