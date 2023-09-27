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

mod manual_collection;
mod mnemonics;

use crate::{
    console_out::ConsoleOut,
    constants,
    programs::{
        exit_result_handlers::ProgramExitResultHandler,
        program_lists::{ProgramList, ProgramListProgram, ProgramSelector},
        Program, ProgramExitResult,
    },
    system_services::SystemServices,
    ui::{console::ConsoleUiContinuePrompt, ContinuePrompt},
    String16,
};
use alloc::sync::Arc;
use macros::s16;

struct PlaceholderProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
    name: String16<'static>,
}

impl<TSystemServices: SystemServices> Program for PlaceholderProgram<TSystemServices> {
    fn name(&self) -> String16<'static> {
        self.name
    }

    fn run(&self) -> ProgramExitResult {
        self.system_services
            .get_console_out()
            .clear()
            .in_colours(constants::ERROR_COLOURS, |c| {
                c.output_utf16(s16!("Not Implemented: "))
            })
            .output_utf16_line(self.name);
        ConsoleUiContinuePrompt::from(&self.system_services).prompt_for_continue();
        ProgramExitResult::Success
    }
}

pub fn get_entropy_program_list<
    'a,
    TSystemServices: SystemServices,
    TProgramSelector: ProgramSelector + 'static,
    TProgramExitResultHandler: ProgramExitResultHandler + 'static,
>(
    system_services: &TSystemServices,
    program_selector: &TProgramSelector,
    exit_result_handler: &TProgramExitResultHandler,
) -> ProgramListProgram<TProgramSelector, TProgramExitResultHandler> {
    let programs: [Arc<dyn Program>; 2] = [
        Arc::from(
            manual_collection::get_manual_entropy_collection_program_list(
                system_services,
                program_selector,
                exit_result_handler,
            ),
        ),
        Arc::from(mnemonics::get_entropy_mnemonic_program_list(
            system_services,
            program_selector,
            exit_result_handler,
        )),
    ];
    ProgramList::from(Arc::from(programs), s16!("Entropy Programs"))
        .as_program(program_selector.clone(), exit_result_handler.clone())
}
