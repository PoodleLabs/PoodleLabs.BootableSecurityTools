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

mod checksums;
mod clipboard_manager;
mod resolution_selection;
mod value_comparer;

use crate::{
    programs::{
        exit_result_handlers::ProgramExitResultHandler,
        program_lists::{ProgramList, ProgramListProgram, ProgramSelector},
        Program,
    },
    system_services::SystemServices,
};
use alloc::sync::Arc;
use macros::s16;

pub fn get_utility_programs_list<
    'a,
    TSystemServices: SystemServices,
    TProgramSelector: ProgramSelector + 'static,
    TProgramExitResultHandler: ProgramExitResultHandler + 'static,
>(
    system_services: &TSystemServices,
    program_selector: &TProgramSelector,
    exit_result_handler: &TProgramExitResultHandler,
) -> ProgramListProgram<TProgramSelector, TProgramExitResultHandler> {
    let programs: [Arc<dyn Program>; 4] = [
        Arc::from(clipboard_manager::ConsoleClipboardManagerProgram::from(
            system_services.clone(),
        )),
        Arc::from(value_comparer::ConsoleValueComparerProgram::from(
            system_services.clone(),
        )),
        Arc::from(checksums::get_checksum_programs(
            system_services,
            program_selector,
            exit_result_handler,
        )),
        Arc::from(resolution_selection::ResolutionSelectionProgram::from(
            system_services.clone(),
        )),
    ];
    ProgramList::from(Arc::from(programs), s16!("Utility Programs"))
        .as_program(program_selector.clone(), exit_result_handler.clone())
}
