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

mod hmac_programs;
mod pbkdf2_programs;
mod simple_hashing_programs;

use super::write_bytes;
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

pub fn get_hashing_programs_list<
    'a,
    TSystemServices: SystemServices,
    TProgramSelector: ProgramSelector + 'static,
    TProgramExitResultHandler: ProgramExitResultHandler + 'static,
>(
    system_services: &TSystemServices,
    program_selector: &TProgramSelector,
    exit_result_handler: &TProgramExitResultHandler,
) -> ProgramListProgram<TProgramSelector, TProgramExitResultHandler> {
    let programs: [Arc<dyn Program>; 3] = [
        Arc::from(simple_hashing_programs::get_simple_hashing_programs_list(
            system_services,
            program_selector,
            exit_result_handler,
        )),
        Arc::from(hmac_programs::get_hmac_programs_list(
            system_services,
            program_selector,
            exit_result_handler,
        )),
        Arc::from(pbkdf2_programs::get_pbkdf2_programs_list(
            system_services,
            program_selector,
            exit_result_handler,
        )),
    ];
    ProgramList::from(Arc::from(programs), s16!("Hashing Programs"))
        .as_program(program_selector.clone(), exit_result_handler.clone())
}

fn write_hash<TSystemServices: SystemServices>(system_services: &TSystemServices, hash: &[u8]) {
    write_bytes(system_services, s16!("Hash"), hash);
}
