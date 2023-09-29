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

mod bip_39;
mod electrum;
mod mnemonic_bip_32_seed_deriver;
mod mnemonic_entropy_decoder;
mod mnemonic_entropy_encoder;

use crate::{
    console_out::ConsoleOut,
    programs::{
        exit_result_handlers::ProgramExitResultHandler,
        program_lists::{ProgramList, ProgramListProgram, ProgramSelector},
        Program,
    },
    system_services::SystemServices,
    String16,
};
use alloc::{format, sync::Arc};
use macros::s16;

pub fn get_entropy_mnemonic_program_list<
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
        Arc::from(bip_39::get_bip_39_mnemonic_program_list(
            system_services,
            program_selector,
            exit_result_handler,
        )),
        Arc::from(electrum::get_electrum_mnemonic_program_list(
            system_services,
            program_selector,
            exit_result_handler,
        )),
    ];
    ProgramList::from(Arc::from(programs), s16!("Entropy Mnemonic Programs"))
        .as_program(program_selector.clone(), exit_result_handler.clone())
}

fn write_mnemonic_length_to<T: ConsoleOut>(
    mnemonic_length_string: String16<'static>,
    bit_length: usize,
    console: &T,
) {
    console
        .output_utf16(mnemonic_length_string)
        .output_utf16(s16!(" ("))
        .output_utf32(&format!("{}\0", bit_length))
        .output_utf16(s16!(" bits)"));
}
