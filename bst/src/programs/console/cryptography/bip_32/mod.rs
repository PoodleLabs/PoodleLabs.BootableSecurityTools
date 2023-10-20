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

mod extended_public_key_derivation;
mod master_key_derivation;

use crate::{
    programs::{
        exit_result_handlers::ProgramExitResultHandler,
        program_lists::{ProgramList, ProgramListProgram, ProgramSelector},
        Program,
    },
    system_services::SystemServices,
};
use alloc::sync::Arc;
use extended_public_key_derivation::ConsoleBip32ExtendedPublicKeyDerivationProgram;
use macros::s16;
use master_key_derivation::ConsoleBip32MasterKeyDerivationProgram;

pub fn get_bip_32_program_list<
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
        Arc::from(ConsoleBip32MasterKeyDerivationProgram::from(
            system_services.clone(),
        )),
        Arc::from(ConsoleBip32ExtendedPublicKeyDerivationProgram::from(
            system_services.clone(),
        )),
    ];

    ProgramList::from(Arc::from(programs), s16!("BIP 32 Programs"))
        .as_program(program_selector.clone(), exit_result_handler.clone())
}
