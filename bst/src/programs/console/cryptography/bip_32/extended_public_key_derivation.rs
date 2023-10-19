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
    programs::{Program, ProgramExitResult},
    system_services::SystemServices,
    ui::{
        console::{ConsoleUiContinuePrompt, ConsoleUiTitle, ConsoleWriteable},
        ContinuePrompt,
    },
    String16,
};
use macros::s16;

pub struct ConsoleBip32ExtendedPublicKeyDerivationProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices>
    ConsoleBip32ExtendedPublicKeyDerivationProgram<TSystemServices>
{
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<TSystemServices: SystemServices> Program
    for ConsoleBip32ExtendedPublicKeyDerivationProgram<TSystemServices>
{
    fn name(&self) -> String16<'static> {
        s16!("BIP 32 Extended Public Key Derivation")
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16_line(s16!("This program takes a BIP 32 extended private key as input and derives the associated extended public key."));
        const _CANCEL_PROMPT: String16 = s16!("Cancel BIP 32 extended public key derivation?");

        ConsoleUiContinuePrompt::from(&self.system_services).prompt_for_continue();
        ProgramExitResult::Success
    }
}
