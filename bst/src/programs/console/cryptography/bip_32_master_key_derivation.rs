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
    programs::{Program, ProgramExitResult},
    system_services::SystemServices,
    String16,
};
use macros::s16;

pub struct ConsoleBip32MasterKeyDerivationProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices> ConsoleBip32MasterKeyDerivationProgram<TSystemServices> {
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<TSystemServices: SystemServices> Program
    for ConsoleBip32MasterKeyDerivationProgram<TSystemServices>
{
    fn name(&self) -> String16<'static> {
        s16!("BIP 32 Master Key Derivation")
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        todo!()
    }
}
