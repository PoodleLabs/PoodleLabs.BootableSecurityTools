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

use super::ProgramExitResultHandler;
use crate::{
    console_out::ConsoleOut,
    programs::{Program, ProgramExitResult},
    String16,
};
use macros::s16;

#[derive(Clone)]
pub struct ConsoleDumpingProgramExitResultHandler<T: ConsoleOut> {
    console: T,
}

impl<T: ConsoleOut> ConsoleDumpingProgramExitResultHandler<T> {
    pub const fn from(console: T) -> Self {
        Self { console }
    }

    fn error_prelude(&self, program: &dyn Program) -> &T {
        self.console
            .output_utf16(s16!("Program '"))
            .output_utf16(program.name())
            .output_utf16_line(s16!("' failed during execution. Output:"))
    }
}

impl<T: ConsoleOut> ProgramExitResultHandler for ConsoleDumpingProgramExitResultHandler<T> {
    fn handle_exit_result(&self, result: ProgramExitResult, program: &dyn Program) {
        match result {
            ProgramExitResult::Success => {}
            ProgramExitResult::UserCancelled => {}
            ProgramExitResult::String16Error(string16) => {
                self.error_prelude(program)
                    .output_utf16_line(String16::from(&string16));
            }
        }
    }
}
