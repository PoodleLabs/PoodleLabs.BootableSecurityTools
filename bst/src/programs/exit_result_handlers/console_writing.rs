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
    constants,
    programs::{Program, ProgramExitResult},
    system_services::SystemServices,
    ui::{console::ConsoleUiContinuePrompt, ContinuePrompt},
    String16,
};
use macros::s16;

#[derive(Clone)]
pub struct ConsoleDumpingProgramExitResultHandler<T: SystemServices> {
    system_services: T,
}

impl<T: SystemServices> ConsoleDumpingProgramExitResultHandler<T> {
    pub const fn from(console: T) -> Self {
        Self {
            system_services: console,
        }
    }
}

impl<T: SystemServices> ProgramExitResultHandler for ConsoleDumpingProgramExitResultHandler<T> {
    fn handle_exit_result(&self, result: ProgramExitResult, program: &dyn Program) {
        match result {
            ProgramExitResult::Success => {}
            ProgramExitResult::UserCancelled => {}
            ProgramExitResult::String16Error(string16) => {
                self.system_services
                    .get_console_out()
                    .in_colours(constants::ERROR_COLOURS, |c| {
                        c.line_start()
                            .new_line()
                            .output_utf16(s16!("Program '"))
                            .output_utf16(program.name())
                            .output_utf16_line(s16!("' failed during execution. Output:"))
                    })
                    .output_utf16_line(String16::from(&string16))
                    .new_line()
                    .in_colours(constants::WARNING_COLOURS, |c| { 
                        c.output_utf16_line(s16!("Please consider reporting this in an issue at:\r\nhttps://github.com/PoodleLabs/PoodleLabs.BootableSecurityTools"))
                    });
                ConsoleUiContinuePrompt::from(&self.system_services).prompt_for_continue();
            }
        }
    }
}
