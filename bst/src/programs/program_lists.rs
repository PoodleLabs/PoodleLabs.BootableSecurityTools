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

use super::{exit_result_handlers::ProgramExitResultHandler, Program, ProgramExitResult};
use crate::String16;
use alloc::sync::Arc;

#[derive(Clone)]
pub enum ProgramSelection {
    None,
    NormalRun(Arc<dyn Program>),
    RunAndBack(Arc<dyn Program>),
}

pub trait ProgramSelector: Clone {
    fn prompt_for_program_selection(
        &self,
        list_name: String16<'static>,
        programs: &[Arc<dyn Program>],
    ) -> ProgramSelection;
}

#[derive(Clone)]
pub struct ProgramList {
    programs: Arc<[Arc<dyn Program>]>,
    name: String16<'static>,
}

impl ProgramList {
    pub const fn from(programs: Arc<[Arc<dyn Program>]>, name: String16<'static>) -> Self {
        Self { programs, name }
    }

    pub const fn as_program<
        'a,
        TSelector: ProgramSelector,
        TResultHandler: ProgramExitResultHandler,
    >(
        self,
        selector: TSelector,
        exit_result_handler: TResultHandler,
    ) -> ProgramListProgram<TSelector, TResultHandler> {
        ProgramListProgram {
            exit_result_handler,
            program_list: self,
            selector: selector,
        }
    }
}

#[derive(Clone)]
pub struct ProgramListProgram<TSelector: ProgramSelector, TResultHandler: ProgramExitResultHandler>
{
    exit_result_handler: TResultHandler,
    program_list: ProgramList,
    selector: TSelector,
}

impl<'a, TSelector: ProgramSelector, TResultHandler: ProgramExitResultHandler> Program
    for ProgramListProgram<TSelector, TResultHandler>
{
    fn run(&self) -> ProgramExitResult {
        loop {
            match self
                .selector
                .prompt_for_program_selection(self.name(), &self.program_list.programs)
            {
                // Exit the loop because the user wanted to.
                ProgramSelection::None => return ProgramExitResult::UserCancelled,

                // Run the selected program and keep running.
                ProgramSelection::NormalRun(program) => {
                    self.exit_result_handler
                        .handle_exit_result(program.run(), program.as_ref());
                }

                // Run the selected program and exit the loop if its run was successful.
                ProgramSelection::RunAndBack(program) => {
                    let result = program.run();
                    let is_success = result == ProgramExitResult::Success;
                    self.exit_result_handler
                        .handle_exit_result(result, program.as_ref());
                    if is_success {
                        return ProgramExitResult::Success;
                    }
                }
            }
        }
    }

    fn name(&self) -> String16<'static> {
        self.program_list.name
    }
}
