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

use super::{
    exit_result_handlers::ProgramExitResultHandler,
    program_lists::{ProgramList, ProgramListProgram, ProgramSelector},
    Program, ProgramExitResult,
};
use crate::{
    system_services::{PowerAction, SystemServices},
    String16,
};
use alloc::sync::Arc;
use macros::s16;

pub fn get_power_options_list<
    'a,
    TSystemServices: SystemServices,
    TProgramSelector: ProgramSelector,
    TProgramExitResultHandler: ProgramExitResultHandler,
>(
    system_services: &TSystemServices,
    program_selector: &TProgramSelector,
    exit_result_handler: &TProgramExitResultHandler,
) -> ProgramListProgram<TProgramSelector, TProgramExitResultHandler> {
    let programs: [Arc<dyn Program>; 3] = [
        Arc::from(ShutdownProgram::from(system_services.clone())),
        Arc::from(RebootProgram::from(system_services.clone())),
        Arc::from(ResetProgram::from(system_services.clone())),
    ];

    ProgramList::from(Arc::from(programs), s16!("Power Options"))
        .as_program(program_selector.clone(), exit_result_handler.clone())
}

pub struct ShutdownProgram<T: SystemServices> {
    system_services: T,
}

impl<T: SystemServices> ShutdownProgram<T> {
    pub const fn from(system_services: T) -> Self {
        Self { system_services }
    }
}

impl<T: SystemServices> Program for ShutdownProgram<T> {
    fn run(&self) -> ProgramExitResult {
        self.system_services.execute_power_action(PowerAction::Off);
        ProgramExitResult::Success
    }

    fn name(&self) -> String16<'static> {
        s16!("Shutdown")
    }
}

pub struct RebootProgram<T: SystemServices> {
    system_services: T,
}

impl<T: SystemServices> RebootProgram<T> {
    pub const fn from(system_services: T) -> Self {
        Self { system_services }
    }
}

impl<T: SystemServices> Program for RebootProgram<T> {
    fn run(&self) -> ProgramExitResult {
        self.system_services
            .execute_power_action(PowerAction::Reboot);
        ProgramExitResult::Success
    }

    fn name(&self) -> String16<'static> {
        s16!("Reboot")
    }
}

pub struct ResetProgram<T: SystemServices> {
    system_services: T,
}

impl<T: SystemServices> ResetProgram<T> {
    pub const fn from(system_services: T) -> Self {
        Self { system_services }
    }
}

impl<T: SystemServices> Program for ResetProgram<T> {
    fn run(&self) -> ProgramExitResult {
        self.system_services
            .execute_power_action(PowerAction::Reset);
        ProgramExitResult::Success
    }

    fn name(&self) -> String16<'static> {
        s16!("Reset")
    }
}
