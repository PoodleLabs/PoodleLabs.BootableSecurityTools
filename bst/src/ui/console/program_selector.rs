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

use super::{ConsoleUiList, ConsoleUiListStyles, ConsoleUiTitle, ConsoleUiTitleStyles};
use crate::{
    console_out::ConsoleOut,
    programs::{
        program_lists::{ProgramSelection, ProgramSelector},
        Program,
    },
    system_services::SystemServices,
    String16,
};
use alloc::{boxed::Box, sync::Arc};

#[derive(Clone)]
pub struct ConsoleUiProgramSelector<T: SystemServices> {
    title_styles: ConsoleUiTitleStyles,
    list_styles: ConsoleUiListStyles,
    system_services: T,
}

impl<T: SystemServices> ConsoleUiProgramSelector<T> {
    pub const fn from(
        title_styles: ConsoleUiTitleStyles,
        list_styles: ConsoleUiListStyles,
        system_services: T,
    ) -> Self {
        Self {
            system_services,
            title_styles,
            list_styles,
        }
    }
}

impl<T: SystemServices> ProgramSelector for ConsoleUiProgramSelector<T> {
    fn prompt_for_program_selection(
        &self,
        list_name: String16<'static>,
        programs: &[Arc<dyn Program>],
    ) -> ProgramSelection {
        // Build a UI list from the list of programs.
        let mut program_list = ConsoleUiList::from(
            ConsoleUiTitle::from(list_name, self.title_styles),
            self.list_styles,
            Box::<[Arc<dyn Program>]>::from(programs),
        );

        // Clear the console.
        self.system_services.get_console_out().clear();

        // Prompt the user to select a program from the list.
        match program_list.prompt_for_selection(&self.system_services) {
            Some((program, modifier_keys, _)) => {
                if modifier_keys.alt() {
                    // The user selected a program while holding the ALT key;
                    // we will run the program and exit the list if successful.
                    ProgramSelection::RunAndBack(program.clone())
                } else {
                    // The user selected a program; we will run it, and stay in the list.
                    ProgramSelection::NormalRun(program.clone())
                }
            }
            // The user didn't select a program.
            None => ProgramSelection::None,
        }
    }
}
