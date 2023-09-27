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
    programs::{
        exit_result_handlers::ProgramExitResultHandler,
        program_lists::{ProgramList, ProgramListProgram, ProgramSelector},
        Program, ProgramExitResult,
    },
    system_services::SystemServices,
    ui::console::ConsoleUiTextBox,
    String16,
};
use alloc::sync::Arc;
use macros::s16;

pub fn get_instructional_programs_list<
    'a,
    TSystemServices: SystemServices,
    TProgramSelector: ProgramSelector + 'static,
    TProgramExitResultHandler: ProgramExitResultHandler + 'static,
>(
    system_services: &TSystemServices,
    program_selector: &TProgramSelector,
    exit_result_handler: &TProgramExitResultHandler,
) -> ProgramListProgram<TProgramSelector, TProgramExitResultHandler> {
    let programs: [Arc<dyn Program>; 1] = [
        instructional_program(
        s16!("Test Instructions"),
        s16!("These instructions test the instructional program.\r\na\r\nb\r\nc\r\nd\r\ne\r\nf\r\ng\r\nh\r\ni\r\nj\r\nk\r\nl\r\nm\r\nn\r\no\r\np\r\nq\r\nr\r\ns\r\nt\r\nu\r\nv\r\nw\r\nx\r\ny\r\nz\r\n0\r\n1\r\n2\r\n3\r\n4\r\n5\r\n6\r\n7\r\n8\r\n9\r\n10\r\n11\r\n12\r\n13\r\n14\r\n15\r\n16\r\n17\r\n18\r\n19\r\n20\r\n21\r\n22\r\n23\r\n24\r\n25\r\n26"),
        system_services
    )];

    ProgramList::from(Arc::from(programs), s16!("Instructional Programs"))
        .as_program(program_selector.clone(), exit_result_handler.clone())
}

fn instructional_program<TSystemServices: SystemServices>(
    name: String16<'static>,
    content: String16<'static>,
    system_services: &TSystemServices,
) -> Arc<dyn Program> {
    Arc::from(ConsoleInstructionalProgram::from(
        system_services.clone(),
        content,
        name,
    ))
}

struct ConsoleInstructionalProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
    content: String16<'static>,
    name: String16<'static>,
}

impl<TSystemServices: SystemServices> ConsoleInstructionalProgram<TSystemServices> {
    pub const fn from(
        system_services: TSystemServices,
        content: String16<'static>,
        name: String16<'static>,
    ) -> Self {
        Self {
            system_services,
            content,
            name,
        }
    }
}

impl<TSystemServices: SystemServices> Program for ConsoleInstructionalProgram<TSystemServices> {
    fn name(&self) -> String16<'static> {
        self.name
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        let console_size = console.size();
        ConsoleUiTextBox::from(
            &self.system_services,
            constants::TEXT_DISPLAY
                .with_title(constants::BIG_TITLE)
                .with_scroll_text_height(console_size.height() - constants::BIG_TITLE.height() - 1),
        )
        .render_text(
            console_size.width(),
            s16!("Instructions"),
            self.content.content_slice().into(),
        );

        ProgramExitResult::Success
    }
}
