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

pub mod console;
pub mod exit_result_handlers;
pub mod power_option_programs;
pub mod program_lists;

use crate::{console_out::ConsoleOut, ui::console::ConsoleWriteable, String16};
use alloc::{boxed::Box, sync::Arc};

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProgramExitResult {
    Success,
    UserCancelled,
    String16Error(Box<[u16]>),
}

pub trait Program {
    fn name(&self) -> String16<'static>;

    fn run(&self) -> ProgramExitResult;
}

impl ConsoleWriteable for Arc<dyn Program> {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        console.output_utf16(self.name());
    }
}
