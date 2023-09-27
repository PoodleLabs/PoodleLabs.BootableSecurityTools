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

mod alignment;
mod data_input;
mod list;
mod point;
mod scroll_text;

pub use alignment::UiElementAlignment;
pub use data_input::{DataInput, DataInputType};
pub use list::UiListType;
pub use point::Point;

use crate::String16;

pub trait ConfirmationPrompt {
    fn prompt_for_confirmation(&self, label: String16) -> bool;
}

pub trait ContinuePrompt {
    fn prompt_for_continue(&self);
}
