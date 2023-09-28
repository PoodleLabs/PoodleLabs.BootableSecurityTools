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

mod clipboard;
mod confirmation_prompt;
mod continue_prompt;
mod data_input;
mod label;
mod list;
mod mnemonic_input;
mod numeric_input;
mod program_selector;
mod scroll_text;
mod text_box;
mod title;

pub use clipboard::{prompt_for_clipboard_select, prompt_for_clipboard_write};
pub use confirmation_prompt::ConsoleUiConfirmationPrompt;
pub use continue_prompt::ConsoleUiContinuePrompt;
pub use data_input::{
    prompt_for_bytes_from_any_data_type, prompt_for_data_input, prompt_for_u128, prompt_for_u16,
    prompt_for_u32, prompt_for_u64, prompt_for_u8, text_input_paste_handler,
};
pub use label::ConsoleUiLabel;
pub use list::{ConsoleUiList, ConsoleUiListEntryStyle, ConsoleUiListStyles};
pub use mnemonic_input::get_mnemonic_input;
pub use numeric_input::{ConsoleUiNumericInput, ConsoleUiNumericInputStyles};
pub use program_selector::ConsoleUiProgramSelector;
pub use scroll_text::{ConsoleUiScrollText, ConsoleUiScrollTextStyles};
pub use text_box::{ConsoleUiTextBox, ConsoleUiTextBoxStyles};
pub use title::{ConsoleUiTitle, ConsoleUiTitleStyles};

use crate::{console_out::ConsoleOut, String16};

pub trait ConsoleWriteable {
    fn write_to<T: ConsoleOut>(&self, console: &T);
}

impl<'a> ConsoleWriteable for String16<'a> {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        console.output_utf16(self.clone());
    }
}
