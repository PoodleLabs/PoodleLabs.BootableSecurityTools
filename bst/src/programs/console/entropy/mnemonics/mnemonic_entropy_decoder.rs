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
    bitcoin::mnemonics::{MnemonicParseResult, MnemonicParser},
    clipboard::ClipboardEntry,
    console_out::ConsoleOut,
    constants,
    programs::{console::write_bytes, Program, ProgramExitResult},
    system_services::SystemServices,
    ui::console::{
        get_mnemonic_input, prompt_for_clipboard_write, ConsoleUiTitle, ConsoleWriteable,
    },
    String16,
};
use macros::s16;

pub struct ConsoleMnemonicEntropyDecoder<
    TMnemonicParser: MnemonicParser,
    TSystemServices: SystemServices,
> {
    clipboard_entry_name: String16<'static>,
    mnemonic_parser: TMnemonicParser,
    system_services: TSystemServices,
    name: String16<'static>,
}

impl<TMnemonicParser: MnemonicParser, TSystemServices: SystemServices>
    ConsoleMnemonicEntropyDecoder<TMnemonicParser, TSystemServices>
{
    pub const fn from(
        clipboard_entry_name: String16<'static>,
        mnemonic_parser: TMnemonicParser,
        system_services: TSystemServices,
        name: String16<'static>,
    ) -> Self {
        Self {
            clipboard_entry_name,
            mnemonic_parser,
            system_services,
            name,
        }
    }
}

impl<TMnemonicParser: MnemonicParser, TSystemServices: SystemServices> Program
    for ConsoleMnemonicEntropyDecoder<TMnemonicParser, TSystemServices>
where
    TMnemonicParser::TParseResult: ConsoleWriteable,
{
    fn name(&self) -> String16<'static> {
        self.name
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        let mnemonic_format = self.mnemonic_parser.mnemonic_format();
        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16(s16!(
                "This program decodes entropy from a mnemonic utilizing the "
            ))
            .output_utf16(mnemonic_format.name())
            .output_utf16(s16!(" format, and "))
            .output_utf16(mnemonic_format.word_list().name())
            .output_utf16_line(s16!(
                " word list, validates it, and extracts the underlying bytes."
            ))
            .in_colours(constants::WARNING_COLOURS, |c| {
                c.output_utf16_line(s16!(
                    "NOTE: This is not the same as building a HD wallet seed!"
                ))
            });

        let mnemonic_input_result = get_mnemonic_input(
            |r| r.can_get_bytes(),
            &self.system_services,
            &self.mnemonic_parser,
            5,
        );

        match mnemonic_input_result {
            Some((_, parse_result)) => match parse_result.get_bytes() {
                Some(bytes) => {
                    write_bytes(&self.system_services, self.clipboard_entry_name, &bytes);
                    prompt_for_clipboard_write(
                        &self.system_services,
                        ClipboardEntry::Bytes(self.clipboard_entry_name, bytes.into()),
                    );

                    ProgramExitResult::Success
                }
                None => ProgramExitResult::UserCancelled,
            },
            None => ProgramExitResult::UserCancelled,
        }
    }
}
