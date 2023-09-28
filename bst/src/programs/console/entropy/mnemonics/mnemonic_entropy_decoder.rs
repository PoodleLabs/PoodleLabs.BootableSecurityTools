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
use alloc::{boxed::Box, vec::Vec};
use macros::s16;

pub trait MnemonicByteParseResult: ConsoleWriteable {
    fn get_bytes(self) -> Option<Box<[u8]>>;

    fn can_get_bytes(&self) -> bool;
}

pub struct ConsoleMnemonicEntropyDecoder<
    TSystemServices: SystemServices,
    TMnemonicParseResult: MnemonicByteParseResult,
    FMnemonicParser: Fn(&Vec<String16<'static>>) -> TMnemonicParseResult,
> {
    clipboard_entry_name: String16<'static>,
    mnemonic_format_name: String16<'static>,
    word_list: &'static [String16<'static>],
    word_list_name: String16<'static>,
    system_services: TSystemServices,
    mnemonic_parser: FMnemonicParser,
    longest_word_length: usize,
    name: String16<'static>,
    max_words: usize,
}

impl<
        TSystemServices: SystemServices,
        TMnemonicParseResult: MnemonicByteParseResult,
        FMnemonicParser: Fn(&Vec<String16<'static>>) -> TMnemonicParseResult,
    > ConsoleMnemonicEntropyDecoder<TSystemServices, TMnemonicParseResult, FMnemonicParser>
{
    pub const fn from(
        clipboard_entry_name: String16<'static>,
        mnemonic_format_name: String16<'static>,
        word_list: &'static [String16<'static>],
        word_list_name: String16<'static>,
        system_services: TSystemServices,
        mnemonic_parser: FMnemonicParser,
        longest_word_length: usize,
        name: String16<'static>,
        max_words: usize,
    ) -> Self {
        Self {
            clipboard_entry_name,
            mnemonic_format_name,
            longest_word_length,
            system_services,
            mnemonic_parser,
            word_list_name,
            word_list,
            max_words,
            name,
        }
    }
}

impl<
        TSystemServices: SystemServices,
        TMnemonicParseResult: MnemonicByteParseResult,
        FMnemonicParser: Fn(&Vec<String16<'static>>) -> TMnemonicParseResult,
    > Program
    for ConsoleMnemonicEntropyDecoder<TSystemServices, TMnemonicParseResult, FMnemonicParser>
{
    fn name(&self) -> String16<'static> {
        self.name
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16(s16!("This program decodes entropy from the "))
            .output_utf16(self.mnemonic_format_name)
            .output_utf16(s16!(" Mnemonic Format utilizing the "))
            .output_utf16(self.word_list_name)
            .output_utf16_line(s16!(
                " word list, validates it, and extracts the underlying bytes."
            ))
            .in_colours(constants::WARNING_COLOURS, |c| {
                c.output_utf16_line(s16!(
                    "NOTE: This is not the same as building a HD wallet seed!"
                ))
            });

        let mnemonic_input_result = get_mnemonic_input::<_, TMnemonicParseResult, _, _>(
            |r| r.can_get_bytes(),
            &self.system_services,
            &self.mnemonic_parser,
            self.word_list,
            5,
            self.longest_word_length,
            self.max_words,
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
