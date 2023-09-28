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
    bitcoin::mnemonics::{
        allow_extension_phrase_character, derive_hd_wallet_seed,
        ExtensionPhraseNormalizationSettings,
    },
    clipboard::ClipboardEntry,
    console_out::ConsoleOut,
    constants,
    programs::{console::write_bytes, Program, ProgramExitResult},
    system_services::SystemServices,
    ui::console::{
        get_mnemonic_input, prompt_for_clipboard_write, text_input_paste_handler, ConsoleUiTextBox,
        ConsoleUiTitle, ConsoleWriteable,
    },
    String16,
};
use alloc::vec::Vec;
use macros::s16;

pub trait MnemonicSeedDeriveResult: ConsoleWriteable {
    fn can_derive_seed(&self) -> bool;
}

pub struct ConsoleMnemonicBip39SeedDeriver<
    TSystemServices: SystemServices,
    TMnemonicParseResult: MnemonicSeedDeriveResult,
    FMnemonicParser: Fn(&Vec<String16<'static>>) -> TMnemonicParseResult,
> {
    normalization_settings: ExtensionPhraseNormalizationSettings,
    mnemonic_word_spacing: String16<'static>,
    mnemonic_format_name: String16<'static>,
    word_list: &'static [String16<'static>],
    word_list_name: String16<'static>,
    system_services: TSystemServices,
    mnemonic_parser: FMnemonicParser,
    extension_prefix: &'static [u8],
    longest_word_length: usize,
    name: String16<'static>,
    pbkdf_iterations: u32,
    max_words: usize,
}

impl<
        TSystemServices: SystemServices,
        TMnemonicParseResult: MnemonicSeedDeriveResult,
        FMnemonicParser: Fn(&Vec<String16<'static>>) -> TMnemonicParseResult,
    > ConsoleMnemonicBip39SeedDeriver<TSystemServices, TMnemonicParseResult, FMnemonicParser>
{
    pub const fn from(
        normalization_settings: ExtensionPhraseNormalizationSettings,
        mnemonic_word_spacing: String16<'static>,
        mnemonic_format_name: String16<'static>,
        word_list: &'static [String16<'static>],
        word_list_name: String16<'static>,
        system_services: TSystemServices,
        mnemonic_parser: FMnemonicParser,
        extension_prefix: &'static [u8],
        longest_word_length: usize,
        name: String16<'static>,
        pbkdf_iterations: u32,
        max_words: usize,
    ) -> Self {
        Self {
            normalization_settings,
            mnemonic_word_spacing,
            mnemonic_format_name,
            longest_word_length,
            extension_prefix,
            pbkdf_iterations,
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
        TMnemonicParseResult: MnemonicSeedDeriveResult,
        FMnemonicParser: Fn(&Vec<String16<'static>>) -> TMnemonicParseResult,
    > Program
    for ConsoleMnemonicBip39SeedDeriver<TSystemServices, TMnemonicParseResult, FMnemonicParser>
{
    fn name(&self) -> String16<'static> {
        self.name
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16(s16!(
                "This program derives a BIP 32 HD wallet seed from from the "
            ))
            .output_utf16(self.mnemonic_format_name)
            .output_utf16(s16!(" Mnemonic Format utilizing the "))
            .output_utf16(self.word_list_name)
            .output_utf16_line(s16!(" word list."));

        let mnemonic_input_result = get_mnemonic_input::<_, TMnemonicParseResult, _, _>(
            |r| r.can_derive_seed(),
            &self.system_services,
            &self.mnemonic_parser,
            self.word_list,
            5,
            self.longest_word_length,
            self.max_words,
        );

        match mnemonic_input_result {
            Some((mnemonic, _)) => {
                let mut derived_seed = derive_hd_wallet_seed(
                    self.normalization_settings,
                    mnemonic,
                    self.mnemonic_word_spacing,
                    ConsoleUiTextBox::from(&self.system_services, constants::TEXT_INPUT)
                        .get_text_input(
                            console.size().width(),
                            text_input_paste_handler,
                            s16!("Extension Phrase"),
                            s16!(" Text "),
                            Some(allow_extension_phrase_character),
                        ),
                    self.extension_prefix,
                    self.pbkdf_iterations,
                );

                write_bytes(
                    &self.system_services,
                    s16!("BIP 32 HD Wallet Seed"),
                    &derived_seed,
                );

                prompt_for_clipboard_write(
                    &self.system_services,
                    ClipboardEntry::Bytes(s16!("BIP 32 HD Wallet Seed"), derived_seed[..].into()),
                );

                derived_seed.fill(0);
                ProgramExitResult::Success
            }
            None => ProgramExitResult::UserCancelled,
        }
    }
}
