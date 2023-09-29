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
    bitcoin::mnemonics::{allow_mnemonic_text_character, MnemonicParseResult, MnemonicParser},
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
use macros::s16;

pub struct ConsoleMnemonicBip39SeedDeriver<
    TMnemonicParser: MnemonicParser,
    TSystemServices: SystemServices,
> {
    system_services: TSystemServices,
    mnemonic_parser: TMnemonicParser,
    name: String16<'static>,
}

impl<TMnemonicParser: MnemonicParser, TSystemServices: SystemServices>
    ConsoleMnemonicBip39SeedDeriver<TMnemonicParser, TSystemServices>
{
    pub const fn from(
        system_services: TSystemServices,
        mnemonic_parser: TMnemonicParser,
        name: String16<'static>,
    ) -> Self {
        Self {
            system_services,
            mnemonic_parser,
            name,
        }
    }
}

impl<TMnemonicParser: MnemonicParser, TSystemServices: SystemServices> Program
    for ConsoleMnemonicBip39SeedDeriver<TMnemonicParser, TSystemServices>
where
    TMnemonicParser::TParseResult: ConsoleWriteable,
{
    fn name(&self) -> String16<'static> {
        self.name
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        let mnemonic_format = self.mnemonic_parser.mnemonic_format();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16(s16!(
                "This program derives a BIP 32 HD wallet seed from a mnemonic utilizing the "
            ))
            .output_utf16(mnemonic_format.name())
            .output_utf16(s16!(" format, and "))
            .output_utf16(mnemonic_format.word_list().name())
            .output_utf16_line(s16!(" word list."));

        let mnemonic_input_result = get_mnemonic_input(
            |r| r.can_derive_bip_32_seed(),
            &self.system_services,
            &self.mnemonic_parser,
            5,
        );

        match mnemonic_input_result {
            Some((mnemonic, _)) => {
                let mut derived_seed = self
                    .mnemonic_parser
                    .bip_32_derivation_settings()
                    .derive_hd_wallet_seed(
                        ConsoleUiTextBox::from(&self.system_services, constants::TEXT_INPUT)
                            .get_text_input(
                                console.size().width(),
                                text_input_paste_handler,
                                s16!("Extension Phrase"),
                                s16!(" Text "),
                                Some(allow_mnemonic_text_character),
                            ),
                        mnemonic,
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
