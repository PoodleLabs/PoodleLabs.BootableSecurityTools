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
    bitcoin::{
        base_58_encode_with_checksum,
        hd_wallets::{try_derive_master_key, Bip32KeyNetwork},
    },
    clipboard::ClipboardEntry,
    console_out::ConsoleOut,
    constants,
    programs::{console::write_string_program_output, Program, ProgramExitResult},
    system_services::SystemServices,
    ui::{
        console::{
            prompt_for_clipboard_write, prompt_for_data_input, ConsoleUiConfirmationPrompt,
            ConsoleUiLabel, ConsoleUiList, ConsoleUiTitle, ConsoleWriteable,
        },
        ConfirmationPrompt, DataInput, DataInputType,
    },
    String16,
};
use macros::s16;

pub struct ConsoleBip32MasterKeyDerivationProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices> ConsoleBip32MasterKeyDerivationProgram<TSystemServices> {
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<TSystemServices: SystemServices> Program
    for ConsoleBip32MasterKeyDerivationProgram<TSystemServices>
{
    fn name(&self) -> String16<'static> {
        s16!("BIP 32 Master Key Derivation")
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16_line(s16!("This program takes 16-64 (inclusive) bytes of input and derives a BIP 32 master key for a HD Wallet."))
            .in_colours(constants::WARNING_COLOURS, |c| c.output_utf16_line(
                    s16!("If your bytes were sourced from a mnemonic, you should use the BIP 32 seed, not the decoded entropy bytes.")));
        const CANCEL_PROMPT: String16 = s16!("Cancel BIP 32 master key derivation?");

        // Get the bytes to derive a master key from.
        let mut bytes = loop {
            match prompt_for_data_input(
                None,
                &[DataInputType::Bytes],
                &self.system_services,
                CANCEL_PROMPT,
                s16!("Wallet Seed Bytes"),
            ) {
                DataInput::Bytes(mut b) => {
                    if b.len() >= 16 && b.len() <= 64 {
                        break b;
                    } else {
                        b.fill(0);
                        console.in_colours(constants::ERROR_COLOURS, |c| {
                            c.line_start().new_line().output_utf16(s16!(
                                "BIP 32 Master Key Derivation requires between 16 and 64 bytes."
                            ))
                        });
                    }
                }
                _ => return ProgramExitResult::UserCancelled,
            };
        };

        let version_list_label = ConsoleUiLabel::from(s16!("Select key type to generate"));
        let mut version_list = ConsoleUiList::from(
            ConsoleUiTitle::from(s16!(" KEY TYPE "), constants::SMALL_TITLE),
            constants::SELECT_LIST,
            &[Bip32KeyNetwork::MainNet, Bip32KeyNetwork::TestNet][..],
        );

        // Prompt the user to select a BIP 32 key version.
        let version = loop {
            version_list_label.write_to(&console);
            match version_list.prompt_for_selection(&self.system_services) {
                Some((v, ..)) => break *v,
                None => {
                    if ConsoleUiConfirmationPrompt::from(&self.system_services)
                        .prompt_for_confirmation(CANCEL_PROMPT)
                    {
                        return ProgramExitResult::UserCancelled;
                    }
                }
            }
        };

        // Try to derive the key.
        let key_derivation_result = try_derive_master_key(version, &bytes);
        bytes.fill(0);

        match key_derivation_result {
            Some(k) => {
                // Serialize the key.
                let base58_key = base_58_encode_with_checksum(&k.as_bytes());
                k.zero();

                const LABEL: String16 = s16!("BIP 32 Master Key");
                write_string_program_output(
                    &self.system_services,
                    LABEL,
                    String16::from(&base58_key),
                );

                prompt_for_clipboard_write(
                    &self.system_services,
                    ClipboardEntry::String16(LABEL, base58_key.into()),
                );

                ProgramExitResult::Success
            }
            None => {
                // We generated a key outside the bounds of valid secp256k1 keys. This is extremely unlikely,
                // and knowing the input would be a useful test vector because such a test vector is not yet known.
                s16!("BIP 32 Key Derivation escaped the range of valid secp256k1 keys.")
                    .to_program_error()
            }
        }
    }
}

impl ConsoleWriteable for Bip32KeyNetwork {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        console.output_utf16(match self {
            Bip32KeyNetwork::MainNet => s16!("Main Net"),
            Bip32KeyNetwork::TestNet => s16!("Test Net"),
        });
    }
}
