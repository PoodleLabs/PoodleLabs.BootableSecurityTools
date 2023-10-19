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
        hd_wallets::{Bip32KeyType, SerializedExtendedKey},
        validate_checksum_in,
    },
    console_out::ConsoleOut,
    constants,
    integers::{NumericBase, NumericBases},
    programs::{Program, ProgramExitResult},
    system_services::SystemServices,
    ui::{
        console::{
            prompt_for_data_input, ConsoleUiConfirmationPrompt, ConsoleUiKeyValue, ConsoleUiLabel,
            ConsoleUiTitle, ConsoleWriteable,
        },
        ConfirmationPrompt, DataInput, DataInputType,
    },
    String16,
};
use macros::s16;

pub struct ConsoleBip32ExtendedPublicKeyDerivationProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices>
    ConsoleBip32ExtendedPublicKeyDerivationProgram<TSystemServices>
{
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<TSystemServices: SystemServices> Program
    for ConsoleBip32ExtendedPublicKeyDerivationProgram<TSystemServices>
{
    fn name(&self) -> String16<'static> {
        s16!("BIP 32 Extended Public Key Derivation")
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16_line(s16!("This program takes a BIP 32 extended private key as input and derives the associated extended public key."));
        const CANCEL_PROMPT: String16 = s16!("Cancel BIP 32 extended public key derivation?");

        // Get the serialized extended private key bytes to derive an extended public key from.
        let key = loop {
            match prompt_for_data_input(
                Some(NumericBases::Base58.into()),
                &[DataInputType::Bytes],
                &self.system_services,
                CANCEL_PROMPT,
                s16!("Wallet Seed Bytes"),
            ) {
                DataInput::Bytes(mut b) => {
                    // We should expect a 4 byte checksum at the end of the key, but it shouldn't break things if it's not present.
                    if b.len() == 82 {
                        let (checksum_is_valid, _) = validate_checksum_in(&b);
                        if !checksum_is_valid {
                            // The checksum failed; check if the user wants to use the key anyway.
                            if !ConsoleUiConfirmationPrompt::from(&self.system_services)
                                .prompt_for_confirmation(s16!(
                                    "The input key failed checksumming. Use it anyway?"
                                ))
                            {
                                // The user doesn't want to continue; zero the input and try again.
                                b.fill(0);
                                continue;
                            }
                        }

                        // Drop the checksum once we've verified it.
                        b[78..].fill(0);
                        b.truncate(78);
                    }

                    // Extended keys are exactly 78 bytes in length.
                    if b.len() == 78 {
                        // Deserialize the extended key.
                        let serialized_key = match SerializedExtendedKey::from_bytes(&b) {
                            Some(k) => k,
                            None => {
                                return s16!("Failed to deserialize extended key.")
                                    .to_program_error()
                            }
                        };

                        // We're done with the input bytes; zero them out.
                        b.fill(0);

                        // Try to parse the key type.
                        match serialized_key.try_get_key_type() {
                            Ok(t) => match t.key_type() {
                                Bip32KeyType::Private => {
                                    // The user input a valid private key; break out of the input loop with it.
                                    break serialized_key;
                                }
                                Bip32KeyType::Public => {
                                    // The user input a public key; we can't derive a public key from a public key, so zero the key, write an error, and try again.
                                    serialized_key.zero();
                                    console.in_colours(constants::ERROR_COLOURS, |c| {
                                        c.line_start().new_line().output_utf16(s16!(
                                            "Cannot derive an extended public key from an extended public key."
                                        ))
                                    });
                                }
                            },
                            Err(e) => {
                                // Failed to parse the key type; zero the key, write an error, and try again.
                                serialized_key.zero();
                                console.in_colours(constants::ERROR_COLOURS, |c| {
                                    c.line_start().new_line().output_utf16(e)
                                });
                            }
                        }
                    } else {
                        // User input length != 78 bytes; prompt again.
                        b.fill(0);
                        console.in_colours(constants::ERROR_COLOURS, |c| {
                            c.line_start().new_line().output_utf16(s16!(
                                "BIP 32 Master Keys must be exactly 78 bytes long."
                            ))
                        });
                    }
                }
                _ => return ProgramExitResult::UserCancelled,
            };
        };

        // Write out key information.
        ConsoleUiLabel::from(s16!("Extended Private Key Information")).write_to(&console);
        ConsoleUiKeyValue::from(
            s16!("Network"),
            key.try_get_key_type().unwrap().key_network().into(),
        )
        .write_to(&console);
        ConsoleUiKeyValue::from(
            s16!("Depth"),
            String16::from(&NumericBase::BASE_10.build_string_from_bytes(&[key.depth()], true)),
        )
        .write_to(&console);
        ConsoleUiKeyValue::from(
            s16!("Parent Fingerprint"),
            String16::from(
                &NumericBase::BASE_16.build_string_from_bytes(key.parent_fingerprint(), true),
            ),
        )
        .write_to(&console);
        ConsoleUiKeyValue::from(
            s16!("Child Number"),
            String16::from(&NumericBase::BASE_10.build_string_from_bytes(key.child_number(), true)),
        )
        .write_to(&console);

        // Prompt to confirm for public key derivation, given the above information.
        if ConsoleUiConfirmationPrompt::from(&self.system_services)
            .prompt_for_confirmation(s16!("Derive extended public key?"))
        {
            todo!()
        } else {
            ProgramExitResult::UserCancelled
        }
    }
}