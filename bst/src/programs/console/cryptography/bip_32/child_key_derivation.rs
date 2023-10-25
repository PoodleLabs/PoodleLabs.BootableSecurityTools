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
        hd_wallets::{
            DerivationPathPoint, SerializedExtendedKey, HARDENED_CHILD_DERIVATION_THRESHOLD,
            MAX_DERIVATION_POINT,
        },
        validate_checksum_in,
    },
    console_out::ConsoleOut,
    constants,
    integers::{BigUnsigned, NumericBase, NumericBases},
    programs::{Program, ProgramExitResult},
    system_services::SystemServices,
    ui::{
        console::{
            prompt_for_data_input, prompt_for_u32, ConsoleUiConfirmationPrompt,
            ConsoleUiContinuePrompt, ConsoleUiKeyValue, ConsoleUiLabel, ConsoleUiTitle,
            ConsoleWriteable,
        },
        ConfirmationPrompt, ContinuePrompt, DataInput, DataInputType,
    },
    String16,
};
use alloc::vec::Vec;
use macros::s16;

pub struct ConsoleBip32ChildKeyDerivationProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices> ConsoleBip32ChildKeyDerivationProgram<TSystemServices> {
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<TSystemServices: SystemServices> Program
    for ConsoleBip32ChildKeyDerivationProgram<TSystemServices>
{
    fn name(&self) -> String16<'static> {
        s16!("BIP 32 Child Key Derivation")
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16_line(s16!("This program takes a BIP 32 extended key as input, along with a derivation path and derives the associated child key."));
        const CANCEL_PROMPT: String16 = s16!("Cancel BIP 32 child key derivation?");

        // Get the serialized extended key bytes to derive child from.
        let parent_key = loop {
            match prompt_for_data_input(
                Some(NumericBases::Base58.into()),
                &[DataInputType::Bytes],
                &self.system_services,
                CANCEL_PROMPT,
                s16!("Parent Key"),
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
                        match serialized_key.try_get_key_version() {
                            // The key has a valid type; we can use it.
                            Ok(_) => break serialized_key,
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
                                "BIP 32 extended keys are exactly 78 bytes in length (plus an optional 4 byte checksum)."
                            ))
                        });
                    }
                }
                _ => return ProgramExitResult::UserCancelled,
            };
        };

        // Get the network the private key is for.
        let key_version = parent_key.try_get_key_version().unwrap();
        let key_network = key_version.key_network();
        let key_type = key_version.key_type();

        // Write out key information.
        ConsoleUiLabel::from(s16!("Extended Key Information")).write_to(&console);
        ConsoleUiKeyValue::from(s16!("Type"), key_type.into()).write_to(&console);
        ConsoleUiKeyValue::from(s16!("Network"), key_network.into()).write_to(&console);
        ConsoleUiKeyValue::from(
            s16!("Depth"),
            String16::from(
                &NumericBase::BASE_10.build_string_from_bytes(&[parent_key.depth()], true),
            ),
        )
        .write_to(&console);
        ConsoleUiKeyValue::from(
            s16!("Parent Fingerprint"),
            String16::from(
                &NumericBase::BASE_16
                    .build_string_from_bytes(parent_key.parent_fingerprint(), true),
            ),
        )
        .write_to(&console);
        ConsoleUiKeyValue::from(
            s16!("Child Number"),
            String16::from(
                &NumericBase::BASE_10.build_string_from_bytes(parent_key.child_number(), true),
            ),
        )
        .write_to(&console);

        // Create a vector for building up the derivation path.
        let mut derivation_path_points = Vec::new();

        // Create a big unsigned to work with.
        let mut working_big_unsigned = BigUnsigned::with_capacity(32);
        loop {
            loop {
                // Prompt the user to enter a derivation path point.
                let point_integer = match prompt_for_u32(
                    |u| {
                        if u <= MAX_DERIVATION_POINT {
                            None
                        } else {
                            Some(s16!("Derivation path points must be < 2^31."))
                        }
                    },
                    s16!("Derivation Path Point"),
                    &self.system_services,
                    s16!("Complete the derivation path?"),
                    Some(NumericBases::Decimal.into()),
                ) {
                    Some(v) => v,
                    // The user indicated the derivation path is complete.
                    None => break,
                };

                // Check whether this point should be hardened.
                let is_hardened = ConsoleUiConfirmationPrompt::from(&self.system_services)
                    .prompt_for_confirmation(s16!("Harden this derivation path point?"));

                // Add the point to the derivation path.
                derivation_path_points.push(DerivationPathPoint::from(if is_hardened {
                    point_integer | HARDENED_CHILD_DERIVATION_THRESHOLD
                } else {
                    point_integer
                }));
            }

            if derivation_path_points.len() == 0 {
                // The user didn't enter any derivation path points; the key wouldn't change if we tried to derive it.
                console
                    .line_start()
                    .new_line()
                    .in_colours(constants::SUCCESS_COLOURS, |c| {
                        c.output_utf16_line(s16!(
                            "A derivation path of 'm/' just returns m; there's no child to derive."
                        ))
                    });

                ConsoleUiContinuePrompt::from(&self.system_services).prompt_for_continue();
                return ProgramExitResult::Success;
            }

            // Write out the derivation path for the user to confirm.
            ConsoleUiLabel::from(s16!("Derivation Path")).write_to(&console);
            console.output_utf16(s16!("m/"));
            for point in &derivation_path_points {
                // We write hardened derivation path points as "[x - 2^31]'/", and unhardened derivation path points as "[x]/".
                let (point_numeric, point_terminator) = if point.is_for_hardened_key() {
                    (point.numeric_value() & MAX_DERIVATION_POINT, s16!("'/"))
                } else {
                    (point.numeric_value(), s16!("/"))
                };

                working_big_unsigned.copy_digits_from(&point_numeric.to_be_bytes());
                console.output_utf16(String16::from(
                    &NumericBase::BASE_10.build_string_from_big_unsigned(
                        &mut working_big_unsigned,
                        true,
                        1,
                    ),
                ));
                console.output_utf16(point_terminator);
            }

            if ConsoleUiConfirmationPrompt::from(&self.system_services)
                .prompt_for_confirmation(s16!("Derive the above path?"))
            {
                // User confirmed derivation path; break out of the derivation path input loop to continue program execution.
                break;
            }

            // User indicated they don't want to derive the above path; clear and try again.
            derivation_path_points.clear();
            continue;
        }

        // Derive child key.
        todo!()
    }
}
