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
    console_out::ConsoleOut,
    constants,
    cryptography::asymmetric::ecc::secp256k1,
    hashing::{Hasher, Sha512},
    integers::BigUnsigned,
    programs::{console::write_bytes, Program, ProgramExitResult},
    system_services::SystemServices,
    ui::{
        console::{
            prompt_for_clipboard_write, prompt_for_data_input, ConsoleUiConfirmationPrompt,
            ConsoleUiContinuePrompt, ConsoleUiTitle, ConsoleWriteable,
        },
        ConfirmationPrompt, ContinuePrompt, DataInput, DataInputType,
    },
    String16,
};
use alloc::vec;
use core::cmp::Ordering;
use macros::s16;

const ITERATIVE_HASHING_KEY: &[u8] = "Extremely Large Numer Private Key".as_bytes();

pub struct ConsoleEllipticCurvePublicKeyDerivationProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices>
    ConsoleEllipticCurvePublicKeyDerivationProgram<TSystemServices>
{
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<TSystemServices: SystemServices> Program
    for ConsoleEllipticCurvePublicKeyDerivationProgram<TSystemServices>
{
    fn name(&self) -> String16<'static> {
        s16!("Elliptic Curve Public Key Derivation")
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16_line(s16!("This program derives a public key from a private key using Elliptic Curve cryptography."));
        const CANCEL_PROMPT: String16 = s16!("Cancel public key derivation?");

        // TODO: Select a curve.

        // Get the private key to derive a public key from.
        let mut private_key = loop {
            match prompt_for_data_input(
                None,
                &[DataInputType::Number],
                &self.system_services,
                CANCEL_PROMPT,
                s16!("Private Key"),
            ) {
                DataInput::Number(mut b) => {
                    if b.is_zero() {
                        // Zero is an invalid private key.
                        console.in_colours(constants::ERROR_COLOURS, |c| {
                            c.line_start()
                                .new_line()
                                .output_utf16(s16!("Zero is not a valid private key."))
                        });

                        continue;
                    } else if b.cmp(secp256k1::n()) != Ordering::Less {
                        // Private keys must be less than the N value of the curve. We'll ask the user what to do.
                        console.in_colours(constants::WARNING_COLOURS, |c| {
                            c.line_start().new_line().output_utf16_line(s16!(
                                "The input is >= the curve's N value; we cannot derive a public key from it directly."
                            )).output_utf16(s16!("If you use it as a private key, it will not be portable with other applications!"))
                        });

                        // The user can either try inputting a different key, or we can iteratively hash the key until we
                        // get a valid key. Prompt them to select a behaviour.
                        if ConsoleUiConfirmationPrompt::from(&self.system_services)
                            .prompt_for_confirmation(s16!(
                                "Use the input by hashing until it yields a valid private key?"
                            ))
                        {
                            let mut hasher = Sha512::new();
                            let mut hash_buffer = vec![0u8; Sha512::HASH_SIZE];
                            let mut hmac = hasher.build_hmac(ITERATIVE_HASHING_KEY);
                            break loop {
                                hmac.write_hmac_to(&b.borrow_digits(), &mut hash_buffer);
                                // TODO: 32 should depend on the byte size of a private key.
                                hash_buffer.truncate(32);

                                // Give the hash buffer to a BigUnsigned; we'll compare and, if it's a valid private key, use it.
                                let integer = BigUnsigned::from_vec(hash_buffer);
                                if integer.is_non_zero()
                                    && integer.cmp(secp256k1::n()) == Ordering::Less
                                {
                                    // Zero out the original integer, reset the hasher, and exit the loop with our new value.
                                    b.zero();
                                    hasher.reset();
                                    break integer;
                                }

                                // Increment the oversized private key.
                                b.add_u8(1);

                                // Take back ownership of the hash buffer.
                                hash_buffer = integer.extract_be_bytes();

                                // Reset the hash buffer to the correct length.
                                hash_buffer.truncate(0);
                                hash_buffer.extend((0..Sha512::HASH_SIZE).into_iter().map(|_| 0))
                            };
                        } else {
                            // We don't want to hash to use the provided oversized private key; zero it and try input again.
                            b.zero();
                            continue;
                        }
                    }

                    // The key was not zero, and not oversized; we can use it as-is.
                    break b;
                }
                _ => return ProgramExitResult::UserCancelled,
            };
        };

        console.in_colours(constants::SUCCESS_COLOURS, |c| {
            c.line_start()
                .new_line()
                .output_utf16(s16!("Deriving public key..."))
        });

        let point = match secp256k1::point_multiplication_context().multiply_point(
            secp256k1::g_x(),
            secp256k1::g_y(),
            &private_key,
        ) {
            Some(point) => point,
            None => {
                console.in_colours(constants::ERROR_COLOURS, |c| {
                    c.line_start().new_line().output_utf16(s16!(
                        "Failed to derive a public key; this shouldn't have happened."
                    ))
                });

                ConsoleUiContinuePrompt::from(&self.system_services).prompt_for_continue();
                return ProgramExitResult::String16Error(
                    s16!("Public key derivation failure.")
                        .content_slice()
                        .into(),
                );
            }
        };

        // We're done with the private key; zero it.
        private_key.zero();

        // Serialize the public key for output.
        let serialized_point = match secp256k1::serialized_public_key_bytes(point) {
            Some(serialized_point) => serialized_point,
            None => {
                console.in_colours(constants::ERROR_COLOURS, |c| {
                    c.line_start().new_line().output_utf16(s16!(
                        "Failed to serialize the public key; this shouldn't have happened."
                    ))
                });

                ConsoleUiContinuePrompt::from(&self.system_services).prompt_for_continue();
                return ProgramExitResult::String16Error(
                    s16!("Public key serialization failure.")
                        .content_slice()
                        .into(),
                );
            }
        };

        write_bytes(&self.system_services, s16!("Public Key"), &serialized_point);
        prompt_for_clipboard_write(
            &self.system_services,
            crate::clipboard::ClipboardEntry::Bytes(
                s16!("secp256k1 Public Key"),
                (&serialized_point[..]).into(),
            ),
        );

        ProgramExitResult::Success
    }
}
