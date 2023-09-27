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
    hashing::{Hasher, Sha512},
    integers::{NumericBases, NumericCollector, NumericCollectorRoundBase},
    programs::{
        console::write_bytes,
        exit_result_handlers::ProgramExitResultHandler,
        program_lists::{ProgramList, ProgramListProgram, ProgramSelector},
        Program, ProgramExitResult,
    },
    system_services::SystemServices,
    ui::{
        console::{
            prompt_for_bytes_from_any_data_type, prompt_for_clipboard_write, prompt_for_u16,
            prompt_for_u32, prompt_for_u8, ConsoleUiConfirmationPrompt, ConsoleUiLabel,
            ConsoleUiList, ConsoleUiTitle, ConsoleWriteable,
        },
        ConfirmationPrompt,
    },
    String16,
};
use alloc::{format, sync::Arc, vec};
use macros::s16;

fn von_neumann_info<TSystemServices: SystemServices>(
    system_services: &TSystemServices,
    singular_name: String16,
    source_name: String16,
    round: String16,
    bits: String16,
) {
    let console = system_services.get_console_out();
    console
        .output_utf16(s16!("This program collects entropy from "))
        .output_utf16(source_name)
        .output_utf16(s16!(
            " and performs Von Neumann bias correction on the results. You should use a single "
        ))
        .output_utf16(singular_name)
        .output_utf16_line(s16!(", as bias correction only works when the bias is stable across each round, and each round is entirely independent. Given those two properties, you will receive truly random, unbiased input."))
        .output_utf16(s16!("Each ")).output_utf16(round).output_utf16(s16!(" collects an average of "))
        .output_utf16(bits)
        .output_utf16(s16!(" of entropy; the more biased the input, fewer bits per "))
        .output_utf16(round)
        .output_utf16_line(s16!(" are collected."));
}

fn raw_source_info<TSystemServices: SystemServices>(
    system_services: &TSystemServices,
    multi_source: Option<String16>,
    source_name: String16,
    bits: String16,
) {
    let console = system_services.get_console_out();
    console
        .output_utf16(s16!("This program collects entropy from "))
        .output_utf16(source_name)
        .output_utf16(s16!(" without performing any bias correction"));
    match multi_source {
        Some(plural) => {
            console
                .output_utf16(s16!("; you can use multiple "))
                .output_utf16(plural)
                .output_utf16_line(s16!(" them all at once, and enter them one by one."));
        }
        None => {
            console.output_utf16_line(s16!("."));
        }
    }

    console
        .output_utf16(s16!("Each round collects "))
        .output_utf16(bits)
        .output_utf16_line(s16!(" of entropy."));
}

pub fn get_manual_entropy_collection_program_list<
    'a,
    TSystemServices: SystemServices,
    TProgramSelector: ProgramSelector + 'static,
    TProgramExitResultHandler: ProgramExitResultHandler + 'static,
>(
    system_services: &TSystemServices,
    program_selector: &TProgramSelector,
    exit_result_handler: &TProgramExitResultHandler,
) -> ProgramListProgram<TProgramSelector, TProgramExitResultHandler> {
    let programs: [Arc<dyn Program>; 10] = [
        Arc::from(power_of_2_base_programs(
            s16!("Coinflips"),
            system_services,
            program_selector,
            s16!("Raw Coinflips"),
            |s| {
                raw_source_info(
                    s,
                    Some(s16!("coins, flip")),
                    s16!("coinflips"),
                    s16!("1 bit"),
                )
            },
            raw_round_from_list::<2, TSystemServices>,
            s16!("Raw Coinflip Entropy"),
            NumericCollectorRoundBase::SubByte(2),
            s16!("Bias Corrected Coinflips"),
            |s| {
                von_neumann_info(
                    s,
                    s16!("coin"),
                    s16!("coinflips"),
                    s16!("flip"),
                    s16!("0.5 bits"),
                )
            },
            bias_corrected_round_from_list::<2, 1, TSystemServices>,
            s16!("Bias Corrected Coinflip Entropy"),
            exit_result_handler,
        )),
        Arc::from(power_of_2_base_programs(
            s16!("D4 Rolls"),
            system_services,
            program_selector,
            s16!("Raw D4 Rolls"),
            |s| {
                raw_source_info(
                    s,
                    Some(s16!("D4s, roll")),
                    s16!("four-sided dice rolls"),
                    s16!("2 bits"),
                )
            },
            raw_round_from_list::<4, TSystemServices>,
            s16!("Raw D4 Roll Entropy"),
            NumericCollectorRoundBase::SubByte(4),
            s16!("Bias Corrected D4 Rolls"),
            |s| {
                von_neumann_info(
                    s,
                    s16!("dice"),
                    s16!("four-sided dice rolls"),
                    s16!("roll"),
                    s16!("1 bit"),
                )
            },
            bias_corrected_round_from_list::<4, 2, TSystemServices>,
            s16!("Bias Corrected D4 Roll Entropy"),
            exit_result_handler,
        )),
        Arc::from(non_power_of_2_base_program(
            |s| {
                raw_source_info(
                    s,
                    Some(s16!("D6s, roll")),
                    s16!("six-sided dice rolls"),
                    s16!("~2.58 bits"),
                )
            },
            raw_round_from_list::<6, TSystemServices>,
            s16!("D6 Rolls"),
            NumericCollectorRoundBase::SubByte(6),
            system_services,
            s16!("D6 Roll Entropy"),
        )),
        Arc::from(power_of_2_base_programs(
            s16!("D8 Rolls"),
            system_services,
            program_selector,
            s16!("Raw D8 Rolls"),
            |s| {
                raw_source_info(
                    s,
                    Some(s16!("D8s, roll")),
                    s16!("eight-sided dice rolls"),
                    s16!("3 bits"),
                )
            },
            raw_round_from_list::<8, TSystemServices>,
            s16!("Raw D8 Roll Entropy"),
            NumericCollectorRoundBase::SubByte(8),
            s16!("Bias Corrected D8 Rolls"),
            |s| {
                von_neumann_info(
                    s,
                    s16!("dice"),
                    s16!("eight-sided dice rolls"),
                    s16!("roll"),
                    s16!("1.5 bits"),
                )
            },
            bias_corrected_round_from_list::<8, 3, TSystemServices>,
            s16!("Bias Corrected D8 Roll Entropy"),
            exit_result_handler,
        )),
        Arc::from(non_power_of_2_base_program(
            |s| {
                raw_source_info(
                    s,
                    Some(s16!("D10s, roll")),
                    s16!("ten-sided dice rolls"),
                    s16!("~3.32 bits"),
                )
            },
            raw_round_from_list::<10, TSystemServices>,
            s16!("D10 Rolls"),
            NumericCollectorRoundBase::SubByte(10),
            system_services,
            s16!("D10 Roll Entropy"),
        )),
        Arc::from(non_power_of_2_base_program(
            |s| {
                raw_source_info(
                    s,
                    Some(s16!("D12s, roll")),
                    s16!("twelve-sided dice rolls"),
                    s16!("~3.58 bits"),
                )
            },
            raw_round_from_numeric_input::<12, TSystemServices>,
            s16!("D12 Rolls"),
            NumericCollectorRoundBase::SubByte(12),
            system_services,
            s16!("D12 Roll Entropy"),
        )),
        Arc::from(power_of_2_base_programs(
            s16!("D16 Rolls"),
            system_services,
            program_selector,
            s16!("Raw D16 Rolls"),
            |s| {
                raw_source_info(
                    s,
                    Some(s16!("D16s, roll")),
                    s16!("sixteen-sided dice rolls"),
                    s16!("4 bits"),
                )
            },
            raw_round_from_numeric_input::<16, TSystemServices>,
            s16!("Raw D16 Roll Entropy"),
            NumericCollectorRoundBase::SubByte(16),
            s16!("Bias Corrected D16 Rolls"),
            |s| {
                von_neumann_info(
                    s,
                    s16!("dice"),
                    s16!("sixteen-sided dice rolls"),
                    s16!("roll"),
                    s16!("2 bits"),
                )
            },
            bias_corrected_round_from_numeric_input::<16, 4, TSystemServices>,
            s16!("Bias Corrected D16 Roll Entropy"),
            exit_result_handler,
        )),
        Arc::from(non_power_of_2_base_program(
            |s| {
                raw_source_info(
                    s,
                    Some(s16!("D20s, roll")),
                    s16!("twenty-sided dice rolls"),
                    s16!("~4.32 bits"),
                )
            },
            raw_round_from_numeric_input::<20, TSystemServices>,
            s16!("D20 Rolls"),
            NumericCollectorRoundBase::SubByte(20),
            system_services,
            s16!("D20 Roll Entropy"),
        )),
        Arc::from(non_power_of_2_base_program(
            |s| {
                raw_source_info(
                    s,
                    Some(s16!("D100s, roll")),
                    s16!("D100 rolls"),
                    s16!("~6.64 bits"),
                )
            },
            raw_round_from_numeric_input::<100, TSystemServices>,
            s16!("D100 Rolls"),
            NumericCollectorRoundBase::SubByte(100),
            system_services,
            s16!("D100 Roll Entropy"),
        )),
        Arc::from(power_of_2_base_programs(
            s16!("Random Bytes"),
            system_services,
            program_selector,
            s16!("Raw Random Bytes"),
            |s| {
                raw_source_info(
                    s,
                    None,
                    s16!("externally-sourced random bytes"),
                    s16!("8 bits"),
                )
            },
            raw_round_from_numeric_input::<256, TSystemServices>,
            s16!("Raw Random Byte Entropy"),
            NumericCollectorRoundBase::WholeByte,
            s16!("Bias Corrected Random Bytes"),
            |s| {
                von_neumann_info(
                    s,
                    s16!("random byte generator"),
                    s16!("externally generated random bytes"),
                    s16!("input"),
                    s16!("4 bits"),
                )
            },
            bias_corrected_round_from_numeric_input::<256, 8, TSystemServices>,
            s16!("Bias Corrected Random Byte Entropy"),
            exit_result_handler,
        )),
    ];
    ProgramList::from(
        Arc::from(programs),
        s16!("Manual Entropy Collection Programs"),
    )
    .as_program(program_selector.clone(), exit_result_handler.clone())
}

fn power_of_2_base_programs<
    'a,
    const BITS_PER_ROUND: usize,
    TSystemServices: SystemServices,
    TProgramSelector: ProgramSelector + 'static,
    TProgramExitResultHandler: ProgramExitResultHandler + 'static,
    FRawWriteInfo: Fn(&TSystemServices) + 'static,
    FRawRound: Fn(&TSystemServices, String16<'static>, u16, f64) -> Option<[Option<u8>; 1]> + 'static,
    FVonNeumannWriteInfo: Fn(&TSystemServices) + 'static,
    FVonNeumannRound: Fn(&TSystemServices, String16<'static>, u16, f64) -> Option<[Option<u8>; BITS_PER_ROUND]>
        + 'static,
>(
    list_name: String16<'static>,
    system_services: &TSystemServices,
    program_selector: &TProgramSelector,
    raw_program_name: String16<'static>,
    raw_program_write_info: FRawWriteInfo,
    raw_program_round_collector: FRawRound,
    raw_program_clipboard_entry_name: String16<'static>,
    raw_program_base: NumericCollectorRoundBase,
    von_neumann_program_name: String16<'static>,
    von_neumann_program_write_info: FVonNeumannWriteInfo,
    von_neumann_program_round_collector: FVonNeumannRound,
    von_neumann_program_clipboard_entry_name: String16<'static>,
    exit_result_handler: &TProgramExitResultHandler,
) -> ProgramListProgram<TProgramSelector, TProgramExitResultHandler> {
    let programs: [Arc<dyn Program>; 2] = [
        Arc::from(ConsoleManualEntropyCollectionProgram::<
            1,
            TSystemServices,
            FRawWriteInfo,
            FRawRound,
        >::from(
            raw_program_clipboard_entry_name,
            system_services.clone(),
            raw_program_base,
            raw_program_name,
            raw_program_round_collector,
            raw_program_write_info,
        )),
        Arc::from(ConsoleManualEntropyCollectionProgram::<
            BITS_PER_ROUND,
            TSystemServices,
            FVonNeumannWriteInfo,
            FVonNeumannRound,
        >::from(
            von_neumann_program_clipboard_entry_name,
            system_services.clone(),
            NumericCollectorRoundBase::SubByte(2),
            von_neumann_program_name,
            von_neumann_program_round_collector,
            von_neumann_program_write_info,
        )),
    ];
    ProgramList::from(Arc::from(programs), list_name)
        .as_program(program_selector.clone(), exit_result_handler.clone())
}

fn non_power_of_2_base_program<
    TSystemServices: SystemServices,
    FWriteInfo: Fn(&TSystemServices),
    FRound: Fn(&TSystemServices, String16<'static>, u16, f64) -> Option<[Option<u8>; 1]>,
>(
    write_info: FWriteInfo,
    round_collector: FRound,
    name: String16<'static>,
    base: NumericCollectorRoundBase,
    system_services: &TSystemServices,
    clipboard_entry_name: String16<'static>,
) -> ConsoleManualEntropyCollectionProgram<1, TSystemServices, FWriteInfo, FRound> {
    ConsoleManualEntropyCollectionProgram::from(
        clipboard_entry_name,
        system_services.clone(),
        base,
        name,
        round_collector,
        write_info,
    )
}

fn bias_corrected_round<
    const BASE: usize,
    const BITS_PER_INPUT: usize,
    TSystemServices: SystemServices,
    FInput: Fn(&TSystemServices, String16<'static>, String16<'static>, u16, f64) -> Option<[Option<u8>; 1]>,
>(
    system_services: &TSystemServices,
    cancel_prompt: String16<'static>,
    target_bytes: u16,
    collected_bits: f64,
    input: FInput,
) -> Option<[Option<u8>; BITS_PER_INPUT]> {
    // Get the first input for the round.
    let input_1 = match (input)(
        system_services,
        cancel_prompt,
        s16!("Round Input #1"),
        target_bytes,
        collected_bits,
    ) {
        None => return None,
        Some(i) => i,
    };

    // Get the second input for the round.
    let input_2 = match (input)(
        system_services,
        cancel_prompt,
        s16!("Round Input #2"),
        target_bytes,
        collected_bits,
    ) {
        None => return None,
        Some(i) => i,
    };

    // Check each bit of both inputs; if they are different, take the bit from the first input.
    let mut r = [None; BITS_PER_INPUT];
    for i in 0..BITS_PER_INPUT {
        let r1 = 1 & (input_1[0].unwrap() >> i);
        let r2 = 1 & (input_2[0].unwrap() >> i);
        if r1 != r2 {
            r[i] = Some(r1);
        }
    }

    Some(r)
}

fn bias_corrected_round_from_list<
    const BASE: usize,
    const BITS_PER_INPUT: usize,
    TSystemServices: SystemServices,
>(
    system_services: &TSystemServices,
    cancel_prompt: String16<'static>,
    target_bytes: u16,
    collected_bits: f64,
) -> Option<[Option<u8>; BITS_PER_INPUT]> {
    bias_corrected_round::<BASE, BITS_PER_INPUT, TSystemServices, _>(
        system_services,
        cancel_prompt,
        target_bytes,
        collected_bits,
        round_from_list::<BASE, TSystemServices>,
    )
}

fn raw_round_from_list<const BASE: usize, TSystemServices: SystemServices>(
    system_services: &TSystemServices,
    cancel_prompt: String16<'static>,
    target_bytes: u16,
    collected_bits: f64,
) -> Option<[Option<u8>; 1]> {
    round_from_list::<BASE, TSystemServices>(
        system_services,
        cancel_prompt,
        if BASE == 2 {
            s16!("Coinflip")
        } else {
            s16!("Dice Roll")
        },
        target_bytes,
        collected_bits,
    )
}

fn round_from_list<const BASE: usize, TSystemServices: SystemServices>(
    system_services: &TSystemServices,
    cancel_prompt: String16<'static>,
    label: String16<'static>,
    target_bytes: u16,
    collected_bits: f64,
) -> Option<[Option<u8>; 1]> {
    const FLIP_OPTIONS: [String16; 2] = [s16!("Heads"), s16!("Tails")];
    const NUMERIC_OPTIONS: [String16; 10] = [
        s16!("One"),
        s16!("Two"),
        s16!("Three"),
        s16!("Four"),
        s16!("Five"),
        s16!("Six"),
        s16!("Seven"),
        s16!("Eight"),
        s16!("Nine"),
        s16!("Ten"),
    ];

    // If we're collecting base2, it's from a coin, otherwise, it's from a dice.
    let options = if BASE == 2 {
        &FLIP_OPTIONS
    } else {
        // We only get the first BASE numbers, so, for example, a D6 doesn't have Seven, Eight, Nine or ten.
        &NUMERIC_OPTIONS[..BASE]
    };

    // Build the select list for the input options.
    let mut list = ConsoleUiList::from(
        ConsoleUiTitle::from(
            if BASE == 2 {
                s16!(" Coin Flip ")
            } else {
                s16!(" Dice Roll ")
            },
            constants::SMALL_TITLE,
        ),
        constants::SELECT_LIST,
        options,
    );

    let console = system_services.get_console_out();
    loop {
        ConsoleUiLabel::from(label).write_to(&console);
        // Write progress information.
        console.line_start().output_utf32_line(&format!(
            "Collected {} of {} bits.\0",
            collected_bits,
            target_bytes * 8
        ));

        // Prompt the user to select an input for the round.
        match list.prompt_for_selection(system_services) {
            Some((_, _, i)) => {
                return Some([Some(i as u8)]);
            }
            None => {
                if ConsoleUiConfirmationPrompt::from(system_services)
                    .prompt_for_confirmation(cancel_prompt)
                {
                    return None;
                }
            }
        }
    }
}

fn bias_corrected_round_from_numeric_input<
    const BASE: usize,
    const BITS_PER_INPUT: usize,
    TSystemServices: SystemServices,
>(
    system_services: &TSystemServices,
    cancel_prompt: String16<'static>,
    target_bytes: u16,
    collected_bits: f64,
) -> Option<[Option<u8>; BITS_PER_INPUT]> {
    bias_corrected_round::<BASE, BITS_PER_INPUT, TSystemServices, _>(
        system_services,
        cancel_prompt,
        target_bytes,
        collected_bits,
        round_from_numeric_input::<BASE, TSystemServices>,
    )
}

fn raw_round_from_numeric_input<const BASE: usize, TSystemServices: SystemServices>(
    system_services: &TSystemServices,
    cancel_prompt: String16<'static>,
    target_bytes: u16,
    collected_bits: f64,
) -> Option<[Option<u8>; 1]> {
    round_from_numeric_input::<BASE, TSystemServices>(
        system_services,
        cancel_prompt,
        if BASE == 256 {
            s16!("Random Byte")
        } else {
            s16!("Dice Roll")
        },
        target_bytes,
        collected_bits,
    )
}

fn round_from_numeric_input<const BASE: usize, TSystemServices: SystemServices>(
    system_services: &TSystemServices,
    cancel_prompt: String16<'static>,
    label: String16<'static>,
    target_bytes: u16,
    collected_bits: f64,
) -> Option<[Option<u8>; 1]> {
    // Write progress information.
    let console = system_services.get_console_out();
    ConsoleUiLabel::from(label).write_to(&console);
    console.line_start().output_utf32_line(&format!(
        "Collected {} bits of {}.\0",
        collected_bits,
        target_bytes * 8
    ));

    // Get an input from the user for the round.
    match prompt_for_u8(
        |i| {
            if i == 0 && BASE != 256 {
                Some(s16!("Value must be larger than 0."))
            } else if i as usize > BASE {
                Some(s16!("Value was too large."))
            } else {
                None
            }
        },
        if BASE == 256 {
            s16!("Byte")
        } else {
            s16!("Dice Roll")
        },
        system_services,
        cancel_prompt,
        Some(NumericBases::Decimal.into()),
    ) {
        Some(i) => Some([Some(if BASE == 256 { i } else { i - 1 })]),
        None => None,
    }
}

struct ConsoleManualEntropyCollectionProgram<
    const ROUND_VALUE_COUNT: usize,
    TSystemServices: SystemServices,
    FWriteInfo: Fn(&TSystemServices),
    FRound: Fn(&TSystemServices, String16<'static>, u16, f64) -> Option<[Option<u8>; ROUND_VALUE_COUNT]>,
> {
    clipboard_entry_name: String16<'static>,
    system_services: TSystemServices,
    base: NumericCollectorRoundBase,
    name: String16<'static>,
    round_collector: FRound,
    write_info: FWriteInfo,
}

impl<
        const ROUND_VALUE_COUNT: usize,
        TSystemServices: SystemServices,
        FWriteInfo: Fn(&TSystemServices),
        FRound: Fn(
            &TSystemServices,
            String16<'static>,
            u16,
            f64,
        ) -> Option<[Option<u8>; ROUND_VALUE_COUNT]>,
    >
    ConsoleManualEntropyCollectionProgram<ROUND_VALUE_COUNT, TSystemServices, FWriteInfo, FRound>
{
    pub const fn from(
        clipboard_entry_name: String16<'static>,
        system_services: TSystemServices,
        base: NumericCollectorRoundBase,
        name: String16<'static>,
        round_collector: FRound,
        write_info: FWriteInfo,
    ) -> Self {
        Self {
            clipboard_entry_name,
            system_services,
            round_collector,
            write_info,
            base,
            name,
        }
    }
}

impl<
        const ROUND_VALUE_COUNT: usize,
        TSystemServices: SystemServices,
        FWriteInfo: Fn(&TSystemServices),
        FRound: Fn(
            &TSystemServices,
            String16<'static>,
            u16,
            f64,
        ) -> Option<[Option<u8>; ROUND_VALUE_COUNT]>,
    > Program
    for ConsoleManualEntropyCollectionProgram<
        ROUND_VALUE_COUNT,
        TSystemServices,
        FWriteInfo,
        FRound,
    >
{
    fn name(&self) -> String16<'static> {
        self.name
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        // Write the program header.
        ConsoleUiTitle::from(self.name, constants::BIG_TITLE).write_to(&console);
        (self.write_info)(&self.system_services);

        const CANCEL_PROMPT_STRING: String16<'static> = s16!("Cancel manual entropy collection?");

        // Get the number of bytes to collect.
        let byte_count = match prompt_for_u16(
            |b| match b {
                0 => Some(s16!("Must collect at least one byte.")),
                _ => None,
            },
            s16!("Number of bytes to collect"),
            &self.system_services,
            CANCEL_PROMPT_STRING,
            Some(NumericBases::Decimal.into()),
        ) {
            None => return ProgramExitResult::UserCancelled,
            Some(c) => c,
        };

        // Collect until the desired bytes are collected.
        let mut collector = NumericCollector::with_byte_capacity(byte_count as usize);
        while ((collector.bit_counter() / 8f64) as u16) < byte_count {
            // Get a round of input.
            let round = match (self.round_collector)(
                &self.system_services,
                CANCEL_PROMPT_STRING,
                byte_count,
                collector.bit_counter(),
            ) {
                None => return ProgramExitResult::UserCancelled,
                Some(r) => r,
            };

            // Add the round's values to the collector.
            for round_value in round {
                match round_value {
                    Some(v) => {
                        _ = collector.try_add_round(v, self.base).unwrap();
                    }
                    None => {}
                };
            }
        }

        // Extract the bytes from the collector.
        let mut bytes = vec![0u8; collector.padded_byte_count()];
        collector.copy_padded_bytes_to(&mut bytes);

        // Empty the bytes pre-emptively (they'd otherwise be zeroed on de-allocation).
        collector
            .extract_big_integer(Some(0))
            .take_data_ownership()
            .multiply(0);

        // Output the raw collected bytes.
        write_bytes(&self.system_services, s16!("Collected Bytes"), &bytes);

        if bytes.len() > byte_count as usize {
            // The base didn't allow for collecting the exact amount of desired entropy; PBKDF2 will be used to compress it.
            console.line_start().new_line().in_colours(constants::WARNING_COLOURS, |c| c.output_utf16_line(s16!(
                "The collected bytes must be compressed; PBKDF2 with SHA512 will be used to achieve this."
            )));

            // Get the number of PBKDF2 iterations to perform.
            let iterations = match prompt_for_u32(
                |b| match b {
                    0 => Some(s16!("Iterations must be greater than 0.")),
                    _ => None,
                },
                s16!("PBKDF2 Iterations"),
                &self.system_services,
                CANCEL_PROMPT_STRING,
                Some(NumericBases::Decimal.into()),
            ) {
                None => return ProgramExitResult::UserCancelled,
                Some(c) => c,
            };

            // Prompt the user for a PBKDF2 salt.
            let salt = match prompt_for_bytes_from_any_data_type(
                &self.system_services,
                CANCEL_PROMPT_STRING,
                s16!("PBKDF2 Salt"),
            ) {
                Ok(s) => s,
                Err(r) => return r,
            };

            // Start performing PBKDF2
            console
                .line_start()
                .new_line()
                .in_colours(constants::WARNING_COLOURS, |c| {
                    c.output_utf16_line(s16!("Performing PBKDF2..."))
                });

            // Write the PBKDF2 output.
            let mut output = vec![0u8; byte_count as usize];
            Sha512::new()
                .build_hmac(&bytes)
                .pbkdf2(&salt, iterations, &mut output);
            write_bytes(&self.system_services, s16!("Compressed Bytes"), &output);

            // Prompt the user to add the compressed bytes to the clipboard.
            prompt_for_clipboard_write(
                &self.system_services,
                ClipboardEntry::Bytes(self.clipboard_entry_name, output.into()),
            );
        } else {
            // The exact requested number of bytes was generated; prompt the user to add them to the clipboard.
            prompt_for_clipboard_write(
                &self.system_services,
                ClipboardEntry::Bytes(self.clipboard_entry_name, bytes.into()),
            );
        }

        ProgramExitResult::Success
    }
}
