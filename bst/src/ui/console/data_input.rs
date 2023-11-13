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

use super::{
    text_box::PasteResult, ConsoleUiConfirmationPrompt, ConsoleUiLabel, ConsoleUiList,
    ConsoleUiNumericInput, ConsoleUiScrollText, ConsoleUiTextBox, ConsoleUiTitle, ConsoleWriteable,
};
use crate::{
    clipboard::ClipboardEntry,
    console_out::ConsoleOut,
    constants,
    integers::{NumericBase, NumericBaseWithCharacterPredicate, NumericBases},
    programs::ProgramExitResult,
    system_services::SystemServices,
    ui::{ConfirmationPrompt, DataInput, DataInputType},
    String16,
};
use alloc::{vec, vec::Vec};
use macros::s16;

pub fn prompt_for_bytes_from_any_data_type<TSystemServices: SystemServices>(
    system_services: &TSystemServices,
    cancel_prompt_string: String16,
    label: String16<'static>,
) -> Result<Vec<u8>, ProgramExitResult> {
    match prompt_for_data_input(
        None,
        &[
            DataInputType::Text,
            DataInputType::Bytes,
            DataInputType::Number,
        ],
        system_services,
        cancel_prompt_string,
        label,
    ) {
        DataInput::Number(number) => Ok(number.extract_be_bytes()),
        DataInput::None => Err(ProgramExitResult::UserCancelled),
        DataInput::Text(mut text) => {
            // Build a UTF8 buffer.
            let text_string = String16::from(&text);
            let mut utf8_buffer = Vec::with_capacity(text_string.utf8_content_length());

            // Write to the UTF8 buffer.
            text_string.write_content_to_utf8_vec(&mut utf8_buffer);

            // Pre-emptively clear the text input.
            text.fill(0);
            Ok(utf8_buffer)
        }
        DataInput::Bytes(bytes) => Ok(bytes),
    }
}

pub fn prompt_for_data_input<TSystemServices: SystemServices>(
    base: Option<NumericBaseWithCharacterPredicate>,
    allowed_input_types: &[DataInputType],
    system_services: &TSystemServices,
    cancel_prompt_string: String16,
    label: String16<'static>,
) -> DataInput {
    let console = system_services.get_console_out();
    if allowed_input_types.len() == 0 {
        // There's no allowed input types, so we can just return none; the user can't possibly input data.
        return DataInput::None;
    }

    loop {
        let data_input_type = if allowed_input_types.len() == 1 {
            // There's one allowed input type, so we don't need to ask the user what type of data they'd like to input.
            allowed_input_types[0]
        } else {
            loop {
                // Ask the user to pick a data type to input.
                let mut input_type_list =
                    ConsoleUiList::<'static, DataInputType, &[DataInputType]>::from(
                        ConsoleUiTitle::from(s16!(" Input Data Type "), constants::SMALL_TITLE),
                        constants::SELECT_LIST,
                        allowed_input_types,
                    );

                ConsoleUiLabel::from(label).write_to(&console);
                match input_type_list.prompt_for_selection(system_services) {
                    Some((data_input_type, _, _)) => {
                        break data_input_type.clone();
                    }
                    None => {
                        if ConsoleUiConfirmationPrompt::from(system_services)
                            .prompt_for_confirmation(cancel_prompt_string)
                        {
                            // User cancelled; return none.
                            return DataInput::None;
                        }
                    }
                }
            }
        };

        match data_input_type {
            DataInputType::Text => {
                // Get text input from the user.
                break DataInput::Text(
                    ConsoleUiTextBox::from(system_services, constants::TEXT_INPUT).get_text_input(
                        console.size().width(),
                        text_input_paste_handler,
                        label,
                        s16!(" Text "),
                        None,
                    ),
                );
            }
            DataInputType::Bytes => {
                // Get byte input from the user.
                match ConsoleUiNumericInput::from(system_services, constants::BYTE_INPUT)
                    .get_numeric_input(console.size().width(), label, base)
                {
                    Some(n) => {
                        // If the user entered some numbers, grab the padded bytes.
                        let mut vec = vec![0u8; n.padded_byte_count()];
                        n.copy_padded_bytes_to(&mut vec);

                        // Pre-emptively zero the numeric collector; there might be sensitive data,
                        // and it's preferable to not rely on dealloc zeroing.
                        n.extract_big_unsigned().zero();
                        break DataInput::Bytes(vec);
                    }
                    None => {
                        if ConsoleUiConfirmationPrompt::from(system_services)
                            .prompt_for_confirmation(cancel_prompt_string)
                        {
                            // User cancelled, then confirmed; return nothing.
                            return DataInput::None;
                        }
                    }
                }
            }
            DataInputType::Number => {
                // Get number input from the user.
                match ConsoleUiNumericInput::from(system_services, constants::NUMERIC_INPUT)
                    .get_numeric_input(console.size().width(), label, base)
                {
                    Some(n) => {
                        // Extract the underlying big unsigned integer and just return it.
                        break DataInput::Number(n.extract_big_unsigned());
                    }
                    None => {
                        if ConsoleUiConfirmationPrompt::from(system_services)
                            .prompt_for_confirmation(cancel_prompt_string)
                        {
                            // User cancelled, then confirmed; return nothing.
                            return DataInput::None;
                        }
                    }
                }
            }
        }
    }
}

pub fn prompt_for_u8<
    'a,
    TSystemServices: SystemServices,
    FValidate: Fn(u8) -> Option<String16<'a>>,
>(
    validate: FValidate,
    label: String16<'static>,
    system_services: &TSystemServices,
    cancel_prompt_string: String16<'static>,
    base: Option<NumericBaseWithCharacterPredicate>,
) -> Option<u8> {
    prompt_for_unsigned_integer(
        validate,
        u8::from_be_bytes,
        label,
        s16!("256 (2^8)"),
        cancel_prompt_string,
        system_services,
        base,
    )
}

pub fn prompt_for_u16<
    'a,
    TSystemServices: SystemServices,
    FValidate: Fn(u16) -> Option<String16<'a>>,
>(
    validate: FValidate,
    label: String16<'static>,
    system_services: &TSystemServices,
    cancel_prompt_string: String16<'static>,
    base: Option<NumericBaseWithCharacterPredicate>,
) -> Option<u16> {
    prompt_for_unsigned_integer(
        validate,
        u16::from_be_bytes,
        label,
        s16!("65,536 (2^16)"),
        cancel_prompt_string,
        system_services,
        base,
    )
}

pub fn prompt_for_u32<
    'a,
    TSystemServices: SystemServices,
    FValidate: Fn(u32) -> Option<String16<'a>>,
>(
    validate: FValidate,
    label: String16<'static>,
    system_services: &TSystemServices,
    cancel_prompt_string: String16<'static>,
    base: Option<NumericBaseWithCharacterPredicate>,
) -> Option<u32> {
    prompt_for_unsigned_integer(
        validate,
        u32::from_be_bytes,
        label,
        s16!("4,294,967,296 (2^32)"),
        cancel_prompt_string,
        system_services,
        base,
    )
}

fn prompt_for_unsigned_integer<
    'a,
    const SIZE: usize,
    T: Copy + PartialEq,
    TSystemServices: SystemServices,
    FConvert: Fn([u8; SIZE]) -> T,
    FValidate: Fn(T) -> Option<String16<'a>>,
>(
    validate: FValidate,
    from_be_bytes: FConvert,
    label: String16<'static>,
    overflow_number: String16,
    cancel_prompt_string: String16,
    system_services: &TSystemServices,
    base: Option<NumericBaseWithCharacterPredicate>,
) -> Option<T> {
    let console = system_services.get_console_out();
    loop {
        // Prompt the user for a number.
        let mut number = match prompt_for_data_input(
            base,
            &[DataInputType::Number],
            system_services,
            cancel_prompt_string,
            label,
        ) {
            // If they entered one, extract it.
            DataInput::Number(i) => i,
            // If they cancelled, return nothing.
            _ => return None,
        };

        if number.digit_count() <= SIZE {
            // If the returned number fits within the size of the requested integer, extract its bytes.
            let mut buffer = [0u8; SIZE];
            number.copy_digits_to(&mut buffer[SIZE - number.digit_count()..]);

            // Turn those bytes into the uint type.
            let integer = from_be_bytes(buffer);

            // Pre-emptively zero the number now we've turned it into the target uint type.
            number.zero();

            // Validate the resulting integer.
            match validate(integer) {
                Some(error) => {
                    // Didn't pass validation; write the error and try again.
                    console
                        .line_start()
                        .new_line()
                        .in_colours(constants::ERROR_COLOURS, |c| c.output_utf16_line(error));
                }
                // The number passed validation; return it!
                None => return Some(integer),
            }
        } else {
            // The returned number is too big; write an error.
            console
                .line_start()
                .new_line()
                .in_colours(constants::ERROR_COLOURS, |c| {
                    c.output_utf16(label)
                        .output_utf16(s16!(" must be less than "))
                        .output_utf16(overflow_number)
                        .output_utf16_line(s16!("."))
                });

            // Pre-emptively zero the number before we try again.
            number.zero();
        }
    }
}

pub fn text_input_paste_handler<TSystemServices: SystemServices>(
    clipboard_entry: ClipboardEntry,
    scroll_text: &mut ConsoleUiScrollText,
    system_services: &TSystemServices,
) -> PasteResult {
    let console = system_services.get_console_out();
    match &clipboard_entry {
        // Empty clipboard pastes don't do anything.
        ClipboardEntry::Empty => PasteResult::ContinueAsNormal,
        ClipboardEntry::Bytes(_, bytes) => {
            // User pasted bytes into a text input. Give them a warning because this might not be what they meant to do.
            console
                .line_start()
                .new_line()
                .in_colours(
                    constants::WARNING_COLOURS,
                    |c| c.output_utf16_line(s16!("Attempting to paste the following clipboard bytes entry into a text input:")));
            clipboard_entry.write_to(&console);

            console.line_start().new_line();
            // Prompt the user to pick a base to write the bytes in.
            match ConsoleUiList::<'_, NumericBases, &[NumericBases]>::from(
                ConsoleUiTitle::from(s16!(" Write In Base "), constants::SMALL_TITLE),
                constants::SELECT_LIST,
                &NumericBases::BASES,
            )
            .prompt_for_selection(system_services)
            {
                Some((base, _, _)) => {
                    // They picked a base; turn the bytes into a string and write it.
                    for character in
                        Into::<&NumericBase>::into(*base).build_string_from_bytes(bytes, false)
                    {
                        scroll_text.insert_character(character);
                    }
                }
                // They cancelled picking a base. Just finish up; they can try pasting again if they want to.
                None => {}
            };

            // We threw up some new UI under the scrolltext; the scrolltext will need to be re-drawn.
            PasteResult::Rewrite
        }
        ClipboardEntry::String16(_, content) => {
            // We're pasting text into text. It's really simple.
            for character in content.into_iter() {
                scroll_text.insert_character(*character);
            }

            // Didn't need to show any fancy UI for this; no need to redraw.
            PasteResult::ContinueAsNormal
        }
    }
}
