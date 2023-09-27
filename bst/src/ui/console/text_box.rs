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
    clipboard::prompt_for_clipboard_select, scroll_text::ConsoleUiScrollTextStyles, ConsoleUiLabel,
    ConsoleUiScrollText, ConsoleUiTitle, ConsoleUiTitleStyles, ConsoleWriteable,
};
use crate::{
    clipboard::ClipboardEntry,
    console_out::{ConsoleColours, ConsoleOut},
    keyboard_in::{BehaviourKey, Key, KeyboardIn},
    system_services::SystemServices,
    ui::Point,
    String16,
};
use alloc::vec::Vec;
use macros::{c16, s16};

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum PasteResult {
    ContinueAsNormal,
    RewritePadding,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConsoleUiTextBoxStyles {
    scroll_text_styles: ConsoleUiScrollTextStyles,
    completion_message_colours: ConsoleColours,
    title_styles: ConsoleUiTitleStyles,
}

#[allow(dead_code)]
impl ConsoleUiTextBoxStyles {
    pub const fn from(
        scroll_text_styles: ConsoleUiScrollTextStyles,
        completion_message_colours: ConsoleColours,
        title_styles: ConsoleUiTitleStyles,
    ) -> Self {
        Self {
            completion_message_colours,
            scroll_text_styles,
            title_styles,
        }
    }

    pub const fn with_completion_message(self, colours: ConsoleColours) -> Self {
        Self {
            completion_message_colours: colours,
            scroll_text_styles: self.scroll_text_styles,
            title_styles: self.title_styles,
        }
    }

    pub const fn with_scroll_text(self, styles: ConsoleUiScrollTextStyles) -> Self {
        Self {
            completion_message_colours: self.completion_message_colours,
            title_styles: self.title_styles,
            scroll_text_styles: styles,
        }
    }

    pub const fn with_title(self, styles: ConsoleUiTitleStyles) -> Self {
        Self {
            completion_message_colours: self.completion_message_colours,
            scroll_text_styles: self.scroll_text_styles,
            title_styles: styles,
        }
    }

    pub const fn with_scroll_text_height(self, height: usize) -> Self {
        Self {
            scroll_text_styles: self.scroll_text_styles.with_height(height),
            completion_message_colours: self.completion_message_colours,
            title_styles: self.title_styles,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ConsoleUiTextBox<'a, TSystemServices: SystemServices> {
    system_services: &'a TSystemServices,
    styles: ConsoleUiTextBoxStyles,
}

impl<'a, TSystemServices: SystemServices> ConsoleUiTextBox<'a, TSystemServices> {
    pub const fn from(
        system_services: &'a TSystemServices,
        styles: ConsoleUiTextBoxStyles,
    ) -> Self {
        Self {
            system_services,
            styles,
        }
    }

    pub fn render_text(&self, box_width: usize, label: String16<'static>, content: &[u16]) {
        // Build a scroll text to use.
        let console = self.system_services.get_console_out();
        let mut scroll_text = ConsoleUiScrollText::from(
            None,
            self.styles.scroll_text_styles,
            content,
            self.pad_console_bottom(None, label), // Write padding to ensure the scroll text will fit on the screen.
            box_width,
        );

        scroll_text.go_to_start();
        loop {
            // Output the scroll text.
            scroll_text.write_to(&console);

            // Output the completion message.
            console
                .line_start()
                .in_colours(self.styles.completion_message_colours, |c| {
                    c.output_utf16(s16!("Press ESC to exit text view."))
                });

            // Read some input from the keyboard.
            let input = self.system_services.get_keyboard_in().read_key();

            // Get any modifier keys held during the key press.
            match input.key() {
                Key::Behaviour(b) => match b {
                    BehaviourKey::UpArrow => {
                        scroll_text.viewport_up();
                    }
                    BehaviourKey::DownArrow => {
                        scroll_text.viewport_down();
                    }
                    BehaviourKey::PageUp => {
                        scroll_text.page_up(true);
                    }
                    BehaviourKey::PageDown => {
                        scroll_text.page_down(true);
                    }
                    BehaviourKey::Home => {
                        scroll_text.go_to_start();
                    }
                    BehaviourKey::End => {
                        scroll_text.go_to_end();
                    }
                    BehaviourKey::Escape => {
                        // The user completed. Break the read loop and move the cursor to the end of the UI,
                        // before dropping to a new line.
                        console.line_start();
                        break;
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    pub fn get_text_input<
        FPaste: Fn(ClipboardEntry, &mut ConsoleUiScrollText, &TSystemServices) -> PasteResult,
    >(
        &self,
        input_width: usize,
        paste_handler: FPaste,
        label: String16<'static>,
        prompt: String16<'static>,
        character_predicate: Option<fn(character: u16) -> bool>,
    ) -> Vec<u16> {
        // Build a scroll text to use.
        let console = self.system_services.get_console_out();
        let mut scroll_text = ConsoleUiScrollText::from(
            character_predicate,
            self.styles.scroll_text_styles,
            &[],
            self.pad_console_bottom(Some(label), prompt), // Write padding to ensure the scroll text will fit on the screen.
            input_width,
        );

        loop {
            // Output the scroll text.
            scroll_text.write_to(&console);

            // Output the completion message.
            console
                .line_start()
                .in_colours(self.styles.completion_message_colours, |c| {
                    c.output_utf16(s16!("Press ESC to complete."))
                });

            // Store the position of the cursor after all content is written, to revert to it if we exit.
            let end_position = console.cursor().position();

            // Move the cursor to the scroll text's cursor position for input.
            scroll_text.set_input_cursor_position(&console);

            // Show the cursor while we wait for input.
            console.set_cursor_visibility(true);

            // Read some input from the keyboard.
            let input = self.system_services.get_keyboard_in().read_key();

            // We've read key input; we can hide the cursor again for now.
            console.set_cursor_visibility(false);

            // Get any modifier keys held during the key press.
            let modifiers = input.modifier_keys();
            match input.key() {
                Key::Behaviour(b) => match b {
                    BehaviourKey::UpArrow => {
                        if modifiers.control() {
                            scroll_text.viewport_up();
                        } else {
                            scroll_text.move_cursor_up();
                        }
                    }
                    BehaviourKey::RightArrow => {
                        scroll_text.move_cursor_right();
                    }
                    BehaviourKey::DownArrow => {
                        if modifiers.control() {
                            scroll_text.viewport_down();
                        } else {
                            scroll_text.move_cursor_down();
                        }
                    }
                    BehaviourKey::LeftArrow => {
                        scroll_text.move_cursor_left();
                    }
                    BehaviourKey::PageUp => {
                        scroll_text.page_up(modifiers.control());
                    }
                    BehaviourKey::PageDown => {
                        scroll_text.page_down(modifiers.control());
                    }
                    BehaviourKey::Home => {
                        if modifiers.control() {
                            scroll_text.go_to_start();
                        } else {
                            scroll_text.move_cursor_to_start_of_line();
                        }
                    }
                    BehaviourKey::End => {
                        if modifiers.control() {
                            scroll_text.go_to_end();
                        } else {
                            scroll_text.move_cursor_to_end_of_line();
                        }
                    }
                    BehaviourKey::Delete => {
                        scroll_text.delete();
                    }
                    BehaviourKey::Escape => {
                        // The user completed. Break the read loop and move the cursor to the end of the UI,
                        // before dropping to a new line.
                        console.set_cursor_position(end_position).line_start();
                        break;
                    }
                    BehaviourKey::BackSpace => {
                        scroll_text.backspace();
                    }
                    BehaviourKey::Return => {
                        if modifiers.alt() {
                            // Users can hold alt to enter a CR by itself.
                            scroll_text.insert_character(c16!("\r"));
                        } else if modifiers.control() {
                            // Users can holdd control to enter a LF by itself.
                            scroll_text.insert_character(c16!("\n"));
                        } else {
                            // If ctrl/alt weren't held, default to CR LF, which is the proper newline combination for UEFI consoles.
                            scroll_text
                                .insert_characters([c16!("\r"), c16!("\n")][..].iter().cloned());
                        }
                    }
                    BehaviourKey::Tab => {
                        scroll_text.insert_character(c16!("\t"));
                    }
                    _ => {}
                },
                Key::Digit(d) => {
                    if modifiers.control() {
                        // CTRL + a number pastes content from the clipboard.
                        let clipboard_entry =
                            self.system_services.clipboard().get_entry(match d.digit() {
                                0 => 9usize,
                                _ => (d.digit() as usize) - 1,
                            });

                        if clipboard_entry != ClipboardEntry::Empty {
                            // If there's a clipboard entry, paste it.
                            // We move the cursor to the UI end in case we need to render a menu.
                            // This occurs when pasing bytes into a text input, so the user can select a base.
                            console.set_cursor_position(end_position);
                            self.write_clipboard(
                                // We won't force a redraw; the paste handler will decide whether to trigger one.
                                false,
                                &paste_handler,
                                label,
                                prompt,
                                clipboard_entry,
                                &mut scroll_text,
                            )
                        }
                    } else {
                        // If the user presses a digit while not holding CTRL, we just input the digit.
                        scroll_text.insert_character(d.character());
                    }
                }
                Key::Symbol(s) => {
                    if modifiers.control() && (s == c16!("V") || s == c16!("v")) {
                        // CTRL + V, or (incidentally) CTRL + SHIFT + V pastes from the clipboard.
                        // We move the cursor to the UI end because we need to render a menu.
                        console.set_cursor_position(end_position);

                        // Propmt the user to select a clipboard entry.
                        match prompt_for_clipboard_select(
                            self.system_services,
                            s16!("Cancel Paste?"),
                            s16!("Select a clipboard entry to paste"),
                        ) {
                            Some((e, _)) => {
                                if e != ClipboardEntry::Empty {
                                    // The user selected a non-empty clipboard item. Paste it.
                                    self.write_clipboard(
                                        // We've already rendered a menu, so we definitely need to redraw.
                                        true,
                                        &paste_handler,
                                        label,
                                        prompt,
                                        e,
                                        &mut scroll_text,
                                    );
                                } else {
                                    // The user selected an empty clipboard item.
                                    // There's nothing to do, but we still need to redraw.
                                    self.redraw(label, prompt, &mut scroll_text);
                                }
                            }
                            None => {
                                // The user selected no clipboard item.
                                // There's nothing to do, but we still need to redraw.
                                self.redraw(label, prompt, &mut scroll_text);
                            }
                        }
                    } else {
                        // Any non-paste symbol keypress should try to insert the character into the input.
                        scroll_text.insert_character(s);
                    }
                }
            }
        }

        // Return ownership of the content of the scroll text.
        scroll_text.take_ownership_of_content()
    }

    fn pad_console_bottom(
        &self,
        label: Option<String16<'static>>,
        prompt: String16<'static>,
    ) -> Point {
        // Write the label for the scroll text.
        let console = self.system_services.get_console_out();
        match label {
            Some(label) => {
                ConsoleUiLabel::from(label).write_to(&console);
            }
            None => {}
        }

        // Write the title for the scroll text.
        let title = ConsoleUiTitle::from(prompt, self.styles.title_styles);
        title.write_to(&console);

        // We need to make sure there's enough space at the end of the screen to draw the viewport.
        let height = self.styles.scroll_text_styles.height();
        console.line_start();
        for _ in 0..height {
            console.new_line();
        }

        // Move the cursor back to where we should draw the viewport.
        console.cursor().position() - Point::from(0, height)
    }

    fn redraw(
        &self,
        label: String16<'static>,
        prompt: String16<'static>,
        scroll_text: &mut ConsoleUiScrollText,
    ) {
        // Make sure we're at the start of a line.
        self.system_services.get_console_out().line_start();

        // Draw the viewport and update the underlying position to reflect its new position in the console.
        scroll_text.change_position(self.pad_console_bottom(Some(label), prompt));
    }

    fn write_clipboard<
        FPaste: Fn(ClipboardEntry, &mut ConsoleUiScrollText, &TSystemServices) -> PasteResult,
    >(
        &self,
        mut redraw: bool,
        paste_handler: FPaste,
        label: String16<'static>,
        prompt: String16<'static>,
        clipboard_entry: ClipboardEntry,
        scroll_text: &mut ConsoleUiScrollText,
    ) {
        // Handle the paste.
        match paste_handler(clipboard_entry, scroll_text, &self.system_services) {
            PasteResult::ContinueAsNormal => { /* The paste handler didn't request a redraw. */ }
            PasteResult::RewritePadding => {
                // The paste handler requested a redraw.
                redraw = true;
            }
        }

        if redraw {
            // Whether the paste handler requested a redraw, or one was required due to selecting the
            // clipboard entry from a list, redraw the scroll text.
            self.redraw(label, prompt, scroll_text);
        }
    }
}
