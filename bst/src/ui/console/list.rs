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

use super::{ConsoleUiTitle, ConsoleWriteable};
use crate::{
    console_out::{ConsoleColours, ConsoleOut},
    input::keyboard::{BehaviourKey, Key, KeyboardIn, ModifierKeys},
    system_services::SystemServices,
    ui::{list::UiList, Point, UiListType},
};
use alloc::format;
use core::ops::Deref;
use macros::s16;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConsoleUiListEntryStyle {
    content_base_colours: ConsoleColours,
    identifier_colours: ConsoleColours,
}

impl ConsoleUiListEntryStyle {
    pub const fn from(
        content_base_colours: ConsoleColours,
        identifier_colours: ConsoleColours,
    ) -> Self {
        Self {
            content_base_colours,
            identifier_colours,
        }
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConsoleUiListStyles {
    page_information_highlight_colours: ConsoleColours,
    page_information_base_colours: ConsoleColours,
    selected_entry_style: ConsoleUiListEntryStyle,
    empty_list_message_colours: ConsoleColours,
    cancel_message_colours: ConsoleColours,
    entry_style: ConsoleUiListEntryStyle,
    list_type: UiListType,
}

#[allow(dead_code)]
impl ConsoleUiListStyles {
    pub const fn from(
        page_information_highlight_colours: ConsoleColours,
        page_information_base_colours: ConsoleColours,
        selected_entry_style: ConsoleUiListEntryStyle,
        empty_list_message_colours: ConsoleColours,
        cancel_message_colours: ConsoleColours,
        entry_style: ConsoleUiListEntryStyle,
        list_type: UiListType,
    ) -> Self {
        Self {
            page_information_highlight_colours,
            page_information_base_colours,
            empty_list_message_colours,
            cancel_message_colours,
            selected_entry_style,
            entry_style,
            list_type,
        }
    }

    pub const fn with_page_information_styles(
        &self,
        base_colours: ConsoleColours,
        highlight_colours: ConsoleColours,
    ) -> Self {
        Self::from(
            highlight_colours,
            base_colours,
            self.selected_entry_style,
            self.empty_list_message_colours,
            self.cancel_message_colours,
            self.entry_style,
            self.list_type,
        )
    }

    pub const fn with_selected_entry_styles(&self, styles: ConsoleUiListEntryStyle) -> Self {
        Self::from(
            self.page_information_highlight_colours,
            self.page_information_base_colours,
            styles,
            self.empty_list_message_colours,
            self.cancel_message_colours,
            self.entry_style,
            self.list_type,
        )
    }

    pub const fn with_entry_styles(&self, styles: ConsoleUiListEntryStyle) -> Self {
        Self::from(
            self.page_information_highlight_colours,
            self.page_information_base_colours,
            self.selected_entry_style,
            self.empty_list_message_colours,
            self.cancel_message_colours,
            styles,
            self.list_type,
        )
    }

    pub const fn with_empty_message_colours(&self, colours: ConsoleColours) -> Self {
        Self::from(
            self.page_information_highlight_colours,
            self.page_information_base_colours,
            self.selected_entry_style,
            colours,
            self.cancel_message_colours,
            self.entry_style,
            self.list_type,
        )
    }

    pub const fn with_cancel_message_colours(&self, colours: ConsoleColours) -> Self {
        Self::from(
            self.page_information_highlight_colours,
            self.page_information_base_colours,
            self.selected_entry_style,
            self.empty_list_message_colours,
            colours,
            self.entry_style,
            self.list_type,
        )
    }

    pub const fn with_list_type(&self, list_type: UiListType) -> Self {
        Self::from(
            self.page_information_highlight_colours,
            self.page_information_base_colours,
            self.selected_entry_style,
            self.empty_list_message_colours,
            self.cancel_message_colours,
            self.entry_style,
            list_type,
        )
    }
}

pub struct ConsoleUiList<'a, TEntry: ConsoleWriteable, TList: Deref<Target = [TEntry]>> {
    ui_list: UiList<TEntry, TList>,
    styles: ConsoleUiListStyles,
    title: ConsoleUiTitle<'a>,
}

impl<'a, TEntry: ConsoleWriteable, TList: Deref<Target = [TEntry]>>
    ConsoleUiList<'a, TEntry, TList>
{
    pub fn from(title: ConsoleUiTitle<'a>, style: ConsoleUiListStyles, items: TList) -> Self {
        Self {
            ui_list: UiList::from(
                match style.list_type {
                    UiListType::Select => 10,
                    UiListType::Ordered(ps) | UiListType::Unordered(ps, _) => {
                        if ps == 0 {
                            panic!("Tried to create a list with a page size of 0.")
                        } else {
                            ps
                        }
                    }
                },
                items,
            ),
            styles: style,
            title,
        }
    }

    pub fn prompt_for_selection<TSystemServices: SystemServices>(
        &mut self,
        system_services: &TSystemServices,
    ) -> Option<(&TEntry, ModifierKeys, usize)> {
        let keyboard_in = system_services.get_keyboard_in();
        let console = system_services.get_console_out();
        // Selection should always start on page 0 with nothing selected.
        self.ui_list.reset();

        // Write the list once to ensure we have space on the screen.
        self.write_to(&console);

        // Move the cursor back to where the list should be rendered.
        let cursor_start = console.cursor().position()
            - Point::from(
                0,
                // Calculate the total height of the list.
                // Start with the height of the title.
                self.title.height()
                    // Plus a line for each list entry, or one for the empty message.
                    // Note: The first page is always guaranteed to be the longest, and we always start on the first page.
                    + self.ui_list.current_page_size().max(1)
                    + if self.ui_list.page_count() > 1 { 
                        // Plus a page information line, and an exit line.
                        2 
                    } else { 
                        // Plus an exit line.
                        1
                    },
            );

        // A place to store where the cursor ends up after drawing the UI; we need to blank space when the length of
        // the UI changes because we move to a page with fewer items.
        let mut cursor_end = cursor_start;
        loop {
            // Move the cursor back to where the list UI starts.
            console.set_cursor_position(cursor_start);

            // Write the list to the console.
            self.write_to(&console);

            // Grab the cursor position after drawing the list.
            let e = console.cursor().position();

            // Blank lines this draw didn't write to up to the previous draw's cursor end.
            let mut cursor_position = e;
            while cursor_position.y() < cursor_end.y() {
                console.blank_remaining_line();
                cursor_position = console.cursor().position();
            }

            // Update the cursor end position.
            cursor_end = e;

            // Move the cursor back to where it ended before blanking.
            console.set_cursor_position(e);

            loop {
                // Read some input from the keyboard.
                // We loop so we don't redraw unless we need to. Break triggers a redraw.
                let input = keyboard_in.read_key();
                match input.key() {
                    Key::Behaviour(k) => match k {
                        BehaviourKey::UpArrow => {
                            if self.ui_list.has_items() {
                                self.ui_list.select_prev();
                                break;
                            }
                        }
                        BehaviourKey::RightArrow | BehaviourKey::PageDown => {
                            if self.ui_list.can_move_next_page() {
                                self.ui_list.move_next_page();
                                break;
                            }
                        }
                        BehaviourKey::DownArrow => {
                            if self.ui_list.has_items() {
                                self.ui_list.select_next();
                                break;
                            }
                        }
                        BehaviourKey::LeftArrow | BehaviourKey::PageUp => {
                            if self.ui_list.can_move_prev_page() {
                                self.ui_list.move_prev_page();
                                break;
                            }
                        }
                        BehaviourKey::Escape => {
                            // User pressed escape: we exit the list without any selection.
                            return None;
                        }
                        BehaviourKey::Return => match self.ui_list.selected_index() {
                            Some(i) => {
                                // User pressed return, and there is a selected item.
                                return Some((
                                    &self.ui_list.item_at_index(i),
                                    input.modifier_keys(),
                                    self.ui_list.get_element_index(i),
                                ));
                            }
                            None => { /* User pressed return, there's no selected item; do nothing. */}
                        },
                        _ => { /* Unhandled behaviour key does nothing. */ }
                    },
                    Key::Digit(d) => {
                        // User pressed a digit; let's check if that's a selection.
                        let digit = d.digit() as usize;
                        let i = match digit {
                            0 => 9,
                            _ => digit - 1,
                        };

                        // We only do digit selection if we're in a select list.
                        if self.styles.list_type == UiListType::Select
                            // Check we actually have enough items on the page to select the corresponding entry.
                            && i < self.ui_list.current_page_size()
                        {
                            // Selection success!
                            return Some((
                                &self.ui_list.item_at_index(i),
                                input.modifier_keys(),
                                self.ui_list.get_element_index(i),
                            ));
                        }

                        // Not a select list, or pressed a digit out of range of the current page?
                        // You don't even get a redraw.
                    }
                    Key::Symbol(_) => { /* Symbols don't do anything when you're in a list. */}
                }
            }
        }
    }
}

impl<'a, TEntry: ConsoleWriteable, TList: Deref<Target = [TEntry]>> ConsoleWriteable
    for ConsoleUiList<'a, TEntry, TList>
{
    fn write_to<TOut: ConsoleOut>(&self, console: &TOut) {
        // Write the title.
        self.title.write_to(console);
        if self.ui_list.current_page_size() == 0 {
            // There aren't any pages; the list is empty. Tell the user.
            console
                .line_start()
                .in_colours(self.styles.empty_list_message_colours, |c| {
                    c.output_utf16(s16!("There are no entries in this list."))
                        .blank_remaining_line()
                });
        } else {
            // There's pages, so there's items. Render the current page.
            for i in 0..self.ui_list.current_page_size() {
                // Is the item we're rendering selected? If so, we want to render it with a different style.
                let style = if self.ui_list.is_selected_index(i) {
                    self.styles.selected_entry_style
                } else {
                    self.styles.entry_style
                };

                // Write the list item indicator.
                console
                    .line_start()
                    .in_colours(style.identifier_colours, |c| match self.styles.list_type {
                        // Select lists' items are indicated with the key to press to select the item.
                        UiListType::Select => c.output_utf32(&format!("  {}. \0", (i + 1) % 10)),
                        // Ordered lists' items are indicated with their (1-indexed) position in the underlying list.
                        UiListType::Ordered(_) => c.output_utf32(&format!(
                            "  {}. \0",
                            self.ui_list.get_element_index(i) + 1
                        )),
                        // Unordered lists' items are indicated with a simple character based on styling.
                        UiListType::Unordered(_, d) => c.output_utf16(s16!("  ")).output_utf16(d),
                    });

                // Write the list item. We kinda just hope and pray this won't wrap.
                console.in_colours(style.content_base_colours, |c| {
                    self.ui_list.item_at_index(i).write_to(console);
                    c.blank_remaining_line()
                });
            }

            // Make sure we're not still on a list item's line. Shouldn't happen because of blanking, but to be safe.
            console.line_start();
            if self.ui_list.page_count() > 1 {
                // If there's more than one page, we want to render a page information line.
                if self.ui_list.can_move_prev_page() {
                    // If we can move to a previous page, we render an arrow to indicate that.
                    console.in_colours(self.styles.page_information_highlight_colours, |c| {
                        c.output_utf16(s16!("<- "))
                    });
                }

                // Write the 'Page X of Y' message.
                console.in_colours(self.styles.page_information_base_colours, |c| {
                    c.output_utf16(s16!("Page "))
                });

                console.in_colours(self.styles.page_information_highlight_colours, |c| {
                    c.output_utf32(&format!("{}\0", self.ui_list.current_page() + 1))
                });

                console.in_colours(self.styles.page_information_base_colours, |c| {
                    c.output_utf16(s16!(" of "))
                });

                console.in_colours(self.styles.page_information_highlight_colours, |c| {
                    c.output_utf32(&format!("{}\0", self.ui_list.page_count()))
                });

                if self.ui_list.can_move_next_page() {
                    // If we can move to a next page, we render an arrow to indicate that.
                    console.in_colours(self.styles.page_information_highlight_colours, |c| {
                        c.output_utf16(s16!(" ->"))
                    });
                }

                // Make sure we've finished the line.
                console.blank_remaining_line();
            }
        }

        // Write the completion message.
        console.in_colours(self.styles.cancel_message_colours, |c| {
            c.output_utf16_line(s16!("Press ESC to exit."))
        });
    }
}
