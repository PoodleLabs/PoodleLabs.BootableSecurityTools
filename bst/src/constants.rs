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
    console_out::{ConsoleColour, ConsoleColours},
    ui::{
        console::{
            ConsoleUiListEntryStyle, ConsoleUiListStyles, ConsoleUiNumericInputStyles,
            ConsoleUiScrollTextStyles, ConsoleUiTextBoxStyles, ConsoleUiTitleStyles,
        },
        UiElementAlignment, UiListType,
    },
    String16,
};
use macros::{c16, s16};

///////////////////////////////////
//// CONSOLE STYLING CONSTANTS ////
///////////////////////////////////

// NOTE ON COLOURS:
// For UEFI, foreground colours can be any value inside the ConsoleColour enum,
// but background colours can only be one of the following:
// - Inherit
// - Black
// - Blue
// - Green
// - Cyan
// - Red
// - Magenta
// - Brown
// - LightGray
// Use of any of the subsequent values in the ConsoleColour enum will transpose it to the 'dark' variant, for example:
// DarkGray -> Black
// White -> LightGray
// There is no guarantee that your particular devices will support every single colour;
// I have devices which render LightCyan as white, for example.
// If you want to customize the appearance of the tools, you will unfortunately need to iteratively test your colour selections.

// The below constants cover all existing styles in the application, but you could add specialized styles by searching for uses
// of the below values and adding new varibles to this file where you want to add a custom style to a specific element.

/////////////////
// CORE STYLES //
/////////////////

// The base colours for BST.
pub const DEFAULT_COLOURS: ConsoleColours =
    ConsoleColours::from(ConsoleColour::White, ConsoleColour::Black);

// The colours to write input prompts in.
pub const PROMPT_COLOURS: ConsoleColours =
    ConsoleColours::foreground_only(ConsoleColour::LightCyan);

// The colours to write labels in.
pub const LABEL_COLOURS: ConsoleColours = ConsoleColours::foreground_only(ConsoleColour::LightBlue);

// The colours to write selected text in.
pub const SELECTED_TEXT_COLOURS: ConsoleColours =
    ConsoleColours::from(ConsoleColour::Black, ConsoleColour::LightGray);

// The colours to write success messages in.
pub const SUCCESS_COLOURS: ConsoleColours =
    ConsoleColours::foreground_only(ConsoleColour::LightGreen);

// The colours to write warnings in.
pub const WARNING_COLOURS: ConsoleColours = ConsoleColours::foreground_only(ConsoleColour::Yellow);

// These colours are used for errors within the 'normal' operation of the tools.
pub const ERROR_COLOURS: ConsoleColours = ConsoleColours::foreground_only(ConsoleColour::LightRed);

// These colours are used to render BST's equivalent to the dreaded BSOD; you shouldn't encounter them.
pub const ERROR_SCREEN_COLOURS: ConsoleColours =
    ConsoleColours::from(ConsoleColour::White, ConsoleColour::Red);

// These colours are used to render shutdown messages in the top left corner of the screen.
pub const SHUTDOWN_MESSGE_COLOURS: ConsoleColours =
    ConsoleColours::from(ConsoleColour::White, ConsoleColour::Red);

//////////////////////
// BIG TITLE STYLES //
//////////////////////

// Border colours for big titles; used for program titles.
pub const BIG_TITLE_BORDER_COLOURS: ConsoleColours =
    ConsoleColours::foreground_only(ConsoleColour::Green);

// The border character for big titles.
pub const BIG_TITLE_BORDER_CHARACTER: u16 = c16!("-");

// Padding colours for big titles.
pub const BIG_TITLE_PADDING_COLOURS: ConsoleColours = ConsoleColours::INHERIT;

// The padding character for big titles.
pub const BIG_TITLE_PADDING_CHARACTER: u16 = c16!(" ");

/// The content alignment for big titles.
pub const BIG_TITLE_CONTENT_ALIGNMENT: UiElementAlignment = UiElementAlignment::Left;

// The content colours for big titles.
pub const BIG_TITLE_CONTENT_COLOURS: ConsoleColours =
    ConsoleColours::foreground_only(ConsoleColour::LightGreen);

pub const BIG_TITLE: ConsoleUiTitleStyles = ConsoleUiTitleStyles::from(
    BIG_TITLE_CONTENT_COLOURS,
    BIG_TITLE_PADDING_COLOURS,
    BIG_TITLE_BORDER_COLOURS,
    BIG_TITLE_CONTENT_ALIGNMENT,
    BIG_TITLE_BORDER_CHARACTER,
    BIG_TITLE_PADDING_CHARACTER,
    1,
);

////////////////////////
// SMALL TITLE STYLES //
////////////////////////

// Padding colours for small titles; used for headings for sections, inputs and lists inside programs.
pub const SMALL_TITLE_PADDING_COLOURS: ConsoleColours =
    ConsoleColours::foreground_only(ConsoleColour::Green);

// The padding character for small titles.
pub const SMALL_TITLE_PADDING_CHARACTER: u16 = c16!("-");

/// The content alignment for small titles.
pub const SMALL_TITLE_CONTENT_ALIGNMENT: UiElementAlignment = UiElementAlignment::Left;

// The content colours for small titles.
pub const SMALL_TITLE_CONTENT_COLOURS: ConsoleColours =
    ConsoleColours::foreground_only(ConsoleColour::LightGreen);

pub const SMALL_TITLE: ConsoleUiTitleStyles = ConsoleUiTitleStyles::from(
    SMALL_TITLE_CONTENT_COLOURS,
    SMALL_TITLE_PADDING_COLOURS,
    ConsoleColours::INHERIT,
    SMALL_TITLE_CONTENT_ALIGNMENT,
    c16!(" "),
    SMALL_TITLE_PADDING_CHARACTER,
    0,
);

/////////////////
// LIST STYLES //
/////////////////

// The colours for the character(s) marking the beginning of each list entry.
pub const LIST_ENTRY_DELIMITER_COLOURS: ConsoleColours =
    ConsoleColours::foreground_only(ConsoleColour::Blue);

// The delimiter for unordered list entries; ordered/select lists are delimited with '1. ', '2. ', etc.
pub const UNORDERED_LIST_ENTRY_DELIMITER: String16 = s16!("- ");

// The base colours for list entries' content.
pub const LIST_ENTRY_CONTENT_COLOURS: ConsoleColours =
    ConsoleColours::foreground_only(ConsoleColour::White);

// The colours for page information highlight text (eg: page number, page count, arrows).
pub const LIST_PAGE_INFORMATION_HIGHLIGHT_COLOURS: ConsoleColours =
    ConsoleColours::foreground_only(ConsoleColour::LightCyan);

// The base colours for page information text.
pub const LIST_PAGE_INFORMATION_BASE_COLOURS: ConsoleColours =
    ConsoleColours::foreground_only(ConsoleColour::White);

// The page size for lists (select lists will always have a page size of 10).
pub const LIST_PAGE_SIZE: usize = 10;

pub const UNORDERED_LIST: ConsoleUiListStyles = ConsoleUiListStyles::from(
    LIST_PAGE_INFORMATION_HIGHLIGHT_COLOURS,
    LIST_PAGE_INFORMATION_BASE_COLOURS,
    ConsoleUiListEntryStyle::from(SELECTED_TEXT_COLOURS, SELECTED_TEXT_COLOURS),
    WARNING_COLOURS,
    PROMPT_COLOURS,
    ConsoleUiListEntryStyle::from(LIST_ENTRY_CONTENT_COLOURS, LIST_ENTRY_DELIMITER_COLOURS),
    UiListType::Unordered(LIST_PAGE_SIZE, UNORDERED_LIST_ENTRY_DELIMITER),
);

pub const ORDERED_LIST: ConsoleUiListStyles =
    UNORDERED_LIST.with_list_type(UiListType::Ordered(LIST_PAGE_SIZE));

pub const SELECT_LIST: ConsoleUiListStyles = ORDERED_LIST.with_list_type(UiListType::Select);

////////////////////////
// SCROLL TEXT STYLES //
////////////////////////

// Colours for scroll text boxes, including text/numeric inputs.
pub const SCROLL_TEXT_CONTENT_COLOURS: ConsoleColours =
    ConsoleColours::from(ConsoleColour::Black, ConsoleColour::LightGray);

// Scroll text boxes render a character in the below colours to the right of any line which wraps.
pub const SCROLL_TEXT_WRAP_INDICATOR_COLOURS: ConsoleColours =
    ConsoleColours::foreground_only(ConsoleColour::Red);

// The described above indicator's character.
pub const SCROLL_TEXT_WRAP_INDICATOR_CHARACTER: String16 = s16!("-");

// Scroll text boxes render a character in the top left to indicate what portion of the text the viewport is currently showing.
pub const SCROLL_TEXT_SCROLL_INDICATOR_COLOURS: ConsoleColours =
    ConsoleColours::foreground_only(ConsoleColour::Blue);

// The character used when the entire text fits within the scroll text's viewport. IMPORTANT: Do not remove the trailing spaces.
pub const SCROLL_TEXT_SCROLL_INDICATOR_CHARACTER_NO_SCROLL: String16 = s16!("* ");

// The character used when the top of the content is visible, but it overflows the scroll text's viewport.
pub const SCROLL_TEXT_SCROLL_INDICATOR_CHARACTER_SCROLL_DOWN: String16 = s16!("↓ ");

// The character used when the content overflows the scroll text's viewport up and down.
pub const SCROLL_TEXT_SCROLL_INDICATOR_CHARACTER_SCROLL_UP_OR_DOWN: String16 = s16!("| ");

// The character used when the bottom of the content is visible, but it overflows the scroll text's viewport.
pub const SCROLL_TEXT_SCROLL_INDICATOR_CHARACTER_SCROLL_UP: String16 = s16!("↑ ");

// Scroll text height for text input.
pub const SCROLL_TEXT_DISPLAY_HEIGHT: usize = 20;

// Scroll text height for text input.
pub const TEXT_INPUT_HEIGHT: usize = 5;

// Scroll text height for byte input.
pub const BYTE_INPUT_HEIGHT: usize = 5;

// Scroll text height for numeric input.
pub const NUMERIC_INPUT_HEIGHT: usize = 2;

// The height of an immutable text display.
pub const TEXT_DISPLAY_HEIGHT: usize = 10;

pub const SCROLL_TEXT: ConsoleUiScrollTextStyles = ConsoleUiScrollTextStyles::from(
    SCROLL_TEXT_SCROLL_INDICATOR_COLOURS,
    SCROLL_TEXT_WRAP_INDICATOR_COLOURS,
    SCROLL_TEXT_WRAP_INDICATOR_CHARACTER,
    SCROLL_TEXT_CONTENT_COLOURS,
    SCROLL_TEXT_DISPLAY_HEIGHT,
);

pub const TEXT_DISPLAY: ConsoleUiTextBoxStyles = ConsoleUiTextBoxStyles::from(
    SCROLL_TEXT.with_height(TEXT_DISPLAY_HEIGHT),
    PROMPT_COLOURS,
    SMALL_TITLE,
);

pub const TEXT_INPUT: ConsoleUiTextBoxStyles = ConsoleUiTextBoxStyles::from(
    SCROLL_TEXT.with_height(TEXT_INPUT_HEIGHT),
    PROMPT_COLOURS,
    SMALL_TITLE,
);

pub const BYTE_INPUT: ConsoleUiNumericInputStyles = ConsoleUiNumericInputStyles::from(
    SMALL_TITLE,
    SELECT_LIST,
    TEXT_INPUT.with_scroll_text(SCROLL_TEXT.with_height(BYTE_INPUT_HEIGHT)),
);

pub const NUMERIC_INPUT: ConsoleUiNumericInputStyles = BYTE_INPUT.with_text_input_styles(
    TEXT_INPUT.with_scroll_text(SCROLL_TEXT.with_height(NUMERIC_INPUT_HEIGHT)),
);
