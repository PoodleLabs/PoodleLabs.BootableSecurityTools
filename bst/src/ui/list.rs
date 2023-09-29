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

use crate::String16;
use core::ops::Deref;

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum UiListType {
    Select,
    Ordered(usize),
    Unordered(usize, String16<'static>),
}

pub(in crate::ui) struct UiList<TEntry, TList: Deref<Target = [TEntry]>> {
    selected_index: Option<usize>,
    current_page: usize,
    page_size: usize,
    items: TList,
}

impl<TEntry, TList: Deref<Target = [TEntry]>> UiList<TEntry, TList> {
    pub const fn from(page_size: usize, items: TList) -> Self {
        Self {
            selected_index: None,
            current_page: 0,
            page_size,
            items,
        }
    }

    pub const fn get_element_index(&self, index: usize) -> usize {
        self.page_index_offset() + index
    }

    pub const fn is_selected_index(&self, index: usize) -> bool {
        match self.selected_index {
            Some(i) => i == index,
            None => false,
        }
    }

    pub const fn selected_index(&self) -> Option<usize> {
        self.selected_index
    }

    pub const fn can_move_prev_page(&self) -> bool {
        self.current_page > 0
    }

    pub const fn current_page(&self) -> usize {
        self.current_page
    }

    pub fn item_at_index(&self, index: usize) -> &TEntry {
        &self.items[self.get_element_index(index)]
    }

    pub fn reset_selected_on_page_change(&mut self) {
        self.selected_index = match self.selected_index {
            Some(_) => Some(0),
            None => None,
        }
    }

    pub fn current_page_size(&self) -> usize {
        let remaining_items = self.items.len() - self.page_index_offset();
        if remaining_items > self.page_size {
            self.page_size
        } else {
            remaining_items
        }
    }

    pub fn can_move_next_page(&self) -> bool {
        self.current_page < (self.page_count() - 1)
    }

    pub fn page_count(&self) -> usize {
        // Divide the number of items by the page size, rounding up, then clamp to at least 1 page.
        ((self.items.len() + (self.page_size - 1)) / self.page_size).max(1)
    }

    pub fn move_prev_page(&mut self) {
        if self.can_move_prev_page() {
            self.current_page -= 1;
            self.reset_selected_on_page_change();
        }
    }

    pub fn move_next_page(&mut self) {
        if self.can_move_next_page() {
            self.current_page += 1;
            self.reset_selected_on_page_change();
        }
    }

    pub fn has_items(&self) -> bool {
        self.items.len() > 0
    }

    pub fn select_next(&mut self) {
        self.selected_index = match self.selected_index {
            Some(i) => {
                if self.current_page_size() > i + 1 {
                    // There's an element to select after the currently selected; select it.
                    Some(i + 1)
                } else {
                    // The currently selected element is the last on the page; select nothing.
                    None
                }
            }
            None => {
                if self.current_page_size() == 0 {
                    // There's nothing to select, so don't select anything.
                    None
                } else {
                    // There's nothing currently selected, so select the first element on the page.
                    Some(0)
                }
            }
        }
    }

    pub fn select_prev(&mut self) {
        self.selected_index = match self.selected_index {
            Some(i) => {
                if i > 0 {
                    // The currently selected element isn't the first on the page, so just select the one above it.
                    Some(i - 1)
                } else {
                    // The currently selected element is the first on the page, so select nothing.
                    None
                }
            }
            None => {
                let page_size = self.current_page_size();
                if page_size == 0 {
                    // There's nothing to select, so don't select anything.
                    None
                } else {
                    // There's nothing currently selected, so select the last element on the page.
                    Some(page_size - 1)
                }
            }
        }
    }

    pub fn reset(&mut self) {
        self.selected_index = None;
        self.current_page = 0;
    }

    const fn page_index_offset(&self) -> usize {
        self.current_page * self.page_size
    }
}
