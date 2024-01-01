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

mod behaviour_keys;
mod digit_keys;
mod modifier_keys;
mod toggle_keys;

pub use behaviour_keys::BehaviourKey;
pub use digit_keys::DigitKey;
pub use modifier_keys::ModifierKeys;
pub use toggle_keys::ToggleKeys;

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub enum Key {
    Behaviour(BehaviourKey),
    Digit(DigitKey),
    Symbol(u16),
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct KeyPress {
    modifier_keys: ModifierKeys,
    toggle_keys: ToggleKeys,
    key: Key,
}

impl KeyPress {
    pub const fn from(key: Key, toggle_keys: ToggleKeys, modifier_keys: ModifierKeys) -> Self {
        Self {
            modifier_keys,
            toggle_keys,
            key,
        }
    }

    pub const fn modifier_keys(self) -> ModifierKeys {
        self.modifier_keys
    }

    #[allow(dead_code)]
    pub const fn toggle_keys(self) -> ToggleKeys {
        self.toggle_keys
    }

    pub const fn key(self) -> Key {
        self.key
    }
}

pub trait KeyboardIn {
    fn read_key(&self) -> KeyPress;
}
