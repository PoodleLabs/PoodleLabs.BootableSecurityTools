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

use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign};

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct DigitKey {
    character: u16,
    digit: u8,
}

impl DigitKey {
    pub const fn from(character: u16, digit: u8) -> Self {
        Self { character, digit }
    }

    pub const fn character(&self) -> u16 {
        self.character
    }

    pub const fn digit(&self) -> u8 {
        self.digit
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum BehaviourKey {
    Unknown,
    UpArrow,
    RightArrow,
    DownArrow,
    LeftArrow,
    Home,
    End,
    Insert,
    Delete,
    PageUp,
    PageDown,
    Escape,
    Pause,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    F13,
    F14,
    F15,
    F16,
    F17,
    F18,
    F19,
    F20,
    F21,
    F22,
    F23,
    F24,
    Mute,
    VolumeUp,
    VolumeDown,
    BrightnessUp,
    BrightnessDown,
    Suspend,
    Hibernate,
    ToggleDisplay,
    Recovery,
    Eject,
    BackSpace,
    Return,
    Tab,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub enum Key {
    Behaviour(BehaviourKey),
    Digit(DigitKey),
    Symbol(u16),
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ToggleKeys(u8);

#[allow(dead_code)]
impl ToggleKeys {
    pub const NONE: Self = Self(0);
    pub const NUM_LOCK: Self = Self(1);
    pub const CAPS_LOCK: Self = Self(2);
    pub const SCROLL_LOCK: Self = Self(4);

    pub const fn num_lock(self) -> bool {
        self.has_any_flag_of(Self::NUM_LOCK)
    }

    pub const fn caps_lock(self) -> bool {
        self.has_any_flag_of(Self::CAPS_LOCK)
    }

    pub const fn scroll_lock(self) -> bool {
        self.has_any_flag_of(Self::SCROLL_LOCK)
    }

    pub const fn has_any_flag_of(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    pub const fn has_all_flags_of(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitAnd for ToggleKeys {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for ToggleKeys {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = Self(self.0 & rhs.0)
    }
}

impl BitOr for ToggleKeys {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for ToggleKeys {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = Self(self.0 | rhs.0)
    }
}

impl BitXor for ToggleKeys {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for ToggleKeys {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = Self(self.0 ^ rhs.0)
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ModifierKeys(u16);

#[allow(dead_code)]
impl ModifierKeys {
    pub const NONE: Self = Self(0);
    pub const RIGHT_SHIFT: Self = Self(1);
    pub const LEFT_SHIFT: Self = Self(2);
    pub const RIGHT_CONTROL: Self = Self(4);
    pub const LEFT_CONTROL: Self = Self(8);
    pub const RIGHT_ALT: Self = Self(16);
    pub const LEFT_ALT: Self = Self(32);
    pub const RIGHT_LOGO: Self = Self(64);
    pub const LEFT_LOGO: Self = Self(128);
    pub const MENU: Self = Self(256);
    pub const SYSTEM_REQUEST: Self = Self(512);

    pub const CONTROL: Self = Self(Self::LEFT_CONTROL.0 | Self::RIGHT_CONTROL.0);
    pub const SHIFT: Self = Self(Self::LEFT_SHIFT.0 | Self::RIGHT_SHIFT.0);
    pub const LOGO: Self = Self(Self::LEFT_LOGO.0 | Self::RIGHT_LOGO.0);
    pub const ALT: Self = Self(Self::LEFT_ALT.0 | Self::RIGHT_ALT.0);

    pub const fn control(self) -> bool {
        self.has_any_flag_of(Self::CONTROL)
    }

    pub const fn shift(self) -> bool {
        self.has_any_flag_of(Self::SHIFT)
    }

    pub const fn logo(self) -> bool {
        self.has_any_flag_of(Self::LOGO)
    }

    pub const fn alt(self) -> bool {
        self.has_any_flag_of(Self::ALT)
    }

    pub const fn right_shift(self) -> bool {
        self.has_any_flag_of(Self::RIGHT_SHIFT)
    }

    pub const fn left_shift(self) -> bool {
        self.has_any_flag_of(Self::LEFT_SHIFT)
    }

    pub const fn right_control(self) -> bool {
        self.has_any_flag_of(Self::RIGHT_CONTROL)
    }

    pub const fn left_control(self) -> bool {
        self.has_any_flag_of(Self::LEFT_CONTROL)
    }

    pub const fn right_alt(self) -> bool {
        self.has_any_flag_of(Self::RIGHT_ALT)
    }

    pub const fn left_alt(self) -> bool {
        self.has_any_flag_of(Self::LEFT_ALT)
    }

    pub const fn right_logo(self) -> bool {
        self.has_any_flag_of(Self::RIGHT_LOGO)
    }

    pub const fn left_logo(self) -> bool {
        self.has_any_flag_of(Self::LEFT_LOGO)
    }

    pub const fn menu(self) -> bool {
        self.has_any_flag_of(Self::MENU)
    }

    pub const fn system_request(self) -> bool {
        self.has_any_flag_of(Self::SYSTEM_REQUEST)
    }

    pub const fn has_any_flag_of(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    pub const fn has_all_flags_of(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitAnd for ModifierKeys {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for ModifierKeys {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = Self(self.0 & rhs.0)
    }
}

impl BitOr for ModifierKeys {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for ModifierKeys {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = Self(self.0 | rhs.0)
    }
}

impl BitXor for ModifierKeys {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for ModifierKeys {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = Self(self.0 ^ rhs.0)
    }
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
