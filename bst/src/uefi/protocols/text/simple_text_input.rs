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
    characters::Character,
    input::keyboard::{BehaviourKey, DigitKey, Key, KeyPress, ModifierKeys, ToggleKeys},
    uefi::{
        core_types::{UefiEventHandle, UefiGuid, UefiStatusCode},
        protocols::UefiProtocol,
        wait_for_event,
    },
};
use macros::c16;

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct UefiScanCode(u16);

impl UefiScanCode {
    pub const NULL: Self = Self::from(0x00);
    pub const UP_ARROW: Self = Self::from(0x01);
    pub const DOWN_ARROW: Self = Self::from(0x02);
    pub const RIGHT_ARROW: Self = Self::from(0x03);
    pub const LEFT_ARROW: Self = Self::from(0x04);
    pub const HOME: Self = Self::from(0x05);
    pub const END: Self = Self::from(0x06);
    pub const INSERT: Self = Self::from(0x07);
    pub const DELETE: Self = Self::from(0x08);
    pub const PAGE_UP: Self = Self::from(0x09);
    pub const PAGE_DOWN: Self = Self::from(0x0a);
    pub const FUNCTION_1: Self = Self::from(0x0b);
    pub const FUNCTION_2: Self = Self::from(0x0c);
    pub const FUNCTION_3: Self = Self::from(0x0d);
    pub const FUNCTION_4: Self = Self::from(0x0e);
    pub const FUNCTION_5: Self = Self::from(0x0f);
    pub const FUNCTION_6: Self = Self::from(0x10);
    pub const FUNCTION_7: Self = Self::from(0x11);
    pub const FUNCTION_8: Self = Self::from(0x12);
    pub const FUNCTION_9: Self = Self::from(0x13);
    pub const FUNCTION_10: Self = Self::from(0x14);
    pub const FUNCTION_11: Self = Self::from(0x15);
    pub const FUNCTION_12: Self = Self::from(0x16);
    pub const ESCAPE: Self = Self::from(0x17);
    pub const PAUSE: Self = Self::from(0x48);
    pub const FUNCTION_13: Self = Self::from(0x68);
    pub const FUNCTION_14: Self = Self::from(0x69);
    pub const FUNCTION_15: Self = Self::from(0x6a);
    pub const FUNCTION_16: Self = Self::from(0x6b);
    pub const FUNCTION_17: Self = Self::from(0x6c);
    pub const FUNCTION_18: Self = Self::from(0x6d);
    pub const FUNCTION_19: Self = Self::from(0x6e);
    pub const FUNCTION_20: Self = Self::from(0x6f);
    pub const FUNCTION_21: Self = Self::from(0x70);
    pub const FUNCTION_22: Self = Self::from(0x71);
    pub const FUNCTION_23: Self = Self::from(0x72);
    pub const FUNCTION_24: Self = Self::from(0x73);
    pub const MUTE: Self = Self::from(0x7F);
    pub const VOLUME_UP: Self = Self::from(0x80);
    pub const VOLUME_DOWN: Self = Self::from(0x81);
    pub const BRIGHTNESS_UP: Self = Self::from(0x100);
    pub const BRIGHTNESS_DOWN: Self = Self::from(0x101);
    pub const SUSPEND: Self = Self::from(0x102);
    pub const HIBERNATE: Self = Self::from(0x103);
    pub const TOGGLE_DISPLAY: Self = Self::from(0x104);
    pub const RECOVERY: Self = Self::from(0x105);
    pub const EJECT: Self = Self::from(0x106);

    const fn from(code: u16) -> Self {
        UefiScanCode(code)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiInputKey {
    scan_code: UefiScanCode,
    unicode_character: u16,
}

impl UefiInputKey {
    const NULL: Self = Self {
        scan_code: UefiScanCode::NULL,
        unicode_character: 0u16,
    };
}

impl Into<Key> for UefiInputKey {
    fn into(self) -> Key {
        match self.scan_code {
            UefiScanCode::NULL => match self.unicode_character {
                c16!("0") => Key::Digit(DigitKey::from(c16!("0"), 0)),
                c16!("1") => Key::Digit(DigitKey::from(c16!("1"), 1)),
                c16!("2") => Key::Digit(DigitKey::from(c16!("2"), 2)),
                c16!("3") => Key::Digit(DigitKey::from(c16!("3"), 3)),
                c16!("4") => Key::Digit(DigitKey::from(c16!("4"), 4)),
                c16!("5") => Key::Digit(DigitKey::from(c16!("5"), 5)),
                c16!("6") => Key::Digit(DigitKey::from(c16!("6"), 6)),
                c16!("7") => Key::Digit(DigitKey::from(c16!("7"), 7)),
                c16!("8") => Key::Digit(DigitKey::from(c16!("8"), 8)),
                c16!("9") => Key::Digit(DigitKey::from(c16!("9"), 9)),
                c16!("\r") | c16!("\n") => Key::Behaviour(BehaviourKey::Return),
                c16!("\u{0008}") => Key::Behaviour(BehaviourKey::BackSpace),
                c16!("\t") => Key::Behaviour(BehaviourKey::Tab),
                _ => {
                    if self.unicode_character.is_printable() {
                        Key::Symbol(self.unicode_character)
                    } else {
                        Key::Behaviour(BehaviourKey::Unknown)
                    }
                }
            },
            UefiScanCode::UP_ARROW => Key::Behaviour(BehaviourKey::UpArrow),
            UefiScanCode::DOWN_ARROW => Key::Behaviour(BehaviourKey::DownArrow),
            UefiScanCode::RIGHT_ARROW => Key::Behaviour(BehaviourKey::RightArrow),
            UefiScanCode::LEFT_ARROW => Key::Behaviour(BehaviourKey::LeftArrow),
            UefiScanCode::HOME => Key::Behaviour(BehaviourKey::Home),
            UefiScanCode::END => Key::Behaviour(BehaviourKey::End),
            UefiScanCode::INSERT => Key::Behaviour(BehaviourKey::Insert),
            UefiScanCode::DELETE => Key::Behaviour(BehaviourKey::Delete),
            UefiScanCode::PAGE_UP => Key::Behaviour(BehaviourKey::PageUp),
            UefiScanCode::PAGE_DOWN => Key::Behaviour(BehaviourKey::PageDown),
            UefiScanCode::FUNCTION_1 => Key::Behaviour(BehaviourKey::F1),
            UefiScanCode::FUNCTION_2 => Key::Behaviour(BehaviourKey::F2),
            UefiScanCode::FUNCTION_3 => Key::Behaviour(BehaviourKey::F3),
            UefiScanCode::FUNCTION_4 => Key::Behaviour(BehaviourKey::F4),
            UefiScanCode::FUNCTION_5 => Key::Behaviour(BehaviourKey::F5),
            UefiScanCode::FUNCTION_6 => Key::Behaviour(BehaviourKey::F6),
            UefiScanCode::FUNCTION_7 => Key::Behaviour(BehaviourKey::F7),
            UefiScanCode::FUNCTION_8 => Key::Behaviour(BehaviourKey::F8),
            UefiScanCode::FUNCTION_9 => Key::Behaviour(BehaviourKey::F9),
            UefiScanCode::FUNCTION_10 => Key::Behaviour(BehaviourKey::F10),
            UefiScanCode::FUNCTION_11 => Key::Behaviour(BehaviourKey::F11),
            UefiScanCode::FUNCTION_12 => Key::Behaviour(BehaviourKey::F12),
            UefiScanCode::ESCAPE => Key::Behaviour(BehaviourKey::Escape),
            UefiScanCode::PAUSE => Key::Behaviour(BehaviourKey::Pause),
            UefiScanCode::FUNCTION_13 => Key::Behaviour(BehaviourKey::F13),
            UefiScanCode::FUNCTION_14 => Key::Behaviour(BehaviourKey::F14),
            UefiScanCode::FUNCTION_15 => Key::Behaviour(BehaviourKey::F15),
            UefiScanCode::FUNCTION_16 => Key::Behaviour(BehaviourKey::F16),
            UefiScanCode::FUNCTION_17 => Key::Behaviour(BehaviourKey::F17),
            UefiScanCode::FUNCTION_18 => Key::Behaviour(BehaviourKey::F18),
            UefiScanCode::FUNCTION_19 => Key::Behaviour(BehaviourKey::F19),
            UefiScanCode::FUNCTION_20 => Key::Behaviour(BehaviourKey::F20),
            UefiScanCode::FUNCTION_21 => Key::Behaviour(BehaviourKey::F21),
            UefiScanCode::FUNCTION_22 => Key::Behaviour(BehaviourKey::F22),
            UefiScanCode::FUNCTION_23 => Key::Behaviour(BehaviourKey::F23),
            UefiScanCode::FUNCTION_24 => Key::Behaviour(BehaviourKey::F24),
            UefiScanCode::MUTE => Key::Behaviour(BehaviourKey::Mute),
            UefiScanCode::VOLUME_UP => Key::Behaviour(BehaviourKey::VolumeUp),
            UefiScanCode::VOLUME_DOWN => Key::Behaviour(BehaviourKey::VolumeDown),
            UefiScanCode::BRIGHTNESS_UP => Key::Behaviour(BehaviourKey::BrightnessUp),
            UefiScanCode::BRIGHTNESS_DOWN => Key::Behaviour(BehaviourKey::BrightnessDown),
            UefiScanCode::SUSPEND => Key::Behaviour(BehaviourKey::Suspend),
            UefiScanCode::HIBERNATE => Key::Behaviour(BehaviourKey::Hibernate),
            UefiScanCode::TOGGLE_DISPLAY => Key::Behaviour(BehaviourKey::ToggleDisplay),
            UefiScanCode::RECOVERY => Key::Behaviour(BehaviourKey::Recovery),
            UefiScanCode::EJECT => Key::Behaviour(BehaviourKey::Eject),
            _ => Key::Behaviour(BehaviourKey::Unknown),
        }
    }
}

#[repr(C)]
#[derive(Debug, Eq, PartialEq, Clone, Copy, PartialOrd, Ord)]
struct UefiKeyShiftState(u32);

impl UefiKeyShiftState {
    const NONE: Self = Self(0);
    const RIGHT_SHIFT: Self = Self(1);
    const LEFT_SHIFT: Self = Self(2);
    const RIGHT_CONTROL: Self = Self(4);
    const LEFT_CONTROL: Self = Self(8);
    const RIGHT_ALT: Self = Self(16);
    const LEFT_ALT: Self = Self(32);
    const RIGHT_LOGO: Self = Self(64);
    const LEFT_LOGO: Self = Self(128);
    const MENU: Self = Self(256);
    const SYSTEM_REQUEST: Self = Self(512);

    const fn right_shift(self) -> bool {
        self.0 & Self::RIGHT_SHIFT.0 != 0
    }

    const fn left_shift(self) -> bool {
        self.0 & Self::LEFT_SHIFT.0 != 0
    }

    const fn right_control(self) -> bool {
        self.0 & Self::RIGHT_CONTROL.0 != 0
    }

    const fn left_control(self) -> bool {
        self.0 & Self::LEFT_CONTROL.0 != 0
    }

    const fn right_alt(self) -> bool {
        self.0 & Self::RIGHT_ALT.0 != 0
    }

    const fn left_alt(self) -> bool {
        self.0 & Self::LEFT_ALT.0 != 0
    }

    const fn right_logo(self) -> bool {
        self.0 & Self::RIGHT_LOGO.0 != 0
    }

    const fn left_logo(self) -> bool {
        self.0 & Self::LEFT_LOGO.0 != 0
    }

    const fn menu(self) -> bool {
        self.0 & Self::MENU.0 != 0
    }

    const fn system_request(self) -> bool {
        self.0 & Self::SYSTEM_REQUEST.0 != 0
    }
}

impl Into<ModifierKeys> for UefiKeyShiftState {
    fn into(self) -> ModifierKeys {
        let mut flags = ModifierKeys::NONE;
        if self.left_alt() {
            flags |= ModifierKeys::LEFT_ALT;
        }

        if self.right_alt() {
            flags |= ModifierKeys::RIGHT_ALT;
        }

        if self.left_control() {
            flags |= ModifierKeys::LEFT_CONTROL;
        }

        if self.right_control() {
            flags |= ModifierKeys::RIGHT_CONTROL;
        }

        if self.left_shift() {
            flags |= ModifierKeys::LEFT_SHIFT;
        }

        if self.right_shift() {
            flags |= ModifierKeys::RIGHT_SHIFT;
        }

        if self.left_logo() {
            flags |= ModifierKeys::LEFT_LOGO;
        }

        if self.right_logo() {
            flags |= ModifierKeys::RIGHT_LOGO;
        }

        if self.menu() {
            flags |= ModifierKeys::MENU;
        }

        if self.system_request() {
            flags |= ModifierKeys::SYSTEM_REQUEST;
        }

        flags
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
struct UefiKeyToggleState(u8);

impl UefiKeyToggleState {
    const NONE: Self = Self(0x00);
    const SCROLL_LOCK: Self = Self(0x01);
    const NUM_LOCK: Self = Self(0x02);
    const CAPS_LOCK: Self = Self(0x03);

    fn scroll_lock_enabled(self) -> bool {
        self.0 & Self::SCROLL_LOCK.0 != 0
    }

    fn num_lock_enabled(self) -> bool {
        self.0 & Self::NUM_LOCK.0 != 0
    }

    fn caps_lock_enabled(self) -> bool {
        self.0 & Self::CAPS_LOCK.0 != 0
    }
}

impl Into<ToggleKeys> for UefiKeyToggleState {
    fn into(self) -> ToggleKeys {
        let mut flags = ToggleKeys::NONE;
        if self.scroll_lock_enabled() {
            flags |= ToggleKeys::SCROLL_LOCK;
        }

        if self.caps_lock_enabled() {
            flags |= ToggleKeys::CAPS_LOCK;
        }

        if self.num_lock_enabled() {
            flags |= ToggleKeys::NUM_LOCK;
        }

        flags
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
struct UefiKeyState {
    key_shift_state: UefiKeyShiftState,
    key_toggle_state: UefiKeyToggleState,
}

impl UefiKeyState {
    const NULL: Self = Self {
        key_shift_state: UefiKeyShiftState::NONE,
        key_toggle_state: UefiKeyToggleState::NONE,
    };
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub(in crate::uefi) struct UefiKeyData {
    key: UefiInputKey,
    key_state: UefiKeyState,
}

impl UefiKeyData {
    const NULL: Self = Self {
        key: UefiInputKey::NULL,
        key_state: UefiKeyState::NULL,
    };
}

impl Into<KeyPress> for UefiKeyData {
    fn into(self) -> KeyPress {
        KeyPress::from(
            self.key.into(),
            self.key_state.key_toggle_state.into(),
            self.key_state.key_shift_state.into(),
        )
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiSimpleTextInput {
    reset: extern "efiapi" fn(this: &Self, extended_verification: bool) -> UefiStatusCode,
    read_key_stroke: extern "efiapi" fn(
        this: &Self,
        input_key: &mut UefiInputKey, /* OUT */
    ) -> UefiStatusCode,
    wait_for_key: UefiEventHandle,
}

impl UefiSimpleTextInput {
    pub const GUID: UefiGuid = UefiGuid::from(
        0x387477c1,
        0x69c7,
        0x11d2,
        0x8e,
        0x39,
        [0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );

    pub fn reset(&self, allow_extended_verification: bool) -> UefiStatusCode {
        (self.reset)(&self, allow_extended_verification)
    }

    pub fn read_key_stroke(&self) -> Result<UefiInputKey, UefiStatusCode> {
        match wait_for_event(self.wait_for_key).into() {
            Ok(_) => {
                let mut key = UefiInputKey::NULL;
                match (self.read_key_stroke)(self, &mut key).into() {
                    Ok(_) => Ok(key),
                    Err(c) => Err(c),
                }
            }
            Err(c) => Err(c),
        }
    }
}

impl UefiProtocol for UefiSimpleTextInput {
    fn guid() -> &'static UefiGuid {
        &Self::GUID
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiSimpleTextInputExtended {
    reset: extern "efiapi" fn(this: &Self, extended_verification: bool) -> UefiStatusCode,
    read_key_stroke: extern "efiapi" fn(
        this: &Self,
        input_key: &mut UefiKeyData, /* OUT */
    ) -> UefiStatusCode,
    wait_for_key: UefiEventHandle,
}

impl UefiSimpleTextInputExtended {
    pub const GUID: UefiGuid = UefiGuid::from(
        0xdd9e7534,
        0x7762,
        0x4698,
        0x8c,
        0x14,
        [0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa],
    );

    pub fn reset(&self, allow_extended_verification: bool) -> UefiStatusCode {
        (self.reset)(&self, allow_extended_verification)
    }

    pub fn read_key_stroke(&self) -> Result<UefiKeyData, UefiStatusCode> {
        match wait_for_event(self.wait_for_key).into() {
            Ok(_) => {
                let mut key = UefiKeyData::NULL;
                match (self.read_key_stroke)(self, &mut key).into() {
                    Ok(_) => Ok(key),
                    Err(c) => Err(c),
                }
            }
            Err(c) => Err(c),
        }
    }
}

impl UefiProtocol for UefiSimpleTextInputExtended {
    fn guid() -> &'static UefiGuid {
        &Self::GUID
    }
}
