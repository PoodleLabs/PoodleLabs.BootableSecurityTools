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
