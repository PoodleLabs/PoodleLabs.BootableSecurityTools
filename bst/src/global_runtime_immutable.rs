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

pub struct GlobalRuntimeImmutable<T, FBuilder: Fn() -> T> {
    builder: FBuilder,
    value: Option<T>,
}

impl<T, FBuilder: Fn() -> T> GlobalRuntimeImmutable<T, FBuilder> {
    pub const fn from(builder: FBuilder) -> Self {
        Self {
            builder,
            value: None,
        }
    }

    pub fn value(&mut self) -> &T {
        if self.value.is_none() {
            self.value = Some((self.builder)());
        }

        self.value.as_ref().unwrap()
    }
}
