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

mod hmac;
mod ripemd_160;
mod sha_256;
mod sha_512;

pub use hmac::Hmac;
pub use ripemd_160::RIPEMD160;
pub use sha_256::Sha256;
pub use sha_512::Sha512;

use crate::String16;

pub trait Hasher<const HASH_SIZE: usize, const BLOCK_SIZE: usize> {
    fn algorithm_name() -> String16<'static>;

    fn is_little_endian() -> bool;

    fn new() -> Self;

    fn processed_bits(&self) -> u64;

    fn write_hash_to(&mut self, buffer: &mut [u8]) -> &mut Self;

    fn feed_bytes(&mut self, bytes: &[u8]) -> &mut Self;

    fn feed_byte(&mut self, byte: u8) -> &mut Self;

    fn reset(&mut self) -> &mut Self;

    fn write_hash_of(&mut self, bytes: &[u8], output: &mut [u8]) -> &mut Self {
        self.feed_bytes(bytes).write_hash_to(output)
    }

    fn build_hmac<'a>(&'a mut self, key: &[u8]) -> Hmac<'a, HASH_SIZE, BLOCK_SIZE, Self>
    where
        Self: Sized,
    {
        Hmac::from(self, key)
    }

    fn get_hash_of(&mut self, bytes: &[u8]) -> [u8; HASH_SIZE] {
        self.feed_bytes(bytes).get_hash()
    }

    fn get_hash(&mut self) -> [u8; HASH_SIZE] {
        let mut output = [0u8; HASH_SIZE];
        self.write_hash_to(&mut output);
        output
    }
}
