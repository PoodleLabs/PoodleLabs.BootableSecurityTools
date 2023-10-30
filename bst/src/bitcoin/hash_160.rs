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

use crate::hashing::{Hasher, Sha256, RIPEMD160};

pub struct Hash160 {
    sha256_buffer: [u8; Sha256::HASH_SIZE],
    ripemd160: RIPEMD160,
    sha256: Sha256,
}

impl Hash160 {
    pub fn new() -> Self {
        Self {
            sha256_buffer: [0u8; Sha256::HASH_SIZE],
            ripemd160: RIPEMD160::new(),
            sha256: Sha256::new(),
        }
    }

    pub fn fingerprint(&mut self, data: &[u8]) -> [u8; 4] {
        let mut fingerprint = [0u8; 4];
        self.sha256.write_hash_of(&data, &mut self.sha256_buffer);
        self.ripemd160.feed_bytes(&self.sha256_buffer);
        self.ripemd160
            .write_hash_to(&mut self.sha256_buffer[..RIPEMD160::HASH_SIZE]);

        fingerprint.copy_from_slice(&self.sha256_buffer[..4]);
        self.reset();
        fingerprint
    }

    #[allow(dead_code)]
    pub fn hash_160(&mut self, bytes: &[u8]) -> [u8; 20] {
        self.sha256.write_hash_of(bytes, &mut self.sha256_buffer);
        let hash = self.ripemd160.get_hash_of(&self.sha256_buffer);
        self.reset();
        hash
    }

    pub fn reset(&mut self) {
        self.sha256_buffer.fill(0);
        self.ripemd160.reset();
        self.sha256.reset();
    }
}
