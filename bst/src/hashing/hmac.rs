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

use super::Hasher;
use alloc::vec;
use core::{mem::size_of, slice};

pub struct Hmac<
    'a,
    const HASH_SIZE: usize,
    const BLOCK_SIZE: usize,
    THasher: Hasher<HASH_SIZE, BLOCK_SIZE>,
> {
    // The underlying hashing algorithm
    hasher: &'a mut THasher,
    // Processed Key Components
    d0: [u8; BLOCK_SIZE],
    d1: [u8; BLOCK_SIZE],
}

impl<
        'a,
        const HASH_SIZE: usize,
        const BLOCK_SIZE: usize,
        THasher: Hasher<HASH_SIZE, BLOCK_SIZE>,
    > Hmac<'a, HASH_SIZE, BLOCK_SIZE, THasher>
{
    pub fn from(hasher: &'a mut THasher, key: &[u8]) -> Self {
        let mut d0 = [0u8; BLOCK_SIZE];
        let mut d1 = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            // Compress the key so it fits in a single block, writing to D0 buffer.
            hasher.feed_bytes(key);
            hasher.write_hash_to(&mut d0[..HASH_SIZE]);
            hasher.reset();
        } else {
            // Write the key to the D0 buffer.
            d0[..key.len()].copy_from_slice(key);
        }

        // Clone the (compressed) key into the D1 buffer.
        d1.copy_from_slice(&d0);
        for i in 0..d0.len() {
            // Process the D0 buffer.
            d0[i] = d0[i] ^ 0x36;
        }

        for i in 0..d1.len() {
            // Process the D1 buffer.
            d1[i] = d1[i] ^ 0x5C;
        }

        // Return the processed key alongside the underlying hasher.
        Self { hasher, d0, d1 }
    }

    pub fn write_hmac_to(&mut self, message: &[u8], buffer: &mut [u8]) -> &mut Self {
        self.hasher
            .feed_bytes(&self.d0)
            .feed_bytes(message)
            .write_hash_to(&mut buffer[..HASH_SIZE])
            .reset()
            .feed_bytes(&self.d1)
            .feed_bytes(buffer)
            .write_hash_to(&mut buffer[..HASH_SIZE])
            .reset();
        self
    }

    pub fn get_hmac(&mut self, message: &[u8]) -> [u8; HASH_SIZE] {
        let mut output = [0u8; HASH_SIZE];
        self.write_hmac_to(message, &mut output);
        output
    }

    pub fn pbkdf2(&mut self, salt: &[u8], iterations: u32, output: &mut [u8]) -> &mut Self {
        if iterations == 0 {
            panic!("Cannot perform PBKDF2 with an iteration count of 0.");
        }

        // Each round of hashing is salted with the input salt, appended with the current block of output starting from 0.
        let mut numbered_salt = vec![0u8; salt.len() + size_of::<u32>()];
        numbered_salt[..salt.len()].copy_from_slice(salt);
        let mut buffer1 = [0u8; HASH_SIZE];
        let mut buffer2 = [0u8; HASH_SIZE];
        let output_length = output.len();
        let mut output_offset = 0usize;
        let mut current_block = 1u32;

        while output_offset < output_length {
            // Write the current block to the salt + block number buffer.
            numbered_salt[salt.len() + 0] = (current_block >> 24) as u8;
            numbered_salt[salt.len() + 1] = (current_block >> 16) as u8;
            numbered_salt[salt.len() + 2] = (current_block >> 8) as u8;
            numbered_salt[salt.len() + 3] = (current_block >> 0) as u8;

            // Perform HMAC on the key and numbered salt, and write to buffer 2.
            self.write_hmac_to(&numbered_salt, &mut buffer2);

            // Copy the HMAC to buffer 1.
            buffer1.copy_from_slice(&buffer2);

            for _ in 1..iterations {
                // HMAC buffer 1's current contents, and overwrite it with the result.
                self.write_hmac_to(
                    unsafe { slice::from_raw_parts(buffer1.as_ptr(), buffer1.len()) },
                    &mut buffer1,
                );

                for i in 0..HASH_SIZE {
                    // Xor buffer 2 with buffer 1.
                    buffer2[i] ^= buffer1[i]
                }
            }

            // Copy the buffer to the output.
            let bytes_from_buffer = HASH_SIZE.min(output_length - output_offset);
            output[output_offset..output_offset + bytes_from_buffer]
                .copy_from_slice(&buffer2[..bytes_from_buffer]);

            // Move to the next block (if we need to).
            output_offset += bytes_from_buffer;
            current_block += 1;
        }

        self.hasher.reset();
        self
    }
}
