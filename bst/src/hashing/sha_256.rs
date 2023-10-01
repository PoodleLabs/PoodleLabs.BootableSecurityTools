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
use crate::String16;
use core::mem::size_of;
use macros::s16;

pub struct Sha256 {
    hash: [u32; Self::HASH_SIZE / size_of::<u32>()],
    block: [u8; Self::BLOCK_SIZE],
    pending_block_offset: usize,
    processed_bits: u64,
    closed: bool,
}

impl Sha256 {
    const PADDING_BUFFER_LENGTH: usize = Self::BLOCK_SIZE + 8;
    const ALGORITHM_NAME: String16<'static> = s16!("SHA256");
    const BLOCK_SIZE: usize = 64;
    const HASH_SIZE: usize = 32;

    const SEED: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    const LOOKUP: [u32; 64] = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4,
        0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE,
        0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F,
        0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC,
        0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
        0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116,
        0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7,
        0xC67178F2,
    ];

    const fn rotate_right(x: u32, n: u8) -> u32 {
        (x >> n) | (x << ((size_of::<u32>() * 8) - n as usize))
    }

    pub fn calculate_double_hash_checksum_for(&mut self, data: &[u8]) -> [u8; 4] {
        let mut hash = self.reset().get_hash_of(data);
        self.reset()
            .feed_bytes(&hash)
            .write_hash_to(&mut hash)
            .reset();

        let mut out_buffer = [0u8; 4];
        out_buffer.copy_from_slice(&hash[..4]);
        out_buffer
    }

    fn process_block_if_full(&mut self) -> &mut Self {
        if self.pending_block_offset != Self::BLOCK_SIZE {
            return self;
        }

        let mut a = self.hash[0];
        let mut b = self.hash[1];
        let mut c = self.hash[2];
        let mut d = self.hash[3];
        let mut e = self.hash[4];
        let mut f = self.hash[5];
        let mut g = self.hash[6];
        let mut h = self.hash[7];
        let mut buffer = [0u32; 64];
        for i in 0..16 {
            let j = i * size_of::<u32>();
            buffer[i] = ((self.block[j + 0] as u32) << 24)
                | ((self.block[j + 1] as u32) << 16)
                | ((self.block[j + 2] as u32) << 8)
                | ((self.block[j + 3] as u32) << 0);
        }

        for i in 16..buffer.len() {
            let temp1 = buffer[i - 2];
            let temp2 = buffer[i - 15];
            buffer[i] =
                (Self::rotate_right(temp1, 17) ^ Self::rotate_right(temp1, 19) ^ (temp1 >> 10))
                    .wrapping_add(
                        Self::rotate_right(temp2, 7) ^ Self::rotate_right(temp2, 18) ^ (temp2 >> 3),
                    )
                    .wrapping_add(buffer[i - 16])
                    .wrapping_add(buffer[i - 7]);
        }

        for i in 0..buffer.len() {
            let temp1 =
                (Self::rotate_right(e, 6) ^ Self::rotate_right(e, 11) ^ Self::rotate_right(e, 25))
                    .wrapping_add((e & f) ^ ((!e) & g))
                    .wrapping_add(Self::LOOKUP[i])
                    .wrapping_add(buffer[i])
                    .wrapping_add(h);

            let temp2 =
                (Self::rotate_right(a, 2) ^ Self::rotate_right(a, 13) ^ Self::rotate_right(a, 22))
                    .wrapping_add((a & b) ^ (a & c) ^ (b & c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.hash[0] = self.hash[0].wrapping_add(a);
        self.hash[1] = self.hash[1].wrapping_add(b);
        self.hash[2] = self.hash[2].wrapping_add(c);
        self.hash[3] = self.hash[3].wrapping_add(d);
        self.hash[4] = self.hash[4].wrapping_add(e);
        self.hash[5] = self.hash[5].wrapping_add(f);
        self.hash[6] = self.hash[6].wrapping_add(g);
        self.hash[7] = self.hash[7].wrapping_add(h);
        self.pending_block_offset = 0;
        self
    }
}

impl Hasher<32, 64> for Sha256 {
    fn algorithm_name() -> String16<'static> {
        Self::ALGORITHM_NAME
    }

    fn is_little_endian() -> bool {
        false
    }

    fn new() -> Self {
        Self {
            hash: Self::SEED.clone(),
            pending_block_offset: 0,
            processed_bits: 0,
            block: [0; 64],
            closed: false,
        }
    }

    fn processed_bits(&self) -> u64 {
        self.processed_bits
    }

    fn write_hash_to(&mut self, buffer: &mut [u8]) -> &mut Self {
        if !self.closed {
            let mut size_temp = self.processed_bits;
            self.feed_byte(0x80);

            let mut block_space = Self::BLOCK_SIZE - self.pending_block_offset;
            if block_space < 8 {
                block_space += Self::BLOCK_SIZE;
            }

            let mut padding_buffer = [0u8; Self::PADDING_BUFFER_LENGTH];
            let padding = &mut padding_buffer[Self::PADDING_BUFFER_LENGTH - block_space..];
            for i in 1..9 {
                padding[block_space - i] = size_temp as u8;
                size_temp >>= 8;
            }

            self.feed_bytes(padding);
            self.closed = true;
        }

        for i in 0..self.hash.len() {
            let offset = i * size_of::<u32>();
            let mut data = self.hash[i];

            for j in 0..size_of::<u32>() {
                buffer[offset + size_of::<u32>() - 1 - j] = data as u8;
                data >>= 8;
            }
        }

        self
    }

    fn feed_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        if self.closed {
            panic!("Tried to add bytes to a closed SHA256 instance; you need to call reset first.");
        }

        if bytes.len() == 0 {
            return self;
        }

        self.processed_bits += bytes.len() as u64 * 8;
        let mut remaining = bytes;
        loop {
            if remaining.len() == 0 {
                break;
            }

            let count = (Self::BLOCK_SIZE - self.pending_block_offset).min(remaining.len());
            self.block[self.pending_block_offset..count + self.pending_block_offset]
                .copy_from_slice(&remaining[..count]);
            self.pending_block_offset += count;
            remaining = &remaining[count..];
            self.process_block_if_full();
        }

        self
    }

    fn feed_byte(&mut self, byte: u8) -> &mut Self {
        if self.closed {
            panic!(
                "Tried to add a byte to a closed SHA256 instance; you need to call reset first."
            );
        }

        self.processed_bits += 8;
        self.block[self.pending_block_offset] = byte;
        self.pending_block_offset += 1;
        self.process_block_if_full()
    }

    fn reset(&mut self) -> &mut Self {
        self.hash.copy_from_slice(&Self::SEED[..]);
        self.pending_block_offset = 0;
        self.processed_bits = 0;
        self.closed = false;
        self.block.fill(0);
        self
    }
}
