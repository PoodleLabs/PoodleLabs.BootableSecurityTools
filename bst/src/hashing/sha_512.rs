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

pub struct Sha512 {
    hash: [u64; Self::HASH_SIZE / size_of::<u64>()],
    block: [u8; Self::BLOCK_SIZE],
    pending_block_offset: usize,
    processed_bits: u64,
    closed: bool,
}

impl Sha512 {
    const PADDING_BUFFER_LENGTH: usize = Self::BLOCK_SIZE + 16;
    const ALGORITHM_NAME: String16<'static> = s16!("SHA512");
    const BLOCK_SIZE: usize = 128;
    const HASH_SIZE: usize = 64;

    const SEED: [u64; 8] = [
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    ];

    const LOOKUP: [u64; 80] = [
        0x428A2F98D728AE22,
        0x7137449123EF65CD,
        0xB5C0FBCFEC4D3B2F,
        0xE9B5DBA58189DBBC,
        0x3956C25BF348B538,
        0x59F111F1B605D019,
        0x923F82A4AF194F9B,
        0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242,
        0x12835B0145706FBE,
        0x243185BE4EE4B28C,
        0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F,
        0x80DEB1FE3B1696B1,
        0x9BDC06A725C71235,
        0xC19BF174CF692694,
        0xE49B69C19EF14AD2,
        0xEFBE4786384F25E3,
        0x0FC19DC68B8CD5B5,
        0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275,
        0x4A7484AA6EA6E483,
        0x5CB0A9DCBD41FBD4,
        0x76F988DA831153B5,
        0x983E5152EE66DFAB,
        0xA831C66D2DB43210,
        0xB00327C898FB213F,
        0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2,
        0xD5A79147930AA725,
        0x06CA6351E003826F,
        0x142929670A0E6E70,
        0x27B70A8546D22FFC,
        0x2E1B21385C26C926,
        0x4D2C6DFC5AC42AED,
        0x53380D139D95B3DF,
        0x650A73548BAF63DE,
        0x766A0ABB3C77B2A8,
        0x81C2C92E47EDAEE6,
        0x92722C851482353B,
        0xA2BFE8A14CF10364,
        0xA81A664BBC423001,
        0xC24B8B70D0F89791,
        0xC76C51A30654BE30,
        0xD192E819D6EF5218,
        0xD69906245565A910,
        0xF40E35855771202A,
        0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8,
        0x1E376C085141AB53,
        0x2748774CDF8EEB99,
        0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63,
        0x4ED8AA4AE3418ACB,
        0x5B9CCA4F7763E373,
        0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC,
        0x78A5636F43172F60,
        0x84C87814A1F0AB72,
        0x8CC702081A6439EC,
        0x90BEFFFA23631E28,
        0xA4506CEBDE82BDE9,
        0xBEF9A3F7B2C67915,
        0xC67178F2E372532B,
        0xCA273ECEEA26619C,
        0xD186B8C721C0C207,
        0xEADA7DD6CDE0EB1E,
        0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA,
        0x0A637DC5A2C898A6,
        0x113F9804BEF90DAE,
        0x1B710B35131C471B,
        0x28DB77F523047D84,
        0x32CAAB7B40C72493,
        0x3C9EBE0A15C9BEBC,
        0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6,
        0x597F299CFC657E2A,
        0x5FCB6FAB3AD6FAEC,
        0x6C44198C4A475817,
    ];

    const fn rotate_right(x: u64, n: u8) -> u64 {
        (x >> n) | (x << ((size_of::<u64>() * 8) - n as usize))
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
        let mut buffer = [0u64; 80];
        for i in 0..16 {
            let j = i * size_of::<u64>();
            buffer[i] = ((self.block[j + 0] as u64) << 56)
                | ((self.block[j + 1] as u64) << 48)
                | ((self.block[j + 2] as u64) << 40)
                | ((self.block[j + 3] as u64) << 32)
                | ((self.block[j + 4] as u64) << 24)
                | ((self.block[j + 5] as u64) << 16)
                | ((self.block[j + 6] as u64) << 8)
                | ((self.block[j + 7] as u64) << 0);
        }

        for i in 16..buffer.len() {
            let temp1 = buffer[i - 2];
            let temp2 = buffer[i - 15];
            buffer[i] =
                (Self::rotate_right(temp1, 19) ^ Self::rotate_right(temp1, 61) ^ (temp1 >> 6))
                    .wrapping_add(
                        Self::rotate_right(temp2, 1) ^ Self::rotate_right(temp2, 8) ^ (temp2 >> 7),
                    )
                    .wrapping_add(buffer[i - 16])
                    .wrapping_add(buffer[i - 7]);
        }

        for i in 0..buffer.len() {
            let temp1 =
                (Self::rotate_right(e, 14) ^ Self::rotate_right(e, 18) ^ Self::rotate_right(e, 41))
                    .wrapping_add((e & f) ^ ((!e) & g))
                    .wrapping_add(Self::LOOKUP[i])
                    .wrapping_add(buffer[i])
                    .wrapping_add(h);

            let temp2 =
                (Self::rotate_right(a, 28) ^ Self::rotate_right(a, 34) ^ Self::rotate_right(a, 39))
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

impl Hasher<64, 128> for Sha512 {
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
            block: [0; 128],
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
            if block_space < 16 {
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
            let offset = i * size_of::<u64>();
            let mut data = self.hash[i];

            for j in 0..size_of::<u64>() {
                buffer[offset + size_of::<u64>() - 1 - j] = data as u8;
                data >>= 8;
            }
        }

        self
    }

    fn feed_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        if self.closed {
            panic!("Tried to add bytes to a closed SHA512 instance; you need to call reset first.");
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
                "Tried to add a byte to a closed SHA512 instance; you need to call reset first."
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
