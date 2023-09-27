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
use core::{mem::size_of, slice};
use macros::s16;

pub struct RIPEMD160 {
    hash: [u32; Self::HASH_SIZE / size_of::<u32>()],
    block: [u8; Self::BLOCK_SIZE],
    pending_block_offset: usize,
    processed_bits: u64,
    closed: bool,
}

impl RIPEMD160 {
    const ALGORITHM_NAME: String16<'static> = s16!("RIPEMD160");
    const BLOCK_SIZE: usize = 64;
    const HASH_SIZE: usize = 20;

    const SEED: [u32; 5] = [0x67452301, 0xEfCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    const fn rotate_left(x: u32, n: u8) -> u32 {
        (x << n) | (x >> ((size_of::<u32>() * 8) - (n as usize)))
    }

    const fn f0(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    const fn f1(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }

    const fn f2(x: u32, y: u32, z: u32) -> u32 {
        (x | !y) ^ z
    }

    const fn f3(x: u32, y: u32, z: u32) -> u32 {
        (x & z) | (y & !z)
    }

    const fn f4(x: u32, y: u32, z: u32) -> u32 {
        x ^ (y | !z)
    }

    fn r0(a: &mut u32, b: u32, c: &mut u32, d: u32, e: u32, x: u32, s: u8) {
        *a = a.wrapping_add(Self::f0(b, *c, d)).wrapping_add(x);
        *a = Self::rotate_left(*a, s).wrapping_add(e);
        *c = Self::rotate_left(*c, 10);
    }

    fn r1(a: &mut u32, b: u32, c: &mut u32, d: u32, e: u32, x: u32, s: u8) {
        *a = a
            .wrapping_add(Self::f1(b, *c, d))
            .wrapping_add(x)
            .wrapping_add(0x5A827999);
        *a = Self::rotate_left(*a, s).wrapping_add(e);
        *c = Self::rotate_left(*c, 10);
    }

    fn r2(a: &mut u32, b: u32, c: &mut u32, d: u32, e: u32, x: u32, s: u8) {
        *a = a
            .wrapping_add(Self::f2(b, *c, d))
            .wrapping_add(x)
            .wrapping_add(0x6ED9EBA1);
        *a = Self::rotate_left(*a, s).wrapping_add(e);
        *c = Self::rotate_left(*c, 10);
    }

    fn r3(a: &mut u32, b: u32, c: &mut u32, d: u32, e: u32, x: u32, s: u8) {
        *a = a
            .wrapping_add(Self::f3(b, *c, d))
            .wrapping_add(x)
            .wrapping_add(0x8F1BBCDC);
        *a = Self::rotate_left(*a, s).wrapping_add(e);
        *c = Self::rotate_left(*c, 10);
    }

    fn r4(a: &mut u32, b: u32, c: &mut u32, d: u32, e: u32, x: u32, s: u8) {
        *a = a
            .wrapping_add(Self::f4(b, *c, d))
            .wrapping_add(x)
            .wrapping_add(0xA953FD4E);
        *a = Self::rotate_left(*a, s).wrapping_add(e);
        *c = Self::rotate_left(*c, 10);
    }

    fn pr4(a: &mut u32, b: u32, c: &mut u32, d: u32, e: u32, x: u32, s: u8) {
        *a = a.wrapping_add(Self::f0(b, *c, d)).wrapping_add(x);
        *a = Self::rotate_left(*a, s).wrapping_add(e);
        *c = Self::rotate_left(*c, 10);
    }

    fn pr3(a: &mut u32, b: u32, c: &mut u32, d: u32, e: u32, x: u32, s: u8) {
        *a = a
            .wrapping_add(Self::f1(b, *c, d))
            .wrapping_add(x)
            .wrapping_add(0x7A6D76E9);
        *a = Self::rotate_left(*a, s).wrapping_add(e);
        *c = Self::rotate_left(*c, 10);
    }

    fn pr2(a: &mut u32, b: u32, c: &mut u32, d: u32, e: u32, x: u32, s: u8) {
        *a = a
            .wrapping_add(Self::f2(b, *c, d))
            .wrapping_add(x)
            .wrapping_add(0x6D703EF3);
        *a = Self::rotate_left(*a, s).wrapping_add(e);
        *c = Self::rotate_left(*c, 10);
    }

    fn pr1(a: &mut u32, b: u32, c: &mut u32, d: u32, e: u32, x: u32, s: u8) {
        *a = a
            .wrapping_add(Self::f3(b, *c, d))
            .wrapping_add(x)
            .wrapping_add(0x5C4DD124);
        *a = Self::rotate_left(*a, s).wrapping_add(e);
        *c = Self::rotate_left(*c, 10);
    }

    fn pr0(a: &mut u32, b: u32, c: &mut u32, d: u32, e: u32, x: u32, s: u8) {
        *a = a
            .wrapping_add(Self::f4(b, *c, d))
            .wrapping_add(x)
            .wrapping_add(0x50A28BE6);
        *a = Self::rotate_left(*a, s).wrapping_add(e);
        *c = Self::rotate_left(*c, 10);
    }

    fn process_buffer(hash: &mut [u32], buffer: &[u32]) {
        let mut a = hash[0];
        let mut b = hash[1];
        let mut c = hash[2];
        let mut d = hash[3];
        let mut e = hash[4];
        let mut aa = a;
        let mut bb = b;
        let mut cc = c;
        let mut dd = d;
        let mut ee = e;

        Self::r0(&mut a, b, &mut c, d, e, buffer[0], 11);
        Self::r0(&mut e, a, &mut b, c, d, buffer[1], 14);
        Self::r0(&mut d, e, &mut a, b, c, buffer[2], 15);
        Self::r0(&mut c, d, &mut e, a, b, buffer[3], 12);
        Self::r0(&mut b, c, &mut d, e, a, buffer[4], 5);
        Self::r0(&mut a, b, &mut c, d, e, buffer[5], 8);
        Self::r0(&mut e, a, &mut b, c, d, buffer[6], 7);
        Self::r0(&mut d, e, &mut a, b, c, buffer[7], 9);
        Self::r0(&mut c, d, &mut e, a, b, buffer[8], 11);
        Self::r0(&mut b, c, &mut d, e, a, buffer[9], 13);
        Self::r0(&mut a, b, &mut c, d, e, buffer[10], 14);
        Self::r0(&mut e, a, &mut b, c, d, buffer[11], 15);
        Self::r0(&mut d, e, &mut a, b, c, buffer[12], 6);
        Self::r0(&mut c, d, &mut e, a, b, buffer[13], 7);
        Self::r0(&mut b, c, &mut d, e, a, buffer[14], 9);
        Self::r0(&mut a, b, &mut c, d, e, buffer[15], 8);

        Self::r1(&mut e, a, &mut b, c, d, buffer[7], 7);
        Self::r1(&mut d, e, &mut a, b, c, buffer[4], 6);
        Self::r1(&mut c, d, &mut e, a, b, buffer[13], 8);
        Self::r1(&mut b, c, &mut d, e, a, buffer[1], 13);
        Self::r1(&mut a, b, &mut c, d, e, buffer[10], 11);
        Self::r1(&mut e, a, &mut b, c, d, buffer[6], 9);
        Self::r1(&mut d, e, &mut a, b, c, buffer[15], 7);
        Self::r1(&mut c, d, &mut e, a, b, buffer[3], 15);
        Self::r1(&mut b, c, &mut d, e, a, buffer[12], 7);
        Self::r1(&mut a, b, &mut c, d, e, buffer[0], 12);
        Self::r1(&mut e, a, &mut b, c, d, buffer[9], 15);
        Self::r1(&mut d, e, &mut a, b, c, buffer[5], 9);
        Self::r1(&mut c, d, &mut e, a, b, buffer[2], 11);
        Self::r1(&mut b, c, &mut d, e, a, buffer[14], 7);
        Self::r1(&mut a, b, &mut c, d, e, buffer[11], 13);
        Self::r1(&mut e, a, &mut b, c, d, buffer[8], 12);

        Self::r2(&mut d, e, &mut a, b, c, buffer[3], 11);
        Self::r2(&mut c, d, &mut e, a, b, buffer[10], 13);
        Self::r2(&mut b, c, &mut d, e, a, buffer[14], 6);
        Self::r2(&mut a, b, &mut c, d, e, buffer[4], 7);
        Self::r2(&mut e, a, &mut b, c, d, buffer[9], 14);
        Self::r2(&mut d, e, &mut a, b, c, buffer[15], 9);
        Self::r2(&mut c, d, &mut e, a, b, buffer[8], 13);
        Self::r2(&mut b, c, &mut d, e, a, buffer[1], 15);
        Self::r2(&mut a, b, &mut c, d, e, buffer[2], 14);
        Self::r2(&mut e, a, &mut b, c, d, buffer[7], 8);
        Self::r2(&mut d, e, &mut a, b, c, buffer[0], 13);
        Self::r2(&mut c, d, &mut e, a, b, buffer[6], 6);
        Self::r2(&mut b, c, &mut d, e, a, buffer[13], 5);
        Self::r2(&mut a, b, &mut c, d, e, buffer[11], 12);
        Self::r2(&mut e, a, &mut b, c, d, buffer[5], 7);
        Self::r2(&mut d, e, &mut a, b, c, buffer[12], 5);

        Self::r3(&mut c, d, &mut e, a, b, buffer[1], 11);
        Self::r3(&mut b, c, &mut d, e, a, buffer[9], 12);
        Self::r3(&mut a, b, &mut c, d, e, buffer[11], 14);
        Self::r3(&mut e, a, &mut b, c, d, buffer[10], 15);
        Self::r3(&mut d, e, &mut a, b, c, buffer[0], 14);
        Self::r3(&mut c, d, &mut e, a, b, buffer[8], 15);
        Self::r3(&mut b, c, &mut d, e, a, buffer[12], 9);
        Self::r3(&mut a, b, &mut c, d, e, buffer[4], 8);
        Self::r3(&mut e, a, &mut b, c, d, buffer[13], 9);
        Self::r3(&mut d, e, &mut a, b, c, buffer[3], 14);
        Self::r3(&mut c, d, &mut e, a, b, buffer[7], 5);
        Self::r3(&mut b, c, &mut d, e, a, buffer[15], 6);
        Self::r3(&mut a, b, &mut c, d, e, buffer[14], 8);
        Self::r3(&mut e, a, &mut b, c, d, buffer[5], 6);
        Self::r3(&mut d, e, &mut a, b, c, buffer[6], 5);
        Self::r3(&mut c, d, &mut e, a, b, buffer[2], 12);

        Self::r4(&mut b, c, &mut d, e, a, buffer[4], 9);
        Self::r4(&mut a, b, &mut c, d, e, buffer[0], 15);
        Self::r4(&mut e, a, &mut b, c, d, buffer[5], 5);
        Self::r4(&mut d, e, &mut a, b, c, buffer[9], 11);
        Self::r4(&mut c, d, &mut e, a, b, buffer[7], 6);
        Self::r4(&mut b, c, &mut d, e, a, buffer[12], 8);
        Self::r4(&mut a, b, &mut c, d, e, buffer[2], 13);
        Self::r4(&mut e, a, &mut b, c, d, buffer[10], 12);
        Self::r4(&mut d, e, &mut a, b, c, buffer[14], 5);
        Self::r4(&mut c, d, &mut e, a, b, buffer[1], 12);
        Self::r4(&mut b, c, &mut d, e, a, buffer[3], 13);
        Self::r4(&mut a, b, &mut c, d, e, buffer[8], 14);
        Self::r4(&mut e, a, &mut b, c, d, buffer[11], 11);
        Self::r4(&mut d, e, &mut a, b, c, buffer[6], 8);
        Self::r4(&mut c, d, &mut e, a, b, buffer[15], 5);
        Self::r4(&mut b, c, &mut d, e, a, buffer[13], 6);

        Self::pr0(&mut aa, bb, &mut cc, dd, ee, buffer[5], 8);
        Self::pr0(&mut ee, aa, &mut bb, cc, dd, buffer[14], 9);
        Self::pr0(&mut dd, ee, &mut aa, bb, cc, buffer[7], 9);
        Self::pr0(&mut cc, dd, &mut ee, aa, bb, buffer[0], 11);
        Self::pr0(&mut bb, cc, &mut dd, ee, aa, buffer[9], 13);
        Self::pr0(&mut aa, bb, &mut cc, dd, ee, buffer[2], 15);
        Self::pr0(&mut ee, aa, &mut bb, cc, dd, buffer[11], 15);
        Self::pr0(&mut dd, ee, &mut aa, bb, cc, buffer[4], 5);
        Self::pr0(&mut cc, dd, &mut ee, aa, bb, buffer[13], 7);
        Self::pr0(&mut bb, cc, &mut dd, ee, aa, buffer[6], 7);
        Self::pr0(&mut aa, bb, &mut cc, dd, ee, buffer[15], 8);
        Self::pr0(&mut ee, aa, &mut bb, cc, dd, buffer[8], 11);
        Self::pr0(&mut dd, ee, &mut aa, bb, cc, buffer[1], 14);
        Self::pr0(&mut cc, dd, &mut ee, aa, bb, buffer[10], 14);
        Self::pr0(&mut bb, cc, &mut dd, ee, aa, buffer[3], 12);
        Self::pr0(&mut aa, bb, &mut cc, dd, ee, buffer[12], 6);

        Self::pr1(&mut ee, aa, &mut bb, cc, dd, buffer[6], 9);
        Self::pr1(&mut dd, ee, &mut aa, bb, cc, buffer[11], 13);
        Self::pr1(&mut cc, dd, &mut ee, aa, bb, buffer[3], 15);
        Self::pr1(&mut bb, cc, &mut dd, ee, aa, buffer[7], 7);
        Self::pr1(&mut aa, bb, &mut cc, dd, ee, buffer[0], 12);
        Self::pr1(&mut ee, aa, &mut bb, cc, dd, buffer[13], 8);
        Self::pr1(&mut dd, ee, &mut aa, bb, cc, buffer[5], 9);
        Self::pr1(&mut cc, dd, &mut ee, aa, bb, buffer[10], 11);
        Self::pr1(&mut bb, cc, &mut dd, ee, aa, buffer[14], 7);
        Self::pr1(&mut aa, bb, &mut cc, dd, ee, buffer[15], 7);
        Self::pr1(&mut ee, aa, &mut bb, cc, dd, buffer[8], 12);
        Self::pr1(&mut dd, ee, &mut aa, bb, cc, buffer[12], 7);
        Self::pr1(&mut cc, dd, &mut ee, aa, bb, buffer[4], 6);
        Self::pr1(&mut bb, cc, &mut dd, ee, aa, buffer[9], 15);
        Self::pr1(&mut aa, bb, &mut cc, dd, ee, buffer[1], 13);
        Self::pr1(&mut ee, aa, &mut bb, cc, dd, buffer[2], 11);

        Self::pr2(&mut dd, ee, &mut aa, bb, cc, buffer[15], 9);
        Self::pr2(&mut cc, dd, &mut ee, aa, bb, buffer[5], 7);
        Self::pr2(&mut bb, cc, &mut dd, ee, aa, buffer[1], 15);
        Self::pr2(&mut aa, bb, &mut cc, dd, ee, buffer[3], 11);
        Self::pr2(&mut ee, aa, &mut bb, cc, dd, buffer[7], 8);
        Self::pr2(&mut dd, ee, &mut aa, bb, cc, buffer[14], 6);
        Self::pr2(&mut cc, dd, &mut ee, aa, bb, buffer[6], 6);
        Self::pr2(&mut bb, cc, &mut dd, ee, aa, buffer[9], 14);
        Self::pr2(&mut aa, bb, &mut cc, dd, ee, buffer[11], 12);
        Self::pr2(&mut ee, aa, &mut bb, cc, dd, buffer[8], 13);
        Self::pr2(&mut dd, ee, &mut aa, bb, cc, buffer[12], 5);
        Self::pr2(&mut cc, dd, &mut ee, aa, bb, buffer[2], 14);
        Self::pr2(&mut bb, cc, &mut dd, ee, aa, buffer[10], 13);
        Self::pr2(&mut aa, bb, &mut cc, dd, ee, buffer[0], 13);
        Self::pr2(&mut ee, aa, &mut bb, cc, dd, buffer[4], 7);
        Self::pr2(&mut dd, ee, &mut aa, bb, cc, buffer[13], 5);

        Self::pr3(&mut cc, dd, &mut ee, aa, bb, buffer[8], 15);
        Self::pr3(&mut bb, cc, &mut dd, ee, aa, buffer[6], 5);
        Self::pr3(&mut aa, bb, &mut cc, dd, ee, buffer[4], 8);
        Self::pr3(&mut ee, aa, &mut bb, cc, dd, buffer[1], 11);
        Self::pr3(&mut dd, ee, &mut aa, bb, cc, buffer[3], 14);
        Self::pr3(&mut cc, dd, &mut ee, aa, bb, buffer[11], 14);
        Self::pr3(&mut bb, cc, &mut dd, ee, aa, buffer[15], 6);
        Self::pr3(&mut aa, bb, &mut cc, dd, ee, buffer[0], 14);
        Self::pr3(&mut ee, aa, &mut bb, cc, dd, buffer[5], 6);
        Self::pr3(&mut dd, ee, &mut aa, bb, cc, buffer[12], 9);
        Self::pr3(&mut cc, dd, &mut ee, aa, bb, buffer[2], 12);
        Self::pr3(&mut bb, cc, &mut dd, ee, aa, buffer[13], 9);
        Self::pr3(&mut aa, bb, &mut cc, dd, ee, buffer[9], 12);
        Self::pr3(&mut ee, aa, &mut bb, cc, dd, buffer[7], 5);
        Self::pr3(&mut dd, ee, &mut aa, bb, cc, buffer[10], 15);
        Self::pr3(&mut cc, dd, &mut ee, aa, bb, buffer[14], 8);

        Self::pr4(&mut bb, cc, &mut dd, ee, aa, buffer[12], 8);
        Self::pr4(&mut aa, bb, &mut cc, dd, ee, buffer[15], 5);
        Self::pr4(&mut ee, aa, &mut bb, cc, dd, buffer[10], 12);
        Self::pr4(&mut dd, ee, &mut aa, bb, cc, buffer[4], 9);
        Self::pr4(&mut cc, dd, &mut ee, aa, bb, buffer[1], 12);
        Self::pr4(&mut bb, cc, &mut dd, ee, aa, buffer[5], 5);
        Self::pr4(&mut aa, bb, &mut cc, dd, ee, buffer[8], 14);
        Self::pr4(&mut ee, aa, &mut bb, cc, dd, buffer[7], 6);
        Self::pr4(&mut dd, ee, &mut aa, bb, cc, buffer[6], 8);
        Self::pr4(&mut cc, dd, &mut ee, aa, bb, buffer[2], 13);
        Self::pr4(&mut bb, cc, &mut dd, ee, aa, buffer[13], 6);
        Self::pr4(&mut aa, bb, &mut cc, dd, ee, buffer[14], 5);
        Self::pr4(&mut ee, aa, &mut bb, cc, dd, buffer[0], 15);
        Self::pr4(&mut dd, ee, &mut aa, bb, cc, buffer[3], 13);
        Self::pr4(&mut cc, dd, &mut ee, aa, bb, buffer[9], 11);
        Self::pr4(&mut bb, cc, &mut dd, ee, aa, buffer[11], 11);

        dd = dd.wrapping_add(c).wrapping_add(hash[1]);
        hash[1] = hash[2].wrapping_add(d).wrapping_add(ee);
        hash[2] = hash[3].wrapping_add(e).wrapping_add(aa);
        hash[3] = hash[4].wrapping_add(a).wrapping_add(bb);
        hash[4] = hash[0].wrapping_add(b).wrapping_add(cc);
        hash[0] = dd;
    }

    fn process_block_if_full(&mut self) -> &mut Self {
        if self.pending_block_offset != Self::BLOCK_SIZE {
            return self;
        }

        self.pending_block_offset = 0;
        Self::process_buffer(&mut self.hash, unsafe {
            slice::from_raw_parts(
                self.block.as_ptr() as *const u32,
                Self::BLOCK_SIZE / size_of::<u32>(),
            )
        });
        self
    }
}

impl Hasher<20, 64> for RIPEMD160 {
    fn algorithm_name() -> String16<'static> {
        Self::ALGORITHM_NAME
    }

    fn is_little_endian() -> bool {
        true
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

    fn feed_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        if self.closed {
            panic!(
                "Tried to add bytes to a closed RIPEMD160 instance; you need to call reset first."
            );
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

    fn write_hash_to(&mut self, buffer: &mut [u8]) -> &mut Self {
        if !self.closed {
            let processed_bytes = (self.processed_bits / 8) as u32;
            let mut buffer = [0u32; 16];

            for i in 0..(processed_bytes & 63) {
                buffer[(i as usize) >> 2] ^= (self.block[i as usize] as u32) << (8 * (i & 3));
            }

            buffer[((processed_bytes >> 2) & 15) as usize] ^=
                1u32 << ((8 * (processed_bytes & 3)) + 7);

            if (processed_bytes & 63) > 55 {
                Self::process_buffer(&mut self.hash, &buffer);
                buffer.fill(0);
            }

            buffer[15] = processed_bytes >> 29;
            buffer[14] = processed_bytes << 3;
            Self::process_buffer(&mut self.hash, &buffer);
            self.closed = true;
        }

        for i in 0..self.hash.len() {
            let offset = i * size_of::<u32>();
            buffer[offset + 0] = (self.hash[i] >> 0) as u8;
            buffer[offset + 1] = (self.hash[i] >> 8) as u8;
            buffer[offset + 2] = (self.hash[i] >> 16) as u8;
            buffer[offset + 3] = (self.hash[i] >> 24) as u8;
        }

        self
    }

    fn feed_byte(&mut self, byte: u8) -> &mut Self {
        if self.closed {
            panic!(
                "Tried to add a byte to a closed RIPEMD160 instance; you need to call reset first."
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
