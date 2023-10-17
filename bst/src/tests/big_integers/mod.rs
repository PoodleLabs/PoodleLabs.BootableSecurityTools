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

use crate::integers::{BigSigned, BigUnsigned};
use rand::{random, thread_rng, Rng};

mod big_signed_integers;
mod big_unsigned_integers;

fn big_unsigned_to_u128(big_unsigned: &BigUnsigned) -> u128 {
    let bytes = big_unsigned.clone_be_bytes();
    let bytes = match bytes.iter().enumerate().find(|(_, x)| **x != 0) {
        Some((i, _)) => &bytes[i..],
        None => return 0,
    };

    let mut u128_buffer = [0u8; 16];
    u128_buffer[16 - bytes.len()..].copy_from_slice(&bytes);
    u128::from_be_bytes(u128_buffer)
}

fn big_signed_to_i128(big_signed: &BigSigned) -> i128 {
    let bytes = big_signed.clone_be_bytes();
    let bytes = match bytes.iter().enumerate().find(|(_, x)| **x != 0) {
        Some((i, _)) => &bytes[i..],
        None => return 0,
    };

    let mut i128_buffer = [0u8; 16];
    i128_buffer[16 - bytes.len()..].copy_from_slice(&bytes);
    let unsigned = i128::from_be_bytes(i128_buffer);
    if big_signed.is_negative() {
        -unsigned
    } else {
        unsigned
    }
}

fn big_signed_to_u128(big_unsigned: &BigSigned) -> u128 {
    let bytes = big_unsigned.clone_be_bytes();
    let bytes = match bytes.iter().enumerate().find(|(_, x)| **x != 0) {
        Some((i, _)) => &bytes[i..],
        None => return 0,
    };

    let mut u128_buffer = [0u8; 16];
    u128_buffer[16 - bytes.len()..].copy_from_slice(&bytes);
    u128::from_be_bytes(u128_buffer)
}

fn i128_to_big_signed(value: i128) -> BigSigned {
    BigSigned::from_be_bytes(value < 0, &value.unsigned_abs().to_be_bytes())
}

fn bytes_to_u128(bytes: &[u8]) -> u128 {
    let mut u128_buffer = [0u8; 16];
    u128_buffer[16 - bytes.len()..].copy_from_slice(&bytes);
    u128::from_be_bytes(u128_buffer)
}

fn bytes_to_i128(bytes: &[u8]) -> i128 {
    let mut i128_buffer = [0u8; 16];
    i128_buffer[16 - bytes.len()..].copy_from_slice(&bytes);
    i128::from_be_bytes(i128_buffer)
}

fn random_byte_length_u128(max_bytes: u8) -> (Vec<u8>, u128) {
    let bytes: Vec<u8> = (1..thread_rng().gen_range(1..max_bytes + 1))
        .into_iter()
        .map(|_| random::<u8>())
        .collect();

    let i = bytes_to_u128(&bytes);
    (bytes, i)
}

fn random_byte_length_i128(max_bytes: u8) -> i128 {
    let bytes: Vec<u8> = (1..thread_rng().gen_range(1..max_bytes + 1))
        .into_iter()
        .map(|_| random::<u8>())
        .collect();

    let i = bytes_to_i128(&bytes);
    if random::<bool>() {
        -i
    } else {
        i
    }
}

fn add_random_count_leading_zero(vec: &mut Vec<u8>) {
    for _ in 0..thread_rng().gen_range(0..3) {
        vec.insert(0, 0);
    }
}

fn random_big_unsigned(max_bytes: u8) -> (BigUnsigned, u128) {
    let (mut bytes, u128) = random_byte_length_u128(max_bytes);
    add_random_count_leading_zero(&mut bytes);
    (BigUnsigned::from_vec(bytes), u128)
}

fn random_big_signed(max_bytes: u8) -> (BigSigned, i128) {
    let i128 = random_byte_length_i128(max_bytes);
    (i128_to_big_signed(i128), i128)
}
