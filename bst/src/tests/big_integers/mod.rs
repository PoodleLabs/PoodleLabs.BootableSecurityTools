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

mod big_signed_integers;
mod big_unsigned_integers;

use crate::integers::{BigSigned, BigUnsigned, BITS_PER_DIGIT};
use core::mem::size_of;
use rand::{random, thread_rng, Rng};

fn big_unsigned_to_u128(big_unsigned: &BigUnsigned) -> u128 {
    if big_unsigned.is_zero() {
        return 0;
    }

    if big_unsigned.digit_count() * BITS_PER_DIGIT > 128 {
        panic!("Tried to read a BigUnsigned with more than 128 bits into a u128");
    }

    let mut bytes = [0u8; size_of::<u128>()];
    big_unsigned.copy_be_bytes_to(&mut bytes);
    u128::from_be_bytes(bytes)
}

fn big_signed_to_i128(big_signed: &BigSigned) -> i128 {
    let aggregate = big_unsigned_to_u128(big_signed.borrow_unsigned());
    if aggregate > i128::MAX as u128 {
        panic!("Tried to read a BigSigned into an i128 with a value larger than i128::MAX.")
    }

    let aggregate = aggregate as i128;
    if big_signed.is_negative() {
        -aggregate
    } else {
        aggregate
    }
}

fn i128_to_big_signed(value: i128) -> BigSigned {
    BigSigned::from_unsigned(
        value < 0,
        BigUnsigned::from_be_bytes(&value.unsigned_abs().to_be_bytes()),
    )
}

fn bytes_to_u128(bytes: &[u8]) -> u128 {
    let mut u128_buffer = [0u8; size_of::<u128>()];
    u128_buffer[size_of::<u128>() - bytes.len()..].copy_from_slice(&bytes);
    u128::from_be_bytes(u128_buffer)
}

fn bytes_to_i128(bytes: &[u8]) -> i128 {
    let mut i128_buffer = [0u8; size_of::<u128>()];
    i128_buffer[size_of::<u128>() - bytes.len()..].copy_from_slice(&bytes);
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
    (BigUnsigned::from_be_bytes(&bytes), u128)
}

fn random_big_signed(max_bytes: u8) -> (BigSigned, i128) {
    let i128 = random_byte_length_i128(max_bytes);
    (i128_to_big_signed(i128), i128)
}
