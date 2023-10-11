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

use crate::integers::BigSigned;
use alloc::vec;
use core::cmp::Ordering;
use rand::{random, thread_rng, Rng};

const RANDOM_ITERATIONS: usize = 100000;

#[test]
fn equal_big_signeds_are_equal() {
    let vbs = [random::<u8>(), random::<u8>(), random::<u8>()];
    let integer_sets = [
        [
            BigSigned::from_be_bytes(false, &vec![0, 0, vbs[0], vbs[1], vbs[2]]),
            BigSigned::from_be_bytes(false, &vec![0, 0, vbs[0], vbs[1], vbs[2]]),
            BigSigned::from_be_bytes(false, &vec![0, vbs[0], vbs[1], vbs[2]]),
            BigSigned::from_be_bytes(false, &vec![0, vbs[0], vbs[1], vbs[2]]),
            BigSigned::from_be_bytes(false, &vec![vbs[0], vbs[1], vbs[2]]),
            BigSigned::from_be_bytes(false, &vec![vbs[0], vbs[1], vbs[2]]),
        ],
        [
            BigSigned::from_be_bytes(true, &vec![0, 0, vbs[0], vbs[1], vbs[2]]),
            BigSigned::from_be_bytes(true, &vec![0, 0, vbs[0], vbs[1], vbs[2]]),
            BigSigned::from_be_bytes(true, &vec![0, vbs[0], vbs[1], vbs[2]]),
            BigSigned::from_be_bytes(true, &vec![0, vbs[0], vbs[1], vbs[2]]),
            BigSigned::from_be_bytes(true, &vec![vbs[0], vbs[1], vbs[2]]),
            BigSigned::from_be_bytes(true, &vec![vbs[0], vbs[1], vbs[2]]),
        ],
    ];

    for i in 0..integer_sets.len() {
        let integer_set = &integer_sets[i];
        for j in 0..integer_set.len() {
            for k in 0..integer_set.len() {
                assert_eq!(integer_set[j], integer_set[k]);
                assert_eq!(integer_set[j].cmp(&integer_set[k]), Ordering::Equal);
            }
        }
    }
}

#[test]
fn unequal_big_signeds_are_unequal() {
    let vbs = [random::<u8>(), random::<u8>(), random::<u8>()];
    let integers = [
        BigSigned::from_be_bytes(true, &vec![1, 1, vbs[0], vbs[1], vbs[2]]),
        BigSigned::from_be_bytes(true, &vec![1, vbs[0], vbs[1], vbs[2]]),
        BigSigned::from_be_bytes(true, &vec![vbs[0], vbs[1], vbs[2]]),
        BigSigned::from_be_bytes(false, &vec![1, 1, vbs[0], vbs[1], vbs[2]]),
        BigSigned::from_be_bytes(false, &vec![1, vbs[0], vbs[1], vbs[2]]),
        BigSigned::from_be_bytes(false, &vec![vbs[0], vbs[1], vbs[2]]),
    ];

    for i in 0..integers.len() {
        for j in 0..integers.len() {
            if i == j {
                continue;
            }

            assert_ne!(integers[i], integers[j]);
            assert_ne!(integers[i].cmp(&integers[j]), Ordering::Equal);
        }
    }
}

#[test]
fn big_signed_less_than() {
    assert_eq!(
        BigSigned::from_be_bytes(false, &[0, 0, 0])
            .cmp(&BigSigned::from_be_bytes(false, &[0, 0, 1])),
        Ordering::Less
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[0, 0, 0])
            .cmp(&BigSigned::from_be_bytes(false, &[0, 1, 0])),
        Ordering::Less
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[0, 0, 0])
            .cmp(&BigSigned::from_be_bytes(false, &[1, 0, 0])),
        Ordering::Less
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[0, 0, 0])
            .cmp(&BigSigned::from_be_bytes(false, &[0, 1, 1])),
        Ordering::Less
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[0, 0, 0])
            .cmp(&BigSigned::from_be_bytes(false, &[1, 0, 1])),
        Ordering::Less
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[0, 0, 0])
            .cmp(&BigSigned::from_be_bytes(false, &[1, 1, 1])),
        Ordering::Less
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[0, 0, 0])
            .cmp(&BigSigned::from_be_bytes(false, &[1, 0, 0, 0])),
        Ordering::Less
    );

    assert_eq!(
        BigSigned::from_be_bytes(true, &[0, 0, 1])
            .cmp(&BigSigned::from_be_bytes(false, &[0, 0, 1])),
        Ordering::Less
    );

    assert_eq!(
        BigSigned::from_be_bytes(true, &[0, 1, 0])
            .cmp(&BigSigned::from_be_bytes(false, &[0, 1, 0])),
        Ordering::Less
    );

    assert_eq!(
        BigSigned::from_be_bytes(true, &[1, 0, 0])
            .cmp(&BigSigned::from_be_bytes(false, &[1, 0, 0])),
        Ordering::Less
    );
}

#[test]
fn big_signed_greater_than() {
    assert_eq!(
        BigSigned::from_be_bytes(false, &[0, 0, 1])
            .cmp(&BigSigned::from_be_bytes(false, &[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[0, 1, 0])
            .cmp(&BigSigned::from_be_bytes(false, &[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[1, 0, 0])
            .cmp(&BigSigned::from_be_bytes(false, &[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[0, 1, 1])
            .cmp(&BigSigned::from_be_bytes(false, &[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[1, 0, 1])
            .cmp(&BigSigned::from_be_bytes(false, &[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[1, 1, 1])
            .cmp(&BigSigned::from_be_bytes(false, &[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[1, 0, 0, 0])
            .cmp(&BigSigned::from_be_bytes(false, &[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[0, 0, 1])
            .cmp(&BigSigned::from_be_bytes(true, &[0, 0, 1])),
        Ordering::Greater
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[0, 1, 0])
            .cmp(&BigSigned::from_be_bytes(true, &[0, 1, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigSigned::from_be_bytes(false, &[1, 0, 0])
            .cmp(&BigSigned::from_be_bytes(true, &[1, 0, 0])),
        Ordering::Greater
    );
}

#[test]
fn big_signed_random_and_test() {
    for _ in 0..RANDOM_ITERATIONS {
        let (mut b1, r1, b2, r2) = random_starter_values(16);
        println!("ORD:{:?};{}", b1.clone_be_bytes(), r1);
        println!("ORR:{:?};{}", b2.clone_be_bytes(), r2);
        b1.and_big_signed(&b2);

        assert_eq!(big_int_to_u128(&b1), r1.unsigned_abs() & r2.unsigned_abs());
        assert_eq!(b1.is_negative(), (r1 < 0) & (r2 < 0))
    }
}

#[test]
fn big_signed_random_xor_test() {
    for _ in 0..RANDOM_ITERATIONS {
        let (mut b1, r1, b2, r2) = random_starter_values(16);
        println!("ORD:{:?};{}", b1.clone_be_bytes(), r1);
        println!("ORR:{:?};{}", b2.clone_be_bytes(), r2);
        b1.xor_big_signed(&b2);

        assert_eq!(big_int_to_u128(&b1), r1.unsigned_abs() ^ r2.unsigned_abs());
        assert_eq!(b1.is_negative(), (r1 < 0) ^ (r2 < 0))
    }
}

#[test]
fn big_signed_random_or_test() {
    for _ in 0..RANDOM_ITERATIONS {
        let (mut b1, r1, b2, r2) = random_starter_values(16);
        println!("ORD:{:?};{}", b1.clone_be_bytes(), r1);
        println!("ORR:{:?};{}", b2.clone_be_bytes(), r2);
        b1.or_big_signed(&b2);

        assert_eq!(big_int_to_u128(&b1), r1.unsigned_abs() | r2.unsigned_abs());
        assert_eq!(b1.is_negative(), (r1 < 0) | (r2 < 0))
    }
}

#[test]
fn big_signed_random_add() {
    for _ in 0..RANDOM_ITERATIONS {
        let (mut b1, r1, b2, r2) = random_starter_values(14);
        println!("AUG:{:?};{}", b1.clone_be_bytes(), r1);
        println!("ADD:{:?};{}", b2.clone_be_bytes(), r2);
        b1.add_big_signed(&b2);

        assert_eq!(big_int_to_i128(&b1), r1 + r2);
    }
}

#[test]
fn big_signed_random_subtract() {
    for _ in 0..RANDOM_ITERATIONS {
        let (mut b1, r1, b2, r2) = random_starter_values(16);
        println!("M:{:?};{}", b1.clone_be_bytes(), r1);
        println!("S:{:?};{}", b2.clone_be_bytes(), r2);
        b1.subtract_big_signed(&b2);

        assert_eq!(big_int_to_i128(&b1), r1 - r2);
    }
}

#[test]
fn big_signed_random_multiply() {
    for _ in 0..RANDOM_ITERATIONS {
        let (mut b1, r1, b2, r2) = random_starter_values(8);
        println!("MPD:{:?};{}", b1.clone_be_bytes(), r1);
        println!("MPR:{:?};{}", b2.clone_be_bytes(), r2);
        b1.multiply_big_signed(&b2);

        assert_eq!(big_int_to_i128(&b1), r1 * r2);
    }
}

#[test]
fn big_signed_random_difference() {
    for _ in 0..RANDOM_ITERATIONS {
        let (mut b1, r1, b2, r2) = random_starter_values(16);
        println!("A:{:?};{}", b1.clone_be_bytes(), r1);
        println!("B:{:?};{}", b2.clone_be_bytes(), r2);
        b1.difference_big_signed(&b2);

        assert_eq!(big_int_to_u128(&b1), r1.abs_diff(r2));
    }
}

fn big_int_to_i128(big_signed: &BigSigned) -> i128 {
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

fn big_int_to_u128(big_unsigned: &BigSigned) -> u128 {
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

fn bytes_to_i128(bytes: &[u8]) -> i128 {
    let mut i128_buffer = [0u8; 16];
    i128_buffer[16 - bytes.len()..].copy_from_slice(&bytes);
    i128::from_be_bytes(i128_buffer)
}

fn random_starter_values(max_bytes: u8) -> (BigSigned, i128, BigSigned, i128) {
    let r1 = random_byte_length_i128(max_bytes);
    let r2 = random_byte_length_i128(max_bytes);
    (i128_to_big_signed(r1), r1, i128_to_big_signed(r2), r2)
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
