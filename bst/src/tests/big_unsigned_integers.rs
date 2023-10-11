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

use crate::integers::BigUnsigned;
use alloc::vec;
use core::cmp::Ordering;
use rand::{random, thread_rng, Rng};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

const RANDOM_ITERATIONS: usize = 100000;

#[test]
fn equal_big_unsigneds_are_equal() {
    let vbs = [random::<u8>(), random::<u8>(), random::<u8>()];
    let integers = [
        BigUnsigned::from_be_bytes(&vec![0, 0, vbs[0], vbs[1], vbs[2]]),
        BigUnsigned::from_be_bytes(&vec![0, 0, vbs[0], vbs[1], vbs[2]]),
        BigUnsigned::from_be_bytes(&vec![0, vbs[0], vbs[1], vbs[2]]),
        BigUnsigned::from_be_bytes(&vec![0, vbs[0], vbs[1], vbs[2]]),
        BigUnsigned::from_be_bytes(&vec![vbs[0], vbs[1], vbs[2]]),
        BigUnsigned::from_be_bytes(&vec![vbs[0], vbs[1], vbs[2]]),
    ];

    for i in 0..integers.len() {
        for j in 0..integers.len() {
            // println!("{}, {}", i, j);
            assert_eq!(integers[i], integers[j]);
            assert_eq!(integers[i].cmp(&integers[j]), Ordering::Equal);
        }
    }
}

#[test]
fn unequal_big_unsigneds_are_unequal() {
    let vbs = [random::<u8>(), random::<u8>(), random::<u8>()];
    let integers = [
        BigUnsigned::from_be_bytes(&vec![1, 1, vbs[0], vbs[1], vbs[2]]),
        BigUnsigned::from_be_bytes(&vec![1, vbs[0], vbs[1], vbs[2]]),
        BigUnsigned::from_be_bytes(&vec![vbs[0], vbs[1], vbs[2]]),
    ];

    for i in 0..integers.len() {
        for j in 0..integers.len() {
            if i == j {
                continue;
            }

            // println!("{}, {}", i, j);
            assert_ne!(integers[i], integers[j]);
            assert_ne!(integers[i].cmp(&integers[j]), Ordering::Equal);
        }
    }
}

#[test]
fn big_unsigned_less_than() {
    assert_eq!(
        BigUnsigned::from_be_bytes(&[0, 0, 0]).cmp(&BigUnsigned::from_be_bytes(&[0, 0, 1])),
        Ordering::Less
    );

    assert_eq!(
        BigUnsigned::from_be_bytes(&[0, 0, 0]).cmp(&BigUnsigned::from_be_bytes(&[0, 1, 0])),
        Ordering::Less
    );

    assert_eq!(
        BigUnsigned::from_be_bytes(&[0, 0, 0]).cmp(&BigUnsigned::from_be_bytes(&[1, 0, 0])),
        Ordering::Less
    );

    assert_eq!(
        BigUnsigned::from_be_bytes(&[0, 0, 0]).cmp(&BigUnsigned::from_be_bytes(&[0, 1, 1])),
        Ordering::Less
    );

    assert_eq!(
        BigUnsigned::from_be_bytes(&[0, 0, 0]).cmp(&BigUnsigned::from_be_bytes(&[1, 0, 1])),
        Ordering::Less
    );

    assert_eq!(
        BigUnsigned::from_be_bytes(&[0, 0, 0]).cmp(&BigUnsigned::from_be_bytes(&[1, 1, 1])),
        Ordering::Less
    );

    assert_eq!(
        BigUnsigned::from_be_bytes(&[0, 0, 0]).cmp(&BigUnsigned::from_be_bytes(&[1, 0, 0, 0])),
        Ordering::Less
    );
}

#[test]
fn big_unsigned_greater_than() {
    assert_eq!(
        BigUnsigned::from_be_bytes(&[0, 0, 1]).cmp(&BigUnsigned::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigUnsigned::from_be_bytes(&[0, 1, 0]).cmp(&BigUnsigned::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigUnsigned::from_be_bytes(&[1, 0, 0]).cmp(&BigUnsigned::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigUnsigned::from_be_bytes(&[0, 1, 1]).cmp(&BigUnsigned::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigUnsigned::from_be_bytes(&[1, 0, 1]).cmp(&BigUnsigned::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigUnsigned::from_be_bytes(&[1, 1, 1]).cmp(&BigUnsigned::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigUnsigned::from_be_bytes(&[1, 0, 0, 0]).cmp(&BigUnsigned::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );
}

#[test]
fn big_unsigned_random_and_test() {
    for _ in 0..RANDOM_ITERATIONS {
        let (r1_bytes, r1, r2_bytes, r2) = random_starter_values(16);
        let mut b1 = BigUnsigned::from_be_bytes(&r1_bytes);
        let b2 = BigUnsigned::from_be_bytes(&r2_bytes);
        println!("ORD:{:?};{}", b1.clone_be_bytes(), r1);
        println!("ORR:{:?};{}", b2.clone_be_bytes(), r2);
        b1.and_big_unsigned(&b2);

        assert_eq!(big_int_to_u128(&b1), r1 & r2);
    }
}

#[test]
fn big_unsigned_random_xor_test() {
    for _ in 0..RANDOM_ITERATIONS {
        let (r1_bytes, r1, r2_bytes, r2) = random_starter_values(16);
        let mut b1 = BigUnsigned::from_be_bytes(&r1_bytes);
        let b2 = BigUnsigned::from_be_bytes(&r2_bytes);
        println!("ORD:{:?};{}", b1.clone_be_bytes(), r1);
        println!("ORR:{:?};{}", b2.clone_be_bytes(), r2);
        b1.xor_big_unsigned(&b2);

        assert_eq!(big_int_to_u128(&b1), r1 ^ r2);
    }
}

#[test]
fn big_unsigned_random_or_test() {
    for _ in 0..RANDOM_ITERATIONS {
        let (r1_bytes, r1, r2_bytes, r2) = random_starter_values(16);
        let mut b1 = BigUnsigned::from_be_bytes(&r1_bytes);
        let b2 = BigUnsigned::from_be_bytes(&r2_bytes);
        println!("ORD:{:?};{}", b1.clone_be_bytes(), r1);
        println!("ORR:{:?};{}", b2.clone_be_bytes(), r2);
        b1.or_big_unsigned(&b2);

        assert_eq!(big_int_to_u128(&b1), r1 | r2);
    }
}

#[test]
fn big_unsigned_random_add() {
    for _ in 0..RANDOM_ITERATIONS {
        let (mut r1_bytes, mut r1, mut r2_bytes, mut r2) = random_starter_values(16);
        add_random_count_leading_zero(&mut r1_bytes);
        add_random_count_leading_zero(&mut r2_bytes);

        let mut b1 = BigUnsigned::from_be_bytes(&r1_bytes);
        let mut b2 = BigUnsigned::from_be_bytes(&r2_bytes);
        const MAX :u128 = 0b10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;
        if r1 >= MAX {
            r1 /= 2;
            let mut r = 0u8;
            b1.divide_u8_with_remainder(2, &mut r);
        }

        if r2 >= MAX {
            r2 /= 2;
            let mut r = 0u8;
            b2.divide_u8_with_remainder(2, &mut r);
        }

        println!("AUG:{:?};{}", b1.clone_be_bytes(), r1);
        println!("ADD:{:?};{}", b2.clone_be_bytes(), r2);
        b1.add_big_unsigned(&b2);

        assert_eq!(big_int_to_u128(&b1), r1 + r2);
    }
}

#[test]
fn big_unsigned_random_subtract() {
    for _ in 0..RANDOM_ITERATIONS {
        let (mut r1_bytes, r1, mut r2_bytes, r2) = random_starter_values(16);
        add_random_count_leading_zero(&mut r1_bytes);
        add_random_count_leading_zero(&mut r2_bytes);

        let mut b1 = BigUnsigned::from_be_bytes(&r1_bytes);
        let b2 = BigUnsigned::from_be_bytes(&r2_bytes);
        println!("M:{:?};{}", b1.clone_be_bytes(), r1);
        println!("S:{:?};{}", b2.clone_be_bytes(), r2);
        b1.subtract_big_unsigned(&b2);

        assert_eq!(big_int_to_u128(&b1), if r1 > r2 { r1 - r2 } else { 0 });
    }
}

#[test]
fn big_unsigned_random_multiply() {
    for _ in 0..RANDOM_ITERATIONS {
        let (mut r1_bytes, r1, mut r2_bytes, r2) = random_starter_values(8);
        add_random_count_leading_zero(&mut r1_bytes);
        add_random_count_leading_zero(&mut r2_bytes);

        let mut b1 = BigUnsigned::from_be_bytes(&r1_bytes);
        let b2 = BigUnsigned::from_be_bytes(&r2_bytes);
        println!("MPD:{:?};{}", b1.clone_be_bytes(), r1);
        println!("MPR:{:?};{}", b2.clone_be_bytes(), r2);
        b1.multiply_big_unsigned(&b2);

        assert_eq!(big_int_to_u128(&b1), r1 * r2);
    }
}

#[test]
fn big_unsigned_edge_case_divide() {
    let mut remainder_buffer = BigUnsigned::with_capacity(16);

    let mut b1 = BigUnsigned::from_be_bytes(&[53, 224, 51, 154, 252]);
    let b2 = BigUnsigned::from_be_bytes(&[53, 224]);
    assert!(b1.divide_big_unsigned_with_remainder(&b2, &mut remainder_buffer));

    assert_eq!(b1, BigUnsigned::from_be_bytes(&[1, 0, 0, 245]));
    assert_eq!(remainder_buffer, BigUnsigned::from_be_bytes(&[11, 156]));

    let mut b1 = BigUnsigned::from_be_bytes(&[136, 105, 0, 123, 4, 215]);
    let b2 = BigUnsigned::from_be_bytes(&[136, 105]);
    assert!(b1.divide_big_unsigned_with_remainder(&b2, &mut remainder_buffer));

    assert_eq!(
        b1,
        BigUnsigned::from_be_bytes(&[0x1, 0x00, 0x00, 0x00, 0xE6])
    );
    assert_eq!(remainder_buffer, BigUnsigned::from_be_bytes(&[0x76, 0x81]));

    let mut b1 = BigUnsigned::from_be_bytes(&[96, 46, 249, 138, 0, 164, 186]);
    let b2 = BigUnsigned::from_be_bytes(&[85, 117]);
    assert!(b1.divide_big_unsigned_with_remainder(&b2, &mut remainder_buffer));

    assert_eq!(
        b1,
        BigUnsigned::from_be_bytes(&[0x01, 0x20, 0x22, 0x00, 0x00, 0x01])
    );
    assert_eq!(remainder_buffer, BigUnsigned::from_be_bytes(&[0x4F, 0x45]));

    let mut b1 = BigUnsigned::from_be_bytes(&[209, 168, 158, 45]);
    let b2 = BigUnsigned::from_be_bytes(&[209, 97, 34]);
    assert!(b1.divide_big_unsigned_with_remainder(&b2, &mut remainder_buffer));

    assert_eq!(b1, BigUnsigned::from_be_bytes(&[0x01, 0x00]));
    assert_eq!(
        remainder_buffer,
        BigUnsigned::from_be_bytes(&[0x47, 0x7C, 0x2D])
    );

    let mut b1 = BigUnsigned::from_be_bytes(&[47, 19, 124, 18, 12]);
    let b2 = BigUnsigned::from_be_bytes(&[4, 250]);
    assert!(b1.divide_big_unsigned_with_remainder(&b2, &mut remainder_buffer));

    assert_eq!(b1, BigUnsigned::from_be_bytes(&[0x09, 0x75, 0xA5, 0xFE]));
    assert_eq!(remainder_buffer, BigUnsigned::from_be_bytes(&[0]));

    let mut b1 = BigUnsigned::from_be_bytes(&[32, 11, 158, 185, 81, 0]);
    let b2 = BigUnsigned::from_be_bytes(&[26, 233]);
    assert!(b1.divide_big_unsigned_with_remainder(&b2, &mut remainder_buffer));

    assert_eq!(
        b1,
        BigUnsigned::from_be_bytes(&[0x01, 0x30, 0xDA, 0x29, 0x00])
    );
    assert_eq!(remainder_buffer, BigUnsigned::from_be_bytes(&[0]));
}

#[test]
fn big_unsigned_random_divide() {
    let parallel_threads = rayon::max_num_threads();
    (0..parallel_threads).into_par_iter().for_each(|i| {
        let iterations = if i == parallel_threads - 1 {
            RANDOM_ITERATIONS / parallel_threads + RANDOM_ITERATIONS % parallel_threads
        } else {
            RANDOM_ITERATIONS / parallel_threads
        };

        let mut remainder_buffer = BigUnsigned::with_capacity(16);
        for _ in 0..iterations {
            let (mut r1_bytes, r1, mut r2_bytes, r2) = random_starter_values(8);
            add_random_count_leading_zero(&mut r1_bytes);
            add_random_count_leading_zero(&mut r2_bytes);

            let mut b1 = BigUnsigned::from_be_bytes(&r1_bytes);
            let b2 = BigUnsigned::from_be_bytes(&r2_bytes);
            println!("DND:{:?};{}", b1.clone_be_bytes(), r1);
            println!("DSR:{:?};{}", b2.clone_be_bytes(), r2);

            let successful_division =
                b1.divide_big_unsigned_with_remainder(&b2, &mut remainder_buffer);

            if r2 == 0 {
                assert!(!successful_division);
            } else {
                assert!(successful_division);
                assert_eq!(big_int_to_u128(&b1), r1 / r2);
                assert_eq!(big_int_to_u128(&remainder_buffer), r1 % r2);
            }
        }
    });
}

#[test]
fn big_unsigned_random_difference() {
    for _ in 0..RANDOM_ITERATIONS {
        let (mut r1_bytes, r1, mut r2_bytes, r2) = random_starter_values(16);
        add_random_count_leading_zero(&mut r1_bytes);
        add_random_count_leading_zero(&mut r2_bytes);

        let mut b1 = BigUnsigned::from_be_bytes(&r1_bytes);
        let b2 = BigUnsigned::from_be_bytes(&r2_bytes);
        println!("A:{:?};{}", b1.clone_be_bytes(), r1);
        println!("B:{:?};{}", b2.clone_be_bytes(), r2);
        b1.difference_big_unsigned(&b2);

        assert_eq!(big_int_to_u128(&b1), r1.abs_diff(r2));
    }
}

fn big_int_to_u128(big_unsigned: &BigUnsigned) -> u128 {
    let bytes = big_unsigned.clone_be_bytes();
    let bytes = match bytes.iter().enumerate().find(|(_, x)| **x != 0) {
        Some((i, _)) => &bytes[i..],
        None => return 0,
    };

    let mut u128_buffer = [0u8; 16];
    u128_buffer[16 - bytes.len()..].copy_from_slice(&bytes);
    u128::from_be_bytes(u128_buffer)
}

fn bytes_to_u128(bytes: &[u8]) -> u128 {
    let mut u128_buffer = [0u8; 16];
    u128_buffer[16 - bytes.len()..].copy_from_slice(&bytes);
    u128::from_be_bytes(u128_buffer)
}

fn random_starter_values(max_bytes: u8) -> (Vec<u8>, u128, Vec<u8>, u128) {
    let (r1_bytes, r1) = random_byte_length_u128(max_bytes);
    let (r2_bytes, r2) = random_byte_length_u128(max_bytes);
    (r1_bytes, r1, r2_bytes, r2)
}

fn random_byte_length_u128(max_bytes: u8) -> (Vec<u8>, u128) {
    let bytes: Vec<u8> = (1..thread_rng().gen_range(1..max_bytes + 1))
        .into_iter()
        .map(|_| random::<u8>())
        .collect();

    let i = bytes_to_u128(&bytes);
    (bytes, i)
}

fn add_random_count_leading_zero(vec: &mut Vec<u8>) {
    for _ in 0..thread_rng().gen_range(0..3) {
        vec.insert(0, 0);
    }
}
