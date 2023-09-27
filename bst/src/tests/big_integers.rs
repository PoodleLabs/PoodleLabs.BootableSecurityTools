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

use crate::integers::BigInteger;
use alloc::vec;
use core::{cmp::Ordering, num::Wrapping};
use rand::{random, thread_rng, Rng};

#[test]
fn equal_big_integers_are_equal() {
    let vbs = [random::<u8>(), random::<u8>(), random::<u8>()];
    let integers = [
        BigInteger::from_be_bytes(&vec![0, 0, vbs[0], vbs[1], vbs[2]]),
        BigInteger::from_be_bytes(&vec![0, 0, vbs[0], vbs[1], vbs[2]]),
        BigInteger::from_be_bytes(&vec![0, vbs[0], vbs[1], vbs[2]]),
        BigInteger::from_be_bytes(&vec![0, vbs[0], vbs[1], vbs[2]]),
        BigInteger::from_be_bytes(&vec![vbs[0], vbs[1], vbs[2]]),
        BigInteger::from_be_bytes(&vec![vbs[0], vbs[1], vbs[2]]),
    ];

    for i in 0..integers.len() {
        for j in 0..integers.len() {
            println!("{}, {}", i, j);
            assert_eq!(integers[i], integers[j]);
            assert_eq!(integers[i].cmp(&integers[j]), Ordering::Equal);
        }
    }
}

#[test]
fn unequal_big_integers_are_unequal() {
    let vbs = [random::<u8>(), random::<u8>(), random::<u8>()];
    let integers = [
        BigInteger::from_be_bytes(&vec![1, 1, vbs[0], vbs[1], vbs[2]]),
        BigInteger::from_be_bytes(&vec![1, vbs[0], vbs[1], vbs[2]]),
        BigInteger::from_be_bytes(&vec![vbs[0], vbs[1], vbs[2]]),
    ];

    for i in 0..integers.len() {
        for j in 0..integers.len() {
            if i == j {
                continue;
            }

            println!("{}, {}", i, j);
            assert_ne!(integers[i], integers[j]);
            assert_ne!(integers[i].cmp(&integers[j]), Ordering::Equal);
        }
    }
}

#[test]
fn big_integer_less_than() {
    assert_eq!(
        BigInteger::from_be_bytes(&[0, 0, 0]).cmp(&BigInteger::from_be_bytes(&[0, 0, 1])),
        Ordering::Less
    );

    assert_eq!(
        BigInteger::from_be_bytes(&[0, 0, 0]).cmp(&BigInteger::from_be_bytes(&[0, 1, 0])),
        Ordering::Less
    );

    assert_eq!(
        BigInteger::from_be_bytes(&[0, 0, 0]).cmp(&BigInteger::from_be_bytes(&[1, 0, 0])),
        Ordering::Less
    );

    assert_eq!(
        BigInteger::from_be_bytes(&[0, 0, 0]).cmp(&BigInteger::from_be_bytes(&[0, 1, 1])),
        Ordering::Less
    );

    assert_eq!(
        BigInteger::from_be_bytes(&[0, 0, 0]).cmp(&BigInteger::from_be_bytes(&[1, 0, 1])),
        Ordering::Less
    );

    assert_eq!(
        BigInteger::from_be_bytes(&[0, 0, 0]).cmp(&BigInteger::from_be_bytes(&[1, 1, 1])),
        Ordering::Less
    );

    assert_eq!(
        BigInteger::from_be_bytes(&[0, 0, 0]).cmp(&BigInteger::from_be_bytes(&[1, 0, 0, 0])),
        Ordering::Less
    );
}

#[test]
fn big_integer_greater_than() {
    assert_eq!(
        BigInteger::from_be_bytes(&[0, 0, 1]).cmp(&BigInteger::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigInteger::from_be_bytes(&[0, 1, 0]).cmp(&BigInteger::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigInteger::from_be_bytes(&[1, 0, 0]).cmp(&BigInteger::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigInteger::from_be_bytes(&[0, 1, 1]).cmp(&BigInteger::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigInteger::from_be_bytes(&[1, 0, 1]).cmp(&BigInteger::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigInteger::from_be_bytes(&[1, 1, 1]).cmp(&BigInteger::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        BigInteger::from_be_bytes(&[1, 0, 0, 0]).cmp(&BigInteger::from_be_bytes(&[0, 0, 0])),
        Ordering::Greater
    );
}

#[test]
fn big_integer_random_addition_test() {
    let mut big_integer = BigInteger::with_capacity(16);
    let mut expected = Wrapping(0u128);
    let mut buffer = [0u8; 16];
    for _ in 0..10000 {
        let v = random::<u8>();
        expected += v as u128;
        big_integer.add(v);

        if big_integer.byte_count() < 16 {
            let zero_count = 16 - big_integer.byte_count();

            big_integer.copy_bytes_to(&mut buffer[zero_count..]);
            buffer[..zero_count].fill(0);
        } else {
            let bytes = big_integer.to_be_bytes();
            let leading = bytes.len() - 16;
            buffer.clone_from_slice(&bytes[leading..]);
        }

        assert_eq!(u128::from_be_bytes(buffer), expected.0);
    }
}

#[test]
fn big_integer_random_multiplication_test() {
    let mut big_integer = BigInteger::with_capacity(16);
    let mut expected = Wrapping(1u128);
    let mut buffer = [0u8; 16];
    big_integer.add(1);
    for _ in 0..10000 {
        let v = non_zero_random_byte();
        big_integer.multiply(v);
        expected *= v as u128;

        if big_integer.byte_count() < 16 {
            let zero_count = 16 - big_integer.byte_count();

            big_integer.copy_bytes_to(&mut buffer[zero_count..]);
            buffer[..zero_count].fill(0);
        } else {
            let bytes = big_integer.to_be_bytes();
            let leading = bytes.len() - 16;
            buffer.clone_from_slice(&bytes[leading..]);
        }

        assert_eq!(u128::from_be_bytes(buffer), expected.0);
    }
}

#[test]
fn big_integer_random_division_test() {
    let mut big_integer = BigInteger::from_be_bytes(&u128::MAX.to_be_bytes());
    let mut expected = Wrapping(u128::MAX);
    let mut buffer = [0u8; 16];

    big_integer.copy_bytes_to(&mut buffer);
    for _ in 0..1024 {
        let v = non_zero_random_byte();
        let v128 = v as u128;

        let expected_remainder = (expected.0 % v128) as u8;
        expected /= v128;

        let remainder = big_integer.divide(v);
        big_integer.copy_bytes_to(&mut buffer);

        assert_eq!(u128::from_be_bytes(buffer), expected.0);
        assert_eq!(remainder.unwrap(), expected_remainder);
        if expected.0 == 0u128 {
            return;
        }
    }
}

#[test]
fn big_integer_random_subtraction_test() {
    let mut big_integer = BigInteger::from_be_bytes(&u128::MAX.to_be_bytes());
    let mut expected = Wrapping(u128::MAX);
    let mut buffer = [0u8; 16];

    big_integer.copy_bytes_to(&mut buffer);
    for _ in 0..10000 {
        let v = non_zero_random_byte();
        big_integer.subtract(v);
        expected -= v as u128;

        big_integer.copy_bytes_to(&mut buffer);
        assert_eq!(u128::from_be_bytes(buffer), expected.0);
    }
}

#[test]
fn big_integer_random_subtraction_wrap_test() {
    let mut big_integer = BigInteger::from_be_bytes(&u128::MAX.to_be_bytes());
    let mut buffer = [0u8; 16];
    big_integer.multiply(0);
    big_integer.add(100);

    big_integer.subtract(99);
    big_integer.copy_bytes_to(&mut buffer);
    assert_eq!(u128::from_be_bytes(buffer), 1u128);

    big_integer.subtract(1);
    big_integer.copy_bytes_to(&mut buffer);
    assert_eq!(u128::from_be_bytes(buffer), 0u128);

    big_integer.subtract(1);
    big_integer.copy_bytes_to(&mut buffer);
    assert_eq!(u128::from_be_bytes(buffer), 0u128);

    big_integer.add(1);
    big_integer.subtract(255);
    big_integer.copy_bytes_to(&mut buffer);
    assert_eq!(u128::from_be_bytes(buffer), 0u128);
}

#[test]
fn big_integer_random_and_test() {
    for _ in 0..10000 {
        let (r1_bytes, r1, r2_bytes, r2) = random_binary_conditional_op_starter_values();
        let mut b1 = BigInteger::from_be_bytes(&r1_bytes);
        let b2 = BigInteger::from_be_bytes(&r2_bytes);
        b1.and(&b2);

        assert_eq!(big_int_to_u128(&b1), r1 & r2);
    }
}

#[test]
fn big_integer_random_xor_test() {
    for _ in 0..10000 {
        let (r1_bytes, r1, r2_bytes, r2) = random_binary_conditional_op_starter_values();
        let mut b1 = BigInteger::from_be_bytes(&r1_bytes);
        let b2 = BigInteger::from_be_bytes(&r2_bytes);
        b1.xor(&b2);

        assert_eq!(big_int_to_u128(&b1), r1 ^ r2);
    }
}

#[test]
fn big_integer_random_or_test() {
    for _ in 0..10000 {
        let (r1_bytes, r1, r2_bytes, r2) = random_binary_conditional_op_starter_values();
        let mut b1 = BigInteger::from_be_bytes(&r1_bytes);
        let b2 = BigInteger::from_be_bytes(&r2_bytes);
        b1.or(&b2);

        assert_eq!(big_int_to_u128(&b1), r1 | r2);
    }
}

fn big_int_to_u128(big_integer: &BigInteger) -> u128 {
    let bytes = big_integer.to_be_bytes();
    let mut u128_buffer = [0u8; 16];
    u128_buffer[16 - bytes.len()..].copy_from_slice(&bytes);
    u128::from_be_bytes(u128_buffer)
}

fn bytes_to_u128(bytes: &[u8]) -> u128 {
    let mut u128_buffer = [0u8; 16];
    u128_buffer[16 - bytes.len()..].copy_from_slice(&bytes);
    u128::from_be_bytes(u128_buffer)
}

fn random_binary_conditional_op_starter_values() -> (Vec<u8>, u128, Vec<u8>, u128) {
    let (r1_bytes, r1) = random_u128();
    let (r2_bytes, r2) = random_u128();
    (r1_bytes, r1, r2_bytes, r2)
}

fn random_u128() -> (Vec<u8>, u128) {
    let bytes: Vec<u8> = (0..thread_rng().gen_range(0..17))
        .into_iter()
        .map(|_| random::<u8>())
        .collect();

    let i = bytes_to_u128(&bytes);
    (bytes, i)
}

fn non_zero_random_byte() -> u8 {
    let mut v = 0u8;
    while v == 0 {
        v = random();
    }

    v
}
