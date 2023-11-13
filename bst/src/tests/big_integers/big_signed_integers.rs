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

use crate::{
    integers::{BigSigned, BigUnsigned},
    tests::{
        big_integers::{big_signed_to_i128, random_big_signed, random_big_unsigned},
        PARALLELIZED_TEST_THREAD_COUNT,
    },
};
use alloc::vec;
use core::cmp::Ordering;
use rand::random;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

const RANDOM_ITERATIONS: usize = 100000;

#[test]
fn equal_big_signeds_are_equal() {
    let vbs = [random::<u8>(), random::<u8>(), random::<u8>()];
    let integer_sets = [
        [
            from_digits(false, vec![0, 0, vbs[0], vbs[1], vbs[2]]),
            from_digits(false, vec![0, 0, vbs[0], vbs[1], vbs[2]]),
            from_digits(false, vec![0, vbs[0], vbs[1], vbs[2]]),
            from_digits(false, vec![0, vbs[0], vbs[1], vbs[2]]),
            from_digits(false, vec![vbs[0], vbs[1], vbs[2]]),
            from_digits(false, vec![vbs[0], vbs[1], vbs[2]]),
        ],
        [
            from_digits(true, vec![0, 0, vbs[0], vbs[1], vbs[2]]),
            from_digits(true, vec![0, 0, vbs[0], vbs[1], vbs[2]]),
            from_digits(true, vec![0, vbs[0], vbs[1], vbs[2]]),
            from_digits(true, vec![0, vbs[0], vbs[1], vbs[2]]),
            from_digits(true, vec![vbs[0], vbs[1], vbs[2]]),
            from_digits(true, vec![vbs[0], vbs[1], vbs[2]]),
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
        from_digits(true, vec![1, 1, vbs[0], vbs[1], vbs[2]]),
        from_digits(true, vec![1, vbs[0], vbs[1], vbs[2]]),
        from_digits(true, vec![vbs[0], vbs[1], vbs[2]]),
        from_digits(false, vec![1, 1, vbs[0], vbs[1], vbs[2]]),
        from_digits(false, vec![1, vbs[0], vbs[1], vbs[2]]),
        from_digits(false, vec![vbs[0], vbs[1], vbs[2]]),
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
        from_digits(false, vec![0, 0, 0]).cmp(&from_digits(false, vec![0, 0, 1])),
        Ordering::Less
    );

    assert_eq!(
        from_digits(false, vec![0, 0, 0]).cmp(&from_digits(false, vec![0, 1, 0])),
        Ordering::Less
    );

    assert_eq!(
        from_digits(false, vec![0, 0, 0]).cmp(&from_digits(false, vec![1, 0, 0])),
        Ordering::Less
    );

    assert_eq!(
        from_digits(false, vec![0, 0, 0]).cmp(&from_digits(false, vec![0, 1, 1])),
        Ordering::Less
    );

    assert_eq!(
        from_digits(false, vec![0, 0, 0]).cmp(&from_digits(false, vec![1, 0, 1])),
        Ordering::Less
    );

    assert_eq!(
        from_digits(false, vec![0, 0, 0]).cmp(&from_digits(false, vec![1, 1, 1])),
        Ordering::Less
    );

    assert_eq!(
        from_digits(false, vec![0, 0, 0]).cmp(&from_digits(false, vec![1, 0, 0, 0])),
        Ordering::Less
    );

    assert_eq!(
        from_digits(true, vec![0, 0, 1]).cmp(&from_digits(false, vec![0, 0, 1])),
        Ordering::Less
    );

    assert_eq!(
        from_digits(true, vec![0, 1, 0]).cmp(&from_digits(false, vec![0, 1, 0])),
        Ordering::Less
    );

    assert_eq!(
        from_digits(true, vec![1, 0, 0]).cmp(&from_digits(false, vec![1, 0, 0])),
        Ordering::Less
    );
}

#[test]
fn big_signed_greater_than() {
    assert_eq!(
        from_digits(false, vec![0, 0, 1]).cmp(&from_digits(false, vec![0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        from_digits(false, vec![0, 1, 0]).cmp(&from_digits(false, vec![0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        from_digits(false, vec![1, 0, 0]).cmp(&from_digits(false, vec![0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        from_digits(false, vec![0, 1, 1]).cmp(&from_digits(false, vec![0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        from_digits(false, vec![1, 0, 1]).cmp(&from_digits(false, vec![0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        from_digits(false, vec![1, 1, 1]).cmp(&from_digits(false, vec![0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        from_digits(false, vec![1, 0, 0, 0]).cmp(&from_digits(false, vec![0, 0, 0])),
        Ordering::Greater
    );

    assert_eq!(
        from_digits(false, vec![0, 0, 1]).cmp(&from_digits(true, vec![0, 0, 1])),
        Ordering::Greater
    );

    assert_eq!(
        from_digits(false, vec![0, 1, 0]).cmp(&from_digits(true, vec![0, 1, 0])),
        Ordering::Greater
    );

    assert_eq!(
        from_digits(false, vec![1, 0, 0]).cmp(&from_digits(true, vec![1, 0, 0])),
        Ordering::Greater
    );
}

#[test]
fn big_signed_random_subtract() {
    for _ in 0..RANDOM_ITERATIONS {
        let (mut b1, r1) = random_big_signed(16);
        let (b2, r2) = random_big_signed(16);
        b1.subtract_big_signed(&b2);

        let expected_result = r1 - r2;
        assert_eq!(big_signed_to_i128(&b1), expected_result);
        assert_eq!(b1.is_negative(), expected_result < 0);
    }
}

#[test]
fn big_signed_random_multiply() {
    for _ in 0..RANDOM_ITERATIONS {
        let (mut b1, r1) = random_big_signed(8);
        let (b2, r2) = random_big_signed(8);
        b1.multiply_big_signed(&b2);

        let expected_product = r1 * r2;
        assert_eq!(big_signed_to_i128(&b1), expected_product);
        assert_eq!(b1.is_negative(), expected_product < 0);
    }
}

#[test]
fn big_signed_random_divide_by_unsigned_with_signed_modulus() {
    (0..PARALLELIZED_TEST_THREAD_COUNT)
        .into_par_iter()
        .for_each(|i| {
            let iterations = if i == PARALLELIZED_TEST_THREAD_COUNT - 1 {
                RANDOM_ITERATIONS / PARALLELIZED_TEST_THREAD_COUNT
                    + RANDOM_ITERATIONS % PARALLELIZED_TEST_THREAD_COUNT
            } else {
                RANDOM_ITERATIONS / PARALLELIZED_TEST_THREAD_COUNT
            };

            let mut modulus_buffer = BigSigned::with_capacity(16);
            for _ in 0..iterations {
                let (mut b1, r1) = random_big_signed(16);
                let (b2, r2) = random_big_unsigned(15);
                let r2i = r2 as i128;

                let successful_division =
                    b1.divide_big_unsigned_with_signed_modulus(&b2, &mut modulus_buffer);
                if r2 == 0 {
                    assert!(!successful_division);
                } else {
                    assert!(successful_division);
                    let expected_quotient = r1 / r2i;
                    assert_eq!(big_signed_to_i128(&b1), expected_quotient);
                    assert_eq!(b1.is_negative(), expected_quotient < 0);

                    let expected_modulus = ((r1 % r2i) + r2i) % r2i;
                    assert_eq!(big_signed_to_i128(&modulus_buffer), expected_modulus);
                    assert_eq!(modulus_buffer.is_negative(), expected_modulus < 0);
                }
            }
        });
}

fn from_digits(is_negative: bool, digits: Vec<u8>) -> BigSigned {
    BigSigned::from_unsigned(is_negative, BigUnsigned::from_vec(digits))
}
