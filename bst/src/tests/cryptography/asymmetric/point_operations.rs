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
    cryptography::asymmetric::ecc::{EccPoint, EllipticCurvePointAdditionContext},
    global_runtime_immutable::GlobalRuntimeImmutable,
    integers::{BigSigned, BigUnsigned},
};

static mut P1: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| BigUnsigned::from_be_bytes(&2551u16.to_be_bytes()));

static mut A1: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| BigUnsigned::from_be_bytes(&5u16.to_be_bytes()));
// B1 = 1326

static mut P2: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| BigUnsigned::from_be_bytes(&97u16.to_be_bytes()));

static mut A2: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| BigUnsigned::from_be_bytes(&2u16.to_be_bytes()));
// B2 = 3

#[test]
fn point_addition_1() {
    let mut context = point_addition_context_1();

    let p1 = point(22, 2321);
    let p2 = point(605, 851);
    let p3 = point(1777, 1229);
    let p4 = point(2444, 1207);
    let p5 = point(993, 1231);

    // Infinity
    let inf = EccPoint::infinity(4);
    let mut p = inf.clone();

    // Inf + Inf = Inf
    p = add(p, &inf, &inf, &mut context);
    assert_eq!(p, inf);

    // Inf + P = P
    p = add(p, &inf, &p1, &mut context);
    assert_eq!(p, p1);

    p = add(p, &inf, &p2, &mut context);
    assert_eq!(p, p2);

    p = add(p, &inf, &p3, &mut context);
    assert_eq!(p, p3);

    p = add(p, &inf, &p4, &mut context);
    assert_eq!(p, p4);

    p = add(p, &inf, &p5, &mut context);
    assert_eq!(p, p5);

    // P + Inf = P
    p = add(p, &p1, &inf, &mut context);
    assert_eq!(p, p1);

    p = add(p, &p2, &inf, &mut context);
    assert_eq!(p, p2);

    p = add(p, &p3, &inf, &mut context);
    assert_eq!(p, p3);

    p = add(p, &p4, &inf, &mut context);
    assert_eq!(p, p4);

    p = add(p, &p5, &inf, &mut context);
    assert_eq!(p, p5);

    // P + P = Double
    let mut e = inf.clone();

    e = double(e, &p1, &mut context);
    p = add(p, &p1, &p1, &mut context);
    assert_eq!(p, e);

    e = double(e, &p2, &mut context);
    p = add(p, &p2, &p2, &mut context);
    assert_eq!(p, e);

    e = double(e, &p3, &mut context);
    p = add(p, &p3, &p3, &mut context);
    assert_eq!(p, e);

    e = double(e, &p4, &mut context);
    p = add(p, &p4, &p4, &mut context);
    assert_eq!(p, e);

    e = double(e, &p5, &mut context);
    p = add(p, &p5, &p5, &mut context);
    assert_eq!(p, e);

    ////////////
    // P1 + Q //
    ////////////
    // (22, 2321) + (605, 851) = (1777, 1229)
    p = add(p, &p1, &p2, &mut context);
    assert_eq!(p, point(1777, 1229));

    // (22, 2321) + (1777, 1229) = (993, 1231)
    p = add(p, &p1, &p3, &mut context);
    assert_eq!(p, point(993, 1231));

    // (22, 2321) + (2444, 1207) = (1070, 929)
    p = add(p, &p1, &p4, &mut context);
    assert_eq!(p, point(1070, 929));

    // (22, 2321) + (993, 1231) = (2444, 1207)
    p = add(p, &p1, &p5, &mut context);
    assert_eq!(p, point(2444, 1207));

    ////////////
    // P2 + Q //
    ////////////
    // (605, 851) + (22, 2321) = (1777, 1229)
    p = add(p, &p2, &p1, &mut context);
    assert_eq!(p, point(1777, 1229));

    // (605, 851) + (1777, 1229) = (2444, 1207)
    p = add(p, &p2, &p3, &mut context);
    assert_eq!(p, point(2444, 1207));

    // (605, 851) + (2444, 1207) = (140, 192)
    p = add(p, &p2, &p4, &mut context);
    assert_eq!(p, point(140, 192));

    // (605, 851) + (993, 1231) = (1070, 929)
    p = add(p, &p2, &p5, &mut context);
    assert_eq!(p, point(1070, 929));

    ////////////
    // P3 + Q //
    ////////////
    // (1777, 1229) + (22, 2321) = (993, 1231)
    p = add(p, &p3, &p1, &mut context);
    assert_eq!(p, point(993, 1231));

    // (1777, 1229) + (605, 851) = (2444, 1207)
    p = add(p, &p3, &p2, &mut context);
    assert_eq!(p, point(2444, 1207));

    // (1777, 1229) + (2444, 1207) = (130, 2438)
    p = add(p, &p3, &p4, &mut context);
    assert_eq!(p, point(130, 2438));

    // (1777, 1229) + (993, 1231) = (140, 192)
    p = add(p, &p3, &p5, &mut context);
    assert_eq!(p, point(140, 192));

    ////////////
    // P4 + Q //
    ////////////
    // (2444, 1207) + (22, 2321) = (1070, 929)
    p = add(p, &p4, &p1, &mut context);
    assert_eq!(p, point(1070, 929));

    // (2444, 1207) + (605, 851) = (140, 192)
    p = add(p, &p4, &p2, &mut context);
    assert_eq!(p, point(140, 192));

    // (2444, 1207) + (1777, 1229) = (130, 2438)
    p = add(p, &p4, &p3, &mut context);
    assert_eq!(p, point(130, 2438));

    // (2444, 1207) + (993, 1231) = (1851, 587)
    p = add(p, &p4, &p5, &mut context);
    assert_eq!(p, point(1851, 587));

    ////////////
    // P5 + Q //
    ////////////
    // (993, 1231) + (22, 2321) = (2444, 1207)
    p = add(p, &p5, &p1, &mut context);
    assert_eq!(p, point(2444, 1207));

    // (993, 1231) + (605, 851) = (1070, 929)
    p = add(p, &p5, &p2, &mut context);
    assert_eq!(p, point(1070, 929));

    // (993, 1231) + (1777, 1229) = (140, 192)
    p = add(p, &p5, &p3, &mut context);
    assert_eq!(p, point(140, 192));

    // (993, 1231) + (2444, 1207) = (1851, 587)
    p = add(p, &p5, &p4, &mut context);
    assert_eq!(p, point(1851, 587));
}

#[test]
fn point_addition_2() {
    let mut context = point_addition_context_2();

    let p1 = point(17, 10);
    let p2 = point(95, 31);
    let p3 = point(22, 5);
    let p4 = point(39, 6);
    let p5 = point(56, 8);

    // Infinity
    let inf = EccPoint::infinity(2);
    let mut p = inf.clone();

    // Inf + Inf = Inf
    p = add(p, &inf, &inf, &mut context);
    assert_eq!(p, inf);

    // Inf + P = P
    p = add(p, &inf, &p1, &mut context);
    assert_eq!(p, p1);

    p = add(p, &inf, &p2, &mut context);
    assert_eq!(p, p2);

    p = add(p, &inf, &p3, &mut context);
    assert_eq!(p, p3);

    p = add(p, &inf, &p4, &mut context);
    assert_eq!(p, p4);

    p = add(p, &inf, &p5, &mut context);
    assert_eq!(p, p5);

    // P + Inf = P
    p = add(p, &p1, &inf, &mut context);
    assert_eq!(p, p1);

    p = add(p, &p2, &inf, &mut context);
    assert_eq!(p, p2);

    p = add(p, &p3, &inf, &mut context);
    assert_eq!(p, p3);

    p = add(p, &p4, &inf, &mut context);
    assert_eq!(p, p4);

    p = add(p, &p5, &inf, &mut context);
    assert_eq!(p, p5);

    // P + P = Double
    let mut e = inf.clone();

    e = double(e, &p1, &mut context);
    p = add(p, &p1, &p1, &mut context);
    assert_eq!(p, e);

    e = double(e, &p2, &mut context);
    p = add(p, &p2, &p2, &mut context);
    assert_eq!(p, e);

    e = double(e, &p3, &mut context);
    p = add(p, &p3, &p3, &mut context);
    assert_eq!(p, e);

    e = double(e, &p4, &mut context);
    p = add(p, &p4, &p4, &mut context);
    assert_eq!(p, e);

    e = double(e, &p5, &mut context);
    p = add(p, &p5, &p5, &mut context);
    assert_eq!(p, e);

    ////////////
    // P1 + Q //
    ////////////
    // (17, 10) + (95, 31) = (1, 54)
    p = add(p, &p1, &p2, &mut context);
    assert_eq!(p, point(1, 54));

    // (17, 10) + (22, 5) = (59, 32)
    p = add(p, &p1, &p3, &mut context);
    assert_eq!(p, point(59, 32));

    // (17, 10) + (39, 6) = (25, 62)
    p = add(p, &p1, &p4, &mut context);
    assert_eq!(p, point(25, 62));

    // (17, 10) + (56, 8) = (27, 90)
    p = add(p, &p1, &p5, &mut context);
    assert_eq!(p, point(27, 90));

    ////////////
    // P2 + Q //
    ////////////
    // (95, 31) + (17, 10) = (1, 54)
    p = add(p, &p2, &p1, &mut context);
    assert_eq!(p, point(1, 54));

    // (95, 31) + (22, 5) = (29, 43)
    p = add(p, &p2, &p3, &mut context);
    assert_eq!(p, point(29, 43));

    // (95, 31) + (39, 6) = (28, 63)
    p = add(p, &p2, &p4, &mut context);
    assert_eq!(p, point(28, 63));

    // (95, 31) + (56, 8) = (76, 20)
    p = add(p, &p2, &p5, &mut context);
    assert_eq!(p, point(76, 20));

    ////////////
    // P3 + Q //
    ////////////
    // (22, 5) + (17, 10) = (59, 32)
    p = add(p, &p3, &p1, &mut context);
    assert_eq!(p, point(59, 32));

    // (22, 5) + (95, 31) = (29, 43)
    p = add(p, &p3, &p2, &mut context);
    assert_eq!(p, point(29, 43));

    // (22, 5) + (39, 6) = (84, 37)
    p = add(p, &p3, &p4, &mut context);
    assert_eq!(p, point(84, 37));

    // (22, 5) + (56, 8) = (30, 0)
    p = add(p, &p3, &p5, &mut context);
    assert_eq!(p, point(30, 0));

    ////////////
    // P4 + Q //
    ////////////
    // (39, 6) + (17, 10) = (25, 62)
    p = add(p, &p4, &p1, &mut context);
    assert_eq!(p, point(25, 62));

    // (39, 6) + (95, 31) = (28, 63)
    p = add(p, &p4, &p2, &mut context);
    assert_eq!(p, point(28, 63));

    // (39, 6) + (22, 5) = (84, 37)
    p = add(p, &p4, &p3, &mut context);
    assert_eq!(p, point(84, 37));

    // (39, 6) + (56, 8) = (0, 10)
    p = add(p, &p4, &p5, &mut context);
    assert_eq!(p, point(0, 10));

    ////////////
    // P5 + Q //
    ////////////
    // (56, 8) + (17, 10) = (27, 90)
    p = add(p, &p5, &p1, &mut context);
    assert_eq!(p, point(27, 90));

    // (56, 8) + (95, 31) = (76, 20)
    p = add(p, &p5, &p2, &mut context);
    assert_eq!(p, point(76, 20));

    // (56, 8) + (22, 5) = (30, 0)
    p = add(p, &p5, &p3, &mut context);
    assert_eq!(p, point(30, 0));

    // (56, 8) + (39, 6) = (0, 10)
    p = add(p, &p5, &p4, &mut context);
    assert_eq!(p, point(0, 10));
}

#[test]
fn point_doubling_1() {
    let mut context = point_addition_context_1();
    let mut p = EccPoint::infinity(4);

    // (22, 2321) + (22, 2321) = (605, 851)
    p = double(p, &point(22, 2321), &mut context);
    assert_eq!(p, point(605, 851));

    // (605, 851) + (605, 851) = (993, 1231)
    p = double(p, &point(605, 851), &mut context);
    assert_eq!(p, point(993, 1231));

    // (1777, 1229) + (1777, 1229) = (1070, 929)
    p = double(p, &point(1777, 1229), &mut context);
    assert_eq!(p, point(1070, 929));

    // (2444, 1207) + (2444, 1207) = (2483, 1068)
    p = double(p, &point(2444, 1207), &mut context);
    assert_eq!(p, point(2483, 1068));

    // (993, 1231) + (993, 1231) = (130, 2438)
    p = double(p, &point(993, 1231), &mut context);
    assert_eq!(p, point(130, 2438));
}

#[test]
fn point_doubling_2() {
    let mut context = point_addition_context_2();
    let mut p = EccPoint::infinity(2);

    // (17, 10) + (17, 10) = (32, 90)
    p = double(p, &point(17, 10), &mut context);
    assert_eq!(p, point(32, 90));

    // (95, 31) + (95, 31) = (74, 77)
    p = double(p, &point(95, 31), &mut context);
    assert_eq!(p, point(74, 77));

    // (22, 5) + (22, 5) = (21, 24)
    p = double(p, &point(22, 5), &mut context);
    assert_eq!(p, point(21, 24));

    // (39, 6) + (39, 6) = (92, 16)
    p = double(p, &point(39, 6), &mut context);
    assert_eq!(p, point(92, 16));

    // (56, 8) + (56, 8) = (21, 73)
    p = double(p, &point(56, 8), &mut context);
    assert_eq!(p, point(21, 73));
}

fn point_addition_context_1() -> EllipticCurvePointAdditionContext {
    EllipticCurvePointAdditionContext::from(p1(), a1(), 4)
}

fn point_addition_context_2() -> EllipticCurvePointAdditionContext {
    EllipticCurvePointAdditionContext::from(p2(), a2(), 2)
}

fn p1() -> &'static BigUnsigned {
    unsafe { P1.value() }
}

fn a1() -> &'static BigUnsigned {
    unsafe { A1.value() }
}

fn p2() -> &'static BigUnsigned {
    unsafe { P2.value() }
}

fn a2() -> &'static BigUnsigned {
    unsafe { A2.value() }
}

fn point(x: u16, y: u16) -> EccPoint {
    EccPoint::from(
        BigSigned::from_unsigned(false, BigUnsigned::from_be_bytes(&x.to_be_bytes())),
        BigSigned::from_unsigned(false, BigUnsigned::from_be_bytes(&y.to_be_bytes())),
    )
}

fn add(
    mut p: EccPoint,
    augend: &EccPoint,
    addend: &EccPoint,
    addition_context: &mut EllipticCurvePointAdditionContext,
) -> EccPoint {
    p.set_equal_to(augend);
    p.add(addend, addition_context);
    p
}

fn double(
    mut p: EccPoint,
    point: &EccPoint,
    addition_context: &mut EllipticCurvePointAdditionContext,
) -> EccPoint {
    p.set_equal_to(point);
    p.double(addition_context);
    p
}
