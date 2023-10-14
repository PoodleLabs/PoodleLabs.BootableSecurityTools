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

use super::EllipticCurvePointAdditionContext;
use crate::integers::{BigSigned, BigUnsigned};

// Note: the below illustrations were 'drawn' in VS Codium; they must be viewed with a monospace font with
// support for all included characters, with minimal line spacing.
// They are, of course, rough approximations, due to the medium.
//
// An Elliptic Curve looks something like this:
//_____________________________________________________________________________________________________
//|                                                 |                                 ▄▉▉▀            |
//|                                                 |                                ▄▉▀              |
//|                                                 |                              ▄▉▉▀               |
//|                                                 |                            ▄▉▉▀                 |
//|                                                 |                          ▄▉▉▀                   |
//|                             ▄▄▄▄▄▄▄▄▄           |                       ▄▉▉▉▀                     |
//|                          ▄▄▉▀▀▀▀▀▀▀▀▉▉▉▉▄       |                    ▄▉▉▉▀                        |
//|                       ▄▄▉▀▀            ▀▉▉▉▉▄   |                ▄▉▉▉▉▀                           |
//|                     ▄▉▀▀                   ▀▉▉▉▉▄            ▄▉▉▉▉▀                               |
//|                   ▄▉▀                          ▀▉▉▉▉▄    ▄▉▉▉▉▀                                   |
//|                  ▄▉▀                            |  ▀▉▉▉▉▉▉▀                                       |
//|                 ▄▉▀                             |                                                 |
//|                ▄▉▀                              |                                                 |
//|               ▄▉▀                               |                                                 |
//|              ▄▉▀                                |                                                 |
//|              ▉▉                                 |                                                 |
//|             ▉▉▀                                 |                                                 |
//|-------------▉▉----------------------------------+-------------------------------------------------| X
//|             ▉▉▄                                 |                                                 |
//|              ▉▉                                 |                                                 |
//|              ▀▉▄                                |                                                 |
//|               ▀▉▄                               |                                                 |
//|                ▀▉▄                              |                                                 |
//|                 ▀▉▄                             |                                                 |
//|                  ▀▉▄                            |  ▄▉▉▉▉▉▉▄                                       |
//|                   ▀▉▄                          ▄▉▉▉▉▀    ▀▉▉▉▉▄                                   |
//|                     ▀▉▄▄                   ▄▉▉▉▉▀            ▀▉▉▉▉▄                               |
//|                       ▀▀▉▄▄            ▄▉▉▉▉▀   |                ▀▉▉▉▉▄                           |
//|                          ▀▀▉▄▄▄▄▄▄▄▄▉▉▉▉▀       |                    ▀▉▉▉▄                        |
//|                             ▀▀▀▀▀▀▀▀▀           |                       ▀▉▉▉▄                     |
//|                                                 |                          ▀▉▉▄                   |
//|                                                 |                            ▀▉▉▄                 |
//|                                                 |                              ▀▉▉▄               |
//|                                                 |                                ▀▉▄              |
//|                                                 |                                 ▀▉▉▄            |
//¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
//                                                  Y
//
// Elliptic Curve Cryptograpy requires the addition of points on a curve, P and Q, for a third point R.
// This is achieved by drawing a line between points P and Q, then making R the inverse of the point at
// which the line intersects the curve again:
//_____________________________________________________________________________________________________
//|                                                 |                                 ▄▉▉▀            |
//|                                                 |                                ▄▉▀              |
//|                                                 |                              ▄▉▉▀               |
//|                                                 |                            ▄▉▉▀                 |
//|                                                 |                          ▄▉▉▀                   |
//|                             ▄▄▄▄▄▄▄▄▄           |                       ▄▉▉▉▀              _____--|
//|                          ▄▄▉▀▀▀▀▀▀▀▀▉▉▉▉▄       |                    ▄▉▉▉▀  _____-----¯¯¯¯¯       |
//|                       ▄▄▉▀▀            ▀▉▉▉▉▄   |       _____----▄r▉▉▉▀¯¯¯¯¯                      |
//|                     ▄▉▀▀                 __▀▉▉Q▉▄--¯¯¯¯¯     ▄▉▉▉▉▀                               |
//|                   ▄▉▀     _____-----¯¯¯¯¯      ▀▉▉▉▉▄    ▄▉▉▉▉▀   :                               |
//|            _____-▄P--¯¯¯¯¯                      |  ▀▉▉▉▉▉▉▀       :                               |
//|__-----¯¯¯¯¯     ▄▉▀                             |                 :                               |
//|                ▄▉▀                              |                 :                               |
//|               ▄▉▀                               |                 :                               |
//|              ▄▉▀                                |                 :                               |
//|              ▉▉                                 |                 :                               |
//|             ▉▉▀                                 |                 :                               |
//|-------------▉▉----------------------------------+-----------------+-------------------------------| X
//|             ▉▉▄                                 |                 :                               |
//|              ▉▉                                 |                 :                               |
//|              ▀▉▄                                |                 :                               |
//|               ▀▉▄                               |                 :                               |
//|                ▀▉▄                              |                 :                               |
//|                 ▀▉▄                             |                 :                               |
//|                  ▀▉▄                            |  ▄▉▉▉▉▉▉▄       :                               |
//|                   ▀▉▄                          ▄▉▉▉▉▀    ▀▉▉▉▉▄   :                               |
//|                     ▀▉▄▄                   ▄▉▉▉▉▀            ▀▉▉▉▉▄                               |
//|                       ▀▀▉▄▄            ▄▉▉▉▉▀   |                ▀R▉▉▉▄                           |
//|                          ▀▀▉▄▄▄▄▄▄▄▄▉▉▉▉▀       |                    ▀▉▉▉▄                        |
//|                             ▀▀▀▀▀▀▀▀▀           |                       ▀▉▉▉▄                     |
//|                                                 |                          ▀▉▉▄                   |
//|                                                 |                            ▀▉▉▄                 |
//|                                                 |                              ▀▉▉▄               |
//|                                                 |                                ▀▉▄              |
//|                                                 |                                 ▀▉▉▄            |
//¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
//                                                  Y
//
// Any non-vertical line is guaranteed to intersect the curve at a point other than our augend and addend;
// remember: the curve shown is the most interesting region of the curve's space, but the curve continues
// on beyond the bounds shown, approaching verticality in both positive and negative Y directions.
//
// Note that there is one point on the curve where Y = 0, and for all other X coordinates, there are
// exactly two possible Y coordinates, which are the inverse of one another.
//
// When two points have the same X coordinate, but different Y coordinates, the line between them is
// vertical, and does not intersect the curve at any other point. In such a case, we create an imaginary
// point 'Infinity'. This point is the 'neutral' point of an elliptic curve such that X + Infinity = X.
//
//                                 Inf                    Inf                Inf
//_____________________________________________________________________________________________________
//|                                 :               |      :                  :       ▄▉▉▀            |
//|                                 :               |      :                  :      ▄▉▀              |
//|                                 :               |      :                  :    ▄▉▉▀               |
//|                                 :               |      :                  :  ▄▉▉▀                 |
//|                                 :               |      :                  :▄▉▉▀                   |
//|                             ▄▄▄▄▄▄▄▄▄           |      :                ▄▉P▉▀                     |
//|                          ▄▄▉▀▀▀▀P▀▀▀▉▉▉▉▄       |      :             ▄▉▉▉▀:                       |
//|                       ▄▄▉▀▀     :      ▀▉▉▉▉▄   |      :         ▄▉▉▉▉▀   :                       |
//|                     ▄▉▀▀        :          ▀▉▉▉▉▄      :     ▄▉▉▉▉▀       :                       |
//|                   ▄▉▀           :              ▀▉▉▉▉▄  : ▄▉▉▉▉▀           :                       |
//|                  ▄▉▀            :               |  ▀▉▉▉P▉▉▀               :                       |
//|                 ▄▉▀             :               |      :                  :                       |
//|                ▄▉▀              :               |      :                  :                       |
//|               ▄▉▀               :               |      :                  :                       |
//|              ▄▉▀                :               |      :                  :                       |
//|              ▉▉                 :               |      :                  :                       |
//|             ▉▉▀                 :               |      :                  :                       |
//|------------>▉▉<-Y=0-------------+---------------+------+------------------+-----------------------| X
//|             ▉▉▄                 :               |      :                  :                       |
//|              ▉▉                 :               |      :                  :                       |
//|              ▀▉▄                :               |      :                  :                       |
//|               ▀▉▄               :               |      :                  :                       |
//|                ▀▉▄              :               |      :                  :                       |
//|                 ▀▉▄             :               |      :                  :                       |
//|                  ▀▉▄            :               |  ▄▉▉▉P▉▉▄               :                       |
//|                   ▀▉▄           :              ▄▉▉▉▉▀  : ▀▉▉▉▉▄           :                       |
//|                     ▀▉▄▄        :          ▄▉▉▉▉▀      :     ▀▉▉▉▉▄       :                       |
//|                       ▀▀▉▄▄     :      ▄▉▉▉▉▀   |      :         ▀▉▉▉▉▄   :                       |
//|                          ▀▀▉▄▄▄▄P▄▄▄▉▉▉▉▀       |      :             ▀▉▉▉▄:                       |
//|                             ▀▀▀▀▀▀▀▀▀           |      :                ▀▉P▉▄                     |
//|                                 :               |      :                  :▀▉▉▄                   |
//|                                 :               |      :                  :  ▀▉▉▄                 |
//|                                 :               |      :                  :    ▀▉▉▄               |
//|                                 :               |      :                  :      ▀▉▄              |
//|                                 :               |      :                  :       ▀▉▉▄            |
//¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
//                                                  Y
//
// When adding a point to itself, we have a similar problem in that there are multiple lines we could draw.
// In such a case, we 'double' the point, drawing the line as the tangent of the point on the curve:
//_____________________________________________________________________________________________________
//|                                                 |                                 ▄▉▉▀            |
//|                                                 |                                ▄r▀              |
//|                                                 |                  _____-----¯¯▄▉▉▀               |
//|                                                 |   _____-----¯¯¯¯¯          ▄▉▉▀ :               |
//|                                      _____-----¯|¯¯¯                       ▄▉▉▀   :               |
//|                       _____-▄P▄▄¯¯¯¯¯           |                       ▄▉▉▉▀     :               |
//|        _____-----¯¯¯¯¯   ▄▄▉▀▀▀▀▀▀▀▀▉▉▉▉▄       |                    ▄▉▉▉▀        :               |
//|---¯¯¯¯¯               ▄▄▉▀▀            ▀▉▉▉▉▄   |                ▄▉▉▉▉▀           :               |
//|                     ▄▉▀▀                   ▀▉▉▉▉▄            ▄▉▉▉▉▀               :               |
//|                   ▄▉▀                          ▀▉▉▉▉▄    ▄▉▉▉▉▀                   :               |
//|                  ▄▉▀                            |  ▀▉▉▉▉▉▉▀                       :               |
//|                 ▄▉▀                             |                                 :               |
//|                ▄▉▀                              |                                 :               |
//|               ▄▉▀                               |                                 :               |
//|              ▄▉▀                                |                                 :               |
//|              ▉▉                                 |                                 :               |
//|             ▉▉▀                                 |                                 :               |
//|-------------▉▉----------------------------------+---------------------------------+---------------| X
//|             ▉▉▄                                 |                                 :               |
//|              ▉▉                                 |                                 :               |
//|              ▀▉▄                                |                                 :               |
//|               ▀▉▄                               |                                 :               |
//|                ▀▉▄                              |                                 :               |
//|                 ▀▉▄                             |                                 :               |
//|                  ▀▉▄                            |  ▄▉▉▉▉▉▉▄                       :               |
//|                   ▀▉▄                          ▄▉▉▉▉▀    ▀▉▉▉▉▄                   :               |
//|                     ▀▉▄▄                   ▄▉▉▉▉▀            ▀▉▉▉▉▄               :               |
//|                       ▀▀▉▄▄            ▄▉▉▉▉▀   |                ▀▉▉▉▉▄           :               |
//|                          ▀▀▉▄▄▄▄▄▄▄▄▉▉▉▉▀       |                    ▀▉▉▉▄        :               |
//|                             ▀▀▀▀▀▀▀▀▀           |                       ▀▉▉▉▄     :               |
//|                                                 |                          ▀▉▉▄   :               |
//|                                                 |                            ▀▉▉▄ :               |
//|                                                 |                              ▀▉▉▄               |
//|                                                 |                                ▀R▄              |
//|                                                 |                                 ▀▉▉▄            |
//¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
//                                                  Y
//
// Note that the tangent where Y = 0 is vertical, and so the result is infinity:
//             Inf
//_____________________________________________________________________________________________________
//|             :                                   |                                 ▄▉▉▀            |
//|             :                                   |                                ▄▉▀              |
//|             :                                   |                              ▄▉▉▀               |
//|             :                                   |                            ▄▉▉▀                 |
//|             :                                   |                          ▄▉▉▀                   |
//|             :               ▄▄▄▄▄▄▄▄▄           |                       ▄▉▉▉▀                     |
//|             :            ▄▄▉▀▀▀▀▀▀▀▀▉▉▉▉▄       |                    ▄▉▉▉▀                        |
//|             :         ▄▄▉▀▀            ▀▉▉▉▉▄   |                ▄▉▉▉▉▀                           |
//|             :       ▄▉▀▀                   ▀▉▉▉▉▄            ▄▉▉▉▉▀                               |
//|             :     ▄▉▀                          ▀▉▉▉▉▄    ▄▉▉▉▉▀                                   |
//|             :    ▄▉▀                            |  ▀▉▉▉▉▉▉▀                                       |
//|             :   ▄▉▀                             |                                                 |
//|             :  ▄▉▀                              |                                                 |
//|             : ▄▉▀                               |                                                 |
//|             :▄▉▀                                |                                                 |
//|             :▉▉                                 |                                                 |
//|             ▉▉▀                                 |                                                 |
//|------------P▉▉<-Y=0-----------------------------+-------------------------------------------------| X
//|             ▉▉▄                                 |                                                 |
//|             :▉▉                                 |                                                 |
//|             :▀▉▄                                |                                                 |
//|             : ▀▉▄                               |                                                 |
//|             :  ▀▉▄                              |                                                 |
//|             :   ▀▉▄                             |                                                 |
//|             :    ▀▉▄                            |  ▄▉▉▉▉▉▉▄                                       |
//|             :     ▀▉▄                          ▄▉▉▉▉▀    ▀▉▉▉▉▄                                   |
//|             :       ▀▉▄▄                   ▄▉▉▉▉▀            ▀▉▉▉▉▄                               |
//|             :         ▀▀▉▄▄            ▄▉▉▉▉▀   |                ▀▉▉▉▉▄                           |
//|             :            ▀▀▉▄▄▄▄▄▄▄▄▉▉▉▉▀       |                    ▀▉▉▉▄                        |
//|             :               ▀▀▀▀▀▀▀▀▀           |                       ▀▉▉▉▄                     |
//|             :                                   |                          ▀▉▉▄                   |
//|             :                                   |                            ▀▉▉▄                 |
//|             :                                   |                              ▀▉▉▄               |
//|             :                                   |                                ▀▉▄              |
//|             :                                   |                                 ▀▉▉▄            |
//¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
//                                                  Y

#[derive(Debug, Clone)]
pub struct Point {
    is_infinity: bool,
    x: BigSigned,
    y: BigSigned,
}

impl Point {
    pub fn infinity(integer_capacity: usize) -> Self {
        Self {
            x: BigSigned::with_capacity(integer_capacity),
            y: BigSigned::with_capacity(integer_capacity),
            is_infinity: true,
        }
    }

    pub fn from(x: BigSigned, y: BigSigned) -> Self {
        Self {
            is_infinity: x.is_zero() && y.is_zero(),
            x,
            y,
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.is_infinity
    }

    pub fn x(&self) -> &BigSigned {
        &self.x
    }

    pub fn y(&self) -> &BigSigned {
        &self.y
    }

    pub fn add(
        &mut self,
        addend: &Point,
        addition_context: &mut EllipticCurvePointAdditionContext,
    ) {
        if self.is_infinity {
            // Infinity + X = X
            self.set_equal_to(addend);
        }

        if addend.is_infinity {
            // X + Infinity = X
            return;
        }

        if self.x.eq(&addend.x) {
            // The X values are identical; there will be special-case logic for addition.
            if self.y.eq(&addend.y) {
                // The points are identical; we need to use the double method.
                self.double(addition_context);
            } else {
                // The points are not identical, but their X values are. The only possibility is that the Y values are inverses of one another
                // (as in Py = -Qy), in which case, the points cancel out to infinity.
                self.set_infinity();
            }

            // Special case addition logic was applied; don't do anything more.
            return;
        }

        // Point addition and doubling has two steps:
        // 1. Draw a line between the two points or, if the points are identical, draw a line at the tangent to the curve. Take the slope of that line.
        // 2. From the slope, we can calculate the next point at which the line intersects the curve. That is our addition/doubling result.
        //
        // We are adding two distinct points; we need to calculate the slope, then calculate the result from that slope.

        // Store the augend's original value for later.
        addition_context.store_augend(&self);

        // TODO: Calculate the slope.

        // The sum-from-slope calculation is identical for distinct point addition and point doubling.
        // The slope is stored in the point addition context, along with the original augend value.
        // Calculate the sum point, passing in the addend.
        self.calculate_new_point_from_slope(Some(addend), addition_context)
    }

    pub fn double(&mut self, addition_context: &mut EllipticCurvePointAdditionContext) {
        if self.is_infinity {
            // Infinity + Infinity = Infinity
            return;
        }

        if self.y.is_zero() {
            // When calculating the slope of a doubled point, we take the tangent for the point on the curve,
            // and then the value is the third point that tangent intersects with. But when Py = 0, the tangent
            // is vertical, and there is no third point. In this case, the result is infinity.
            self.set_infinity();
            return;
        }

        // Point addition and doubling has two steps:
        // 1. Draw a line between the two points or, if the points are identical, draw a line at the tangent to the curve. Take the slope of that line.
        // 2. From the slope, we can calculate the next point at which the line intersects the curve. That is our addition/doubling result.
        //
        // We are doubling a point; we need to calculate the slope, then calculate the result from that slope.

        // Store the point's original value for later.
        addition_context.store_augend(&self);

        // TODO: Calculate the slope.

        // The sum-from-slope calculation is identical for distinct point addition and point doubling.
        // The slope is stored in the point addition context, along with the original point.
        // Calculate the sum point; the addend is the same as the augend.
        self.calculate_new_point_from_slope(None, addition_context)
    }

    pub fn set_equal_to_unsigned(&mut self, x: &BigUnsigned, y: &BigUnsigned) {
        self.x.set_equal_to_unsigned(x, false);
        self.y.set_equal_to_unsigned(y, false);
        self.is_infinity = x.is_zero() && y.is_zero();
    }

    pub fn set_equal_to(&mut self, other: &Point) {
        self.is_infinity = other.is_infinity;
        self.x.set_equal_to(&other.x);
        self.y.set_equal_to(&other.y);
    }

    pub fn set_infinity(&mut self) {
        self.is_infinity = true;
        self.x.zero();
        self.y.zero();
    }

    fn calculate_new_point_from_slope(
        &mut self,
        addend: Option<&Point>,
        addition_context: &mut EllipticCurvePointAdditionContext,
    ) {
        // Point addition and doubling has two steps:
        // 1. Draw a line between the two points or, if the points are identical, draw a line at the tangent to the curve. Take the slope of that line.
        // 2. From the slope, we can calculate the next point at which the line intersects the curve. That is our addition/doubling result.
        //
        // We have calulated the slope already. It, along with the original augend point, is stored in the provided point addition context.
        // In the case of distinct point addition, the addend is passed in as the other parameter. In the case of point doubling, the
        // addend is the same as the augend.

        todo!()
    }
}
