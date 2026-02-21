// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED_UINT} from "../types/Constants8141.sol";
import {ValidationData, getValidationResult} from "../types/Types8141.sol";

/// @notice Intersect two ValidationData values, taking the most restrictive result.
/// @dev Ported from ZeroDev Kernel v3 KernelValidationResult.sol.
///      Computes: max(validAfter), min(validUntil), and checks aggregator compatibility.
function _intersectValidationData(ValidationData a, ValidationData b)
    pure
    returns (ValidationData validationData)
{
    assembly {
        // xor(a,b) == shows only matching bits
        // and(xor(a,b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff)
        //   == filters out the validAfter and validUntil bits
        // if the result is not zero, then aggregator part is not matching
        // validCase:  a == 0 || b == 0 || xor(a,b) == 0
        // invalidCase: a * b != 0 && xor(a,b) != 0
        let sum := shl(96, add(a, b))
        switch or(
            iszero(and(xor(a, b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff)),
            or(eq(sum, shl(96, a)), eq(sum, shl(96, b)))
        )
        case 1 {
            validationData := and(or(a, b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff)
            // validAfter — take the larger (more restrictive)
            let a_vd := and(0xffffffffffff0000000000000000000000000000000000000000000000000000, a)
            let b_vd := and(0xffffffffffff0000000000000000000000000000000000000000000000000000, b)
            validationData := or(validationData, xor(a_vd, mul(xor(a_vd, b_vd), gt(b_vd, a_vd))))
            // validUntil — take the smaller (more restrictive)
            a_vd := and(0x000000000000ffffffffffff0000000000000000000000000000000000000000, a)
            if iszero(a_vd) { a_vd := 0x000000000000ffffffffffff0000000000000000000000000000000000000000 }
            b_vd := and(0x000000000000ffffffffffff0000000000000000000000000000000000000000, b)
            if iszero(b_vd) { b_vd := 0x000000000000ffffffffffff0000000000000000000000000000000000000000 }
            let until := xor(a_vd, mul(xor(a_vd, b_vd), lt(b_vd, a_vd)))
            if iszero(until) { until := 0x000000000000ffffffffffff0000000000000000000000000000000000000000 }
            validationData := or(validationData, until)
        }
        default { validationData := SIG_VALIDATION_FAILED_UINT }
    }
}
