// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title NativeFalconVerifier
/// @notice Pure Solidity implementation of the Falcon-512 core verification path.
/// @dev This intentionally accepts a precomputed hash-to-point challenge and
///      mirrors the FALCON_CORE precompile logic for gas-cost research.
contract NativeFalconVerifier {
    uint256 internal constant N = 512;
    int256 internal constant Q = 12289;
    int256 internal constant BETA_SQUARED = 34_034_726;

    int256 internal constant NTT_PSI = 10302;
    int256 internal constant NTT_INV_N = 12265;
    int256 internal constant NTT_INV_PSI = 8974;

    uint256 internal constant SIGNATURE_SIZE = 666;
    uint256 internal constant PUBLIC_KEY_SIZE = 896;
    uint256 internal constant CHALLENGE_SIZE = 896;
    uint256 internal constant SIGNATURE_BODY_OFFSET = 41;
    uint256 internal constant SIGNATURE_BODY_SIZE = 625;
    uint8 internal constant SIGNATURE_HEADER = 0x39;

    /// @notice Verifies a Falcon-512 signature against a precomputed challenge.
    /// @param sig Padded Falcon-512 signature: header || nonce || compressed s2.
    /// @param pubkey Falcon-512 public key polynomial packed as 512 big-endian 14-bit coefficients.
    /// @param challenge Hash-to-point polynomial packed using the same 14-bit encoding.
    function verify(bytes calldata sig, bytes calldata pubkey, bytes calldata challenge) external pure returns (bool) {
        return _verify(sig, pubkey, challenge, true);
    }

    /// @notice Research-only schoolbook verifier retained for gas comparison.
    function verifySchoolbook(bytes calldata sig, bytes calldata pubkey, bytes calldata challenge)
        external
        pure
        returns (bool)
    {
        return _verify(sig, pubkey, challenge, false);
    }

    function _verify(bytes calldata sig, bytes calldata pubkey, bytes calldata challenge, bool useNTT)
        internal
        pure
        returns (bool)
    {
        if (
            sig.length != SIGNATURE_SIZE || pubkey.length != PUBLIC_KEY_SIZE || challenge.length != CHALLENGE_SIZE
                || uint8(sig[0]) != SIGNATURE_HEADER
        ) {
            return false;
        }

        (int256[512] memory h, bool pkOk) = _decodePolynomial(pubkey);
        if (!pkOk) return false;

        (int256[512] memory s2, bool sigOk) = _decompressSignature(sig);
        if (!sigOk) return false;

        (int256[512] memory c, bool challengeOk) = _decodePolynomial(challenge);
        if (!challengeOk) return false;

        int256[512] memory hs2 = useNTT ? _polyMulNTT(h, s2) : _polyMulSchoolbook(h, s2);
        int256[512] memory s1 = _polySub(c, hs2);
        return _normCheck(s1, s2);
    }

    /// @dev Unpacks 512 big-endian 14-bit coefficients and rejects values >= q.
    function _decodePolynomial(bytes calldata data) internal pure returns (int256[512] memory poly, bool ok) {
        uint256 acc;
        uint256 accLen;
        uint256 offset;

        unchecked {
            for (uint256 i; i < N; ++i) {
                while (accLen < 14) {
                    if (offset >= data.length) return (poly, false);
                    acc = (acc << 8) | uint8(data[offset]);
                    accLen += 8;
                    ++offset;
                }
                accLen -= 14;
                uint256 value = (acc >> accLen) & 0x3fff;
                if (value >= uint256(Q)) return (poly, false);
                poly[i] = int256(value);
                acc &= _lowBitMask(accLen);
            }
        }
        return (poly, acc == 0);
    }

    /// @dev Decodes the 625-byte padded compressed s2 polynomial.
    function _decompressSignature(bytes calldata sig) internal pure returns (int256[512] memory s2, bool ok) {
        uint256 acc;
        uint256 accLen;
        uint256 offset = SIGNATURE_BODY_OFFSET;
        uint256 bodyEnd = SIGNATURE_BODY_OFFSET + SIGNATURE_BODY_SIZE;

        unchecked {
            for (uint256 i; i < N; ++i) {
                while (accLen < 8) {
                    if (offset >= bodyEnd) return (s2, false);
                    acc = (acc << 8) | uint8(sig[offset]);
                    accLen += 8;
                    ++offset;
                }
                accLen -= 8;
                uint256 encoded = (acc >> accLen) & 0xff;
                acc &= _lowBitMask(accLen);

                bool negative = encoded & 0x80 != 0;
                int256 coefficient = int256(encoded & 0x7f);

                while (true) {
                    if (accLen == 0) {
                        if (offset >= bodyEnd) return (s2, false);
                        acc = uint8(sig[offset]);
                        accLen = 8;
                        ++offset;
                    }
                    --accLen;
                    uint256 bit = (acc >> accLen) & 1;
                    acc &= _lowBitMask(accLen);
                    if (bit == 1) break;

                    coefficient += 128;
                    if (coefficient > 2047) return (s2, false);
                }

                if (negative) {
                    if (coefficient == 0) return (s2, false);
                    coefficient = -coefficient;
                }
                s2[i] = coefficient;
            }

            if (acc != 0) return (s2, false);
            while (offset < bodyEnd) {
                if (sig[offset] != 0) return (s2, false);
                ++offset;
            }
        }
        return (s2, true);
    }

    /// @dev Negacyclic NTT multiplication modulo (x^512 + 1, q).
    function _polyMulNTT(int256[512] memory a, int256[512] memory b)
        internal
        pure
        returns (int256[512] memory result)
    {
        int256[512] memory right;
        int256 psiPower = 1;

        unchecked {
            for (uint256 i; i < N; ++i) {
                a[i] = _normalize(a[i]) * psiPower % Q;
                right[i] = _normalize(b[i]) * psiPower % Q;
                psiPower = psiPower * NTT_PSI % Q;
            }

            _nttForward(a);
            _nttForward(right);
            for (uint256 i; i < N; ++i) {
                a[i] = a[i] * right[i] % Q;
            }
            _nttInverse(a);

            psiPower = 1;
            for (uint256 i; i < N; ++i) {
                result[i] = a[i] * psiPower % Q;
                psiPower = psiPower * NTT_INV_PSI % Q;
            }
        }
    }

    function _nttForward(int256[512] memory values) internal pure {
        _normalizeAndBitReverse(values);

        unchecked {
            for (uint256 length = 2; length <= N; length <<= 1) {
                int256 rootStep = _forwardRootStep(length);
                uint256 half = length >> 1;
                for (uint256 offset; offset < N; offset += length) {
                    int256 root = 1;
                    for (uint256 j; j < half; ++j) {
                        int256 even = values[offset + j];
                        int256 odd = values[offset + j + half] * root % Q;
                        int256 sum = even + odd;
                        if (sum >= Q) sum -= Q;
                        int256 difference = even - odd;
                        if (difference < 0) difference += Q;
                        values[offset + j] = sum;
                        values[offset + j + half] = difference;
                        root = root * rootStep % Q;
                    }
                }
            }
        }
    }

    function _nttInverse(int256[512] memory values) internal pure {
        _normalizeAndBitReverse(values);

        unchecked {
            for (uint256 length = 2; length <= N; length <<= 1) {
                int256 rootStep = _inverseRootStep(length);
                uint256 half = length >> 1;
                for (uint256 offset; offset < N; offset += length) {
                    int256 root = 1;
                    for (uint256 j; j < half; ++j) {
                        int256 even = values[offset + j];
                        int256 odd = values[offset + j + half] * root % Q;
                        int256 sum = even + odd;
                        if (sum >= Q) sum -= Q;
                        int256 difference = even - odd;
                        if (difference < 0) difference += Q;
                        values[offset + j] = sum;
                        values[offset + j + half] = difference;
                        root = root * rootStep % Q;
                    }
                }
            }
            for (uint256 i; i < N; ++i) {
                values[i] = values[i] * NTT_INV_N % Q;
            }
        }
    }

    function _normalizeAndBitReverse(int256[512] memory values) internal pure {
        unchecked {
            for (uint256 i; i < N; ++i) {
                values[i] = _normalize(values[i]);
            }
            uint256 j;
            for (uint256 i = 1; i < N; ++i) {
                uint256 bit = N >> 1;
                while ((j & bit) != 0) {
                    j ^= bit;
                    bit >>= 1;
                }
                j ^= bit;
                if (i < j) {
                    (values[i], values[j]) = (values[j], values[i]);
                }
            }
        }
    }

    function _forwardRootStep(uint256 length) internal pure returns (int256) {
        if (length == 2) return 12288;
        if (length == 4) return 1479;
        if (length == 8) return 8246;
        if (length == 16) return 4134;
        if (length == 32) return 5860;
        if (length == 64) return 7311;
        if (length == 128) return 12149;
        if (length == 256) return 8340;
        return 3400;
    }

    function _inverseRootStep(uint256 length) internal pure returns (int256) {
        if (length == 2) return 12288;
        if (length == 4) return 10810;
        if (length == 8) return 7143;
        if (length == 16) return 10984;
        if (length == 32) return 8747;
        if (length == 64) return 9650;
        if (length == 128) return 790;
        if (length == 256) return 1696;
        return 2859;
    }

    function _normalize(int256 value) internal pure returns (int256) {
        value %= Q;
        if (value < 0) value += Q;
        return value;
    }

    /// @dev Schoolbook multiplication modulo (x^512 + 1, q).
    function _polyMulSchoolbook(int256[512] memory a, int256[512] memory b)
        internal
        pure
        returns (int256[512] memory result)
    {
        int256[512] memory acc;

        unchecked {
            for (uint256 i; i < N; ++i) {
                int256 ai = a[i];
                for (uint256 j; j < N; ++j) {
                    uint256 k = i + j;
                    int256 product = ai * b[j];
                    if (k < N) {
                        acc[k] += product;
                    } else {
                        acc[k - N] -= product;
                    }
                }
            }

            for (uint256 i; i < N; ++i) {
                int256 reduced = acc[i] % Q;
                if (reduced < 0) reduced += Q;
                result[i] = reduced;
            }
        }
    }

    /// @dev Computes a - b coefficient-wise modulo q.
    function _polySub(int256[512] memory a, int256[512] memory b) internal pure returns (int256[512] memory result) {
        unchecked {
            for (uint256 i; i < N; ++i) {
                int256 value = a[i] - b[i];
                if (value < 0) value += Q;
                result[i] = value;
            }
        }
    }

    /// @dev Checks ||s1||^2 + ||s2||^2 <= beta^2 with centered s1 coefficients.
    function _normCheck(int256[512] memory s1, int256[512] memory s2) internal pure returns (bool) {
        int256 squaredNorm;

        unchecked {
            for (uint256 i; i < N; ++i) {
                int256 v1 = s1[i];
                if (v1 > Q / 2) v1 -= Q;
                squaredNorm += v1 * v1;

                int256 v2 = s2[i];
                squaredNorm += v2 * v2;
                if (squaredNorm > BETA_SQUARED) return false;
            }
        }
        return true;
    }

    function _lowBitMask(uint256 bitLength) internal pure returns (uint256) {
        if (bitLength == 0) return 0;
        return (uint256(1) << bitLength) - 1;
    }
}
