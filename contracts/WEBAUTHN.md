# WebAuthn Integration in CoinbaseSmartWallet8141

## Overview

CoinbaseSmartWallet8141 now supports **WebAuthn (Passkey)** signatures in addition to traditional Ethereum ECDSA signatures. This enables users to sign transactions using biometric authentication (Face ID, Touch ID, Windows Hello) or hardware security keys.

## Architecture

### Multi-Owner Support

The wallet supports two types of owners:

1. **Ethereum Address Owners** (32 bytes)
   - Traditional ECDSA signatures (secp256k1)
   - Stored as `abi.encode(address)`

2. **WebAuthn Public Key Owners** (64 bytes)
   - P256 (secp256r1) signatures
   - Stored as `abi.encode(uint256 x, uint256 y)`

### WebAuthn Library

The `WebAuthn.sol` library implements P256 signature verification following the WebAuthn standard:

**Key Features:**
- Authenticator data validation
- Client data JSON parsing and verification
- P256 signature verification using RIP-7212 precompile (address 0x100)
- User Verification (UV) flag enforcement
- Base64URL encoding for challenge verification

**WebAuthnAuth Structure:**
```solidity
struct WebAuthnAuth {
    bytes authenticatorData;  // Authenticator data from WebAuthn response
    bytes clientDataJSON;     // Client data JSON from WebAuthn response
    uint256 challengeIndex;   // Index of "challenge" field in clientDataJSON
    uint256 typeIndex;        // Index of "type" field in clientDataJSON
    uint256 r;                // P256 signature r component
    uint256 s;                // P256 signature s component
}
```

## Implementation Details

### Signature Validation Flow

1. **Frame Transaction Signature Wrapper**
   ```solidity
   struct SignatureWrapper {
       uint256 ownerIndex;      // Which owner signed (0, 1, 2, ...)
       bytes signatureData;     // ECDSA (65 bytes) or WebAuthnAuth (encoded)
   }
   ```

2. **Owner Type Detection**
   - 32 bytes → Ethereum address owner → ECDSA validation
   - 64 bytes → WebAuthn public key owner → P256 validation

3. **WebAuthn Signature Validation**
   ```solidity
   function _validateWebAuthnSignature(
       bytes memory ownerBytes,
       bytes32 sigHash,
       bytes memory signatureData
   ) internal view returns (bool) {
       // Extract public key (x, y) from ownerBytes
       uint256 x;
       uint256 y;
       assembly {
           x := mload(add(ownerBytes, 32))
           y := mload(add(ownerBytes, 64))
       }

       // Decode WebAuthnAuth from signature data
       WebAuthn.WebAuthnAuth memory webAuthnAuth =
           abi.decode(signatureData, (WebAuthn.WebAuthnAuth));

       // Verify signature with UV flag required
       return WebAuthn.verify(
           abi.encodePacked(sigHash),
           true,  // requireUV (User Verification)
           webAuthnAuth,
           x,
           y
       );
   }
   ```

## Usage Examples

### Creating a Wallet with WebAuthn Owner

```solidity
// WebAuthn public key from passkey
uint256 x = 0x1234...;
uint256 y = 0x5678...;

bytes[] memory owners = new bytes[](1);
owners[0] = abi.encode(x, y);

CoinbaseSmartWallet8141 wallet = new CoinbaseSmartWallet8141(owners);
```

### Creating a Wallet with Mixed Owners

```solidity
address ethOwner = 0x...;
uint256 passkeyX = 0x...;
uint256 passkeyY = 0x...;

bytes[] memory owners = new bytes[](2);
owners[0] = abi.encode(ethOwner);       // Ethereum address
owners[1] = abi.encode(passkeyX, passkeyY);  // WebAuthn public key

CoinbaseSmartWallet8141 wallet = new CoinbaseSmartWallet8141(owners);
```

### Adding WebAuthn Owner to Existing Wallet

```solidity
// Must be called in SENDER frame (during wallet execution)
wallet.addOwnerPublicKey(x, y);

// Verify it was added
bool isOwner = wallet.isOwnerPublicKey(x, y);
```

## Security Features

### User Verification Requirement

The implementation requires the UV (User Verification) flag to be set in the authenticator data. This ensures:
- Biometric authentication was performed (Face ID, Touch ID)
- PIN/password was entered
- User presence is verified

```solidity
// Bit 2 (0x04) = User Verified
bytes1 flags = webAuthnAuth.authenticatorData[32];
if ((flags & 0x04) != 0x04) return false;
```

### Challenge Binding

The WebAuthn signature is bound to the specific transaction:
1. Frame transaction sigHash is used as the challenge
2. Challenge is base64url-encoded and embedded in clientDataJSON
3. Signature covers hash of (authenticatorData || sha256(clientDataJSON))

### P256 Verification

Uses RIP-7212 P256VERIFY precompile for efficient verification:
- Address: `0x100`
- Input: `abi.encodePacked(messageHash, r, s, x, y)`
- Output: `1` if valid, `0` otherwise
- Fallback: Returns `false` if precompile not available

## Testing

### Unit Tests (Foundry)

```bash
forge test --match-contract CoinbaseSmartWallet8141Test
```

**Test Coverage:**
- ✅ `test_WebAuthnOwner` - Create wallet with WebAuthn owner
- ✅ `test_MixedOwners` - Create wallet with both owner types
- ✅ `test_Initialize` - Owner initialization
- ✅ `test_OwnerAtIndex` - Owner retrieval

### E2E Tests (TypeScript)

```bash
# Start devnet with P256_VERIFIER precompile
bash devnet/run.sh

# Run E2E test
npx tsx script/send_coinbase_e2e.ts
```

The E2E script tests:
- Wallet deployment with multiple owners
- Owner verification
- Frame transaction execution with ECDSA signatures
- (WebAuthn signature execution requires client-side passkey integration)

## WebAuthn Signature Format

### TypeScript Example (Conceptual)

```typescript
import { secp256r1 } from '@noble/curves/p256';

// Sign with WebAuthn (browser API)
const credential = await navigator.credentials.get({
  publicKey: {
    challenge: sigHashBytes,
    rpId: "example.com",
    userVerification: "required",
  }
});

// Extract WebAuthn response
const { authenticatorData, clientDataJSON, signature } = credential.response;

// Parse P256 signature (DER encoded)
const { r, s } = parseDERSignature(signature);

// Encode for contract
const webAuthnAuth = {
  authenticatorData,
  clientDataJSON,
  challengeIndex: findChallengeIndex(clientDataJSON),
  typeIndex: findTypeIndex(clientDataJSON),
  r: BigInt(r),
  s: BigInt(s),
};

const signatureData = encodeAbiParameters(
  parseAbiParameters("(bytes,bytes,uint256,uint256,uint256,uint256)"),
  [webAuthnAuth]
);

const signatureWrapper = encodeAbiParameters(
  parseAbiParameters("uint256, bytes"),
  [ownerIndex, signatureData]
);
```

## Files Modified/Created

### Created Files

1. **contracts/src/lib/WebAuthn.sol**
   - WebAuthn signature verification library
   - P256 precompile integration
   - Client data JSON parsing
   - Base64URL encoding

2. **contracts/WEBAUTHN.md**
   - This documentation file

### Modified Files

1. **contracts/src/example/CoinbaseSmartWallet8141.sol**
   - Added `import {WebAuthn} from "../lib/WebAuthn.sol"`
   - Implemented `_validateWebAuthnSignature()` function
   - Changed signature validation to `view` (was `pure`)

2. **contracts/test/CoinbaseSmartWallet8141.t.sol**
   - Added `test_WebAuthnOwner()` test
   - Added `test_MixedOwners()` test

## Limitations

### Current Limitations

1. **E2E Testing**: Full E2E testing with real WebAuthn signatures requires:
   - Browser integration with WebAuthn API
   - Authenticator (biometric device or security key)
   - Custom TypeScript client implementation

2. **Precompile Dependency**: P256 verification requires:
   - RIP-7212 precompile at address 0x100
   - Falls back to `false` if precompile unavailable
   - Production deployment needs precompile support

3. **No Fallback Verification**:
   - When P256_VERIFIER is unavailable, verification returns `false`
   - Could integrate FreshCryptoLib or similar for fallback
   - Trade-off: Higher gas costs without precompile

### Future Enhancements

1. **Passkey Registration Flow**
   - Add on-chain registration events
   - Store credential IDs for lookup
   - Support credential counter verification

2. **Batch Signature Verification**
   - Verify multiple WebAuthn signatures in one call
   - Optimize for wallets with many passkey owners

3. **Fallback P256 Verification**
   - Integrate library-based P256 verification
   - Enable WebAuthn on chains without precompile
   - Gas optimization for batch operations

## References

- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [RIP-7212: P256VERIFY Precompile](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md)
- [Coinbase Smart Wallet](https://github.com/coinbase/smart-wallet)
- [EIP-8141: Frame Transactions](https://eips.ethereum.org/EIPS/eip-8141)
