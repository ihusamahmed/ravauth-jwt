# ravauth-jwt

A zero-trust JWT library for Rust — secure by design, not by configuration.

Built for [ravAuth](https://github.com/ihusamahmed/ravauth-lite), extracted as a standalone crate so anyone can use it.

## Supported Algorithms

| Algorithm | Key Type | Use Case |
|-----------|----------|----------|
| **HS256** | `HmacKey` | Symmetric — single service signs & verifies |
| **EdDSA** (Ed25519) | `Ed25519SigningKey` / `Ed25519VerifyingKey` | Asymmetric — auth server signs, microservices verify with public key |

**EdDSA (Ed25519) is recommended** for production. It's the most secure JWT algorithm: no nonce pitfalls (unlike ECDSA), small 32-byte keys (unlike RSA), deterministic signatures, and fast. Use HS256 only when a single service both signs and verifies.

## Why Another JWT Library?

Most JWT libraries are flexible by default and secure by opt-in. This inverts that:

- **Algorithm is pinned at the type level** — an `HmacKey` can only produce/verify HS256. An `Ed25519SigningKey` can only produce/verify EdDSA. No runtime algorithm selection. No `none` algorithm. No algorithm confusion.
- **Cross-algorithm confusion is impossible** — an HS256 token is rejected by EdDSA keys and vice versa.
- **Asymmetric key separation** — `Ed25519SigningKey` (private) vs `Ed25519VerifyingKey` (public). Distribute only the public key to services that should never mint tokens.
- **Dangerous headers are rejected** — `jku`, `jwk`, `x5u`, `x5c`, `crit` cause immediate rejection.
- **Payload is parsed after signature verification** — invalid tokens leak no information.
- **`exp` is mandatory** — you cannot skip expiration checking.
- **Constant-time comparison** — HMAC uses `verify_slice`, Ed25519 uses `dalek`'s built-in verification.

## Quick Start — EdDSA (Recommended)

```rust
use ravauth_jwt::{Ed25519SigningKey, Ed25519VerifyingKey, ValidationConfig};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
struct MyClaims {
    sub: String,
    exp: i64,
}

// Auth server: generate key pair
let signing_key = Ed25519SigningKey::generate();

let claims = MyClaims { sub: "user-123".into(), exp: 4102444800 };
let token = signing_key.sign(&claims).unwrap();

// Export public key bytes for distribution to microservices
let pub_bytes = signing_key.verifying_key().to_bytes();

// Microservice: verify with public key only (cannot mint new tokens)
let verifying_key = Ed25519VerifyingKey::from_bytes(&pub_bytes).unwrap();
let verified: MyClaims = verifying_key.verify(&token, &ValidationConfig::default()).unwrap();
assert_eq!(verified.sub, "user-123");
```

## Quick Start — HS256

```rust
use ravauth_jwt::{HmacKey, ValidationConfig};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
struct MyClaims {
    sub: String,
    exp: i64,
    role: String,
}

// Create a key (strict=true requires >= 32 bytes per NIST)
let key = HmacKey::new(b"my-secret-key-that-is-at-least-32-bytes!", true).unwrap();

// Sign
let claims = MyClaims {
    sub: "user-123".into(),
    exp: 4102444800, // year 2100
    role: "admin".into(),
};
let token = key.sign(&claims).unwrap();

// Verify
let config = ValidationConfig::default();
let verified: MyClaims = key.verify(&token, &config).unwrap();
assert_eq!(verified.sub, "user-123");
```

## Claim Validation

```rust
use ravauth_jwt::ValidationConfig;

let config = ValidationConfig::default()
    .with_leeway(60)                        // clock skew tolerance (seconds)
    .with_max_size(4096)                    // max token bytes (DoS prevention)
    .require_claim("iss", "my-auth-server") // reject if iss != "my-auth-server"
    .require_claim("aud", "my-app");        // reject if aud != "my-app"
```

## Security Properties

| Defense | Implementation |
|---|---|
| Algorithm pinning | Key type determines algorithm — no runtime selection |
| `none` algorithm | Permanently rejected — no code path exists |
| Algorithm confusion | HS256 tokens rejected by EdDSA keys and vice versa |
| Constant-time comparison | HMAC `verify_slice` / Ed25519 `dalek` verification |
| Dangerous headers | `jku`, `jwk`, `x5u`, `x5c`, `crit` → immediate rejection |
| Strict base64url | No padding, no lenient decoding |
| Mandatory `exp` | Cannot be skipped |
| `nbf` enforcement | Rejected when present and not yet valid |
| `iss` / `aud` validation | Configurable via `require_claim()` |
| Max token size | 8KB default (configurable) |
| Clock skew | 30s default (configurable) |
| Key length | HMAC: >= 32 bytes (NIST), Ed25519: exactly 32 bytes |
| `kid` support | For key rotation workflows |
| Payload parsed after signature | No info leak from invalid tokens |
| Asymmetric key separation | `Ed25519SigningKey` (private) vs `Ed25519VerifyingKey` (public) |

## Key Rotation

```rust
// HS256
let key = HmacKey::new(b"my-secret-key-that-is-at-least-32-bytes!", true)
    .unwrap()
    .with_kid("hmac-2026-01");

// EdDSA
let key = Ed25519SigningKey::generate()
    .with_kid("ed-2026-01");

// kid is included in the JWT header for routing to the correct key
let token = key.sign(&claims).unwrap();
```

## `RegisteredClaims` Helper

When you need to inspect standard claims without a full struct:

```rust
use ravauth_jwt::RegisteredClaims;

let registered: RegisteredClaims = key.verify(&token, &config).unwrap();
println!("Subject: {:?}", registered.sub);
println!("Issuer: {:?}", registered.iss);
```

## Minimum Supported Rust Version

Rust 1.85+

## License

Apache-2.0
