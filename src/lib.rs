//! # ravauth-jwt
//!
//! A zero-trust JWT library for Rust — secure by design.
//!
//! ## Supported Algorithms
//!
//! | Algorithm | Key Type | Use Case |
//! |-----------|----------|----------|
//! | **HS256** | [`HmacKey`] | Symmetric — single service signs & verifies |
//! | **EdDSA** (Ed25519) | [`Ed25519SigningKey`] / [`Ed25519VerifyingKey`] | Asymmetric — auth server signs, microservices verify with public key |
//!
//! **EdDSA (Ed25519) is recommended** for production systems. It's the most secure
//! JWT algorithm: no nonce pitfalls (unlike ECDSA), small 32-byte keys (unlike RSA),
//! deterministic signatures, and fast. Use HS256 only when a single service both
//! signs and verifies tokens.
//!
//! ## Security Properties
//!
//! - **Algorithm pinning**: Key type determines algorithm. An `HmacKey` can only produce/verify
//!   HS256 tokens. An `Ed25519SigningKey` can only produce/verify EdDSA tokens. No runtime
//!   algorithm selection. No way to use the wrong algorithm.
//! - **`none` algorithm permanently rejected**: No code path exists to create or accept unsigned tokens.
//! - **Algorithm confusion defense**: Header `alg` must match the key's algorithm exactly.
//!   An HS256 token cannot be verified with an EdDSA key, and vice versa.
//! - **Constant-time signature comparison**: HMAC uses `verify_slice`, Ed25519 uses `dalek`'s
//!   built-in verification (which is constant-time).
//! - **Dangerous header rejection**: Tokens with `jku`, `jwk`, `x5u`, `x5c`, or `crit` headers
//!   are rejected immediately — these are common injection vectors.
//! - **Strict base64url**: No padding accepted, no lenient decoding. Malformed encoding = rejection.
//! - **Mandatory `exp` validation**: Cannot be skipped or disabled.
//! - **`nbf` enforcement**: When present, token is rejected if not yet valid.
//! - **`iss` / `aud` validation**: Configurable, enforced when set.
//! - **Max token size**: Configurable (default 8KB) to prevent DoS via oversized tokens.
//! - **Clock skew tolerance**: Configurable (default 30 seconds).
//! - **Payload parsed after signature**: Invalid tokens leak no information about their payload.
//! - **`kid` support**: Ready for key rotation workflows.
//! - **Asymmetric key separation**: `Ed25519SigningKey` (private, can sign) vs
//!   `Ed25519VerifyingKey` (public, can only verify). Distribute only the public key
//!   to services that should never mint tokens.
//!
//! ## Quick Start — HS256 (Symmetric)
//!
//! ```rust
//! use ravauth_jwt::{HmacKey, ValidationConfig};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Debug, Serialize, Deserialize)]
//! struct MyClaims {
//!     sub: String,
//!     exp: i64,
//!     role: String,
//! }
//!
//! let key = HmacKey::new(b"my-secret-key-that-is-at-least-32-bytes!", true).unwrap();
//!
//! let claims = MyClaims {
//!     sub: "user-123".into(),
//!     exp: 4102444800,
//!     role: "admin".into(),
//! };
//! let token = key.sign(&claims).unwrap();
//!
//! let config = ValidationConfig::default();
//! let verified: MyClaims = key.verify(&token, &config).unwrap();
//! assert_eq!(verified.sub, "user-123");
//! ```
//!
//! ## Quick Start — EdDSA (Asymmetric, Recommended)
//!
//! ```rust
//! use ravauth_jwt::{Ed25519SigningKey, Ed25519VerifyingKey, ValidationConfig};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Debug, Serialize, Deserialize)]
//! struct MyClaims {
//!     sub: String,
//!     exp: i64,
//! }
//!
//! // Auth server: generate key pair
//! let signing_key = Ed25519SigningKey::generate();
//!
//! let claims = MyClaims { sub: "user-123".into(), exp: 4102444800 };
//! let token = signing_key.sign(&claims).unwrap();
//!
//! // Distribute public key to microservices
//! let pub_bytes = signing_key.verifying_key().to_bytes();
//!
//! // Microservice: verify with public key only
//! let verifying_key = Ed25519VerifyingKey::from_bytes(&pub_bytes).unwrap();
//! let verified: MyClaims = verifying_key.verify(&token, &ValidationConfig::default()).unwrap();
//! assert_eq!(verified.sub, "user-123");
//! ```

mod ed25519;
mod error;
mod header;
mod key;
mod validation;

pub use ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
pub use error::JwtError;
pub use key::HmacKey;
pub use validation::ValidationConfig;

// Re-export for convenience
pub use validation::RegisteredClaims;
