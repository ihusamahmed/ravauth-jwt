//! EdDSA (Ed25519) signing and verification keys.
//!
//! Ed25519 is the strongest JWT signing algorithm available:
//! - **No nonce pitfalls** (unlike ECDSA which has catastrophic nonce reuse bugs)
//! - **Small keys** (32 bytes vs RSA's 2048+ bits)
//! - **Fast** (faster than RSA and ECDSA)
//! - **Deterministic signatures** (same input always produces same signature)
//! - **IETF RFC 8037** standard for JWS
//!
//! Use `Ed25519SigningKey` when you need to both sign and verify tokens (e.g. auth server).
//! Use `Ed25519VerifyingKey` when you only need to verify tokens (e.g. API gateway, microservice).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{de::DeserializeOwned, Serialize};
use zeroize::Zeroize;

use crate::error::JwtError;
use crate::header::{Algorithm, Header};
use crate::validation::ValidationConfig;

/// Ed25519 signing key (private key). Can sign AND verify tokens.
///
/// The algorithm is **pinned at the type level** — this key can ONLY produce
/// and verify EdDSA (Ed25519) tokens. No runtime algorithm selection.
///
/// # Example
/// ```rust
/// use ravauth_jwt::{Ed25519SigningKey, ValidationConfig};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///     sub: String,
///     exp: i64,
/// }
///
/// let signing_key = Ed25519SigningKey::generate();
/// let claims = Claims { sub: "user-1".into(), exp: 4102444800 };
/// let token = signing_key.sign(&claims).unwrap();
///
/// // Verify with the signing key
/// let verified: Claims = signing_key.verify(&token, &ValidationConfig::default()).unwrap();
/// assert_eq!(verified.sub, "user-1");
///
/// // Or extract the public verifying key for distribution
/// let verifying_key = signing_key.verifying_key();
/// let verified: Claims = verifying_key.verify(&token, &ValidationConfig::default()).unwrap();
/// assert_eq!(verified.sub, "user-1");
/// ```
/// Key material is **zeroized on drop** — no secrets left in freed memory.
pub struct Ed25519SigningKey {
    inner: SigningKey,
    kid: Option<String>,
}

impl Drop for Ed25519SigningKey {
    fn drop(&mut self) {
        // Zeroize the signing key bytes
        let mut bytes = self.inner.to_bytes();
        bytes.zeroize();
        // Overwrite inner with a dummy key derived from zeroed bytes
        // (the zeroed bytes are already overwritten, but this ensures
        //  the struct's memory is not holding the original key)
        self.inner = SigningKey::from_bytes(&[0u8; 32]);
    }
}

impl Clone for Ed25519SigningKey {
    fn clone(&self) -> Self {
        let mut bytes = self.inner.to_bytes();
        let cloned = Self {
            inner: SigningKey::from_bytes(&bytes),
            kid: self.kid.clone(),
        };
        bytes.zeroize();
        cloned
    }
}

impl Ed25519SigningKey {
    /// Generate a new random Ed25519 signing key.
    pub fn generate() -> Self {
        let mut csprng = rand_core::OsRng;
        Self {
            inner: SigningKey::generate(&mut csprng),
            kid: None,
        }
    }

    /// Create from raw 32-byte secret key.
    ///
    /// # Errors
    /// Returns `KeyTooShort` if `bytes` is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, JwtError> {
        if bytes.len() != 32 {
            return Err(JwtError::KeyTooShort(bytes.len(), 32));
        }
        let mut array: [u8; 32] = bytes.try_into().unwrap();
        let key = Self {
            inner: SigningKey::from_bytes(&array),
            kid: None,
        };
        array.zeroize();
        Ok(key)
    }

    /// Attach a key ID (`kid`) for key rotation support.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Export the raw 32-byte secret key.
    ///
    /// # Security
    /// The returned bytes are **not** automatically zeroized. The caller MUST
    /// ensure they are zeroized after use (e.g., with `zeroize::Zeroize`).
    /// Prefer using [`Ed25519SigningKey::verifying_key()`] to extract only
    /// the public key when possible.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Extract the public verifying key for distribution to services
    /// that only need to verify tokens (not sign them).
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey {
            inner: self.inner.verifying_key(),
            kid: self.kid.clone(),
        }
    }

    /// Sign claims and produce a compact JWS token string.
    pub fn sign<T: Serialize>(&self, claims: &T) -> Result<String, JwtError> {
        let header = Header::eddsa(self.kid.clone());

        let header_json =
            serde_json::to_vec(&header).map_err(|e| JwtError::Serialization(e.to_string()))?;
        let payload_json =
            serde_json::to_vec(claims).map_err(|e| JwtError::Serialization(e.to_string()))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let signature: Signature = self.inner.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{}.{}", signing_input, sig_b64))
    }

    /// Verify a token and decode its claims.
    /// Delegates to the verifying key's verification logic.
    pub fn verify<T: DeserializeOwned>(
        &self,
        token: &str,
        config: &ValidationConfig,
    ) -> Result<T, JwtError> {
        self.verifying_key().verify(token, config)
    }
}

/// Ed25519 verifying key (public key). Can ONLY verify tokens, not sign them.
///
/// Distribute this to microservices or API gateways that need to validate
/// tokens but should never be able to mint new ones.
///
/// # Example
/// ```rust
/// use ravauth_jwt::{Ed25519SigningKey, Ed25519VerifyingKey, ValidationConfig};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///     sub: String,
///     exp: i64,
/// }
///
/// // Auth server signs
/// let signing_key = Ed25519SigningKey::generate();
/// let claims = Claims { sub: "user-1".into(), exp: 4102444800 };
/// let token = signing_key.sign(&claims).unwrap();
///
/// // Export public key bytes for distribution
/// let pub_bytes = signing_key.verifying_key().to_bytes();
///
/// // API gateway verifies (only has public key)
/// let verifying_key = Ed25519VerifyingKey::from_bytes(&pub_bytes).unwrap();
/// let verified: Claims = verifying_key.verify(&token, &ValidationConfig::default()).unwrap();
/// assert_eq!(verified.sub, "user-1");
/// ```
#[derive(Clone)]
pub struct Ed25519VerifyingKey {
    inner: VerifyingKey,
    kid: Option<String>,
}

impl Ed25519VerifyingKey {
    /// Create from raw 32-byte public key.
    ///
    /// # Errors
    /// Returns `KeyTooShort` if `bytes` is not exactly 32 bytes,
    /// or `InvalidSignature` if the bytes are not a valid Ed25519 public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, JwtError> {
        if bytes.len() != 32 {
            return Err(JwtError::KeyTooShort(bytes.len(), 32));
        }
        let array: [u8; 32] = bytes.try_into().unwrap();
        let inner = VerifyingKey::from_bytes(&array).map_err(|_| JwtError::InvalidSignature)?;
        Ok(Self { inner, kid: None })
    }

    /// Attach a key ID (`kid`) for key rotation support.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Export the raw 32-byte public key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Verify a token and decode its claims.
    ///
    /// Performs ALL checks in the correct, secure order:
    /// 1. **Size check** — reject oversized tokens (DoS prevention)
    /// 2. **Structural validation** — exactly 3 non-empty dot-separated segments
    /// 3. **Header parsing** — strict base64url, dangerous field rejection, algorithm = EdDSA
    /// 4. **Signature verification** — Ed25519 signature check
    /// 5. **Payload parsing** — only AFTER signature is verified (no info leak)
    /// 6. **Temporal validation** — `exp` (mandatory), `nbf` (when present)
    /// 7. **Claim validation** — required claims checked against config
    pub fn verify<T: DeserializeOwned>(
        &self,
        token: &str,
        config: &ValidationConfig,
    ) -> Result<T, JwtError> {
        // 1. Size check
        if token.len() > config.max_token_bytes() {
            return Err(JwtError::TokenTooLarge(
                token.len(),
                config.max_token_bytes(),
            ));
        }

        // 2. Structural validation — exactly 3 segments
        let segments: Vec<&str> = token.splitn(4, '.').collect();
        if segments.len() != 3 {
            return Err(JwtError::MalformedStructure);
        }
        let (header_b64, payload_b64, sig_b64) = (segments[0], segments[1], segments[2]);

        if header_b64.is_empty() || payload_b64.is_empty() || sig_b64.is_empty() {
            return Err(JwtError::MalformedStructure);
        }

        // 3. Header parsing + validation (pinned to EdDSA)
        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| JwtError::InvalidBase64("header"))?;
        let header: Header = serde_json::from_slice(&header_bytes)
            .map_err(|e| JwtError::InvalidJson("header", e.to_string()))?;

        header.validate(Algorithm::EdDSA, config.required_typ())?;

        // 4. Signature verification
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| JwtError::InvalidBase64("signature"))?;

        if sig_bytes.len() != 64 {
            return Err(JwtError::InvalidSignature);
        }
        let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
        let signature = Signature::from_bytes(&sig_array);

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        self.inner
            .verify_strict(signing_input.as_bytes(), &signature)
            .map_err(|_| JwtError::InvalidSignature)?;

        // 5. Payload parsing (only AFTER signature verified — no info leak)
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| JwtError::InvalidBase64("payload"))?;

        // Parse as raw Value first for claim validation
        let payload_value: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| JwtError::InvalidJson("payload", e.to_string()))?;

        // 6 & 7. Temporal + claim validation
        config.validate_payload(&payload_value)?;

        // 8. Deserialize into caller's type
        serde_json::from_value(payload_value)
            .map_err(|e| JwtError::InvalidJson("payload (type mismatch)", e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestClaims {
        sub: String,
        exp: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        nbf: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        iss: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        role: Option<String>,
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn claims(exp_offset: i64) -> TestClaims {
        TestClaims {
            sub: "user-123".into(),
            exp: now() + exp_offset,
            nbf: None,
            iss: None,
            aud: None,
            role: None,
        }
    }

    // ── Happy Path ──

    #[test]
    fn sign_and_verify_with_signing_key() {
        let sk = Ed25519SigningKey::generate();
        let c = claims(3600);
        let token = sk.sign(&c).unwrap();
        let v: TestClaims = sk.verify(&token, &ValidationConfig::default()).unwrap();
        assert_eq!(v.sub, "user-123");
    }

    #[test]
    fn verify_with_public_key() {
        let sk = Ed25519SigningKey::generate();
        let vk = sk.verifying_key();
        let c = claims(3600);
        let token = sk.sign(&c).unwrap();
        let v: TestClaims = vk.verify(&token, &ValidationConfig::default()).unwrap();
        assert_eq!(v.sub, "user-123");
    }

    #[test]
    fn public_key_roundtrip_via_bytes() {
        let sk = Ed25519SigningKey::generate();
        let c = claims(3600);
        let token = sk.sign(&c).unwrap();

        // Export public key bytes and recreate
        let pub_bytes = sk.verifying_key().to_bytes();
        let vk = Ed25519VerifyingKey::from_bytes(&pub_bytes).unwrap();
        let v: TestClaims = vk.verify(&token, &ValidationConfig::default()).unwrap();
        assert_eq!(v.sub, "user-123");
    }

    #[test]
    fn private_key_roundtrip_via_bytes() {
        let sk1 = Ed25519SigningKey::generate();
        let c = claims(3600);
        let token = sk1.sign(&c).unwrap();

        // Export and recreate signing key
        let sk2 = Ed25519SigningKey::from_bytes(&sk1.to_bytes()).unwrap();
        let v: TestClaims = sk2.verify(&token, &ValidationConfig::default()).unwrap();
        assert_eq!(v.sub, "user-123");
    }

    #[test]
    fn kid_in_header() {
        let sk = Ed25519SigningKey::generate().with_kid("ed-key-v1");
        let c = claims(3600);
        let token = sk.sign(&c).unwrap();
        let v: TestClaims = sk.verify(&token, &ValidationConfig::default()).unwrap();
        assert_eq!(v.sub, "user-123");
    }

    #[test]
    fn custom_claims_roundtrip() {
        let sk = Ed25519SigningKey::generate();
        let mut c = claims(3600);
        c.role = Some("admin".into());
        let token = sk.sign(&c).unwrap();
        let v: TestClaims = sk.verify(&token, &ValidationConfig::default()).unwrap();
        assert_eq!(v.role.unwrap(), "admin");
    }

    // ── Signature Attacks ──

    #[test]
    fn reject_wrong_key() {
        let sk1 = Ed25519SigningKey::generate();
        let sk2 = Ed25519SigningKey::generate();
        let c = claims(3600);
        let token = sk1.sign(&c).unwrap();
        let r: Result<TestClaims, _> = sk2.verify(&token, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::InvalidSignature)));
    }

    #[test]
    fn reject_tampered_payload() {
        let sk = Ed25519SigningKey::generate();
        let c = claims(3600);
        let token = sk.sign(&c).unwrap();
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let mut bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        bytes[0] ^= 0xff;
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(&bytes),
            parts[2]
        );
        let r: Result<TestClaims, _> = sk.verify(&tampered, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::InvalidSignature)));
    }

    #[test]
    fn reject_empty_signature() {
        let sk = Ed25519SigningKey::generate();
        let c = claims(3600);
        let token = sk.sign(&c).unwrap();
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let tampered = format!("{}.{}.", parts[0], parts[1]);
        let r: Result<TestClaims, _> = sk.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err());
    }

    // ── Algorithm Confusion ──

    #[test]
    fn reject_hs256_token_on_eddsa_key() {
        // Sign with HMAC, try to verify with EdDSA key
        let hmac_key =
            crate::HmacKey::new(b"test-secret-that-is-at-least-32-bytes-long!!", true).unwrap();
        let c = claims(3600);
        let token = hmac_key.sign(&c).unwrap();

        let eddsa_key = Ed25519SigningKey::generate();
        let r: Result<TestClaims, _> = eddsa_key.verify(&token, &ValidationConfig::default());
        assert!(r.is_err()); // AlgorithmMismatch — header says HS256, key expects EdDSA
    }

    #[test]
    fn reject_eddsa_token_on_hmac_key() {
        // Sign with EdDSA, try to verify with HMAC key
        let eddsa_key = Ed25519SigningKey::generate();
        let c = claims(3600);
        let token = eddsa_key.sign(&c).unwrap();

        let hmac_key =
            crate::HmacKey::new(b"test-secret-that-is-at-least-32-bytes-long!!", true).unwrap();
        let r: Result<TestClaims, _> = hmac_key.verify(&token, &ValidationConfig::default());
        assert!(r.is_err()); // AlgorithmMismatch — header says EdDSA, key expects HS256
    }

    #[test]
    fn reject_none_algorithm() {
        let sk = Ed25519SigningKey::generate();
        let c = claims(3600);
        let token = sk.sign(&c).unwrap();
        let tampered = forge_alg(&token, "none");
        let r: Result<TestClaims, _> = sk.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err());
    }

    // ── Structural Attacks ──

    #[test]
    fn reject_empty_string() {
        let sk = Ed25519SigningKey::generate();
        let r: Result<TestClaims, _> = sk.verify("", &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::MalformedStructure)));
    }

    #[test]
    fn reject_oversized_token() {
        let sk = Ed25519SigningKey::generate();
        let big = "a".repeat(9000);
        let token = format!("{}.{}.{}", big, big, big);
        let r: Result<TestClaims, _> = sk.verify(&token, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::TokenTooLarge(_, _))));
    }

    // ── Dangerous Headers ──

    #[test]
    fn reject_jku_header() {
        let sk = Ed25519SigningKey::generate();
        let c = claims(3600);
        let token = sk.sign(&c).unwrap();
        let tampered = inject_header(&token, "jku", "\"https://evil.com/jwks\"");
        let r: Result<TestClaims, _> = sk.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err());
    }

    // ── Temporal Attacks ──

    #[test]
    fn reject_expired() {
        let sk = Ed25519SigningKey::generate();
        let c = claims(-3600);
        let token = sk.sign(&c).unwrap();
        let r: Result<TestClaims, _> = sk.verify(&token, &ValidationConfig::default());
        assert!(r.is_err());
    }

    #[test]
    fn accept_within_leeway() {
        let sk = Ed25519SigningKey::generate();
        let c = claims(-20);
        let token = sk.sign(&c).unwrap();
        let r: Result<TestClaims, _> = sk.verify(&token, &ValidationConfig::default());
        assert!(r.is_ok());
    }

    #[test]
    fn reject_not_yet_valid() {
        let sk = Ed25519SigningKey::generate();
        let mut c = claims(3600);
        c.nbf = Some(now() + 3600);
        let token = sk.sign(&c).unwrap();
        let r: Result<TestClaims, _> = sk.verify(&token, &ValidationConfig::default());
        assert!(r.is_err());
    }

    // ── Claim Validation ──

    #[test]
    fn require_issuer() {
        let sk = Ed25519SigningKey::generate();
        let mut c = claims(3600);
        c.iss = Some("evil".into());
        let token = sk.sign(&c).unwrap();
        let config = ValidationConfig::default().require_claim("iss", "ravauth");
        let r: Result<TestClaims, _> = sk.verify(&token, &config);
        assert!(matches!(r, Err(JwtError::ClaimValidation(_))));
    }

    #[test]
    fn accept_correct_issuer() {
        let sk = Ed25519SigningKey::generate();
        let mut c = claims(3600);
        c.iss = Some("ravauth".into());
        let token = sk.sign(&c).unwrap();
        let config = ValidationConfig::default().require_claim("iss", "ravauth");
        let v: TestClaims = sk.verify(&token, &config).unwrap();
        assert_eq!(v.iss.unwrap(), "ravauth");
    }

    // ── Key Length ──

    #[test]
    fn reject_wrong_size_private_key() {
        assert!(Ed25519SigningKey::from_bytes(b"too-short").is_err());
    }

    #[test]
    fn reject_wrong_size_public_key() {
        assert!(Ed25519VerifyingKey::from_bytes(b"too-short").is_err());
    }

    // ── Helpers ──

    fn forge_alg(token: &str, alg: &str) -> String {
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let mut header: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        header["alg"] = serde_json::Value::String(alg.into());
        let new_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        format!("{}.{}.{}", new_header, parts[1], parts[2])
    }

    fn inject_header(token: &str, field: &str, value: &str) -> String {
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let mut header: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        header[field] = serde_json::from_str(value).unwrap();
        let new_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        format!("{}.{}.{}", new_header, parts[1], parts[2])
    }
}
