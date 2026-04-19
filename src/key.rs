use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{de::DeserializeOwned, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::JwtError;
use crate::header::Header;
use crate::validation::ValidationConfig;

/// Minimum key length in bytes. NIST recommends >= 256 bits for HMAC-SHA256.
const MIN_KEY_BYTES: usize = 32;

/// Minimum key length in non-strict (dev) mode — 128 bits.
const MIN_KEY_BYTES_DEV: usize = 16;

/// An HMAC-SHA256 signing and verification key.
///
/// The algorithm is **pinned at the type level** — this key can ONLY produce
/// and verify HS256 tokens. There is no runtime algorithm selection.
///
/// # Example
/// ```rust
/// use ravauth_jwt::{HmacKey, ValidationConfig};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///     sub: String,
///     exp: i64,
/// }
///
/// let key = HmacKey::new(b"my-secret-key-that-is-at-least-32-bytes!", true).unwrap();
///
/// let claims = Claims { sub: "user-1".into(), exp: 4102444800 };
/// let token = key.sign(&claims).unwrap();
/// let verified: Claims = key.verify(&token, &ValidationConfig::default()).unwrap();
/// assert_eq!(verified.sub, "user-1");
/// ```
/// Secret is **zeroized on drop** — no key material left in freed memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HmacKey {
    secret: Vec<u8>,
    #[zeroize(skip)]
    kid: Option<String>,
}

impl HmacKey {
    /// Create a new HMAC-SHA256 key.
    ///
    /// When `strict` is `true`, the key must be at least 32 bytes (256 bits),
    /// per NIST recommendations for HMAC-SHA256. When `strict` is `false`
    /// (development/testing), the minimum is 16 bytes (128 bits). Empty or
    /// trivially short keys are never allowed.
    ///
    /// # Errors
    /// Returns `KeyTooShort` if `secret` is below the minimum for the mode.
    pub fn new(secret: &[u8], strict: bool) -> Result<Self, JwtError> {
        if strict && secret.len() < MIN_KEY_BYTES {
            return Err(JwtError::KeyTooShort(secret.len(), MIN_KEY_BYTES));
        }
        if !strict && secret.len() < MIN_KEY_BYTES_DEV {
            return Err(JwtError::KeyTooShort(secret.len(), MIN_KEY_BYTES_DEV));
        }
        Ok(Self {
            secret: secret.to_vec(),
            kid: None,
        })
    }

    /// Attach a key ID (`kid`) for key rotation support.
    /// The `kid` will be included in the JWT header.
    ///
    /// # Errors
    /// Returns `ClaimValidation` if `kid` is empty, too long, or contains invalid characters.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Result<Self, JwtError> {
        let kid = kid.into();
        Header::validate_kid(&kid)?;
        self.kid = Some(kid);
        Ok(self)
    }

    /// Sign claims and produce a compact JWS token string.
    ///
    /// The claims type must implement `Serialize`. It **must** include an `exp` field
    /// (numeric) or verification will always fail.
    ///
    /// # Errors
    /// Returns `Serialization` if the claims cannot be serialized to JSON.
    pub fn sign<T: Serialize>(&self, claims: &T) -> Result<String, JwtError> {
        let header = Header::hs256(self.kid.clone());

        let header_json =
            serde_json::to_vec(&header).map_err(|e| JwtError::Serialization(e.to_string()))?;
        let payload_json =
            serde_json::to_vec(claims).map_err(|e| JwtError::Serialization(e.to_string()))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(signing_input.as_bytes());
        let signature = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature);

        Ok(format!("{}.{}", signing_input, sig_b64))
    }

    /// Verify a token and decode its claims.
    ///
    /// Performs ALL checks in the correct, secure order:
    /// 1. **Size check** — reject oversized tokens (DoS prevention)
    /// 2. **Structural validation** — exactly 3 non-empty dot-separated segments
    /// 3. **Header parsing** — strict base64url, dangerous field rejection, algorithm check
    /// 4. **Signature verification** — constant-time HMAC comparison
    /// 5. **Payload parsing** — only AFTER signature is verified (no info leak)
    /// 6. **Temporal validation** — `exp` (mandatory), `nbf` (when present)
    /// 7. **Claim validation** — required claims checked against config
    ///
    /// # Type Parameter
    /// `T` must implement `DeserializeOwned`. Use your own claims struct, or
    /// [`RegisteredClaims`](crate::RegisteredClaims) to extract only standard fields.
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

        // 3. Header parsing + validation
        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| JwtError::InvalidBase64("header"))?;
        let header: Header = serde_json::from_slice(&header_bytes)
            .map_err(|e| JwtError::InvalidJson("header", e.to_string()))?;

        header.validate(crate::header::Algorithm::HS256, config.required_typ())?;

        // 4. Signature verification (constant-time)
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| JwtError::InvalidBase64("signature"))?;

        // HMAC-SHA256 produces exactly 32 bytes. Reject wrong-length signatures
        // before crypto comparison to prevent truncation or extension attacks.
        if sig_bytes.len() != 32 {
            return Err(JwtError::InvalidSignature);
        }

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(signing_input.as_bytes());
        mac.verify_slice(&sig_bytes)
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
        #[serde(skip_serializing_if = "Option::is_none")]
        permissions: Option<Vec<String>>,
    }

    fn key() -> HmacKey {
        HmacKey::new(b"test-secret-that-is-at-least-32-bytes-long!!", true).unwrap()
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
            permissions: None,
        }
    }

    // ── Happy Path ──

    #[test]
    fn sign_and_verify() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let v: TestClaims = k.verify(&token, &ValidationConfig::default()).unwrap();
        assert_eq!(v.sub, "user-123");
    }

    #[test]
    fn custom_claims_roundtrip() {
        let k = key();
        let mut c = claims(3600);
        c.role = Some("admin".into());
        c.permissions = Some(vec!["read:users".into(), "write:users".into()]);
        let token = k.sign(&c).unwrap();
        let v: TestClaims = k.verify(&token, &ValidationConfig::default()).unwrap();
        assert_eq!(v.role.unwrap(), "admin");
        assert_eq!(v.permissions.unwrap(), vec!["read:users", "write:users"]);
    }

    #[test]
    fn kid_in_header() {
        let k = key().with_kid("key-v1").unwrap();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let v: TestClaims = k.verify(&token, &ValidationConfig::default()).unwrap();
        assert_eq!(v.sub, "user-123");
    }

    #[test]
    fn registered_claims_extraction() {
        let k = key();
        let mut c = claims(3600);
        c.iss = Some("ravauth".into());
        let token = k.sign(&c).unwrap();
        let reg: crate::RegisteredClaims = k.verify(&token, &ValidationConfig::default()).unwrap();
        assert_eq!(reg.sub.unwrap(), "user-123");
        assert_eq!(reg.iss.unwrap(), "ravauth");
    }

    // ── Structural Attacks ──

    #[test]
    fn reject_empty_string() {
        let k = key();
        let r: Result<TestClaims, _> = k.verify("", &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::MalformedStructure)));
    }

    #[test]
    fn reject_two_segments() {
        let k = key();
        let r: Result<TestClaims, _> = k.verify("aaa.bbb", &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::MalformedStructure)));
    }

    #[test]
    fn reject_four_segments() {
        let k = key();
        let r: Result<TestClaims, _> = k.verify("a.b.c.d", &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::MalformedStructure)));
    }

    #[test]
    fn reject_empty_segments() {
        let k = key();
        let r: Result<TestClaims, _> = k.verify("..sig", &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::MalformedStructure)));
    }

    #[test]
    fn reject_oversized_token() {
        let k = key();
        let big = "a".repeat(9000);
        let token = format!("{}.{}.{}", big, big, big);
        let r: Result<TestClaims, _> = k.verify(&token, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::TokenTooLarge(_, _))));
    }

    // ── Algorithm Confusion ──

    #[test]
    fn reject_none_algorithm() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let tampered = forge_alg(&token, "none");
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err());
    }

    #[test]
    fn reject_rs256_confusion() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let tampered = forge_alg(&token, "RS256");
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err());
    }

    // ── Signature Attacks ──

    #[test]
    fn reject_wrong_key() {
        let k1 = key();
        let k2 = HmacKey::new(b"different-secret-also-32-bytes-or-more!!", true).unwrap();
        let c = claims(3600);
        let token = k1.sign(&c).unwrap();
        let r: Result<TestClaims, _> = k2.verify(&token, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::InvalidSignature)));
    }

    #[test]
    fn reject_tampered_payload() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let mut bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        bytes[0] ^= 0xff;
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(&bytes),
            parts[2]
        );
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::InvalidSignature)));
    }

    #[test]
    fn reject_empty_signature() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let tampered = format!("{}.{}.", parts[0], parts[1]);
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err());
    }

    // ── Temporal Attacks ──

    #[test]
    fn reject_expired() {
        let k = key();
        let c = claims(-3600);
        let token = k.sign(&c).unwrap();
        let r: Result<TestClaims, _> = k.verify(&token, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::Expired(_, _))));
    }

    #[test]
    fn accept_within_leeway() {
        let k = key();
        let c = claims(-20); // expired 20s ago, within 30s leeway
        let token = k.sign(&c).unwrap();
        let r: Result<TestClaims, _> = k.verify(&token, &ValidationConfig::default());
        assert!(r.is_ok());
    }

    #[test]
    fn reject_outside_leeway() {
        let k = key();
        let c = claims(-60); // expired 60s ago
        let token = k.sign(&c).unwrap();
        let r: Result<TestClaims, _> = k.verify(&token, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::Expired(_, _))));
    }

    #[test]
    fn reject_not_yet_valid() {
        let k = key();
        let mut c = claims(3600);
        c.nbf = Some(now() + 3600); // not valid for 1 hour
        let token = k.sign(&c).unwrap();
        let r: Result<TestClaims, _> = k.verify(&token, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::NotYetValid(_, _))));
    }

    #[test]
    fn reject_missing_exp() {
        #[derive(Serialize, Deserialize)]
        struct NoExp {
            sub: String,
        }
        let k = key();
        let token = k.sign(&NoExp { sub: "x".into() }).unwrap();
        let r: Result<NoExp, _> = k.verify(&token, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::MissingClaim("exp"))));
    }

    // ── Claim Validation ──

    #[test]
    fn reject_wrong_issuer() {
        let k = key();
        let mut c = claims(3600);
        c.iss = Some("evil".into());
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default().require_claim("iss", "ravauth");
        let r: Result<TestClaims, _> = k.verify(&token, &config);
        assert!(matches!(r, Err(JwtError::ClaimValidation(_))));
    }

    #[test]
    fn reject_missing_issuer_when_required() {
        let k = key();
        let c = claims(3600); // iss = None
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default().require_claim("iss", "ravauth");
        let r: Result<TestClaims, _> = k.verify(&token, &config);
        assert!(matches!(r, Err(JwtError::ClaimValidation(_))));
    }

    #[test]
    fn reject_wrong_audience() {
        let k = key();
        let mut c = claims(3600);
        c.aud = Some("wrong".into());
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default().require_claim("aud", "my-app");
        let r: Result<TestClaims, _> = k.verify(&token, &config);
        assert!(matches!(r, Err(JwtError::ClaimValidation(_))));
    }

    #[test]
    fn accept_correct_iss_and_aud() {
        let k = key();
        let mut c = claims(3600);
        c.iss = Some("ravauth".into());
        c.aud = Some("my-app".into());
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default()
            .require_claim("iss", "ravauth")
            .require_claim("aud", "my-app");
        let v: TestClaims = k.verify(&token, &config).unwrap();
        assert_eq!(v.iss.unwrap(), "ravauth");
        assert_eq!(v.aud.unwrap(), "my-app");
    }

    #[test]
    fn require_custom_claim() {
        let k = key();
        let mut c = claims(3600);
        c.role = Some("viewer".into());
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default().require_claim("role", "admin");
        let r: Result<TestClaims, _> = k.verify(&token, &config);
        assert!(matches!(r, Err(JwtError::ClaimValidation(_))));
    }

    // ── Dangerous Headers ──

    #[test]
    fn reject_jku_header() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let tampered = inject_header(&token, "jku", "\"https://evil.com/jwks\"");
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err());
    }

    #[test]
    fn reject_jwk_header() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let tampered = inject_header(&token, "jwk", "{\"kty\":\"oct\"}");
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err());
    }

    #[test]
    fn reject_x5u_header() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let tampered = inject_header(&token, "x5u", "\"https://evil.com/cert\"");
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err());
    }

    #[test]
    fn reject_crit_header() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let tampered = inject_header(&token, "crit", "[\"exp\"]");
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err());
    }

    // ── Key Length ──

    #[test]
    fn reject_short_key_strict() {
        assert!(matches!(
            HmacKey::new(b"short", true),
            Err(JwtError::KeyTooShort(5, 32))
        ));
    }

    #[test]
    fn allow_short_key_dev() {
        // Non-strict still requires 16 bytes minimum
        assert!(HmacKey::new(b"sixteen-byte-ok!", false).is_ok());
    }

    #[test]
    fn reject_very_short_key_dev() {
        // Even non-strict rejects keys under 16 bytes
        assert!(matches!(
            HmacKey::new(b"short", false),
            Err(JwtError::KeyTooShort(5, 16))
        ));
    }

    // ── Custom Max Size ──

    #[test]
    fn custom_max_size() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default().with_max_size(10);
        let r: Result<TestClaims, _> = k.verify(&token, &config);
        assert!(matches!(r, Err(JwtError::TokenTooLarge(_, _))));
    }

    // ── None Algorithm Rejection ──

    #[test]
    fn reject_none_mixed_case() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        for variant in &["nOnE", "noNe", "nONE", "NoNe", "NONE", "None", "none"] {
            let tampered = forge_alg(&token, variant);
            let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
            assert!(r.is_err(), "should reject alg={}", variant);
        }
    }

    // ── Token Type Validation ──

    #[test]
    fn reject_wrong_typ() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        // Default header typ is "JWT", require "access"
        let config = ValidationConfig::default().require_typ("access");
        let r: Result<TestClaims, _> = k.verify(&token, &config);
        assert!(matches!(r, Err(JwtError::ClaimValidation(_))));
    }

    #[test]
    fn accept_correct_typ() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        // Default typ is "JWT"
        let config = ValidationConfig::default().require_typ("JWT");
        let r: Result<TestClaims, _> = k.verify(&token, &config);
        assert!(r.is_ok());
    }

    // ── Max Age / Issued-At Validation ──

    #[test]
    fn reject_old_token_with_max_age() {
        let k = key();
        #[derive(Debug, Serialize, Deserialize)]
        struct ClaimsWithIat {
            sub: String,
            exp: i64,
            iat: i64,
        }
        let c = ClaimsWithIat {
            sub: "user-123".into(),
            exp: now() + 86400, // expires tomorrow
            iat: now() - 7200,  // issued 2 hours ago
        };
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default().with_max_age(3600); // max 1 hour
        let r: Result<ClaimsWithIat, _> = k.verify(&token, &config);
        assert!(matches!(r, Err(JwtError::ClaimValidation(_))));
    }

    #[test]
    fn accept_fresh_token_with_max_age() {
        let k = key();
        #[derive(Debug, Serialize, Deserialize)]
        struct ClaimsWithIat {
            sub: String,
            exp: i64,
            iat: i64,
        }
        let c = ClaimsWithIat {
            sub: "user-123".into(),
            exp: now() + 3600,
            iat: now() - 60, // issued 1 minute ago
        };
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default().with_max_age(3600);
        let r: Result<ClaimsWithIat, _> = k.verify(&token, &config);
        assert!(r.is_ok());
    }

    #[test]
    fn reject_missing_iat_when_max_age_set() {
        let k = key();
        let c = claims(3600); // no iat field
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default().with_max_age(3600);
        let r: Result<TestClaims, _> = k.verify(&token, &config);
        assert!(matches!(r, Err(JwtError::MissingClaim("iat"))));
    }

    #[test]
    fn reject_future_iat() {
        let k = key();
        #[derive(Debug, Serialize, Deserialize)]
        struct ClaimsWithIat {
            sub: String,
            exp: i64,
            iat: i64,
        }
        let c = ClaimsWithIat {
            sub: "user-123".into(),
            exp: now() + 7200,
            iat: now() + 3600, // issued in the future
        };
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default().with_max_age(3600);
        let r: Result<ClaimsWithIat, _> = k.verify(&token, &config);
        assert!(matches!(r, Err(JwtError::ClaimValidation(_))));
    }

    // ── Opaque Error Messages ──

    #[test]
    fn external_error_is_opaque() {
        let k = key();
        let r: Result<TestClaims, _> = k.verify("bad.token.here", &ValidationConfig::default());
        let err = r.unwrap_err();
        assert_eq!(err.to_external(), "invalid token");
        // Different internal errors all map to same external message
        let r2: Result<TestClaims, _> = k.verify("", &ValidationConfig::default());
        let err2 = r2.unwrap_err();
        assert_eq!(err2.to_external(), "invalid token");
    }

    // ── Dynamic Claim Names ──

    #[test]
    fn require_claim_with_dynamic_name() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let claim_name = String::from("sub");
        let config = ValidationConfig::default().require_claim(claim_name, "user-123");
        let r: Result<TestClaims, _> = k.verify(&token, &config);
        assert!(r.is_ok());
    }

    // ── Temporal Overflow Handling ──

    #[test]
    fn no_panic_on_exp_i64_max() {
        // A crafted token with exp = i64::MAX must not panic (overflow)
        let k = key();
        #[derive(Debug, Serialize, Deserialize)]
        struct MaxExpClaims {
            sub: String,
            exp: i64,
        }
        let c = MaxExpClaims {
            sub: "x".into(),
            exp: i64::MAX,
        };
        let token = k.sign(&c).unwrap();
        // Should succeed — exp is far in the future (saturating_add prevents overflow)
        let r: Result<MaxExpClaims, _> = k.verify(&token, &ValidationConfig::default());
        assert!(r.is_ok());
    }

    #[test]
    fn no_panic_on_nbf_zero_with_large_leeway() {
        // nbf=0, leeway=i64::MAX should not underflow
        let k = key();
        #[derive(Debug, Serialize, Deserialize)]
        struct NbfClaims {
            sub: String,
            exp: i64,
            nbf: i64,
        }
        let c = NbfClaims {
            sub: "x".into(),
            exp: now() + 3600,
            nbf: 0,
        };
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default().with_leeway(i64::MAX);
        let r: Result<NbfClaims, _> = k.verify(&token, &config);
        assert!(r.is_ok()); // nbf=0, saturating_sub(i64::MAX) = 0, now >= 0
    }

    #[test]
    fn no_panic_on_iat_near_zero_with_large_max_age() {
        // iat=0 with max_age=i64::MAX should not overflow in max_age + leeway
        let k = key();
        #[derive(Debug, Serialize, Deserialize)]
        struct IatClaims {
            sub: String,
            exp: i64,
            iat: i64,
        }
        let c = IatClaims {
            sub: "x".into(),
            exp: now() + 3600,
            iat: 0,
        };
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default().with_max_age(i64::MAX);
        let r: Result<IatClaims, _> = k.verify(&token, &config);
        assert!(r.is_ok()); // age is large but max_age.saturating_add(leeway) = i64::MAX
    }

    // ── Negative Parameter Rejection ──

    #[test]
    #[should_panic(expected = "leeway_secs must be non-negative")]
    fn reject_negative_leeway() {
        ValidationConfig::default().with_leeway(-1);
    }

    #[test]
    #[should_panic(expected = "max_age_secs must be non-negative")]
    fn reject_negative_max_age() {
        ValidationConfig::default().with_max_age(-1);
    }

    // ── Negative Timestamp Rejection ──

    #[test]
    fn reject_negative_exp_integer() {
        let k = key();
        #[derive(Debug, Serialize, Deserialize)]
        struct NegExpClaims {
            sub: String,
            exp: i64,
        }
        let c = NegExpClaims {
            sub: "x".into(),
            exp: -1,
        };
        let token = k.sign(&c).unwrap();
        let r: Result<NegExpClaims, _> = k.verify(&token, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::ClaimValidation(_))));
    }

    #[test]
    fn reject_negative_nbf_integer() {
        let k = key();
        #[derive(Debug, Serialize, Deserialize)]
        struct NegNbfClaims {
            sub: String,
            exp: i64,
            nbf: i64,
        }
        let c = NegNbfClaims {
            sub: "x".into(),
            exp: now() + 3600,
            nbf: -100,
        };
        let token = k.sign(&c).unwrap();
        let r: Result<NegNbfClaims, _> = k.verify(&token, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::ClaimValidation(_))));
    }

    #[test]
    fn reject_negative_iat_integer() {
        let k = key();
        #[derive(Debug, Serialize, Deserialize)]
        struct NegIatClaims {
            sub: String,
            exp: i64,
            iat: i64,
        }
        let c = NegIatClaims {
            sub: "x".into(),
            exp: now() + 3600,
            iat: -500,
        };
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default().with_max_age(3600);
        let r: Result<NegIatClaims, _> = k.verify(&token, &config);
        assert!(matches!(r, Err(JwtError::ClaimValidation(_))));
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

    // ── Config Builder Invariants ──

    #[test]
    fn config_fields_are_private() {
        // Can only set via builder methods — these enforce invariants
        let config = ValidationConfig::new().with_leeway(60).with_max_size(4096);
        assert_eq!(config.leeway_secs(), 60);
        assert_eq!(config.max_token_bytes(), 4096);
    }

    #[test]
    #[should_panic(expected = "max_token_bytes must be positive")]
    fn reject_zero_max_size() {
        ValidationConfig::default().with_max_size(0);
    }

    // ── kid Header Validation ──

    #[test]
    fn reject_kid_with_sql_injection() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let tampered = inject_header(&token, "kid", "\"key' OR '1'='1\"");
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err(), "should reject kid with SQL injection chars");
    }

    #[test]
    fn reject_kid_with_path_traversal() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let tampered = inject_header(&token, "kid", "\"../../etc/passwd\"");
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err(), "should reject kid with path traversal");
    }

    #[test]
    fn reject_kid_empty_string() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let tampered = inject_header(&token, "kid", "\"\"");
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err(), "should reject empty kid");
    }

    #[test]
    fn accept_valid_kid() {
        let k = key().with_kid("key-v1.2_prod:primary").unwrap();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let r: Result<TestClaims, _> = k.verify(&token, &ValidationConfig::default());
        assert!(r.is_ok(), "should accept valid kid chars");
    }

    // ── HMAC Signature Length Enforcement ──

    #[test]
    fn reject_truncated_hmac_signature() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        // Truncate signature to 16 bytes
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let truncated = URL_SAFE_NO_PAD.encode(&sig_bytes[..16]);
        let tampered = format!("{}.{}.{}", parts[0], parts[1], truncated);
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::InvalidSignature)));
    }

    #[test]
    fn reject_extended_hmac_signature() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        // Extend signature with extra bytes
        let mut sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        sig_bytes.extend_from_slice(&[0u8; 8]);
        let extended = URL_SAFE_NO_PAD.encode(&sig_bytes);
        let tampered = format!("{}.{}.{}", parts[0], parts[1], extended);
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(matches!(r, Err(JwtError::InvalidSignature)));
    }

    // ── Audience Array Support (RFC 7519) ──

    #[test]
    fn accept_aud_as_array() {
        let k = key();
        // Manually construct a token with aud as array
        let payload = serde_json::json!({
            "sub": "user-123",
            "exp": now() + 3600,
            "aud": ["my-app", "other-app"]
        });
        let token = sign_raw_payload(&k, &payload);
        let config = ValidationConfig::default().require_claim("aud", "my-app");
        let r: Result<serde_json::Value, _> = k.verify(&token, &config);
        assert!(
            r.is_ok(),
            "should accept aud array containing expected value"
        );
    }

    #[test]
    fn reject_aud_array_missing_expected() {
        let k = key();
        let payload = serde_json::json!({
            "sub": "user-123",
            "exp": now() + 3600,
            "aud": ["other-app", "third-app"]
        });
        let token = sign_raw_payload(&k, &payload);
        let config = ValidationConfig::default().require_claim("aud", "my-app");
        let r: Result<serde_json::Value, _> = k.verify(&token, &config);
        assert!(matches!(r, Err(JwtError::ClaimValidation(_))));
    }

    #[test]
    fn accept_aud_as_string() {
        let k = key();
        let mut c = claims(3600);
        c.aud = Some("my-app".into());
        let token = k.sign(&c).unwrap();
        let config = ValidationConfig::default().require_claim("aud", "my-app");
        let r: Result<TestClaims, _> = k.verify(&token, &config);
        assert!(r.is_ok());
    }

    /// Sign a raw serde_json::Value payload (for testing non-standard payloads)
    fn sign_raw_payload(key: &HmacKey, payload: &serde_json::Value) -> String {
        use hmac::Mac;
        let header = crate::header::Header::hs256(None);
        let header_json = serde_json::to_vec(&header).unwrap();
        let payload_json = serde_json::to_vec(payload).unwrap();
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let mut mac = Hmac::<Sha256>::new_from_slice(&key.secret).unwrap();
        mac.update(signing_input.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
        format!("{}.{}", signing_input, sig_b64)
    }

    // ── Unknown Header Fields (deny_unknown_fields) ──

    #[test]
    fn reject_unknown_header_field_x5t() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let tampered = inject_header(&token, "x5t", "\"thumbprint\"");
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err(), "should reject unknown header field x5t");
    }

    #[test]
    fn reject_unknown_header_field_b64() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let tampered = inject_header(&token, "b64", "true");
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err(), "should reject unknown header field b64");
    }

    #[test]
    fn reject_custom_vendor_header() {
        let k = key();
        let c = claims(3600);
        let token = k.sign(&c).unwrap();
        let tampered = inject_header(&token, "x-custom", "\"value\"");
        let r: Result<TestClaims, _> = k.verify(&tampered, &ValidationConfig::default());
        assert!(r.is_err(), "should reject custom vendor header");
    }

    // ── kid Validation on sign() Path ──

    #[test]
    fn reject_kid_sql_injection_on_sign() {
        let r = key().with_kid("key' OR '1'='1");
        assert!(r.is_err(), "with_kid should reject SQL injection");
    }

    #[test]
    fn reject_kid_path_traversal_on_sign() {
        let r = key().with_kid("../../etc/passwd");
        assert!(r.is_err(), "with_kid should reject path traversal");
    }

    #[test]
    fn reject_kid_empty_on_sign() {
        let r = key().with_kid("");
        assert!(r.is_err(), "with_kid should reject empty kid");
    }

    // ── Float Temporal Claim Rejection ──

    #[test]
    fn reject_float_exp() {
        let k = key();
        let payload = serde_json::json!({
            "sub": "user-123",
            "exp": 9.223372036854776e18
        });
        let token = sign_raw_payload(&k, &payload);
        let r: Result<serde_json::Value, _> = k.verify(&token, &ValidationConfig::default());
        assert!(r.is_err(), "should reject float exp");
    }

    #[test]
    fn reject_float_nbf() {
        let k = key();
        let payload = serde_json::json!({
            "sub": "user-123",
            "exp": now() + 3600,
            "nbf": 1.5
        });
        let token = sign_raw_payload(&k, &payload);
        let r: Result<serde_json::Value, _> = k.verify(&token, &ValidationConfig::default());
        assert!(r.is_err(), "should reject float nbf");
    }

    #[test]
    fn reject_float_iat() {
        let k = key();
        let payload = serde_json::json!({
            "sub": "user-123",
            "exp": now() + 3600,
            "iat": 1.5
        });
        let token = sign_raw_payload(&k, &payload);
        let r: Result<serde_json::Value, _> = k.verify(&token, &ValidationConfig::default());
        assert!(r.is_err(), "should reject float iat");
    }

    // ── iat Validation Without max_age ──

    #[test]
    fn reject_future_iat_without_max_age() {
        let k = key();
        let payload = serde_json::json!({
            "sub": "user-123",
            "exp": now() + 7200,
            "iat": now() + 3600
        });
        let token = sign_raw_payload(&k, &payload);
        // No max_age configured — iat should still be validated
        let r: Result<serde_json::Value, _> = k.verify(&token, &ValidationConfig::default());
        assert!(r.is_err(), "should reject future iat even without max_age");
    }

    #[test]
    fn reject_negative_iat_without_max_age() {
        let k = key();
        let payload = serde_json::json!({
            "sub": "user-123",
            "exp": now() + 3600,
            "iat": -100
        });
        let token = sign_raw_payload(&k, &payload);
        let r: Result<serde_json::Value, _> = k.verify(&token, &ValidationConfig::default());
        assert!(
            r.is_err(),
            "should reject negative iat even without max_age"
        );
    }

    #[test]
    fn accept_valid_iat_without_max_age() {
        let k = key();
        let payload = serde_json::json!({
            "sub": "user-123",
            "exp": now() + 3600,
            "iat": now() - 60
        });
        let token = sign_raw_payload(&k, &payload);
        let r: Result<serde_json::Value, _> = k.verify(&token, &ValidationConfig::default());
        assert!(r.is_ok(), "should accept valid iat without max_age");
    }
}
