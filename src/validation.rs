use serde::Deserialize;

use crate::error::JwtError;

/// Controls what the verifier checks beyond the cryptographic signature.
///
/// # Example
/// ```rust
/// use ravauth_jwt::ValidationConfig;
///
/// let config = ValidationConfig::default()
///     .with_leeway(60)
///     .require_claim("iss", "ravauth")
///     .require_claim("aud", "my-app")
///     .require_typ("access")
///     .with_max_age(3600);
/// ```
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Clock skew tolerance in seconds (default: 30).
    /// Use [`with_leeway()`](Self::with_leeway) to set. Private to enforce non-negative invariant.
    leeway_secs: i64,

    /// Maximum token byte length (default: 8192). Prevents DoS via oversized tokens.
    /// Use [`with_max_size()`](Self::with_max_size) to set. Private to enforce positive invariant.
    max_token_bytes: usize,

    /// Maximum token age in seconds, validated against `iat` claim.
    /// When `Some`, tokens older than this are rejected even if `exp` hasn't passed.
    /// When `None` (default), `iat` is not checked.
    max_age_secs: Option<i64>,

    /// Required `typ` header value. When `Some`, tokens with a different
    /// (or missing) `typ` are rejected. Prevents token type confusion
    /// (e.g., refresh token accepted as access token).
    required_typ: Option<String>,

    /// Required exact-match string claims. Each `(claim_name, expected_value)`.
    required_claims: Vec<(String, String)>,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidationConfig {
    /// Create a new config with sensible defaults.
    pub fn new() -> Self {
        Self {
            leeway_secs: 30,
            max_token_bytes: 8192,
            max_age_secs: None,
            required_typ: None,
            required_claims: Vec::new(),
        }
    }

    /// Set clock skew tolerance. Must be non-negative.
    ///
    /// # Panics
    /// Panics if `secs` is negative.
    pub fn with_leeway(mut self, secs: i64) -> Self {
        assert!(secs >= 0, "leeway_secs must be non-negative, got {}", secs);
        self.leeway_secs = secs;
        self
    }

    /// Set maximum token size in bytes.
    ///
    /// # Panics
    /// Panics if `bytes` is zero.
    pub fn with_max_size(mut self, bytes: usize) -> Self {
        assert!(bytes > 0, "max_token_bytes must be positive, got 0");
        self.max_token_bytes = bytes;
        self
    }

    /// Get the current leeway in seconds.
    pub fn leeway_secs(&self) -> i64 {
        self.leeway_secs
    }

    /// Get the current maximum token size in bytes.
    pub fn max_token_bytes(&self) -> usize {
        self.max_token_bytes
    }

    /// Set maximum token age in seconds. Requires `iat` claim in the token.
    /// Tokens older than `secs` seconds are rejected even if `exp` is still valid.
    /// This limits the damage window for stolen long-lived tokens.
    ///
    /// # Panics
    /// Panics if `secs` is negative.
    pub fn with_max_age(mut self, secs: i64) -> Self {
        assert!(secs >= 0, "max_age_secs must be non-negative, got {}", secs);
        self.max_age_secs = Some(secs);
        self
    }

    /// Require the `typ` header to match an exact value (case-sensitive).
    /// Prevents token type confusion attacks (e.g., using a refresh token as access token).
    pub fn require_typ(mut self, typ: impl Into<String>) -> Self {
        self.required_typ = Some(typ.into());
        self
    }

    /// Get the required `typ` value, if set. Used by key verify methods to
    /// validate the header typ field.
    pub(crate) fn required_typ(&self) -> Option<&str> {
        self.required_typ.as_deref()
    }

    /// Require a string claim to match an exact value.
    /// The token is rejected if the claim is missing or doesn't match.
    pub fn require_claim(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.required_claims.push((name.into(), value.into()));
        self
    }

    /// Validate temporal and required claims against the raw JSON payload.
    pub(crate) fn validate_payload(&self, payload: &serde_json::Value) -> Result<(), JwtError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs() as i64;

        // exp is mandatory — must be a non-negative integer value
        let exp = match payload.get("exp") {
            Some(v) => {
                if let Some(i) = v.as_i64() {
                    if i < 0 {
                        return Err(JwtError::ClaimValidation(
                            "exp: numeric value out of range".into(),
                        ));
                    }
                    i
                } else {
                    return Err(JwtError::ClaimValidation(
                        "exp: expected integer value".into(),
                    ));
                }
            }
            None => return Err(JwtError::MissingClaim("exp")),
        };

        if now > exp.saturating_add(self.leeway_secs) {
            return Err(JwtError::Expired(exp, now));
        }

        // nbf is optional but enforced when present
        if let Some(nbf_val) = payload.get("nbf") {
            let nbf = if let Some(i) = nbf_val.as_i64() {
                if i < 0 {
                    return Err(JwtError::ClaimValidation(
                        "nbf: numeric value out of range".into(),
                    ));
                }
                i
            } else {
                return Err(JwtError::ClaimValidation(
                    "nbf: expected integer value".into(),
                ));
            };

            if now < nbf.saturating_sub(self.leeway_secs) {
                return Err(JwtError::NotYetValid(nbf, now));
            }
        }

        // iat sanity validation — always validate when present, regardless of max_age
        if let Some(iat_val) = payload.get("iat") {
            let iat = if let Some(i) = iat_val.as_i64() {
                if i < 0 {
                    return Err(JwtError::ClaimValidation(
                        "iat: numeric value out of range".into(),
                    ));
                }
                i
            } else {
                return Err(JwtError::ClaimValidation(
                    "iat: expected integer value".into(),
                ));
            };

            // Reject tokens with iat in the future (beyond leeway)
            if iat > now.saturating_add(self.leeway_secs) {
                return Err(JwtError::ClaimValidation(
                    "iat: issued in the future".into(),
                ));
            }

            // max_age check (only when configured)
            if let Some(max_age) = self.max_age_secs {
                let age = now.saturating_sub(iat);
                if age > max_age.saturating_add(self.leeway_secs) {
                    return Err(JwtError::ClaimValidation(format!(
                        "token too old: issued {}s ago, max age {}s",
                        age, max_age
                    )));
                }
            }
        } else if self.max_age_secs.is_some() {
            // iat is required when max_age is configured
            return Err(JwtError::MissingClaim("iat"));
        }

        // Required claims
        for (name, expected) in &self.required_claims {
            match payload.get(name.as_str()) {
                Some(val) => {
                    // RFC 7519: "aud" can be a string OR an array of strings.
                    // For "aud", check if the value is an array and if any element matches.
                    if name == "aud" {
                        if let Some(s) = val.as_str() {
                            if s != expected {
                                return Err(JwtError::ClaimValidation(format!(
                                    "{}: expected \"{}\", got \"{}\"",
                                    name, expected, s
                                )));
                            }
                        } else if let Some(arr) = val.as_array() {
                            let found = arr.iter().any(|v| v.as_str() == Some(expected.as_str()));
                            if !found {
                                return Err(JwtError::ClaimValidation(format!(
                                    "{}: expected \"{}\" not found in audience array",
                                    name, expected
                                )));
                            }
                        } else {
                            return Err(JwtError::ClaimValidation(format!(
                                "{}: expected string or array of strings, got {}",
                                name, val
                            )));
                        }
                    } else {
                        let actual = val.as_str().ok_or_else(|| {
                            JwtError::ClaimValidation(format!(
                                "{}: expected string, got {}",
                                name, val
                            ))
                        })?;
                        if actual != expected {
                            return Err(JwtError::ClaimValidation(format!(
                                "{}: expected \"{}\", got \"{}\"",
                                name, expected, actual
                            )));
                        }
                    }
                }
                None => {
                    // Leak-safe: use a generic message for missing claims
                    return Err(JwtError::ClaimValidation(format!(
                        "required claim \"{}\" is missing",
                        name
                    )));
                }
            }
        }

        Ok(())
    }
}

/// Helper struct for extracting registered JWT claims from any token.
/// Useful when you need to inspect standard claims without defining a full claims struct.
///
/// Note: `aud` is deserialized as `serde_json::Value` because RFC 7519 allows it
/// to be either a string or an array of strings. Use [`RegisteredClaims::aud_as_str()`]
/// or [`RegisteredClaims::aud_contains()`] for convenient access.
///
/// # Example
/// ```rust
/// use ravauth_jwt::{HmacKey, ValidationConfig, RegisteredClaims};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MyClaims { sub: String, exp: i64, custom: String }
///
/// let key = HmacKey::new(b"my-secret-key-that-is-at-least-32-bytes!", true).unwrap();
/// let claims = MyClaims { sub: "user-1".into(), exp: 4102444800, custom: "hello".into() };
/// let token = key.sign(&claims).unwrap();
///
/// // Verify and extract only registered claims
/// let registered: RegisteredClaims = key.verify(&token, &ValidationConfig::default()).unwrap();
/// assert_eq!(registered.sub.unwrap(), "user-1");
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct RegisteredClaims {
    pub sub: Option<String>,
    pub iss: Option<String>,
    pub aud: Option<serde_json::Value>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    pub jti: Option<String>,
}

impl RegisteredClaims {
    /// Get `aud` as a single string (returns `None` if it's an array or missing).
    pub fn aud_as_str(&self) -> Option<&str> {
        self.aud.as_ref().and_then(|v| v.as_str())
    }

    /// Check if the `aud` claim contains a specific audience value.
    /// Works for both string and array forms.
    pub fn aud_contains(&self, audience: &str) -> bool {
        match &self.aud {
            Some(v) if v.is_string() => v.as_str() == Some(audience),
            Some(v) if v.is_array() => v
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a.as_str() == Some(audience)),
            _ => false,
        }
    }
}
