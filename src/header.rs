use serde::{Deserialize, Serialize};

use crate::error::JwtError;

/// Supported algorithms — each pinned to a specific key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithm {
    HS256,
    EdDSA,
}

impl Algorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::HS256 => "HS256",
            Algorithm::EdDSA => "EdDSA",
        }
    }
}

/// JWT header. Only fields we produce are serialized.
/// Dangerous fields are deserialized only so we can reject them.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Header {
    pub alg: String,
    pub typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    // Dangerous fields — deserialized to detect and reject
    #[serde(default, skip_serializing)]
    pub jku: Option<serde_json::Value>,
    #[serde(default, skip_serializing)]
    pub jwk: Option<serde_json::Value>,
    #[serde(default, skip_serializing)]
    pub x5u: Option<serde_json::Value>,
    #[serde(default, skip_serializing)]
    pub x5c: Option<serde_json::Value>,
    #[serde(default, skip_serializing)]
    pub crit: Option<serde_json::Value>,
}

impl Header {
    /// Validate a `kid` value. Returns an error if invalid.
    /// Used both during signing (in `with_kid()`) and verification (in `validate()`).
    pub(crate) fn validate_kid(kid: &str) -> Result<(), JwtError> {
        if kid.is_empty() || kid.len() > 256 {
            return Err(JwtError::ClaimValidation(
                "kid: must be 1-256 characters".into(),
            ));
        }
        if !kid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':')
        {
            return Err(JwtError::ClaimValidation(
                "kid: contains invalid characters (allowed: alphanumeric, -, _, ., :)".into(),
            ));
        }
        Ok(())
    }

    /// Create a new JWT header with the given algorithm.
    pub fn new(alg: Algorithm, kid: Option<String>) -> Self {
        Self {
            alg: alg.as_str().to_string(),
            typ: "JWT".to_string(),
            kid,
            jku: None,
            jwk: None,
            x5u: None,
            x5c: None,
            crit: None,
        }
    }

    /// Create a new HS256 JWT header.
    pub fn hs256(kid: Option<String>) -> Self {
        Self::new(Algorithm::HS256, kid)
    }

    /// Create a new EdDSA JWT header.
    pub fn eddsa(kid: Option<String>) -> Self {
        Self::new(Algorithm::EdDSA, kid)
    }

    /// Validate the header for security issues.
    /// The `expected_alg` parameter pins the algorithm to what the key type expects.
    /// The `expected_typ` parameter, when `Some`, requires an exact `typ` match.
    pub fn validate(
        &self,
        expected_alg: Algorithm,
        expected_typ: Option<&str>,
    ) -> Result<(), JwtError> {
        // Reject dangerous header fields (injection vectors)
        if self.jku.is_some() {
            return Err(JwtError::DangerousHeader("jku"));
        }
        if self.jwk.is_some() {
            return Err(JwtError::DangerousHeader("jwk"));
        }
        if self.x5u.is_some() {
            return Err(JwtError::DangerousHeader("x5u"));
        }
        if self.x5c.is_some() {
            return Err(JwtError::DangerousHeader("x5c"));
        }
        if self.crit.is_some() {
            return Err(JwtError::DangerousHeader("crit"));
        }

        // Validate kid — prevent injection attacks via kid field.
        if let Some(ref kid) = self.kid {
            Self::validate_kid(kid)?;
        }

        // Algorithm check — must match the expected algorithm exactly
        // Case-insensitive "none" rejection to prevent bypass via nOnE, NONE, etc.
        if self.alg.eq_ignore_ascii_case("none") {
            return Err(JwtError::UnsupportedAlgorithm(self.alg.clone()));
        }
        // Exact case-sensitive match against expected algorithm
        if self.alg == expected_alg.as_str() {
            // typ validation — prevents token type confusion attacks
            if let Some(expected) = expected_typ {
                if self.typ != expected {
                    return Err(JwtError::ClaimValidation(format!(
                        "typ: expected \"{}\", got \"{}\"",
                        expected, self.typ
                    )));
                }
            }
            Ok(())
        } else {
            Err(JwtError::AlgorithmMismatch(self.alg.clone()))
        }
    }
}
