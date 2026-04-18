/// Errors that can occur during JWT operations.
///
/// Every variant includes enough context for debugging without leaking secrets.
///
/// **Important:** When returning errors to external clients (HTTP responses, APIs),
/// use [`JwtError::to_external()`] to avoid leaking internal validation details.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("token exceeds maximum size ({0} bytes, max {1})")]
    TokenTooLarge(usize, usize),

    #[error("malformed token: expected 3 dot-separated segments")]
    MalformedStructure,

    #[error("invalid base64url in {0}")]
    InvalidBase64(&'static str),

    #[error("invalid JSON in {0}: {1}")]
    InvalidJson(&'static str, String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("algorithm mismatch: header says {0}, key expects different algorithm")]
    AlgorithmMismatch(String),

    #[error("dangerous header field present: {0}")]
    DangerousHeader(&'static str),

    #[error("signature verification failed")]
    InvalidSignature,

    #[error("token expired (exp: {0}, now: {1})")]
    Expired(i64, i64),

    #[error("token not yet valid (nbf: {0}, now: {1})")]
    NotYetValid(i64, i64),

    #[error("missing required claim: {0}")]
    MissingClaim(&'static str),

    #[error("claim validation failed: {0}")]
    ClaimValidation(String),

    #[error("key too short: {0} bytes, minimum {1}")]
    KeyTooShort(usize, usize),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl JwtError {
    /// Convert to an opaque error message safe for external clients.
    ///
    /// In a zero-trust architecture, error responses to clients should not
    /// reveal internal validation details (which stage failed, what was expected).
    /// This method returns a single generic message for all token validation failures,
    /// while preserving distinct messages for key configuration errors.
    ///
    /// Use the `Debug` or `Display` impl for internal logging.
    pub fn to_external(&self) -> &'static str {
        match self {
            JwtError::KeyTooShort(_, _) => "invalid key configuration",
            JwtError::Serialization(_) => "token serialization error",
            _ => "invalid token",
        }
    }
}
