//! JWT token validation for Auth0 authentication.
//!
//! This module provides functionality to validate JWT tokens from Auth0,
//! including signature verification and claims validation.

use crate::Auth0Config;
use crate::server::claims::Claims;
use crate::server::jwks::{JwksCache, JwksError};
use jsonwebtoken::{Validation, decode, decode_header};

/// Error types for token validation operations.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// JWT header is missing the kid (key ID) field
    #[error("JWT header missing 'kid' field")]
    MissingKid,

    /// Failed to decode JWT header
    #[error("Failed to decode JWT header: {0}")]
    HeaderDecodeError(#[from] jsonwebtoken::errors::Error),

    /// Failed to fetch or use JWKS key
    #[error("JWKS error: {0}")]
    JwksError(#[from] JwksError),

    /// Token validation failed
    #[error("Token validation failed: {0}")]
    ValidationFailed(String),

    /// Token has expired
    #[error("Token has expired")]
    TokenExpired,

    /// Invalid audience claim
    #[error("Invalid audience claim")]
    InvalidAudience,

    /// Invalid issuer claim
    #[error("Invalid issuer claim")]
    InvalidIssuer,
}

/// Validates a JWT token and returns the decoded claims.
///
/// This function performs comprehensive JWT validation including:
/// - Decoding the JWT header to extract the key ID (kid)
/// - Fetching the matching public key from JWKS cache
/// - Verifying the JWT signature using the public key
/// - Validating standard claims (aud, iss, exp)
/// - Decoding and returning the Claims struct
///
/// # Arguments
///
/// * `token` - The JWT token string to validate
/// * `config` - Auth0 configuration containing domain and audience
/// * `jwks_cache` - JWKS cache for fetching public keys
///
/// # Errors
///
/// Returns `ValidationError` if:
/// - The JWT header is missing or invalid
/// - The kid is missing from the header
/// - The key cannot be found in JWKS
/// - The signature is invalid
/// - The audience, issuer, or expiration claims are invalid
///
/// # Example
///
/// ```rust,ignore
/// let config = Auth0Config::from_env()?;
/// let jwks_cache = JwksCache::new(config.clone());
/// let claims = validate_token(&token, &config, &jwks_cache).await?;
/// println!("User ID: {}", claims.sub);
/// ```
pub async fn validate_token(
    token: &str,
    config: &Auth0Config,
    jwks_cache: &JwksCache,
) -> Result<Claims, ValidationError> {
    tracing::trace!("Validating JWT token");

    // 1. Decode JWT header to get kid
    let header = decode_header(token)?;
    tracing::trace!("Decoded JWT header: alg={:?}", header.alg);

    let kid = header.kid.ok_or(ValidationError::MissingKid)?;
    tracing::trace!("Found kid in JWT header: {}", kid);

    // 2. Fetch matching key from JWKS cache
    let jwk = jwks_cache.get_key(&kid).await?;
    tracing::trace!("Retrieved JWK for kid: {}", kid);

    // 3. Get algorithm and decoding key
    let algorithm = jwk.algorithm()?;
    let decoding_key = jwk.to_decoding_key()?;
    tracing::trace!("Using algorithm: {:?}", algorithm);

    // 4. Set up validation parameters
    let mut validation = Validation::new(algorithm);
    validation.set_audience(&[&config.audience]);
    validation.set_issuer(&[&config.issuer()]);
    tracing::trace!(
        "Validating with audience: {}, issuer: {}",
        config.audience,
        config.issuer()
    );

    // 5. Decode and validate token
    let token_data = decode::<Claims>(token, &decoding_key, &validation).map_err(|e| {
        tracing::warn!("Token validation failed: {}", e);
        match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => ValidationError::TokenExpired,
            jsonwebtoken::errors::ErrorKind::InvalidAudience => ValidationError::InvalidAudience,
            jsonwebtoken::errors::ErrorKind::InvalidIssuer => ValidationError::InvalidIssuer,
            _ => ValidationError::ValidationFailed(e.to_string()),
        }
    })?;

    tracing::trace!(
        "Successfully validated token for user: {}",
        token_data.claims.sub
    );
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::claims::Claims;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    // Helper function to create test claims
    fn create_test_claims(config: &Auth0Config) -> Claims {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Claims {
            sub: "auth0|test123".to_string(),
            iat: now,
            exp: now + 3600, // Valid for 1 hour
            aud: config.audience.clone(),
            iss: config.issuer(),
            email: Some("test@example.com".to_string()),
            name: Some("Test User".to_string()),
            picture: Some("https://example.com/avatar.jpg".to_string()),
        }
    }

    // Helper function to create expired test claims
    fn create_expired_claims(config: &Auth0Config) -> Claims {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Claims {
            sub: "auth0|test123".to_string(),
            iat: now - 7200, // Issued 2 hours ago
            exp: now - 3600, // Expired 1 hour ago
            aud: config.audience.clone(),
            iss: config.issuer(),
            email: Some("test@example.com".to_string()),
            name: Some("Test User".to_string()),
            picture: Some("https://example.com/avatar.jpg".to_string()),
        }
    }

    // Helper function to create claims with invalid audience
    fn create_invalid_audience_claims(config: &Auth0Config) -> Claims {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Claims {
            sub: "auth0|test123".to_string(),
            iat: now,
            exp: now + 3600,
            aud: "https://wrong-audience.com".to_string(), // Wrong audience
            iss: config.issuer(),
            email: Some("test@example.com".to_string()),
            name: Some("Test User".to_string()),
            picture: Some("https://example.com/avatar.jpg".to_string()),
        }
    }

    // Helper function to create claims with invalid issuer
    fn create_invalid_issuer_claims(config: &Auth0Config) -> Claims {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Claims {
            sub: "auth0|test123".to_string(),
            iat: now,
            exp: now + 3600,
            aud: config.audience.clone(),
            iss: "https://wrong-issuer.auth0.com/".to_string(), // Wrong issuer
            email: Some("test@example.com".to_string()),
            name: Some("Test User".to_string()),
            picture: Some("https://example.com/avatar.jpg".to_string()),
        }
    }

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::MissingKid;
        assert_eq!(err.to_string(), "JWT header missing 'kid' field");

        let err = ValidationError::TokenExpired;
        assert_eq!(err.to_string(), "Token has expired");

        let err = ValidationError::InvalidAudience;
        assert_eq!(err.to_string(), "Invalid audience claim");

        let err = ValidationError::InvalidIssuer;
        assert_eq!(err.to_string(), "Invalid issuer claim");

        let err = ValidationError::ValidationFailed("test error".to_string());
        assert_eq!(err.to_string(), "Token validation failed: test error");
    }

    #[tokio::test]
    async fn test_validate_token_missing_kid() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );
        let jwks_cache = JwksCache::new(config.clone());
        let claims = create_test_claims(&config);

        // Create a token without kid in header
        let header = Header::new(Algorithm::HS256); // Use HS256 which works with secret
        let encoding_key = EncodingKey::from_secret(b"secret");

        let token = encode(&header, &claims, &encoding_key).unwrap();

        let result = validate_token(&token, &config, &jwks_cache).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::MissingKid));
    }

    #[tokio::test]
    async fn test_validate_token_malformed() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );
        let jwks_cache = JwksCache::new(config.clone());

        // Test with completely invalid token format
        let result = validate_token("not.a.valid.jwt.token", &config, &jwks_cache).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::HeaderDecodeError(_)
        ));
    }

    #[tokio::test]
    async fn test_validate_token_empty_string() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );
        let jwks_cache = JwksCache::new(config.clone());

        // Test with empty string
        let result = validate_token("", &config, &jwks_cache).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::HeaderDecodeError(_)
        ));
    }

    // Note: Testing with actual JWKS fetching requires network access and is slow.
    // This test is removed in favor of integration tests that mock the JWKS endpoint.
    // The key-not-found scenario is covered by the JWKS cache tests.

    #[test]
    fn test_validation_error_from_jwks_error() {
        let jwks_err = JwksError::KeyNotFound("test123".to_string());
        let validation_err: ValidationError = jwks_err.into();
        assert!(matches!(validation_err, ValidationError::JwksError(_)));
    }

    #[test]
    fn test_validation_error_from_jwt_error() {
        let jwt_err = decode_header("invalid.token").unwrap_err();
        let validation_err: ValidationError = jwt_err.into();
        assert!(matches!(
            validation_err,
            ValidationError::HeaderDecodeError(_)
        ));
    }

    #[test]
    fn test_expired_claims_creation() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );
        let claims = create_expired_claims(&config);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        assert!(claims.exp < now, "Token should be expired");
    }

    #[test]
    fn test_invalid_audience_claims_creation() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );
        let claims = create_invalid_audience_claims(&config);

        assert_ne!(claims.aud, config.audience, "Audience should be different");
    }

    #[test]
    fn test_invalid_issuer_claims_creation() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );
        let claims = create_invalid_issuer_claims(&config);

        assert_ne!(claims.iss, config.issuer(), "Issuer should be different");
    }
}

#[cfg(test)]
mod integration_tests {
    //! Integration tests for JWT validation scenarios.
    //!
    //! These tests verify the complete JWT validation flow including:
    //! - Malformed tokens
    //! - Missing or invalid headers
    //! - JWKS cache interaction
    //!
    //! Note: Testing with valid Auth0 tokens requires a real Auth0 tenant
    //! and should be done in a staging/integration environment with:
    //! - Valid JWT from Auth0
    //! - Network access to Auth0's JWKS endpoint
    //! - Proper environment variables set (AUTH0_DOMAIN, AUTH0_AUDIENCE)

    use super::*;

    #[tokio::test]
    async fn test_validation_flow_with_malformed_tokens() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );
        let jwks_cache = JwksCache::new(config.clone());

        // Test various malformed token scenarios
        let test_cases = vec![
            ("", "empty string"),
            ("not-a-jwt", "invalid format"),
            ("only.two.parts", "incomplete JWT"),
            ("too.many.parts.in.this.jwt", "too many parts"),
            ("invalid base64!.invalid.invalid", "invalid base64"),
        ];

        for (token, description) in test_cases {
            let result = validate_token(token, &config, &jwks_cache).await;
            assert!(result.is_err(), "Token should be invalid: {}", description);
            assert!(
                matches!(result.unwrap_err(), ValidationError::HeaderDecodeError(_)),
                "Expected HeaderDecodeError for: {}",
                description
            );
        }
    }

    #[tokio::test]
    async fn test_validation_error_types() {
        // Test that each error type is properly created and displayed
        let errors = vec![
            ValidationError::MissingKid,
            ValidationError::TokenExpired,
            ValidationError::InvalidAudience,
            ValidationError::InvalidIssuer,
            ValidationError::ValidationFailed("test".to_string()),
        ];

        for error in errors {
            let error_string = error.to_string();
            assert!(!error_string.is_empty(), "Error should have description");
        }
    }

    #[test]
    fn test_decode_header_failures() {
        // Test various header decode failure scenarios
        let invalid_tokens = vec![
            "not-a-token",
            "",
            "a.b",         // Only 2 parts
            "!!!.!!!.!!!", // Invalid base64
        ];

        for token in invalid_tokens {
            let result = decode_header(token);
            assert!(
                result.is_err(),
                "Should fail to decode header for: {}",
                token
            );
        }
    }
}
