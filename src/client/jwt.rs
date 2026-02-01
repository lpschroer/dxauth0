//! JWT decoding utilities for extracting claims from ID tokens.
//!
//! This module provides functionality to decode JWT ID tokens from Auth0
//! and extract user profile claims. It performs basic JWT parsing without
//! signature verification (verification should be done server-side).

use crate::User;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use tracing;

/// Standard OpenID Connect claims from Auth0 ID token.
///
/// These claims are extracted from the JWT payload and map to the User struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Subject - unique user identifier (required)
    pub sub: String,

    /// User's email address (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Email verification status (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    /// User's full name (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// User's given/first name (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,

    /// User's family/last name (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,

    /// User's nickname (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,

    /// URL to user's profile picture (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,

    /// Issuer - who issued the token (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Audience - who the token is intended for (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// Issued at timestamp (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,

    /// Expiration timestamp (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
}

impl IdTokenClaims {
    /// Converts ID token claims into a User struct.
    ///
    /// Logs the user name at debug level when creating the user.
    pub fn into_user(self) -> User {
        tracing::trace!(
            "Initializing User struct from ID token claims: sub={}, name={:?}, email={:?}",
            self.sub,
            self.name,
            self.email
        );

        User::with_details(self.sub, self.email, self.name, self.picture)
    }
}

/// Decodes a JWT ID token and extracts the claims.
///
/// This function performs basic JWT parsing without signature verification.
/// The token is assumed to be trusted since it comes directly from Auth0
/// via HTTPS. Server-side verification should be performed for API requests.
///
/// # Arguments
///
/// * `token` - The JWT ID token string
///
/// # Returns
///
/// * `Ok(IdTokenClaims)` - Successfully decoded claims
/// * `Err(String)` - Error message if decoding fails
///
/// # Example
///
/// ```ignore
/// let claims = decode_id_token(&id_token)?;
/// let user = claims.into_user();
/// ```
pub fn decode_id_token(token: &str) -> Result<IdTokenClaims, String> {
    tracing::trace!("Decoding ID token to extract user claims");

    // JWT format: header.payload.signature
    let parts: Vec<&str> = token.split('.').collect();

    if parts.len() != 3 {
        tracing::error!("Invalid JWT format: expected 3 parts, got {}", parts.len());
        return Err("Invalid JWT format: must have 3 parts separated by dots".to_string());
    }

    // We only need the payload (middle part)
    let payload = parts[1];

    // Decode base64url
    let decoded_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| format!("Failed to decode base64: {}", e))?;

    // Parse JSON
    let claims: IdTokenClaims = serde_json::from_slice(&decoded_bytes)
        .map_err(|e| format!("Failed to parse JWT claims: {}", e))?;

    tracing::trace!(
        "Successfully decoded ID token: sub={}, email={:?}",
        claims.sub,
        claims.email
    );

    Ok(claims)
}

/// Decodes a JWT ID token and converts it directly to a User struct.
///
/// This is a convenience function that combines `decode_id_token` and `into_user`.
///
/// # Arguments
///
/// * `token` - The JWT ID token string
///
/// # Returns
///
/// * `Ok(User)` - Successfully decoded user
/// * `Err(String)` - Error message if decoding fails
pub fn decode_id_token_to_user(token: &str) -> Result<User, String> {
    let claims = decode_id_token(token)?;
    Ok(claims.into_user())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create a test JWT
    fn create_test_jwt(payload: &str) -> String {
        // Simple header (not verified, so content doesn't matter)
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());

        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());

        // Dummy signature (not verified)
        let signature = "dummy_signature";

        format!("{}.{}.{}", header_b64, payload_b64, signature)
    }

    #[test]
    fn test_decode_id_token_full_claims() {
        let payload = r#"{
            "sub": "auth0|123456",
            "email": "test@example.com",
            "email_verified": true,
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "nickname": "tester",
            "picture": "https://example.com/avatar.jpg",
            "iss": "https://example.auth0.com/",
            "aud": "test_client_id",
            "iat": 1234567890,
            "exp": 1234571490
        }"#;

        let jwt = create_test_jwt(payload);
        let claims = decode_id_token(&jwt).unwrap();

        assert_eq!(claims.sub, "auth0|123456");
        assert_eq!(claims.email.as_deref(), Some("test@example.com"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.name.as_deref(), Some("Test User"));
        assert_eq!(claims.given_name.as_deref(), Some("Test"));
        assert_eq!(claims.family_name.as_deref(), Some("User"));
        assert_eq!(claims.nickname.as_deref(), Some("tester"));
        assert_eq!(
            claims.picture.as_deref(),
            Some("https://example.com/avatar.jpg")
        );
        assert_eq!(claims.iss.as_deref(), Some("https://example.auth0.com/"));
        assert_eq!(claims.aud.as_deref(), Some("test_client_id"));
        assert_eq!(claims.iat, Some(1234567890));
        assert_eq!(claims.exp, Some(1234571490));
    }

    #[test]
    fn test_decode_id_token_minimal_claims() {
        let payload = r#"{
            "sub": "auth0|123456"
        }"#;

        let jwt = create_test_jwt(payload);
        let claims = decode_id_token(&jwt).unwrap();

        assert_eq!(claims.sub, "auth0|123456");
        assert!(claims.email.is_none());
        assert!(claims.name.is_none());
        assert!(claims.picture.is_none());
    }

    #[test]
    fn test_decode_id_token_invalid_format() {
        let invalid_jwt = "not.a.valid.jwt.format";
        let result = decode_id_token(invalid_jwt);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must have 3 parts"));
    }

    #[test]
    fn test_decode_id_token_invalid_base64() {
        let jwt = "header.!@#$%^&*().signature";
        let result = decode_id_token(jwt);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_id_token_invalid_json() {
        let payload = "not valid json";
        let jwt = create_test_jwt(payload);
        let result = decode_id_token(&jwt);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse JWT claims"));
    }

    #[test]
    fn test_claims_into_user() {
        let claims = IdTokenClaims {
            sub: "auth0|123456".to_string(),
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            name: Some("Test User".to_string()),
            given_name: Some("Test".to_string()),
            family_name: Some("User".to_string()),
            nickname: Some("tester".to_string()),
            picture: Some("https://example.com/avatar.jpg".to_string()),
            iss: None,
            aud: None,
            iat: None,
            exp: None,
        };

        let user = claims.into_user();

        assert_eq!(user.id, "auth0|123456");
        assert_eq!(user.email.as_deref(), Some("test@example.com"));
        assert_eq!(user.name.as_deref(), Some("Test User"));
        assert_eq!(
            user.picture.as_deref(),
            Some("https://example.com/avatar.jpg")
        );
    }

    #[test]
    fn test_decode_id_token_to_user() {
        let payload = r#"{
            "sub": "auth0|123456",
            "email": "test@example.com",
            "name": "Test User",
            "picture": "https://example.com/avatar.jpg"
        }"#;

        let jwt = create_test_jwt(payload);
        let user = decode_id_token_to_user(&jwt).unwrap();

        assert_eq!(user.id, "auth0|123456");
        assert_eq!(user.email.as_deref(), Some("test@example.com"));
        assert_eq!(user.name.as_deref(), Some("Test User"));
        assert_eq!(
            user.picture.as_deref(),
            Some("https://example.com/avatar.jpg")
        );
    }

    #[test]
    fn test_claims_serialization() {
        let claims = IdTokenClaims {
            sub: "auth0|123456".to_string(),
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            name: Some("Test User".to_string()),
            given_name: None,
            family_name: None,
            nickname: None,
            picture: None,
            iss: None,
            aud: None,
            iat: None,
            exp: None,
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("auth0|123456"));
        assert!(json.contains("test@example.com"));
        assert!(json.contains("Test User"));
        // Optional None fields should be skipped
        assert!(!json.contains("given_name"));
    }

    #[test]
    fn test_claims_deserialization() {
        let json = r#"{
            "sub": "auth0|123456",
            "email": "test@example.com",
            "name": "Test User"
        }"#;

        let claims: IdTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "auth0|123456");
        assert_eq!(claims.email.as_deref(), Some("test@example.com"));
        assert_eq!(claims.name.as_deref(), Some("Test User"));
    }
}
