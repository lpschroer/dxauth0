//! JWT Claims for Auth0 token validation.
//!
//! This module defines the Claims struct that represents the decoded JWT token
//! from Auth0, including standard JWT claims and Auth0-specific user claims.

use serde::{Deserialize, Deserializer, Serialize};

/// JWT Claims from Auth0 access and ID tokens.
///
/// This struct contains both standard JWT claims (sub, iat, exp, aud, iss)
/// and Auth0-specific user profile claims (email, name, picture).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    /// Subject - unique user identifier (e.g., "auth0|123456")
    pub sub: String,

    /// Issued at - timestamp when the token was issued (Unix epoch)
    pub iat: i64,

    /// Expiration - timestamp when the token expires (Unix epoch)
    pub exp: i64,

    /// Audience - the API identifier this token is intended for.
    /// Auth0 can return this as either a string or an array of strings.
    #[serde(deserialize_with = "deserialize_audience")]
    pub aud: String,

    /// Issuer - the Auth0 domain that issued the token
    pub iss: String,

    /// User's email address (optional, depends on scopes)
    #[serde(default)]
    pub email: Option<String>,

    /// User's display name (optional, depends on scopes)
    #[serde(default)]
    pub name: Option<String>,

    /// URL to user's profile picture (optional, depends on scopes)
    #[serde(default)]
    pub picture: Option<String>,
}

impl Claims {
    /// Checks if the token has expired.
    ///
    /// Compares the expiration timestamp with the current time.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        self.exp <= now
    }

    /// Validates the audience claim contains the expected audience.
    /// Handles both single audience strings and comma-separated multiple audiences.
    pub fn validate_audience(&self, expected_audience: &str) -> bool {
        self.aud == expected_audience || self.aud.split(',').any(|a| a == expected_audience)
    }

    /// Validates the issuer claim matches the expected issuer.
    pub fn validate_issuer(&self, expected_issuer: &str) -> bool {
        self.iss == expected_issuer
    }
}

/// Deserializes the audience claim which can be either a string or an array of strings.
///
/// Auth0 returns the `aud` claim in different formats depending on the configuration:
/// - Single audience: `"aud": "https://api.example.com"`
/// - Multiple audiences: `"aud": ["https://api.example.com", "https://example.auth0.com/userinfo"]`
///
/// This deserializer handles both cases. When multiple audiences are present,
/// they are joined with commas for storage in the `Claims.aud` string field.
///
/// # Arguments
///
/// * `deserializer` - The serde deserializer
///
/// # Returns
///
/// * `Ok(String)` - The audience as a single string (or comma-separated if multiple)
/// * `Err` - Deserialization error if the format is invalid
fn deserialize_audience<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum AudienceValue {
        Single(String),
        Multiple(Vec<String>),
    }

    match AudienceValue::deserialize(deserializer)? {
        AudienceValue::Single(s) => Ok(s),
        AudienceValue::Multiple(v) => Ok(v.join(",")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_claims() -> Claims {
        Claims {
            sub: "auth0|123456".to_string(),
            iat: 1609459200, // 2021-01-01 00:00:00 UTC
            exp: 1609545600, // 2021-01-02 00:00:00 UTC (24 hours later)
            aud: "https://api.example.com".to_string(),
            iss: "https://test.auth0.com/".to_string(),
            email: Some("test@example.com".to_string()),
            name: Some("Test User".to_string()),
            picture: Some("https://example.com/avatar.jpg".to_string()),
        }
    }

    #[test]
    fn test_claims_creation() {
        let claims = test_claims();
        assert_eq!(claims.sub, "auth0|123456");
        assert_eq!(claims.email, Some("test@example.com".to_string()));
        assert_eq!(claims.name, Some("Test User".to_string()));
        assert_eq!(
            claims.picture,
            Some("https://example.com/avatar.jpg".to_string())
        );
    }

    #[test]
    fn test_validate_audience() {
        let claims = test_claims();
        assert!(claims.validate_audience("https://api.example.com"));
        assert!(!claims.validate_audience("https://api.wrong.com"));
    }

    #[test]
    fn test_validate_issuer() {
        let claims = test_claims();
        assert!(claims.validate_issuer("https://test.auth0.com/"));
        assert!(!claims.validate_issuer("https://wrong.auth0.com/"));
    }

    #[test]
    fn test_is_expired_with_past_time() {
        let claims = Claims {
            sub: "auth0|123".to_string(),
            iat: 1000000000,
            exp: 1000001000, // Very old timestamp - definitely expired
            aud: "test".to_string(),
            iss: "test".to_string(),
            email: None,
            name: None,
            picture: None,
        };
        assert!(claims.is_expired());
    }

    #[test]
    fn test_is_expired_with_future_time() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = Claims {
            sub: "auth0|123".to_string(),
            iat: now,
            exp: now + 3600, // Expires in 1 hour
            aud: "test".to_string(),
            iss: "test".to_string(),
            email: None,
            name: None,
            picture: None,
        };
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_serialization() {
        let claims = test_claims();
        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims, deserialized);
    }

    #[test]
    fn test_clone() {
        let claims = test_claims();
        let cloned = claims.clone();
        assert_eq!(claims, cloned);
    }

    #[test]
    fn test_deserialization_with_missing_optional_fields() {
        let json = r#"{
            "sub": "auth0|999",
            "iat": 1609459200,
            "exp": 1609545600,
            "aud": "https://api.example.com",
            "iss": "https://test.auth0.com/"
        }"#;

        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "auth0|999");
        assert_eq!(claims.email, None);
        assert_eq!(claims.name, None);
        assert_eq!(claims.picture, None);
    }

    #[test]
    fn test_deserialization_with_all_fields() {
        let json = r#"{
            "sub": "auth0|123456",
            "iat": 1609459200,
            "exp": 1609545600,
            "aud": "https://api.example.com",
            "iss": "https://test.auth0.com/",
            "email": "test@example.com",
            "name": "Test User",
            "picture": "https://example.com/avatar.jpg"
        }"#;

        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "auth0|123456");
        assert_eq!(claims.email, Some("test@example.com".to_string()));
        assert_eq!(claims.name, Some("Test User".to_string()));
        assert_eq!(
            claims.picture,
            Some("https://example.com/avatar.jpg".to_string())
        );
    }

    #[test]
    fn test_deserialization_with_array_audience() {
        let json = r#"{
            "sub": "auth0|123456",
            "iat": 1609459200,
            "exp": 1609545600,
            "aud": ["https://api.example.com", "https://test.auth0.com/userinfo"],
            "iss": "https://test.auth0.com/"
        }"#;

        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "auth0|123456");
        assert!(claims.aud.contains("https://api.example.com"));
        assert!(claims.aud.contains("https://test.auth0.com/userinfo"));
    }

    #[test]
    fn test_deserialization_with_string_audience() {
        let json = r#"{
            "sub": "auth0|123456",
            "iat": 1609459200,
            "exp": 1609545600,
            "aud": "https://api.example.com",
            "iss": "https://test.auth0.com/"
        }"#;

        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.aud, "https://api.example.com");
    }
}
