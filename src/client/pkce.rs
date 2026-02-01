//! PKCE (Proof Key for Code Exchange) utilities for OAuth 2.0 authorization code flow.
//!
//! This module provides functions to generate code verifiers and code challenges
//! required for the PKCE flow, as specified in RFC 7636.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// Length of the code verifier in bytes (43-128 characters recommended by RFC 7636)
const CODE_VERIFIER_LENGTH: usize = 32;

/// Generates a cryptographically random code verifier for PKCE flow.
///
/// The code verifier is a high-entropy cryptographic random string using the
/// unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~".
pub fn generate_code_verifier() -> String {
    use rand::Rng;

    let random_bytes: Vec<u8> = rand::thread_rng()
        .sample_iter(rand::distributions::Standard)
        .take(CODE_VERIFIER_LENGTH)
        .collect();

    URL_SAFE_NO_PAD.encode(&random_bytes)
}

/// Generates a code challenge from a code verifier using SHA256.
///
/// The code challenge is derived from the code verifier by using SHA256
/// hashing and then base64url encoding the result.
pub fn generate_code_challenge(code_verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();

    URL_SAFE_NO_PAD.encode(hash)
}

/// Builds the authorization URL for Auth0 login with PKCE parameters.
///
/// Returns a complete URL that the user should be redirected to for authentication.
/// The audience parameter is required to receive a JWT access token instead of an opaque token.
pub fn build_authorization_url(
    domain: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    state: &str,
    audience: &str,
) -> String {
    format!(
        "https://{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email&code_challenge={}&code_challenge_method=S256&state={}&audience={}",
        domain,
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(code_challenge),
        urlencoding::encode(state),
        urlencoding::encode(audience)
    )
}

/// Generates a random state parameter for CSRF protection.
pub fn generate_state() -> String {
    use rand::Rng;

    let random_bytes: Vec<u8> = rand::thread_rng()
        .sample_iter(rand::distributions::Standard)
        .take(16)
        .collect();

    URL_SAFE_NO_PAD.encode(&random_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_verifier() {
        let verifier = generate_code_verifier();
        assert!(!verifier.is_empty());
        assert!(verifier.len() >= 43); // RFC 7636 minimum length
    }

    #[test]
    fn test_generate_code_challenge() {
        let verifier = "test_verifier_12345";
        let challenge = generate_code_challenge(verifier);
        assert!(!challenge.is_empty());
        // SHA256 hash encoded in base64 should be 43 characters
        assert_eq!(challenge.len(), 43);
    }

    #[test]
    fn test_code_challenge_is_deterministic() {
        let verifier = "test_verifier_12345";
        let challenge1 = generate_code_challenge(verifier);
        let challenge2 = generate_code_challenge(verifier);
        assert_eq!(challenge1, challenge2);
    }

    #[test]
    fn test_different_verifiers_produce_different_challenges() {
        let verifier1 = "verifier_1";
        let verifier2 = "verifier_2";
        let challenge1 = generate_code_challenge(verifier1);
        let challenge2 = generate_code_challenge(verifier2);
        assert_ne!(challenge1, challenge2);
    }

    #[test]
    fn test_build_authorization_url() {
        let url = build_authorization_url(
            "example.auth0.com",
            "client123",
            "http://localhost:8080/callback",
            "challenge123",
            "state123",
            "https://api.example.com",
        );

        assert!(url.contains("https://example.auth0.com/authorize"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=client123"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback"));
        assert!(url.contains("code_challenge=challenge123"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("scope=openid%20profile%20email"));
        assert!(url.contains("audience=https%3A%2F%2Fapi.example.com"));
    }

    /// Verifies that the authorization URL includes the audience parameter.
    ///
    /// This is critical for receiving JWT access tokens from Auth0.
    /// Without the audience parameter, Auth0 returns opaque access tokens
    /// that cannot be validated locally by the server.
    #[test]
    fn test_authorization_url_includes_audience_for_jwt_access_tokens() {
        let url = build_authorization_url(
            "example.auth0.com",
            "client123",
            "http://localhost:8080/callback",
            "challenge123",
            "state123",
            "https://api.example.com",
        );

        // The audience parameter MUST be present for Auth0 to return JWT access tokens.
        // Without it, Auth0 returns opaque tokens that cannot be decoded or validated.
        assert!(
            url.contains("audience="),
            "Authorization URL must include 'audience' parameter to receive JWT access tokens"
        );

        // Verify the audience value is properly URL-encoded
        assert!(
            url.contains("audience=https%3A%2F%2Fapi.example.com"),
            "Audience parameter must contain the API identifier"
        );
    }

    /// Verifies that an empty audience would still be included in the URL.
    ///
    /// This test documents the expected behavior - the function always includes
    /// the audience parameter, so callers must provide a valid API identifier.
    #[test]
    fn test_authorization_url_requires_non_empty_audience() {
        let url = build_authorization_url(
            "example.auth0.com",
            "client123",
            "http://localhost:8080/callback",
            "challenge123",
            "state123",
            "", // Empty audience - would cause Auth0 to return opaque tokens
        );

        // Even with empty audience, the parameter is included (but empty)
        // This test documents that callers are responsible for providing a valid audience
        assert!(url.contains("audience="));

        // An empty audience would result in "audience=" at the end with no value
        // This would cause Auth0 to return opaque tokens - callers must avoid this
        assert!(
            url.ends_with("audience="),
            "Empty audience results in parameter with no value - callers must provide valid API identifier"
        );
    }

    #[test]
    fn test_generate_state() {
        let state = generate_state();
        assert!(!state.is_empty());

        // Ensure different calls produce different states
        let state2 = generate_state();
        assert_ne!(state, state2);
    }
}
