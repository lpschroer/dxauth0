//! Authentication extractors for Axum request handling.
//!
//! This module provides extractors for authentication data from HTTP requests,
//! including Bearer tokens and authenticated user information.

use crate::server::jwks::JwksCache;
use crate::server::validation::validate_token;
use crate::{Auth0Config, User};
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing;

/// Rejection type for authentication extraction failures.
#[derive(Debug)]
pub enum AuthRejection {
    /// Missing Authorization header
    MissingAuthorizationHeader,

    /// Invalid Authorization header format
    InvalidAuthorizationHeader,

    /// Invalid Bearer token format
    InvalidBearerToken,

    /// Token validation failed
    TokenValidationFailed,

    /// Auth configuration not available
    ConfigurationError,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthRejection::MissingAuthorizationHeader => {
                (StatusCode::UNAUTHORIZED, "Missing Authorization header")
            }
            AuthRejection::InvalidAuthorizationHeader => (
                StatusCode::BAD_REQUEST,
                "Invalid Authorization header format",
            ),
            AuthRejection::InvalidBearerToken => (StatusCode::UNAUTHORIZED, "Invalid Bearer token"),
            AuthRejection::TokenValidationFailed => {
                (StatusCode::UNAUTHORIZED, "Invalid or expired token")
            }
            AuthRejection::ConfigurationError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Authentication configuration error",
            ),
        };
        (status, message).into_response()
    }
}

/// Extractor for Bearer tokens from Authorization header or Cookie header.
///
/// Extracts the JWT from either:
/// - Authorization header: `Authorization: Bearer <token>`
/// - Cookie header: `Cookie: access_token=<token>`
///
/// The Authorization header (Bearer token) is preferred for mobile/desktop clients,
/// while the Cookie header is used for web/browser clients.
///
/// # Example
///
/// ```rust,ignore
/// #[get("/api/protected", token: BearerToken)]
/// async fn protected_endpoint() -> Result<String> {
///     tracing::debug!("Received JWT: {}", token.0);
///     Ok("Protected data".to_string())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct BearerToken(pub String);

impl<S> FromRequestParts<S> for BearerToken
where
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Try to extract from Authorization header first (for mobile/desktop)
        if let Some(auth_header) = parts.headers.get("Authorization") {
            let auth_str = auth_header
                .to_str()
                .map_err(|_| AuthRejection::InvalidAuthorizationHeader)?;

            // Check for Bearer prefix and extract token
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if token.is_empty() {
                    return Err(AuthRejection::InvalidBearerToken);
                }
                tracing::trace!(
                    "Extracted Bearer token from Authorization header: {} chars",
                    token.len()
                );
                return Ok(BearerToken(token.to_string()));
            } else {
                tracing::warn!("Authorization header missing 'Bearer ' prefix");
                return Err(AuthRejection::InvalidAuthorizationHeader);
            }
        }

        // Try to extract from Cookie header (for web/browser)
        if let Some(cookie_header) = parts.headers.get("Cookie") {
            let cookie_str = cookie_header
                .to_str()
                .map_err(|_| AuthRejection::InvalidAuthorizationHeader)?;

            // Parse cookies to find access_token
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some(token) = cookie.strip_prefix("access_token=") {
                    if token.is_empty() {
                        return Err(AuthRejection::InvalidBearerToken);
                    }
                    tracing::trace!("Extracted token from Cookie header: {} chars", token.len());
                    return Ok(BearerToken(token.to_string()));
                }
            }
            tracing::warn!("Cookie header present but no access_token found");
        }

        // Neither Authorization nor Cookie header with access_token found
        tracing::warn!("No Authorization header or Cookie with access_token found");
        Err(AuthRejection::MissingAuthorizationHeader)
    }
}

/// State required for AuthenticatedUser extractor.
///
/// This should be added to the Axum application state to enable
/// JWT validation in protected endpoints.
#[derive(Clone)]
pub struct AuthState {
    /// Auth0 configuration
    pub config: Auth0Config,
    /// JWKS cache for JWT validation
    pub jwks_cache: Arc<JwksCache>,
}

impl AuthState {
    /// Creates a new AuthState with the given configuration.
    pub fn new(config: Auth0Config) -> Self {
        let jwks_cache = Arc::new(JwksCache::new(config.clone()));
        Self { config, jwks_cache }
    }
}

/// Extractor for authenticated users.
///
/// Extracts and validates the JWT from the Authorization header,
/// then returns the authenticated User.
///
/// # Example
///
/// ```rust,ignore
/// #[get("/api/user/data", user: AuthenticatedUser)]
/// async fn get_user_data() -> Result<UserData> {
///     tracing::debug!("Authenticated user: {:?}", user.0);
///     // user.0.id, user.0.email, user.0.name available
///     Ok(fetch_data_for_user(user.0.id).await?)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub User);

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // First, extract the bearer token
        let bearer_token = BearerToken::from_request_parts(parts, state).await?;

        // Get auth state from extensions (set by middleware or app state)
        let auth_state = parts
            .extensions
            .get::<AuthState>()
            .ok_or(AuthRejection::ConfigurationError)?;

        // Validate the token and extract claims
        let claims = validate_token(&bearer_token.0, &auth_state.config, &auth_state.jwks_cache)
            .await
            .map_err(|e| {
                tracing::warn!("JWT validation failed: {}", e);
                AuthRejection::TokenValidationFailed
            })?;

        // Convert claims to user
        let user = User::with_details(
            claims.sub.clone(),
            claims.email.clone(),
            claims.name.clone(),
            claims.picture.clone(),
        );

        Ok(AuthenticatedUser(user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, header::AUTHORIZATION};

    #[tokio::test]
    async fn test_bearer_token_extraction() {
        let req = Request::builder()
            .header(AUTHORIZATION, "Bearer test_token_123")
            .body(())
            .unwrap();

        let (mut parts, _) = req.into_parts();

        let result = BearerToken::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, "test_token_123");
    }

    #[tokio::test]
    async fn test_bearer_token_missing_header() {
        let req = Request::builder().body(()).unwrap();

        let (mut parts, _) = req.into_parts();

        let result = BearerToken::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthRejection::MissingAuthorizationHeader
        ));
    }

    #[tokio::test]
    async fn test_bearer_token_invalid_prefix() {
        let req = Request::builder()
            .header(AUTHORIZATION, "Basic test_token_123")
            .body(())
            .unwrap();

        let (mut parts, _) = req.into_parts();

        let result = BearerToken::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthRejection::InvalidAuthorizationHeader
        ));
    }

    #[tokio::test]
    async fn test_bearer_token_empty_token() {
        let req = Request::builder()
            .header(AUTHORIZATION, "Bearer ")
            .body(())
            .unwrap();

        let (mut parts, _) = req.into_parts();

        let result = BearerToken::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthRejection::InvalidBearerToken
        ));
    }

    #[test]
    fn test_auth_rejection_into_response() {
        let rejection = AuthRejection::MissingAuthorizationHeader;
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let rejection = AuthRejection::TokenValidationFailed;
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let rejection = AuthRejection::ConfigurationError;
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_bearer_token_from_cookie() {
        let req = Request::builder()
            .header("Cookie", "access_token=test_cookie_token_123")
            .body(())
            .unwrap();

        let (mut parts, _) = req.into_parts();

        let result = BearerToken::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, "test_cookie_token_123");
    }

    #[tokio::test]
    async fn test_bearer_token_from_cookie_multiple_cookies() {
        let req = Request::builder()
            .header(
                "Cookie",
                "session=abc; access_token=test_token_456; other=xyz",
            )
            .body(())
            .unwrap();

        let (mut parts, _) = req.into_parts();

        let result = BearerToken::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, "test_token_456");
    }

    #[tokio::test]
    async fn test_bearer_token_from_cookie_empty_token() {
        let req = Request::builder()
            .header("Cookie", "access_token=")
            .body(())
            .unwrap();

        let (mut parts, _) = req.into_parts();

        let result = BearerToken::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthRejection::InvalidBearerToken
        ));
    }

    #[tokio::test]
    async fn test_bearer_token_from_cookie_missing_access_token() {
        let req = Request::builder()
            .header("Cookie", "session=abc; other=xyz")
            .body(())
            .unwrap();

        let (mut parts, _) = req.into_parts();

        let result = BearerToken::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthRejection::MissingAuthorizationHeader
        ));
    }

    #[tokio::test]
    async fn test_bearer_token_prefers_authorization_header() {
        let req = Request::builder()
            .header(AUTHORIZATION, "Bearer auth_token")
            .header("Cookie", "access_token=cookie_token")
            .body(())
            .unwrap();

        let (mut parts, _) = req.into_parts();

        let result = BearerToken::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
        // Should prefer Authorization header over Cookie
        assert_eq!(result.unwrap().0, "auth_token");
    }

    #[test]
    fn test_auth_state_creation() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );

        let auth_state = AuthState::new(config.clone());
        assert_eq!(auth_state.config.domain, "test.auth0.com");
        assert_eq!(auth_state.config.audience, "https://api.test.com");
    }
}
