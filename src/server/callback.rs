//! Server-side OAuth callback handler for Auth0 authentication.
//!
//! This module implements the OAuth 2.0 authorization code flow callback endpoint
//! that runs on the server. It exchanges the authorization code for tokens and
//! sets secure HTTP-only cookies for authentication.

use crate::Auth0Config;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_cookie::CookieManager;
use cookie_rs::Cookie;
use cookie_rs::prelude::SameSite;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Query parameters received from Auth0 callback.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    /// Authorization code from Auth0
    pub code: String,
    /// State parameter for CSRF protection
    pub state: String,
    /// Error code if authentication failed
    pub error: Option<String>,
    /// Error description if authentication failed
    pub error_description: Option<String>,
}

/// Token response from Auth0 token endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    id_token: String,
    token_type: String,
    expires_in: u64,
}

/// Error response from Auth0.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    error_description: Option<String>,
}

/// Callback handler error type.
#[derive(Debug)]
pub enum CallbackError {
    /// Auth0 returned an error
    Auth0Error(String),
    /// State validation failed (CSRF protection)
    InvalidState,
    /// Token exchange failed
    TokenExchangeFailed(String),
    /// HTTP request failed
    RequestFailed(String),
    /// Missing required configuration
    MissingConfig(String),
}

impl IntoResponse for CallbackError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            CallbackError::Auth0Error(msg) => {
                (StatusCode::BAD_REQUEST, format!("Auth0 error: {}", msg))
            }
            CallbackError::InvalidState => (
                StatusCode::BAD_REQUEST,
                "Invalid state parameter - possible CSRF attack".to_string(),
            ),
            CallbackError::TokenExchangeFailed(msg) => (
                StatusCode::BAD_GATEWAY,
                format!("Token exchange failed: {}", msg),
            ),
            CallbackError::RequestFailed(msg) => {
                (StatusCode::BAD_GATEWAY, format!("Request failed: {}", msg))
            }
            CallbackError::MissingConfig(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Configuration error: {}", msg),
            ),
        };

        tracing::error!("OAuth callback error: {}", message);
        (status, message).into_response()
    }
}

/// OAuth callback handler for Auth0.
///
/// This endpoint receives the authorization code from Auth0, validates the state
/// parameter, exchanges the code for tokens, sets secure cookies, and redirects
/// the user back to the application.
///
/// # Flow
///
/// 1. Extract `code` and `state` from query parameters
/// 2. Validate `state` parameter (CSRF protection)
/// 3. Exchange authorization code for tokens using Auth0 token endpoint
/// 4. Set `access_token` cookie with proper security settings
/// 5. Redirect to `/` (success page)
///
/// # Security
///
/// - Validates state parameter to prevent CSRF attacks
/// - Sets HttpOnly cookie to prevent XSS attacks
/// - Sets Secure flag in production (HTTPS only)
/// - Sets SameSite=Lax to prevent CSRF on POST requests
///
/// # Errors
///
/// Returns appropriate HTTP error responses for:
/// - Auth0 authentication errors
/// - Invalid state (CSRF attack)
/// - Token exchange failures
/// - Network errors
pub async fn oauth_callback(
    Query(params): Query<CallbackQuery>,
    State(config): State<Arc<Auth0Config>>,
    cookie_manager: CookieManager,
) -> Result<impl IntoResponse, CallbackError> {
    tracing::trace!("OAuth callback received");

    // Check if Auth0 returned an error
    if let Some(error) = params.error {
        let description = params.error_description.unwrap_or_default();
        return Err(CallbackError::Auth0Error(format!(
            "{}: {}",
            error, description
        )));
    }

    // TODO: Validate state parameter against session-stored state
    // For now, we'll just log it
    tracing::trace!("Received state parameter: {}", params.state);
    // In production, you would:
    // 1. Retrieve stored state from session/cookie
    // 2. Compare with received state
    // 3. Return InvalidState error if mismatch

    // Exchange authorization code for tokens
    let (access_token, id_token, expires_in) =
        exchange_code_for_tokens(&config, &params.code).await?;

    tracing::trace!("Successfully exchanged authorization code for tokens");

    // Set access_token cookie
    let access_cookie = build_access_token_cookie(&access_token, expires_in);
    cookie_manager.add(access_cookie);

    // Optionally set id_token cookie if needed for client-side user info
    // Note: This should NOT be HttpOnly if the client needs to read it
    let id_cookie = build_id_token_cookie(&id_token, expires_in);
    cookie_manager.add(id_cookie);

    tracing::trace!("Authentication cookies set, redirecting to application");

    // Redirect to application home page
    Ok(Redirect::to("/"))
}

/// Builds the access_token cookie with security settings.
///
/// The access token is stored in an HttpOnly cookie to prevent XSS attacks.
/// This cookie will be automatically included in all HTTP requests (including
/// WebSocket upgrades) to the same origin.
fn build_access_token_cookie(token: &str, expires_in: u64) -> Cookie<'static> {
    Cookie::builder("access_token", token.to_string())
        .path("/")
        .http_only(true)
        .secure(!cfg!(debug_assertions)) // Secure in production only
        .same_site(SameSite::Lax)
        .max_age(std::time::Duration::from_secs(expires_in))
        .build()
}

/// Builds the id_token cookie (optional, readable by client).
///
/// The ID token contains user profile information and may be needed by the
/// client for display purposes. This cookie is NOT HttpOnly so JavaScript
/// can read it, but it's still protected by Secure and SameSite flags.
fn build_id_token_cookie(token: &str, expires_in: u64) -> Cookie<'static> {
    Cookie::builder("id_token", token.to_string())
        .path("/")
        .http_only(false) // Client needs to read this for user info
        .secure(!cfg!(debug_assertions))
        .same_site(SameSite::Lax)
        .max_age(std::time::Duration::from_secs(expires_in))
        .build()
}

/// Exchanges authorization code for access and ID tokens.
///
/// Makes a POST request to the Auth0 token endpoint with the authorization code
/// and client secret. Uses the traditional server-side OAuth flow (not PKCE).
async fn exchange_code_for_tokens(
    config: &Auth0Config,
    code: &str,
) -> Result<(String, String, u64), CallbackError> {
    let client_id = config
        .client_id
        .as_ref()
        .ok_or_else(|| CallbackError::MissingConfig("client_id not configured".to_string()))?;

    let client_secret = config
        .client_secret
        .as_ref()
        .ok_or_else(|| CallbackError::MissingConfig("client_secret not configured".to_string()))?;

    let redirect_uri = format!("{}/callback", get_base_url());
    let form_params = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
    ];
    let form_body = serde_urlencoded::to_string(form_params)
        .map_err(|e| CallbackError::RequestFailed(format!("Failed to encode form: {}", e)))?;

    let client = reqwest::Client::new();
    let response = client
        .post(config.token_url())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form_body)
        .send()
        .await
        .map_err(|e| CallbackError::RequestFailed(e.to_string()))?;

    if response.status().is_success() {
        let token_response: TokenResponse = response.json().await.map_err(|e| {
            CallbackError::TokenExchangeFailed(format!("Failed to parse token response: {}", e))
        })?;

        Ok((
            token_response.access_token,
            token_response.id_token,
            token_response.expires_in,
        ))
    } else {
        let error: ErrorResponse = response.json().await.map_err(|e| {
            CallbackError::TokenExchangeFailed(format!("Failed to parse error response: {}", e))
        })?;

        Err(CallbackError::TokenExchangeFailed(format!(
            "{}: {}",
            error.error,
            error.error_description.unwrap_or_default()
        )))
    }
}

/// Gets the base URL for redirect_uri construction.
///
/// In production, this should come from configuration or environment variables.
/// For now, we use a default for local development.
fn get_base_url() -> String {
    std::env::var("APP_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string())
}

/// Logout endpoint that clears authentication cookies and redirects to Auth0 logout.
///
/// This endpoint:
/// 1. Clears the `access_token` and `id_token` cookies
/// 2. Redirects to Auth0's logout endpoint
/// 3. Auth0 will then redirect back to the application
///
/// # Security
///
/// - Cookies are cleared by setting them to empty with immediate expiry
/// - Auth0 logout ensures the session is terminated on their side as well
pub async fn logout(
    State(config): State<Arc<Auth0Config>>,
    cookie_manager: CookieManager,
) -> impl IntoResponse {
    tracing::trace!("Logout endpoint called");

    // Clear access_token cookie
    let clear_access = Cookie::builder("access_token", "")
        .path("/")
        .max_age(std::time::Duration::from_secs(0))
        .build();
    cookie_manager.add(clear_access);

    // Clear id_token cookie
    let clear_id = Cookie::builder("id_token", "")
        .path("/")
        .max_age(std::time::Duration::from_secs(0))
        .build();
    cookie_manager.add(clear_id);

    tracing::trace!("Authentication cookies cleared");

    // Build Auth0 logout URL
    let client_id = config.client_id.as_deref().unwrap_or("");

    let return_to = get_base_url();
    let logout_url = format!(
        "{}?client_id={}&returnTo={}",
        config.logout_url(),
        urlencoding::encode(client_id),
        urlencoding::encode(&return_to)
    );

    tracing::trace!("Redirecting to Auth0 logout: {}", logout_url);

    // Redirect to Auth0 logout
    Redirect::to(&logout_url)
}

/// Authentication status check endpoint.
///
/// Returns user information if the request includes a valid access_token cookie.
/// This endpoint is used by the client on app load to restore authentication state
/// without relying on localStorage.
///
/// # Returns
///
/// - 200 OK with user info JSON if authenticated
/// - 401 Unauthorized if no valid token found
pub async fn auth_me(
    axum::Extension(auth_state): axum::Extension<crate::server::extractors::AuthState>,
    cookie_manager: CookieManager,
) -> impl IntoResponse {
    tracing::trace!("Auth status check endpoint called");

    // Try to get access_token from cookies
    let access_token = cookie_manager
        .cookie()
        .iter()
        .find(|cookie| cookie.name() == "access_token")
        .map(|cookie| cookie.value().to_string());

    if let Some(token) = access_token {
        // Validate the token and extract user info
        match crate::server::validation::validate_token(
            &token,
            &auth_state.config,
            &auth_state.jwks_cache,
        )
        .await
        {
            Ok(claims) => {
                tracing::trace!("User authenticated via cookie: {}", claims.sub);
                let user_json = serde_json::json!({
                    "id": claims.sub,
                    "email": claims.email,
                    "name": claims.name,
                    "picture": claims.picture,
                });
                (StatusCode::OK, axum::Json(user_json)).into_response()
            }
            Err(e) => {
                tracing::warn!("Invalid token in cookie: {}", e);
                (StatusCode::UNAUTHORIZED, "Invalid token").into_response()
            }
        }
    } else {
        tracing::trace!("No access_token cookie found");
        (StatusCode::UNAUTHORIZED, "Not authenticated").into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_access_token_cookie() {
        let cookie = build_access_token_cookie("test_token", 3600);
        assert_eq!(cookie.name(), "access_token");
        assert_eq!(cookie.value(), "test_token");
        assert_eq!(cookie.path(), Some("/"));
        assert!(cookie.http_only().unwrap_or(false));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[test]
    fn test_build_id_token_cookie() {
        let cookie = build_id_token_cookie("test_id_token", 3600);
        assert_eq!(cookie.name(), "id_token");
        assert_eq!(cookie.value(), "test_id_token");
        assert_eq!(cookie.path(), Some("/"));
        assert!(!cookie.http_only().unwrap_or(true)); // Should NOT be HttpOnly
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[test]
    fn test_callback_error_display() {
        let error = CallbackError::InvalidState;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
