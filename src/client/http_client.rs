//! Authentication-aware HTTP client for WASM targets.
//!
//! This module provides utilities for configuring HTTP requests with authentication
//! headers when making server function calls from the browser.

/// Creates a configured reqwest client with authentication headers.
///
/// This function creates a reqwest client that can be used to make authenticated
/// requests to server functions. The client will automatically include the
/// Authorization header with the JWT token if available.
///
/// # Arguments
///
/// * `access_token` - Optional JWT access token to include in requests
///
/// # Returns
///
/// A configured `reqwest::Client` ready for making authenticated requests
#[cfg(target_arch = "wasm32")]
pub fn create_authenticated_client(
    access_token: Option<String>,
) -> Result<reqwest::Client, reqwest::Error> {
    use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

    let mut headers = HeaderMap::new();

    // Add Authorization header if token is available
    if let Some(token) = access_token {
        let auth_value = format!("Bearer {}", token);
        if let Ok(header_value) = HeaderValue::from_str(&auth_value) {
            headers.insert(AUTHORIZATION, header_value);
            tracing::trace!("Added Authorization header to HTTP client");
        } else {
            tracing::warn!("Failed to create Authorization header from token");
        }
    } else {
        tracing::trace!("No access token available - client will make unauthenticated requests");
    }

    // Build the client with custom headers
    reqwest::Client::builder().default_headers(headers).build()
}

/// Gets the current access token from localStorage.
///
/// This is a helper function to retrieve the stored access token
/// for use in creating authenticated HTTP clients.
#[cfg(target_arch = "wasm32")]
pub fn get_stored_access_token() -> Option<String> {
    use web_sys::window;

    let window = window()?;
    let storage = window.local_storage().ok()??;
    storage.get_item("access_token").ok()?
}

/// Adds an Authorization header to a reqwest::RequestBuilder.
///
/// This is a utility function for manually adding auth headers to
/// individual requests when not using a pre-configured client.
///
/// # Arguments
///
/// * `builder` - The reqwest::RequestBuilder to add headers to
/// * `access_token` - The JWT access token
///
/// # Returns
///
/// The RequestBuilder with the Authorization header added
#[cfg(target_arch = "wasm32")]
pub fn add_auth_header(
    builder: reqwest::RequestBuilder,
    access_token: &str,
) -> reqwest::RequestBuilder {
    let auth_value = format!("Bearer {}", access_token);
    builder.header("Authorization", auth_value)
}

/// Non-WASM stub implementations
#[cfg(not(target_arch = "wasm32"))]
pub fn create_authenticated_client(_access_token: Option<String>) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn get_stored_access_token() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_create_authenticated_client_with_token() {
        let token = "test_token_123".to_string();
        let client = create_authenticated_client(Some(token));
        assert!(client.is_ok());
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_create_authenticated_client_without_token() {
        let client = create_authenticated_client(None);
        assert!(client.is_ok());
    }

    #[test]
    fn test_get_stored_access_token_returns_none_in_tests() {
        // In test environment without proper browser context, should return None
        let token = get_stored_access_token();
        assert!(token.is_none());
    }
}
