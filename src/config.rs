//! Auth0 configuration for authentication.
//!
//! This module provides configuration for Auth0 authentication used by both
//! client-side and server-side code. The configuration includes domain, audience,
//! and optional client_id (required for client, not needed for server).

use serde::{Deserialize, Serialize};

/// Auth0 configuration for authentication.
///
/// This struct contains the Auth0 configuration used for both client-side
/// (Single Page Application) and server-side (JWT validation) authentication.
///
/// # Fields
///
/// - `domain`: Auth0 tenant domain (e.g., "your-tenant.auth0.com")
/// - `audience`: Auth0 API audience/identifier
/// - `client_id`: Auth0 application client ID (required for client, optional for server)
/// - `client_secret`: Auth0 application client secret (required for server-side OAuth callback)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Auth0Config {
    /// Auth0 tenant domain (e.g., "your-tenant.auth0.com")
    pub domain: String,

    /// Auth0 API audience/identifier
    pub audience: String,

    /// Auth0 application client ID (public identifier).
    ///
    /// Required for client-side SPA authentication, not needed for server-side JWT validation.
    pub client_id: Option<String>,

    /// Auth0 application client secret (confidential).
    ///
    /// Required for server-side OAuth callback to exchange authorization code for tokens.
    /// MUST be kept secret and only used on the server.
    pub client_secret: Option<String>,
}

impl Auth0Config {
    /// Creates a new Auth0Config for server-side use (without client_id).
    ///
    /// # Example
    ///
    /// ```
    /// # use dxauth0::Auth0Config;
    /// let config = Auth0Config::new_server(
    ///     "your-tenant.auth0.com".to_string(),
    ///     "https://api.example.com".to_string(),
    /// );
    /// assert!(config.client_id.is_none());
    /// ```
    pub fn new_server(domain: String, audience: String) -> Self {
        Self {
            domain,
            audience,
            client_id: None,
            client_secret: None,
        }
    }

    /// Creates a new Auth0Config for client-side use (with client_id).
    ///
    /// # Example
    ///
    /// ```
    /// # use dxauth0::Auth0Config;
    /// let config = Auth0Config::new_client(
    ///     "your-tenant.auth0.com".to_string(),
    ///     "your_client_id".to_string(),
    ///     "https://api.example.com".to_string(),
    /// );
    /// assert_eq!(config.client_id.as_deref(), Some("your_client_id"));
    /// ```
    pub fn new_client(domain: String, client_id: String, audience: String) -> Self {
        Self {
            domain,
            audience,
            client_id: Some(client_id),
            client_secret: None,
        }
    }

    /// Loads Auth0Config for client from compile-time environment variables.
    ///
    /// Expected environment variables:
    /// - `AUTH0_DOMAIN` - Auth0 tenant domain
    /// - `AUTH0_CLIENT_ID` - Auth0 application client ID
    /// - `AUTH0_AUDIENCE` - Auth0 API audience
    ///
    /// Returns `None` if any required environment variable is not set at compile time.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // For development without Auth0 setup, provide explicit test config
    /// let config = Auth0Config::from_env_client().unwrap_or_else(|| {
    ///     Auth0Config::new_client(
    ///         "test.auth0.com".to_string(),
    ///         "test_client_id".to_string(),
    ///         "https://api.test.com".to_string(),
    ///     )
    /// });
    /// ```
    pub fn from_env_client() -> Option<Self> {
        let domain = option_env!("AUTH0_DOMAIN")?;
        let client_id = option_env!("AUTH0_CLIENT_ID")?;
        let audience = option_env!("AUTH0_AUDIENCE")?;

        Some(Self {
            domain: domain.to_string(),
            client_id: Some(client_id.to_string()),
            audience: audience.to_string(),
            client_secret: None,
        })
    }

    /// Loads Auth0Config for server from compile-time environment variables.
    ///
    /// Expected environment variables:
    /// - `AUTH0_DOMAIN` - Auth0 tenant domain
    /// - `AUTH0_CLIENT_ID` - Auth0 application client ID (required for OAuth callback)
    /// - `AUTH0_CLIENT_SECRET` - Auth0 application client secret (required for OAuth callback)
    /// - `AUTH0_AUDIENCE` - Auth0 API audience
    ///
    /// Returns `None` if any required environment variable is not set at compile time.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // For development without Auth0 setup, provide explicit test config
    /// let config = Auth0Config::from_env_server().unwrap_or_else(|| {
    ///     Auth0Config::new_server(
    ///         "test.auth0.com".to_string(),
    ///         "https://api.test.com".to_string(),
    ///     )
    /// });
    /// ```
    pub fn from_env_server() -> Option<Self> {
        let domain = option_env!("AUTH0_DOMAIN")?;
        let client_id = option_env!("AUTH0_CLIENT_ID")?;
        let client_secret = option_env!("AUTH0_CLIENT_SECRET")?;
        let audience = option_env!("AUTH0_AUDIENCE")?;

        Some(Self {
            domain: domain.to_string(),
            audience: audience.to_string(),
            client_id: Some(client_id.to_string()),
            client_secret: Some(client_secret.to_string()),
        })
    }

    /// Loads Auth0Config for client from compile-time environment variables or panics.
    ///
    /// Expected environment variables:
    /// - `AUTH0_DOMAIN` - Auth0 tenant domain
    /// - `AUTH0_CLIENT_ID` - Auth0 application client ID
    /// - `AUTH0_AUDIENCE` - Auth0 API audience
    ///
    /// # Panics
    ///
    /// Panics with a clear error message if any required environment variable
    /// is not set at compile time. Use this in production builds where Auth0
    /// configuration is mandatory.
    pub fn from_env_client_or_panic() -> Self {
        Self::from_env_client().expect(
            "Auth0 client configuration not found. Please set the following environment variables at compile time:\n\
             - AUTH0_DOMAIN\n\
             - AUTH0_CLIENT_ID\n\
             - AUTH0_AUDIENCE\n\n\
             For local development without Auth0, consider using Auth0Config::new_client() with test values."
        )
    }

    /// Loads Auth0Config for server from compile-time environment variables or panics.
    ///
    /// Expected environment variables:
    /// - `AUTH0_DOMAIN` - Auth0 tenant domain
    /// - `AUTH0_CLIENT_ID` - Auth0 application client ID (required for OAuth callback)
    /// - `AUTH0_CLIENT_SECRET` - Auth0 application client secret (required for OAuth callback)
    /// - `AUTH0_AUDIENCE` - Auth0 API audience
    ///
    /// # Panics
    ///
    /// Panics with a clear error message if any required environment variable
    /// is not set at compile time. Use this in production builds where Auth0
    /// configuration is mandatory.
    pub fn from_env_server_or_panic() -> Self {
        Self::from_env_server().expect(
            "Auth0 server configuration not found. Please set the following environment variables at compile time:\n\
             - AUTH0_DOMAIN\n\
             - AUTH0_CLIENT_ID\n\
             - AUTH0_CLIENT_SECRET\n\
             - AUTH0_AUDIENCE\n\n\
             For local development without Auth0, consider using Auth0Config::new_server() with test values.\n\
             See docs/src/guides/auth0-setup.md for setup instructions."
        )
    }

    /// Returns the base URL for Auth0 API endpoints.
    ///
    /// # Example
    ///
    /// ```
    /// # use dxauth0::Auth0Config;
    /// let config = Auth0Config::new_server(
    ///     "test.auth0.com".to_string(),
    ///     "https://api.test.com".to_string(),
    /// );
    /// assert_eq!(config.base_url(), "https://test.auth0.com");
    /// ```
    pub fn base_url(&self) -> String {
        format!("https://{}", self.domain)
    }

    /// Returns the authorization endpoint URL.
    ///
    /// Used by client for initiating the OAuth flow.
    pub fn authorize_url(&self) -> String {
        format!("{}/authorize", self.base_url())
    }

    /// Returns the token endpoint URL.
    ///
    /// Used by client for exchanging authorization code for tokens.
    pub fn token_url(&self) -> String {
        format!("{}/oauth/token", self.base_url())
    }

    /// Returns the logout endpoint URL.
    ///
    /// Used by client for logout flow.
    pub fn logout_url(&self) -> String {
        format!("{}/v2/logout", self.base_url())
    }

    /// Returns the JWKS endpoint URL for JWT validation.
    ///
    /// Used by both client and server for fetching public keys.
    ///
    /// # Example
    ///
    /// ```
    /// # use dxauth0::Auth0Config;
    /// let config = Auth0Config::new_server(
    ///     "test.auth0.com".to_string(),
    ///     "https://api.test.com".to_string(),
    /// );
    /// assert_eq!(config.jwks_url(), "https://test.auth0.com/.well-known/jwks.json");
    /// ```
    pub fn jwks_url(&self) -> String {
        format!("{}/.well-known/jwks.json", self.base_url())
    }

    /// Returns the issuer URL for JWT validation.
    ///
    /// Used by server for validating the `iss` claim in JWTs.
    ///
    /// # Example
    ///
    /// ```
    /// # use dxauth0::Auth0Config;
    /// let config = Auth0Config::new_server(
    ///     "test.auth0.com".to_string(),
    ///     "https://api.test.com".to_string(),
    /// );
    /// assert_eq!(config.issuer(), "https://test.auth0.com/");
    /// ```
    pub fn issuer(&self) -> String {
        format!("{}/", self.base_url())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_server() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );

        assert_eq!(config.domain, "test.auth0.com");
        assert_eq!(config.audience, "https://api.test.com");
        assert!(config.client_id.is_none());
    }

    #[test]
    fn test_new_client() {
        let config = Auth0Config::new_client(
            "test.auth0.com".to_string(),
            "test_client_id".to_string(),
            "https://api.test.com".to_string(),
        );

        assert_eq!(config.domain, "test.auth0.com");
        assert_eq!(config.audience, "https://api.test.com");
        assert_eq!(config.client_id.as_deref(), Some("test_client_id"));
    }

    #[test]
    fn test_base_url() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );
        assert_eq!(config.base_url(), "https://test.auth0.com");
    }

    #[test]
    fn test_authorize_url() {
        let config = Auth0Config::new_client(
            "test.auth0.com".to_string(),
            "test_client_id".to_string(),
            "https://api.test.com".to_string(),
        );
        assert_eq!(config.authorize_url(), "https://test.auth0.com/authorize");
    }

    #[test]
    fn test_token_url() {
        let config = Auth0Config::new_client(
            "test.auth0.com".to_string(),
            "test_client_id".to_string(),
            "https://api.test.com".to_string(),
        );
        assert_eq!(config.token_url(), "https://test.auth0.com/oauth/token");
    }

    #[test]
    fn test_logout_url() {
        let config = Auth0Config::new_client(
            "test.auth0.com".to_string(),
            "test_client_id".to_string(),
            "https://api.test.com".to_string(),
        );
        assert_eq!(config.logout_url(), "https://test.auth0.com/v2/logout");
    }

    #[test]
    fn test_jwks_url() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );
        assert_eq!(
            config.jwks_url(),
            "https://test.auth0.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn test_issuer() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );
        assert_eq!(config.issuer(), "https://test.auth0.com/");
    }

    #[test]
    fn test_clone() {
        let config1 = Auth0Config::new_client(
            "test.auth0.com".to_string(),
            "test_client_id".to_string(),
            "https://api.test.com".to_string(),
        );
        let config2 = config1.clone();
        assert_eq!(config1, config2);
    }

    #[test]
    fn test_serialization() {
        let config = Auth0Config::new_client(
            "test.auth0.com".to_string(),
            "test_client_id".to_string(),
            "https://api.test.com".to_string(),
        );

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Auth0Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_from_env_client() {
        // When environment variables are set at compile time (e.g., from .env file),
        // from_env_client() should return Some with the values
        let config = Auth0Config::from_env_client();

        // If .env file exists with AUTH0_* variables, this will be Some
        // Otherwise it will be None
        if let Some(cfg) = config {
            assert!(!cfg.domain.is_empty());
            assert!(!cfg.audience.is_empty());
            assert!(cfg.client_id.is_some());
        }
    }

    #[test]
    fn test_from_env_server() {
        // When environment variables are set at compile time (e.g., from .env file),
        // from_env_server() should return Some with the values
        let config = Auth0Config::from_env_server();

        // If .env file exists with AUTH0_* variables, this will be Some
        // Otherwise it will be None
        if let Some(cfg) = config {
            assert!(!cfg.domain.is_empty());
            assert!(!cfg.audience.is_empty());
            assert!(cfg.client_id.is_none());
        }
    }

    #[test]
    fn test_from_env_client_or_panic() {
        // When environment variables are set (e.g., from .env file),
        // from_env_client_or_panic() should return the config successfully
        if Auth0Config::from_env_client().is_some() {
            let config = Auth0Config::from_env_client_or_panic();
            assert!(!config.domain.is_empty());
            assert!(config.client_id.is_some());
        }
    }

    #[test]
    fn test_from_env_server_or_panic() {
        // When environment variables are set (e.g., from .env file),
        // from_env_server_or_panic() should return the config successfully
        if Auth0Config::from_env_server().is_some() {
            let config = Auth0Config::from_env_server_or_panic();
            assert!(!config.domain.is_empty());
            assert!(config.client_id.is_none());
        }
    }
}
