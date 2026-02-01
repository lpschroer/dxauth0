//! Client-side authentication utilities for Auth0 integration.
//!
//! This module provides client-side authentication functionality including:
//! - PKCE (Proof Key for Code Exchange) flow utilities
//! - Token storage in browser localStorage
//! - HTTP client configuration with authentication headers
//! - JWT ID token decoding and claims extraction
//! - Dioxus hooks for authentication state management
//!
//! All modules in this package are only available when the `client` feature is enabled.
//!
//! # Example
//!
//! ```rust,ignore
//! use dxauth0::client::{pkce, token_storage, jwt, use_auth};
//!
//! // Generate PKCE challenge for Auth0 login
//! let (verifier, challenge) = pkce::generate_pkce_challenge();
//!
//! // Store tokens after successful authentication
//! token_storage::store_tokens(access_token, id_token, refresh_token);
//!
//! // Decode ID token to get user info
//! let user = jwt::decode_id_token_to_user(&id_token)?;
//!
//! // Use the authentication hook in a Dioxus component
//! let auth = use_auth();
//! auth.login_default();
//! ```

pub mod http_client;
pub mod jwt;
pub mod pkce;
pub mod token_storage;
pub mod use_auth;

// Re-export commonly used types and functions
pub use jwt::{IdTokenClaims, decode_id_token, decode_id_token_to_user};
pub use pkce::{generate_code_challenge, generate_code_verifier};
pub use token_storage::{StoredTokens, TokenStorage};
pub use use_auth::{AuthContext, AuthState, use_auth, use_auth_provider};
