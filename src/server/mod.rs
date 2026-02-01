//! Server-side authentication utilities for Auth0 integration.
//!
//! This module provides server-side authentication functionality including:
//! - JWT claims extraction and validation
//! - JWKS (JSON Web Key Set) fetching and caching
//! - JWT token signature verification and claims validation
//! - Axum extractors for authentication (BearerToken, AuthenticatedUser)
//!
//! All modules in this package are only available when the `server` feature is enabled.
//!
//! # Example
//!
//! ```rust,ignore
//! use dxauth0::server::{extractors::AuthenticatedUser, validation::validate_token};
//!
//! // In a Dioxus server function
//! #[get("/api/protected", user: AuthenticatedUser)]
//! async fn protected_endpoint() -> Result<String> {
//!     tracing::info!("Authenticated user: {}", user.0.id);
//!     Ok(format!("Hello, {}!", user.0.display_name()))
//! }
//! ```
//!
//! # Setting Up Authentication State
//!
//! ```rust,ignore
//! use dxauth0::{Auth0Config, server::extractors::AuthState};
//! use dioxus::server::axum::Extension;
//!
//! let auth0_config = Auth0Config::from_env_server_or_panic();
//! let auth_state = AuthState::new(auth0_config);
//!
//! let router = dioxus::server::router(app)
//!     .layer(Extension(auth_state));
//! ```

pub mod callback;
pub mod claims;
pub mod extractors;
pub mod jwks;
pub mod validation;

// Re-export commonly used types and functions
pub use callback::{CallbackError, CallbackQuery, auth_me, logout, oauth_callback};
pub use claims::Claims;
pub use extractors::{AuthRejection, AuthState, AuthenticatedUser, BearerToken};
pub use jwks::{Jwk, JwksCache, JwksError};
pub use validation::{ValidationError, validate_token};

// Re-export cookie layer and manager for consuming crates
pub use axum_cookie::{CookieLayer, CookieManager};
