//! # dxauth0
//!
//! A comprehensive authentication library for Dioxus fullstack applications using Auth0.
//!
//! This crate provides a complete, feature-gated authentication solution that eliminates
//! code duplication between client and server while maintaining clean separation of concerns.
//!
//! ## Overview
//!
//! `dxauth0` centralizes all Auth0 authentication logic in a single crate with three main components:
//!
//! - **Shared types** (`Auth0Config`, `User`) - Available in all contexts
//! - **Client-side utilities** - PKCE flow, token storage, JWT decoding (WASM-compatible)
//! - **Server-side utilities** - JWT validation, JWKS caching, Axum extractors (native-only)
//!
//! ## Features
//!
//! ### `client` (WASM-compatible)
//!
//! Enables client-side authentication utilities:
//! - PKCE (Proof Key for Code Exchange) flow implementation
//! - Secure token storage using browser LocalStorage
//! - ID token decoding and user profile extraction
//! - HTTP client for token exchange with Auth0
//!
//! **Dependencies**: `dioxus`, `base64`, `sha2`, `rand`, `web-sys`, `wasm-bindgen`, `reqwest`
//!
//! ### `server` (Native-only)
//!
//! Enables server-side authentication utilities:
//! - JWT signature validation using JWKS
//! - Claims extraction and verification
//! - JWKS caching for performance
//! - Axum extractors (`BearerToken`, `AuthenticatedUser`, `AuthState`)
//!
//! **Dependencies**: `axum`, `jsonwebtoken`, `tokio`, `thiserror`, `reqwest`
//!
//! **Note**: Server features are automatically excluded from WASM builds via target guards.
//!
//! ## Usage Examples
//!
//! ### Client-Side (WASM)
//!
//! ```rust,ignore
//! use dxauth0::{Auth0Config, User};
//! use dxauth0::client::{pkce, token_storage::TokenStorage, jwt::decode_id_token_to_user};
//!
//! // Initialize Auth0 config
//! let config = Auth0Config::from_env_client_or_panic();
//!
//! // Generate PKCE challenge
//! let (verifier, challenge) = pkce::generate_pkce_pair();
//!
//! // Build authorization URL
//! let auth_url = config.authorize_url(
//!     "http://localhost:8080/callback",
//!     &challenge,
//!     "openid profile email",
//! );
//!
//! // After callback, exchange code for tokens
//! // (See client::http_client module for token exchange)
//!
//! // Store tokens securely
//! TokenStorage::set_access_token("access_token_here");
//! TokenStorage::set_id_token("id_token_here");
//!
//! // Decode user from ID token
//! let user: User = decode_id_token_to_user("id_token_here")?;
//! ```
//!
//! ### Server-Side (Native)
//!
//! ```rust,ignore
//! use dxauth0::{Auth0Config, User};
//! use dxauth0::server::extractors::{AuthenticatedUser, AuthState};
//! use dioxus::prelude::*;
//! use axum::Extension;
//!
//! // Setup authentication state in your server
//! let auth0_config = Auth0Config::from_env_server_or_panic();
//! let auth_state = AuthState::new(auth0_config);
//!
//! // Add to Axum router
//! let router = dioxus::server::router(app)
//!     .layer(Extension(auth_state));
//!
//! // Use in Dioxus server functions
//! #[get("/api/protected", user: AuthenticatedUser)]
//! pub async fn protected_endpoint() -> Result<String> {
//!     tracing::info!("Authenticated user: {}", user.0.id);
//!     Ok(format!("Hello, {}!", user.0.display_name()))
//! }
//! ```
//!
//! ## Architecture
//!
//! ### Shared Types (Always Available)
//!
//! - `Auth0Config` - Configuration for Auth0 domain, audience, client ID
//! - `User` - User profile with id, email, name, picture
//!
//! ### Client Module (`cfg(feature = "client")`)
//!
//! - `client::pkce` - PKCE code verifier and challenge generation
//! - `client::token_storage` - Secure token persistence in LocalStorage
//! - `client::jwt` - ID token decoding and user extraction
//! - `client::http_client` - Token exchange with Auth0
//!
//! ### Server Module (`cfg(all(feature = "server", not(target_arch = "wasm32")))`)
//!
//! - `server::claims` - JWT claims structure
//! - `server::jwks` - JWKS fetching and caching
//! - `server::validation` - JWT signature and claims validation
//! - `server::extractors` - Axum extractors for authentication
//!
//! ## Platform Compatibility
//!
//! | Feature | WASM (Client) | Native (Server) |
//! |---------|---------------|-----------------|
//! | Shared types | ✅ | ✅ |
//! | Client module | ✅ | ✅ |
//! | Server module | ❌ | ✅ |
//!
//! The server module is explicitly excluded from WASM builds because its dependencies
//! (tokio, axum) don't support WASM. This is enforced through both Cargo.toml target
//! guards and `cfg` attributes.
//!
//! ## Workspace Integration
//!
//! In a Dioxus fullstack workspace:
//!
//! ```toml
//! # client/Cargo.toml
//! [dependencies]
//! dxauth0 = { path = "../dxauth0", features = ["client"] }
//!
//! # server/Cargo.toml
//! [dependencies]
//! dxauth0 = { path = "../dxauth0", features = ["server"], optional = true }
//!
//! [features]
//! server = ["dep:dxauth0", ...]
//! ```
//!
//! This ensures:
//! - Client WASM builds only get client dependencies
//! - Server native builds only get server dependencies
//! - Feature unification doesn't break WASM builds

pub mod config;
pub mod user;

pub mod client;

#[cfg(all(feature = "server", not(target_arch = "wasm32")))]
pub mod server;

pub use config::Auth0Config;
pub use user::User;
