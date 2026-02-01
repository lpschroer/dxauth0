//! Secure token storage with memory-first strategy.
//!
//! This module provides a dual-storage approach for JWT tokens:
//! 1. **Primary (Memory)**: Tokens stored in Dioxus signals - most secure, cleared on page refresh
//! 2. **Secondary (localStorage)**: Tokens persisted across sessions - vulnerable to XSS
//!
//! ## Security Considerations
//!
//! - Memory storage is preferred for active sessions (XSS-resistant)
//! - localStorage is used only for persistence across page refreshes
//! - Tokens should have short expiration times (configured in Auth0)
//! - Always use HTTPS in production to prevent token interception
//!
//! ## Storage Strategy
//!
//! - On login: Store in both memory and localStorage
//! - On page load: Restore from localStorage to memory, then continue using memory
//! - On logout: Clear both memory and localStorage
//! - During session: Always read from memory, never localStorage

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use tracing;

/// Storage key for access token in localStorage
#[cfg(target_arch = "wasm32")]
const TOKEN_STORAGE_KEY: &str = "tolkien_access_token";

/// Storage key for ID token in localStorage
#[cfg(target_arch = "wasm32")]
const ID_TOKEN_STORAGE_KEY: &str = "tolkien_id_token";

/// Storage key for token expiration timestamp
#[cfg(target_arch = "wasm32")]
const TOKEN_EXPIRY_KEY: &str = "tolkien_token_expiry";

/// Stored token data with metadata
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StoredTokens {
    /// Access token (JWT for API calls)
    pub access_token: String,
    /// ID token (JWT with user claims)
    pub id_token: String,
    /// Unix timestamp when token expires (in seconds)
    pub expires_at: u64,
}

impl StoredTokens {
    /// Creates new StoredTokens with expiration calculated from expires_in seconds.
    pub fn new(access_token: String, id_token: String, expires_in: u64) -> Self {
        let expires_at = current_timestamp() + expires_in;
        Self {
            access_token,
            id_token,
            expires_at,
        }
    }

    /// Checks if the token is expired based on current time.
    pub fn is_expired(&self) -> bool {
        current_timestamp() >= self.expires_at
    }

    /// Returns true if token is valid (not expired).
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }
}

/// Token storage manager using memory-first strategy.
///
/// This struct manages token storage across memory (Dioxus Signal) and
/// localStorage, with memory as the primary source of truth.
#[derive(Clone, Copy)]
pub struct TokenStorage {
    /// In-memory token storage (primary, most secure)
    tokens: Signal<Option<StoredTokens>>,
}

impl Default for TokenStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStorage {
    /// Creates a new TokenStorage instance.
    ///
    /// This should be called once at app initialization.
    pub fn new() -> Self {
        Self {
            tokens: Signal::new(None),
        }
    }

    /// Initializes token storage by attempting to restore from localStorage.
    ///
    /// This should be called on app load to restore the previous session.
    /// Returns true if valid tokens were restored, false otherwise.
    #[cfg(target_arch = "wasm32")]
    pub async fn initialize(&mut self) -> bool {
        tracing::trace!("Initializing token storage from localStorage");

        if let Some(tokens) = Self::load_from_local_storage().await {
            if tokens.is_valid() {
                tracing::trace!(
                    "Restored valid tokens from localStorage, expires in {} seconds",
                    tokens.expires_at.saturating_sub(current_timestamp())
                );
                self.tokens.set(Some(tokens));
                true
            } else {
                tracing::warn!("Tokens in localStorage are expired, clearing");
                Self::clear_local_storage().await;
                false
            }
        } else {
            tracing::trace!("No tokens found in localStorage");
            false
        }
    }

    /// Non-WASM stub for initialize.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn initialize(&mut self) -> bool {
        tracing::trace!("Token storage initialization skipped (non-WASM)");
        false
    }

    /// Stores tokens in both memory and localStorage.
    ///
    /// This is called after successful authentication.
    pub async fn store(&mut self, tokens: StoredTokens) {
        tracing::trace!("Storing tokens in memory and localStorage");

        // Primary: Store in memory
        self.tokens.set(Some(tokens.clone()));

        // Secondary: Persist to localStorage
        #[cfg(target_arch = "wasm32")]
        Self::save_to_local_storage(&tokens).await;
    }

    /// Retrieves tokens from memory (primary storage).
    ///
    /// Returns None if no tokens are stored or if they are expired.
    pub fn get(&self) -> Option<StoredTokens> {
        let tokens = self.tokens.read().clone()?;

        if tokens.is_valid() {
            Some(tokens)
        } else {
            tracing::warn!("Tokens in memory are expired");
            None
        }
    }

    /// Retrieves the access token from memory.
    ///
    /// This is a convenience method for getting just the access token.
    pub fn get_access_token(&self) -> Option<String> {
        self.get().map(|t| t.access_token)
    }

    /// Retrieves the ID token from memory.
    ///
    /// This is a convenience method for getting just the ID token.
    pub fn get_id_token(&self) -> Option<String> {
        self.get().map(|t| t.id_token)
    }

    /// Checks if valid tokens are currently stored.
    pub fn has_valid_tokens(&self) -> bool {
        self.get().is_some()
    }

    /// Clears tokens from both memory and localStorage.
    ///
    /// This is called on logout.
    pub async fn clear(&mut self) {
        tracing::trace!("Clearing tokens from memory and localStorage");

        // Clear memory
        self.tokens.set(None);

        // Clear localStorage
        #[cfg(target_arch = "wasm32")]
        Self::clear_local_storage().await;
    }

    /// Loads tokens from localStorage.
    #[cfg(target_arch = "wasm32")]
    async fn load_from_local_storage() -> Option<StoredTokens> {
        let storage = web_sys::window()?.local_storage().ok()??;

        let access_token = storage.get_item(TOKEN_STORAGE_KEY).ok()??;
        let id_token = storage.get_item(ID_TOKEN_STORAGE_KEY).ok()??;
        let expires_at_str = storage.get_item(TOKEN_EXPIRY_KEY).ok()??;
        let expires_at: u64 = expires_at_str.parse().ok()?;

        Some(StoredTokens {
            access_token,
            id_token,
            expires_at,
        })
    }

    /// Saves tokens to localStorage.
    #[cfg(target_arch = "wasm32")]
    async fn save_to_local_storage(tokens: &StoredTokens) {
        if let Some(storage) = web_sys::window()
            .and_then(|w| w.local_storage().ok())
            .flatten()
        {
            let _ = storage.set_item(TOKEN_STORAGE_KEY, &tokens.access_token);
            let _ = storage.set_item(ID_TOKEN_STORAGE_KEY, &tokens.id_token);
            let _ = storage.set_item(TOKEN_EXPIRY_KEY, &tokens.expires_at.to_string());

            tracing::trace!("Tokens saved to localStorage");
        }
    }

    /// Clears tokens from localStorage.
    #[cfg(target_arch = "wasm32")]
    async fn clear_local_storage() {
        if let Some(storage) = web_sys::window()
            .and_then(|w| w.local_storage().ok())
            .flatten()
        {
            let _ = storage.remove_item(TOKEN_STORAGE_KEY);
            let _ = storage.remove_item(ID_TOKEN_STORAGE_KEY);
            let _ = storage.remove_item(TOKEN_EXPIRY_KEY);

            tracing::trace!("Tokens cleared from localStorage");
        }
    }
}

/// Returns current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_tokens_new() {
        let tokens = StoredTokens::new(
            "access_token".to_string(),
            "id_token".to_string(),
            3600, // 1 hour
        );

        assert_eq!(tokens.access_token, "access_token");
        assert_eq!(tokens.id_token, "id_token");
        assert!(tokens.is_valid());
        assert!(!tokens.is_expired());
    }

    #[test]
    fn test_stored_tokens_expired() {
        let tokens = StoredTokens {
            access_token: "access_token".to_string(),
            id_token: "id_token".to_string(),
            expires_at: 0, // Already expired
        };

        assert!(tokens.is_expired());
        assert!(!tokens.is_valid());
    }

    #[test]
    fn test_token_storage_operations() {
        // Note: This test requires a Dioxus runtime and is more of an integration test.
        // We'll test the StoredTokens struct instead, which doesn't require a runtime.
        let tokens = StoredTokens::new("access".to_string(), "id".to_string(), 3600);

        assert!(tokens.is_valid());
        assert_eq!(tokens.access_token, "access");
        assert_eq!(tokens.id_token, "id");
    }

    #[test]
    fn test_current_timestamp() {
        let timestamp = current_timestamp();
        // Should be a reasonable timestamp (after 2020)
        assert!(timestamp > 1_600_000_000);
    }
}
