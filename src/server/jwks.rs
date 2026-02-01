//! JWKS (JSON Web Key Set) caching for JWT validation.
//!
//! This module provides functionality to fetch and cache JWKS from Auth0's
//! `/.well-known/jwks.json` endpoint for JWT signature validation.

use crate::Auth0Config;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Default cache TTL (Time To Live) for JWKS - 1 hour
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Error types for JWKS operations.
#[derive(Debug, thiserror::Error)]
pub enum JwksError {
    /// Failed to fetch JWKS from Auth0
    #[error("Failed to fetch JWKS: {0}")]
    FetchError(#[from] reqwest::Error),

    /// Failed to parse JWKS response
    #[error("Failed to parse JWKS: {0}")]
    ParseError(#[from] serde_json::Error),

    /// Key not found in JWKS
    #[error("Key with kid '{0}' not found in JWKS")]
    KeyNotFound(String),

    /// Invalid key format
    #[error("Invalid key format: {0}")]
    InvalidKey(String),

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// A JSON Web Key from the JWKS endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (e.g., "RSA")
    pub kty: String,

    /// Key ID - used to match keys in JWT header
    pub kid: String,

    /// Algorithm (e.g., "RS256")
    #[serde(default)]
    pub alg: Option<String>,

    /// Public key usage (e.g., "sig" for signature)
    #[serde(rename = "use", default)]
    pub key_use: Option<String>,

    /// RSA modulus (base64url encoded)
    #[serde(default)]
    pub n: Option<String>,

    /// RSA exponent (base64url encoded)
    #[serde(default)]
    pub e: Option<String>,

    /// X.509 certificate chain
    #[serde(default)]
    pub x5c: Option<Vec<String>>,
}

impl Jwk {
    /// Converts the JWK to a DecodingKey for JWT validation.
    pub fn to_decoding_key(&self) -> Result<DecodingKey, JwksError> {
        // Check if we have RSA key components
        if self.kty == "RSA"
            && let (Some(n), Some(e)) = (&self.n, &self.e)
        {
            return DecodingKey::from_rsa_components(n, e)
                .map_err(|e| JwksError::InvalidKey(e.to_string()));
        }

        // Fall back to X.509 certificate if available
        if let Some(x5c) = &self.x5c
            && let Some(cert) = x5c.first()
        {
            return DecodingKey::from_rsa_pem(cert.as_bytes())
                .map_err(|e| JwksError::InvalidKey(e.to_string()));
        }

        Err(JwksError::InvalidKey(
            "No valid key material found in JWK".to_string(),
        ))
    }

    /// Gets the algorithm for this key.
    pub fn algorithm(&self) -> Result<Algorithm, JwksError> {
        let alg = self.alg.as_deref().unwrap_or("RS256"); // Auth0 defaults to RS256

        match alg {
            "RS256" => Ok(Algorithm::RS256),
            "RS384" => Ok(Algorithm::RS384),
            "RS512" => Ok(Algorithm::RS512),
            "ES256" => Ok(Algorithm::ES256),
            "ES384" => Ok(Algorithm::ES384),
            other => Err(JwksError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

/// Response from the JWKS endpoint.
#[derive(Debug, Deserialize)]
struct JwksResponse {
    /// Array of JSON Web Keys
    keys: Vec<Jwk>,
}

/// Cache for JWKS keys with automatic refresh.
pub struct JwksCache {
    /// Auth0 configuration
    config: Auth0Config,

    /// HTTP client for fetching JWKS
    client: reqwest::Client,

    /// Cached keys indexed by kid
    keys: Arc<RwLock<HashMap<String, Jwk>>>,

    /// Timestamp of last successful refresh
    last_refresh: Arc<RwLock<Option<Instant>>>,

    /// Cache TTL
    ttl: Duration,
}

impl JwksCache {
    /// Creates a new JWKS cache with the given configuration.
    pub fn new(config: Auth0Config) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            keys: Arc::new(RwLock::new(HashMap::new())),
            last_refresh: Arc::new(RwLock::new(None)),
            ttl: DEFAULT_CACHE_TTL,
        }
    }

    /// Creates a new JWKS cache with a custom TTL.
    pub fn with_ttl(config: Auth0Config, ttl: Duration) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            keys: Arc::new(RwLock::new(HashMap::new())),
            last_refresh: Arc::new(RwLock::new(None)),
            ttl,
        }
    }

    /// Gets a key by kid, fetching from Auth0 if necessary.
    pub async fn get_key(&self, kid: &str) -> Result<Jwk, JwksError> {
        // Check if we need to refresh the cache
        if self.should_refresh().await {
            tracing::trace!("JWKS cache expired or empty, refreshing...");
            self.fetch_jwks().await?;
        }

        // Try to get the key from cache
        let keys = self.keys.read().await;
        if let Some(key) = keys.get(kid) {
            tracing::trace!("Found key with kid '{}' in cache", kid);
            return Ok(key.clone());
        }

        // Key not found in cache, try refreshing once
        drop(keys); // Release read lock
        tracing::trace!("Key with kid '{}' not in cache, forcing refresh", kid);
        self.fetch_jwks().await?;

        // Try again after refresh
        let keys = self.keys.read().await;
        keys.get(kid)
            .cloned()
            .ok_or_else(|| JwksError::KeyNotFound(kid.to_string()))
    }

    /// Checks if the cache should be refreshed.
    async fn should_refresh(&self) -> bool {
        let last_refresh = self.last_refresh.read().await;
        match *last_refresh {
            None => true, // Never refreshed
            Some(last) => last.elapsed() >= self.ttl,
        }
    }

    /// Fetches JWKS from Auth0 and updates the cache.
    async fn fetch_jwks(&self) -> Result<(), JwksError> {
        let url = self.config.jwks_url();
        tracing::trace!("Fetching JWKS from: {}", url);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            tracing::error!("Failed to fetch JWKS: HTTP {}", response.status());
            return Err(JwksError::FetchError(
                response.error_for_status().unwrap_err(),
            ));
        }

        let jwks: JwksResponse = response.json().await?;
        tracing::trace!("Fetched {} keys from JWKS", jwks.keys.len());

        // Update cache
        let mut keys = self.keys.write().await;
        keys.clear();
        for key in jwks.keys {
            tracing::trace!("Caching key with kid: {}", key.kid);
            keys.insert(key.kid.clone(), key);
        }

        // Update last refresh timestamp
        let mut last_refresh = self.last_refresh.write().await;
        *last_refresh = Some(Instant::now());

        Ok(())
    }

    /// Forces a refresh of the JWKS cache.
    pub async fn force_refresh(&self) -> Result<(), JwksError> {
        self.fetch_jwks().await
    }

    /// Returns the number of keys currently in the cache.
    pub async fn key_count(&self) -> usize {
        self.keys.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_algorithm() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test123".to_string(),
            alg: Some("RS256".to_string()),
            key_use: Some("sig".to_string()),
            n: None,
            e: None,
            x5c: None,
        };

        assert!(jwk.algorithm().is_ok());
        assert_eq!(jwk.algorithm().unwrap(), Algorithm::RS256);
    }

    #[test]
    fn test_jwk_algorithm_default() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test123".to_string(),
            alg: None, // Should default to RS256
            key_use: Some("sig".to_string()),
            n: None,
            e: None,
            x5c: None,
        };

        assert!(jwk.algorithm().is_ok());
        assert_eq!(jwk.algorithm().unwrap(), Algorithm::RS256);
    }

    #[test]
    fn test_jwk_unsupported_algorithm() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test123".to_string(),
            alg: Some("HS256".to_string()), // Not supported for JWKS
            key_use: Some("sig".to_string()),
            n: None,
            e: None,
            x5c: None,
        };

        assert!(jwk.algorithm().is_err());
    }

    #[tokio::test]
    async fn test_jwks_cache_creation() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );

        let cache = JwksCache::new(config);
        assert_eq!(cache.key_count().await, 0);
        assert!(cache.should_refresh().await);
    }

    #[tokio::test]
    async fn test_jwks_cache_with_custom_ttl() {
        let config = Auth0Config::new_server(
            "test.auth0.com".to_string(),
            "https://api.test.com".to_string(),
        );

        let ttl = Duration::from_secs(600);
        let cache = JwksCache::with_ttl(config, ttl);
        assert_eq!(cache.ttl, ttl);
    }
}
