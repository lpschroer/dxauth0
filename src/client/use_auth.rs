//! Authentication hook for managing Auth0 login state and PKCE flow.
//!
//! This hook provides authentication state management and handles the
//! OAuth 2.0 authorization code flow with PKCE for Auth0.

#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
use crate::client::jwt::decode_id_token_to_user;
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
use crate::client::pkce;
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
use crate::client::token_storage::StoredTokens;
use crate::client::token_storage::TokenStorage;
use crate::{Auth0Config, User};

#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
use dioxus::fullstack::{HeaderMap, set_request_headers};
use dioxus::prelude::*;
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
use serde::{Deserialize, Serialize};
use tracing;
#[cfg(target_arch = "wasm32")]
use web_sys;

/// Sets the Authorization header globally for all server function calls.
///
/// This function configures the global request headers used by Dioxus fullstack
/// to include the JWT token for authentication. Once set, all subsequent
/// server function calls will automatically include this authorization header.
///
/// # Arguments
///
/// * `token` - The JWT access token to include in the authentication header
///
/// # Note
///
/// This should be called after successful authentication (login or token restoration).
/// - For mobile/desktop: Uses Bearer token in Authorization header
/// - For web/server (browser/SSR): Uses Cookie header for browser-compatible auth
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
fn set_auth_header(token: &str) {
    let mut headers = HeaderMap::new();
    if let Ok(value) = format!("Bearer {}", token).parse() {
        headers.insert("Authorization", value);
        set_request_headers(headers);
        tracing::trace!("Authorization header set as Bearer token for server function calls");
    }
}

/// Clears all custom headers (used on logout).
///
/// Removes all globally configured request headers, including the Authorization
/// header. This should be called when the user logs out to ensure subsequent
/// server function calls don't include authentication credentials.
///
/// # Note
///
/// Only available in mobile/desktop builds (native clients).
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
#[allow(dead_code)]
fn clear_auth_headers() {
    set_request_headers(HeaderMap::new());
    tracing::trace!("Authorization headers cleared");
}

/// Storage key for PKCE code verifier
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
const CODE_VERIFIER_STORAGE_KEY: &str = "tolkien_code_verifier";
/// Storage key for auth state parameter
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
const AUTH_STATE_STORAGE_KEY: &str = "tolkien_auth_state";

/// Authentication state exposed by the use_auth hook.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthState {
    /// Whether the user is authenticated
    pub is_authenticated: bool,
    /// Whether authentication is being checked/loaded
    pub is_loading: bool,
    /// Access token (JWT)
    pub access_token: Option<String>,
    /// ID token (JWT with user claims)
    pub id_token: Option<String>,
    /// Authenticated user profile
    pub user: Option<User>,
    /// Authentication error message
    pub error: Option<String>,
}

impl Default for AuthState {
    fn default() -> Self {
        Self {
            is_authenticated: false,
            is_loading: true,
            access_token: None,
            id_token: None,
            user: None,
            error: None,
        }
    }
}

/// Token response from Auth0 token endpoint.
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    id_token: String,
    token_type: String,
    expires_in: u64,
}

/// Error response from Auth0.
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    error_description: Option<String>,
}

/// Provides authentication context to the component tree.
///
/// This hook must be called once at the root of your application (e.g., in `App`).
/// It sets up the shared authentication state that all child components can access
/// via `use_auth()`.
///
/// # Example
///
/// ```ignore
/// #[component]
/// pub fn App() -> Element {
///     use_auth_provider();
///     // ... rest of app
/// }
/// ```
pub fn use_auth_provider() {
    let auth_state = use_signal(AuthState::default);
    let token_storage = use_signal(TokenStorage::new);
    let config = use_memo(move || {
        Auth0Config::from_env_client().unwrap_or_else(|| {
            tracing::warn!("Auth0 environment variables not set, using development config");
            Auth0Config::new_client(
                "dev.auth0.com".to_string(),
                "dev_client_id".to_string(),
                "https://api.dev.com".to_string(),
            )
        })
    });

    // Check for existing token on mount and auto-redirect to Auth0 if not authenticated
    use_effect(move || {
        spawn(async move {
            check_existing_authentication(auth_state, token_storage, config).await;
        });
    });

    let login = {
        Callback::new(move |redirect_uri: String| {
            let config = config();
            spawn(async move {
                tracing::trace!("Initiating Auth0 login flow");
                initiate_login(&config, &redirect_uri).await;
            });
        })
    };

    let logout = {
        let mut auth_state = auth_state;
        let mut token_storage = token_storage;
        Callback::new(move |_return_to: String| {
            spawn(async move {
                tracing::trace!("Initiating logout");
                // Clear tokens from storage
                token_storage.write().clear().await;

                // Update auth state
                auth_state.write().is_authenticated = false;
                auth_state.write().access_token = None;
                auth_state.write().id_token = None;
                auth_state.write().user = None;

                // Note: For web builds, logout should go through server endpoint
                // which will clear cookies and redirect to Auth0
                // This callback is kept for compatibility but logout_default()
                // now redirects to /logout endpoint directly
                tracing::trace!("Logout callback completed");
            });
        })
    };

    #[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
    let handle_callback = {
        Callback::new(move |code: String| {
            let config = config();
            spawn(async move {
                handle_auth_callback(auth_state, token_storage, &config, &code).await;
            });
        })
    };

    let context = AuthContext {
        auth_state,
        login,
        logout,
        #[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
        handle_callback,
    };

    use_context_provider(|| context);
}

/// Hook for accessing authentication state and Auth0 login flow.
///
/// This hook retrieves the shared authentication context that was set up
/// by `use_auth_provider()`. It must be used in a component that is a
/// descendant of a component that called `use_auth_provider()`.
///
/// # Panics
///
/// Panics if called without `use_auth_provider()` being called in an ancestor component.
pub fn use_auth() -> AuthContext {
    use_context::<AuthContext>()
}

/// Context object returned by use_auth hook.
#[derive(Clone, Copy)]
pub struct AuthContext {
    /// Current authentication state signal
    auth_state: Signal<AuthState>,
    /// Login function - call with redirect_uri
    pub login: Callback<String>,
    /// Logout function - call with return_to URL
    pub logout: Callback<String>,
    /// Handle OAuth callback - call with authorization code (mobile/desktop only)
    #[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
    pub handle_callback: Callback<String>,
}

impl AuthContext {
    /// Returns true if the user is currently authenticated with valid tokens.
    pub fn is_authenticated(&self) -> bool {
        self.auth_state.read().is_authenticated
    }

    /// Returns true if authentication state is currently being loaded or verified.
    pub fn is_loading(&self) -> bool {
        self.auth_state.read().is_loading
    }

    /// Returns the access token if available.
    ///
    /// This is the JWT token used for authenticating API requests.
    pub fn access_token(&self) -> Option<String> {
        self.auth_state.read().access_token.clone()
    }

    /// Returns the ID token if available.
    ///
    /// This is the JWT token containing user profile information.
    pub fn id_token(&self) -> Option<String> {
        self.auth_state.read().id_token.clone()
    }

    /// Returns the authenticated user profile, if available.
    pub fn user(&self) -> Option<User> {
        self.auth_state.read().user.clone()
    }

    /// Returns any authentication error message.
    pub fn error(&self) -> Option<String> {
        self.auth_state.read().error.clone()
    }

    /// Returns true if there is an authentication error.
    pub fn has_error(&self) -> bool {
        self.auth_state.read().error.is_some()
    }

    /// Initiates login flow with the default callback URL.
    ///
    /// The callback URL is constructed as `{current_origin}/callback`.
    #[cfg(target_arch = "wasm32")]
    pub fn login_default(&self) {
        if let Some(origin) = web_sys::window().and_then(|w| w.location().origin().ok()) {
            let redirect_uri = format!("{}/callback", origin);
            self.login.call(redirect_uri);
        } else {
            tracing::error!("Failed to get window origin for login redirect");
        }
    }

    /// Non-WASM stub for login_default.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn login_default(&self) {
        tracing::warn!("login_default not supported in non-WASM builds");
    }

    /// Initiates logout flow by redirecting to the server logout endpoint.
    ///
    /// For web builds, redirects to the server's `/logout` endpoint which will:
    /// 1. Clear authentication cookies
    /// 2. Redirect to Auth0 logout
    /// 3. Auth0 redirects back to the application
    #[cfg(target_arch = "wasm32")]
    pub fn logout_default(&self) {
        if let Some(window) = web_sys::window() {
            // Redirect to server logout endpoint instead of Auth0 directly
            // The server will clear cookies and handle the Auth0 logout redirect
            let _ = window.location().set_href("/logout");
            tracing::trace!("Redirecting to server logout endpoint");
        } else {
            tracing::error!("Failed to get window for logout redirect");
        }
    }

    /// Non-WASM stub for logout_default.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn logout_default(&self) {
        tracing::warn!("logout_default not supported in non-WASM builds");
    }
}

/// Initiates the Auth0 login flow.
///
/// For web builds, uses standard authorization code flow (server-side with client_secret).
/// For mobile/desktop, uses PKCE flow (client-side).
#[cfg(target_arch = "wasm32")]
async fn initiate_login(config: &Auth0Config, redirect_uri: &str) {
    #[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
    {
        // For mobile/desktop builds, use PKCE flow
        let code_verifier = pkce::generate_code_verifier();
        let code_challenge = pkce::generate_code_challenge(&code_verifier);
        let state = pkce::generate_state();

        // Store PKCE parameters for later verification
        store_code_verifier(&code_verifier).await;
        store_auth_state(&state).await;

        // Build authorization URL with PKCE parameters
        let auth_url = pkce::build_authorization_url(
            &config.domain,
            config
                .client_id
                .as_ref()
                .expect("Client config must have client_id"),
            redirect_uri,
            &code_challenge,
            &state,
            &config.audience,
        );

        tracing::trace!("Redirecting to Auth0 (PKCE flow): {}", auth_url);

        if let Some(window) = web_sys::window() {
            let _ = window.location().set_href(&auth_url);
        }
    }

    #[cfg(all(
        target_arch = "wasm32",
        not(any(feature = "mobile", feature = "desktop"))
    ))]
    {
        // For web builds, use standard authorization code flow without PKCE
        // The server will exchange the code using client_secret
        use crate::client::pkce::generate_state;

        let state = generate_state();

        // Build authorization URL without PKCE parameters
        let auth_url = format!(
            "https://{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email&state={}&audience={}",
            config.domain,
            urlencoding::encode(
                config
                    .client_id
                    .as_ref()
                    .expect("Client config must have client_id")
            ),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(&state),
            urlencoding::encode(&config.audience)
        );

        tracing::trace!("Redirecting to Auth0 (standard flow): {}", auth_url);

        if let Some(window) = web_sys::window() {
            let _ = window.location().set_href(&auth_url);
        }
    }
}

/// Checks if the current route is the callback route.
#[cfg(target_arch = "wasm32")]
fn is_on_callback_route() -> bool {
    web_sys::window()
        .and_then(|w| w.location().pathname().ok())
        .map(|path| path == "/callback")
        .unwrap_or(false)
}

/// Gets the default redirect URI for the current origin.
#[cfg(target_arch = "wasm32")]
fn get_default_redirect_uri() -> String {
    web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_else(|| "http://localhost:8080".to_string())
        + "/callback"
}

/// Restores tokens from storage and updates auth state.
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
async fn restore_tokens_from_storage(
    mut auth_state: Signal<AuthState>,
    token_storage: Signal<TokenStorage>,
) {
    if let Some(tokens) = token_storage.read().get() {
        tracing::trace!("Restored valid tokens from storage");

        // Decode ID token to extract user info
        let user = decode_id_token_to_user(&tokens.id_token).ok().map(|user| {
            tracing::trace!("User decoded from ID token: {:?}", user);
            user
        });

        // Set the Authorization header for all server function calls
        // Note: For web builds, cookies are sent automatically - no need to set headers
        #[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
        set_auth_header(&tokens.access_token);

        auth_state.write().access_token = Some(tokens.access_token);
        auth_state.write().id_token = Some(tokens.id_token);
        auth_state.write().user = user;
        auth_state.write().is_authenticated = true;
        auth_state.write().is_loading = false;
    }
}

/// Redirects to Auth0 login when tokens are expired or missing.
#[cfg(target_arch = "wasm32")]
async fn redirect_to_login_on_expired_tokens(config: &Auth0Config) {
    tracing::trace!("Tokens expired - redirecting to Auth0 login");
    let redirect_uri = get_default_redirect_uri();
    initiate_login(config, &redirect_uri).await;
}

/// Redirects to Auth0 login when no tokens are found.
#[cfg(target_arch = "wasm32")]
async fn redirect_to_login_on_missing_tokens(config: &Auth0Config) {
    tracing::trace!("No stored tokens found - redirecting to Auth0 login");
    let redirect_uri = get_default_redirect_uri();
    initiate_login(config, &redirect_uri).await;
}

/// Checks for existing authentication tokens and initializes auth state.
#[cfg_attr(not(target_arch = "wasm32"), allow(unused))]
async fn check_existing_authentication(
    mut auth_state: Signal<AuthState>,
    #[cfg_attr(
        not(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop"))),
        allow(unused_variables)
    )]
    mut token_storage: Signal<TokenStorage>,
    config: Memo<Auth0Config>,
) {
    tracing::trace!("Checking for existing authentication token");

    #[cfg(target_arch = "wasm32")]
    {
        let config = config();

        if is_on_callback_route() {
            tracing::trace!("On callback route, skipping auth check");
            auth_state.write().is_loading = false;
            return;
        }

        // For mobile/desktop builds, use localStorage for token storage
        #[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
        {
            if token_storage.write().initialize().await {
                restore_tokens_from_storage(auth_state, token_storage).await;

                // Check if restoration was successful
                if !auth_state.read().is_authenticated {
                    redirect_to_login_on_expired_tokens(&config).await;
                }
            } else {
                redirect_to_login_on_missing_tokens(&config).await;
            }
        }

        // For web builds, check authentication via server cookies using /api/auth/me
        #[cfg(all(
            target_arch = "wasm32",
            not(any(feature = "mobile", feature = "desktop"))
        ))]
        {
            match check_auth_from_server_cookies().await {
                Ok(Some(user)) => {
                    tracing::trace!("Successfully restored authentication from server cookies");
                    auth_state.write().user = Some(user);
                    auth_state.write().is_authenticated = true;
                    auth_state.write().is_loading = false;
                }
                Ok(None) => {
                    tracing::trace!("No valid authentication cookie found, redirecting to login");
                    auth_state.write().is_loading = false;
                    redirect_to_login_on_missing_tokens(&config).await;
                }
                Err(e) => {
                    tracing::error!("Failed to check authentication from server: {}", e);
                    auth_state.write().is_loading = false;
                    redirect_to_login_on_missing_tokens(&config).await;
                }
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        tracing::trace!("Non-WASM build, skipping token check");
        auth_state.write().is_loading = false;
    }
}

/// Checks authentication status from server using cookies.
///
/// For web builds, this calls the /api/auth/me endpoint which validates
/// the HttpOnly access_token cookie and returns user information if valid.
#[cfg(target_arch = "wasm32")]
async fn check_auth_from_server_cookies() -> Result<Option<User>, String> {
    tracing::trace!("Checking authentication from server cookies via /api/auth/me");

    // Construct full URL using window origin
    let origin = web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_else(|| "http://localhost:8080".to_string());

    let url = format!("{}/api/auth/me", origin);
    tracing::trace!("Checking auth at: {}", url);

    let client = reqwest::Client::new();

    let response = client.get(&url).send().await.map_err(|e| {
        let err_msg = format!("Failed to check auth status: {}", e);
        tracing::error!("{}", err_msg);
        err_msg
    })?;

    let status = response.status();
    tracing::trace!("Auth status check response status: {}", status);

    if response.status().is_success() {
        let user_json: serde_json::Value = response.json().await.map_err(|e| {
            let err_msg = format!("Failed to parse user data: {}", e);
            tracing::error!("{}", err_msg);
            err_msg
        })?;

        tracing::trace!("Received user data from server: {:?}", user_json);

        let user = User {
            id: user_json["id"]
                .as_str()
                .ok_or_else(|| {
                    let err_msg = "Missing user id in response".to_string();
                    tracing::error!("{}", err_msg);
                    err_msg
                })?
                .to_string(),
            email: user_json["email"].as_str().map(|s| s.to_string()),
            name: user_json["name"].as_str().map(|s| s.to_string()),
            picture: user_json["picture"].as_str().map(|s| s.to_string()),
        };

        tracing::trace!("Successfully authenticated user from cookies: {}", user.id);
        Ok(Some(user))
    } else if response.status() == 401 {
        // Not authenticated
        tracing::trace!("No valid authentication cookie found (401)");
        Ok(None)
    } else {
        let err_msg = format!(
            "Unexpected status code from /api/auth/me: {}",
            response.status()
        );
        tracing::error!("{}", err_msg);
        Err(err_msg)
    }
}

/// Decodes ID token to extract user information.
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
fn decode_user_from_id_token(id_token: &str) -> Option<User> {
    match decode_id_token_to_user(id_token) {
        Ok(user) => {
            tracing::trace!("Successfully decoded user from ID token");
            Some(user)
        }
        Err(e) => {
            tracing::error!("Failed to decode ID token: {}", e);
            None
        }
    }
}

/// Stores tokens and updates auth state after successful authentication.
/// Only used for mobile/desktop builds.
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
async fn store_tokens_and_update_state(
    mut auth_state: Signal<AuthState>,
    mut token_storage: Signal<TokenStorage>,
    access_token: String,
    id_token: String,
    expires_in: u64,
) {
    tracing::trace!("Successfully exchanged code for tokens");

    // Decode ID token to extract user info
    let user = decode_user_from_id_token(&id_token);

    // Store tokens using secure storage strategy
    let stored_tokens = StoredTokens::new(access_token.clone(), id_token.clone(), expires_in);
    token_storage.write().store(stored_tokens).await;
    clear_pkce_storage().await;

    // Set the Authorization header for all server function calls
    // Note: For web builds, cookies are sent automatically - no need to set headers
    #[cfg(any(feature = "mobile", feature = "desktop"))]
    set_auth_header(&access_token);

    auth_state.write().access_token = Some(access_token);
    auth_state.write().id_token = Some(id_token);
    auth_state.write().user = user;
    auth_state.write().is_authenticated = true;
    auth_state.write().is_loading = false;
    auth_state.write().error = None;
}

/// Handles the OAuth callback by exchanging code for tokens.
/// Only used for mobile/desktop builds that use client-side PKCE flow.
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
async fn handle_auth_callback(
    mut auth_state: Signal<AuthState>,
    token_storage: Signal<TokenStorage>,
    config: &Auth0Config,
    code: &str,
) {
    tracing::trace!("Handling Auth0 callback");

    match exchange_code_for_tokens(config, code).await {
        Ok((access_token, id_token, expires_in)) => {
            store_tokens_and_update_state(
                auth_state,
                token_storage,
                access_token,
                id_token,
                expires_in,
            )
            .await;
        }
        Err(err) => {
            tracing::error!("Failed to exchange code for tokens: {}", err);
            auth_state.write().error = Some(err);
            auth_state.write().is_loading = false;
        }
    }
}

/// Initiates logout by redirecting to Auth0 logout endpoint.
/// Only used for mobile/desktop builds.
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
#[allow(dead_code)]
async fn initiate_logout(config: &Auth0Config, return_to: &str) {
    // Clear auth headers before logout
    clear_auth_headers();

    let logout_url = format!(
        "{}?client_id={}&returnTo={}",
        config.logout_url(),
        urlencoding::encode(
            config
                .client_id
                .as_ref()
                .expect("Client config must have client_id")
        ),
        urlencoding::encode(return_to)
    );

    tracing::trace!("Redirecting to Auth0 logout: {}", logout_url);

    if let Some(window) = web_sys::window() {
        let _ = window.location().set_href(&logout_url);
    }
}

/// Exchanges authorization code for access and ID tokens using PKCE.
/// Only used for mobile/desktop builds.
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
async fn exchange_code_for_tokens(
    config: &Auth0Config,
    code: &str,
) -> Result<(String, String, u64), String> {
    let code_verifier = get_stored_code_verifier()
        .await
        .ok_or_else(|| "Code verifier not found in storage".to_string())?;

    {
        let redirect_uri = web_sys::window()
            .and_then(|w| w.location().origin().ok())
            .ok_or_else(|| "Failed to get window origin".to_string())?
            + "/callback";

        let client = reqwest::Client::new();
        let response = client
            .post(config.token_url())
            .form(&[
                ("grant_type", "authorization_code"),
                (
                    "client_id",
                    config
                        .client_id
                        .as_ref()
                        .expect("Client config must have client_id"),
                ),
                ("code", code),
                ("code_verifier", &code_verifier),
                ("redirect_uri", &redirect_uri),
            ])
            .send()
            .await
            .map_err(|e| format!("Token request failed: {}", e))?;

        if response.status().is_success() {
            let token_response: TokenResponse = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse token response: {}", e))?;

            Ok((
                token_response.access_token,
                token_response.id_token,
                token_response.expires_in,
            ))
        } else {
            let error: ErrorResponse = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse error response: {}", e))?;

            Err(format!(
                "Token exchange failed: {} - {}",
                error.error,
                error.error_description.unwrap_or_default()
            ))
        }
    }
}

// PKCE storage helpers (mobile/desktop only, wasm32 target)

#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
async fn store_code_verifier(verifier: &str) {
    if let Some(storage) = web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
    {
        let _ = storage.set_item(CODE_VERIFIER_STORAGE_KEY, verifier);
    }
}

#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
async fn get_stored_code_verifier() -> Option<String> {
    web_sys::window()?
        .local_storage()
        .ok()??
        .get_item(CODE_VERIFIER_STORAGE_KEY)
        .ok()?
}

#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
async fn store_auth_state(state: &str) {
    if let Some(storage) = web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
    {
        let _ = storage.set_item(AUTH_STATE_STORAGE_KEY, state);
    }
}

#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
async fn clear_pkce_storage() {
    if let Some(storage) = web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
    {
        let _ = storage.remove_item(CODE_VERIFIER_STORAGE_KEY);
        let _ = storage.remove_item(AUTH_STATE_STORAGE_KEY);
    }
}

/// Non-WASM stub for initiate_login.
#[cfg(not(target_arch = "wasm32"))]
async fn initiate_login(_config: &Auth0Config, _redirect_uri: &str) {
    tracing::warn!("Auth0 login not supported in non-WASM builds");
}

/// Validates the state parameter from the OAuth callback against stored state.
///
/// This provides CSRF protection by ensuring the state returned from Auth0
/// matches the state we sent in the authorization request.
/// Only used for mobile/desktop builds.
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
pub async fn validate_state(received_state: &str) -> bool {
    if let Some(stored_state) = get_stored_auth_state().await {
        let is_valid = received_state == stored_state;
        if is_valid {
            tracing::trace!("State validation successful");
        } else {
            tracing::error!(
                "State mismatch - stored: {}, received: {}",
                stored_state,
                received_state
            );
        }
        is_valid
    } else {
        tracing::error!("No stored state found for validation");
        false
    }
}

/// Retrieves the stored auth state parameter.
/// Only used for mobile/desktop builds.
#[cfg(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop")))]
async fn get_stored_auth_state() -> Option<String> {
    web_sys::window()?
        .local_storage()
        .ok()??
        .get_item(AUTH_STATE_STORAGE_KEY)
        .ok()?
}

/// Non-mobile/desktop stub for state validation.
#[cfg(not(all(target_arch = "wasm32", any(feature = "mobile", feature = "desktop"))))]
pub async fn validate_state(_received_state: &str) -> bool {
    tracing::warn!("State validation not supported in web builds (server handles validation)");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_state_default() {
        let state = AuthState::default();
        assert!(!state.is_authenticated);
        assert!(state.is_loading);
        assert!(state.access_token.is_none());
        assert!(state.id_token.is_none());
        assert!(state.error.is_none());
    }

    #[test]
    fn test_auth_state_authenticated() {
        let user = User::new("auth0|123456".to_string());
        let state = AuthState {
            is_authenticated: true,
            is_loading: false,
            access_token: Some("test_access_token".to_string()),
            id_token: Some("test_id_token".to_string()),
            user: Some(user.clone()),
            error: None,
        };

        assert!(state.is_authenticated);
        assert!(!state.is_loading);
        assert_eq!(state.access_token.as_deref(), Some("test_access_token"));
        assert_eq!(state.id_token.as_deref(), Some("test_id_token"));
        assert!(state.user.is_some());
        assert_eq!(state.user.as_ref().unwrap().id, "auth0|123456");
        assert!(state.error.is_none());
    }

    #[test]
    fn test_auth_state_error() {
        let state = AuthState {
            is_authenticated: false,
            is_loading: false,
            access_token: None,
            id_token: None,
            user: None,
            error: Some("Authentication failed".to_string()),
        };

        assert!(!state.is_authenticated);
        assert!(!state.is_loading);
        assert!(state.access_token.is_none());
        assert!(state.id_token.is_none());
        assert!(state.user.is_none());
        assert_eq!(state.error.as_deref(), Some("Authentication failed"));
    }

    #[test]
    fn test_auth_state_clone() {
        let user = User::new("auth0|123456".to_string());
        let state1 = AuthState {
            is_authenticated: true,
            is_loading: false,
            access_token: Some("token".to_string()),
            id_token: Some("id".to_string()),
            user: Some(user),
            error: None,
        };

        let state2 = state1.clone();
        assert_eq!(state1, state2);
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_token_response_serialization() {
        let json = r#"{
            "access_token": "test_access",
            "id_token": "test_id",
            "token_type": "Bearer",
            "expires_in": 3600
        }"#;

        let response: Result<TokenResponse, _> = serde_json::from_str(json);
        assert!(response.is_ok());

        let token_response = response.unwrap();
        assert_eq!(token_response.access_token, "test_access");
        assert_eq!(token_response.id_token, "test_id");
        assert_eq!(token_response.token_type, "Bearer");
        assert_eq!(token_response.expires_in, 3600);
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_response_serialization() {
        let json = r#"{
            "error": "invalid_grant",
            "error_description": "Invalid authorization code"
        }"#;

        let response: Result<ErrorResponse, _> = serde_json::from_str(json);
        assert!(response.is_ok());

        let error_response = response.unwrap();
        assert_eq!(error_response.error, "invalid_grant");
        assert_eq!(
            error_response.error_description.as_deref(),
            Some("Invalid authorization code")
        );
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_response_without_description() {
        let json = r#"{
            "error": "invalid_request"
        }"#;

        let response: Result<ErrorResponse, _> = serde_json::from_str(json);
        assert!(response.is_ok());

        let error_response = response.unwrap();
        assert_eq!(error_response.error, "invalid_request");
        assert!(error_response.error_description.is_none());
    }
}
