> [!CAUTION]
> This project is the result of late night tinkering. 
> I hope it fuels your own nocturnal coding, but consume with caution!

# dxauth0

A comprehensive authentication library for Dioxus fullstack applications using Auth0.

## Overview

`dxauth0` provides a complete, feature-gated authentication solution for Dioxus applications that eliminates code duplication between client and server while maintaining clean separation of concerns.

**Key Features:**
- 🔐 Complete Auth0 OAuth 2.0 implementation with platform-specific flows
- 🍪 Server-side cookie authentication for web browsers (HttpOnly, secure)
- 📱 PKCE flow for mobile/desktop applications
- 🎯 Feature-gated client/server modules
- 🌐 WASM-compatible client-side code
- ⚡ High-performance JWT validation with JWKS caching
- 🛡️ Type-safe Axum extractors for server endpoints
- 📦 Zero code duplication between client and server
- 🧪 Comprehensive test coverage

## Features

### Client Features (`web`, `mobile`, `desktop`)

Enables client-side authentication utilities for browser and native applications:

- **PKCE Flow**: RFC 7636-compliant Proof Key for Code Exchange (mobile/desktop)
- **Web Flow**: Standard OAuth authorization code flow (server-side cookie auth)
- **Token Storage**: Secure token persistence using browser LocalStorage or native storage
- **JWT Decoding**: ID token parsing and user profile extraction
- **HTTP Client**: Token exchange and refresh with Auth0
- **Auth State Management**: Reactive authentication state with Dioxus hooks

**Platform Support**: WASM (browser), Native (mobile/desktop)

### `server` (Native-only)

Enables server-side authentication utilities for backend APIs:

- **OAuth Callback Handler**: Server-side authorization code exchange
- **Cookie Management**: HttpOnly, Secure cookie handling for web authentication
- **JWT Validation**: RS256 signature verification using JWKS
- **Claims Extraction**: Automatic parsing and validation of JWT claims
- **JWKS Caching**: Performance-optimized public key caching
- **Axum Extractors**: Type-safe authentication extractors for server functions
- **Auth State**: Shared authentication configuration and JWKS cache

**Platform Support**: Native (Linux, macOS, Windows) - automatically excluded from WASM builds

## Installation

Add to your workspace `Cargo.toml`:

```toml
[workspace]
members = ["client", "server", "dxauth0"]

[workspace.dependencies]
dxauth0 = { path = "dxauth0" }
server = { path = "server" }
```

### Client Setup

```toml
# client/Cargo.toml
[dependencies]
dioxus = { version = "0.7.2", features = ["fullstack", "router"] }
dxauth0 = { path = "../dxauth0", default-features = false }
server = { workspace = true, default-features = false }

[features]
default = []
web = ["dioxus/web", "dxauth0/web"]
mobile = ["dioxus/mobile", "dxauth0/mobile"]
desktop = ["dioxus/desktop", "dxauth0/desktop"]
server = ["dioxus/server", "server/server", "dxauth0/server"]
```

### Server Setup

```toml
# server/Cargo.toml
[dependencies]
dioxus = { version = "0.7.2", features = ["fullstack"] }
dxauth0 = { path = "../dxauth0", default-features = false }

[features]
default = ["server"]
server = ["dioxus/server", "dxauth0/server"]
```

## Usage

### Authentication Flows

`dxauth0` supports two authentication flows depending on the target platform:

| Platform | Flow | Features | Token Storage | Auth Header |
|----------|------|----------|---------------|-------------|
| **Web Browser** | Server-side OAuth | Standard authorization code flow with `client_secret` | HttpOnly cookies | Automatic (cookies) |
| **Mobile/Desktop** | PKCE | Client-side token exchange with PKCE | LocalStorage / Native storage | `Authorization: Bearer <token>` |

**When to use each flow:**

- **Web Browser (Default)**: Uses server-side cookie authentication for maximum security. Cookies are HttpOnly (protected from XSS), automatically included in all requests including WebSocket upgrades, and managed entirely by the server. This is the recommended approach for browser-based applications.

- **Mobile/Desktop**: Uses PKCE (Proof Key for Code Exchange) for native applications where server-side session management is not feasible. The client handles token exchange and storage, sending tokens via Authorization headers. This flow is fully implemented and ready for when mobile/desktop platforms are added to the project.

**Feature flags control which flow is compiled:**

```toml
# Web build - server-side cookie auth
dxauth0 = { workspace = true, features = ["web"] }

# Mobile build - PKCE client-side auth
dxauth0 = { workspace = true, features = ["mobile"] }

# Desktop build - PKCE client-side auth
dxauth0 = { workspace = true, features = ["desktop"] }
```

#### Web Browsers (Server-Side Cookie Auth)

For web applications, authentication uses server-side OAuth callback handling with HttpOnly cookies:

```rust
use dxauth0::client::use_auth_provider;
use dioxus::prelude::*;

#[component]
pub fn App() -> Element {
    // Initialize authentication provider
    use_auth_provider();
    
    rsx! {
        // Your app content
        AuthButton {}
    }
}

#[component]
fn AuthButton() -> Element {
    let auth = use_auth();
    
    let login = move |_| {
        // Redirects to Auth0, which redirects to server's /callback endpoint
        // Server sets HttpOnly cookies and redirects back to app
        auth.login_default();
    };
    
    let logout = move |_| {
        // Redirects to server's /logout endpoint
        // Server clears cookies and redirects to Auth0 logout
        auth.logout_default();
    };
    
    rsx! {
        if auth.is_authenticated() {
            button { onclick: logout, "Log Out" }
            p { "Welcome, {auth.user().name}" }
        } else {
            button { onclick: login, "Log In" }
        }
    }
}
```

**Flow:**
1. User clicks login → Client redirects to Auth0
2. Auth0 redirects to server `/callback` with authorization code
3. Server exchanges code for tokens using `client_secret`
4. Server sets `access_token` cookie (HttpOnly, Secure)
5. Server redirects to `/`
6. Client checks auth via `/api/auth/me` (cookie sent automatically)
7. All requests include cookie (including WebSocket upgrades)

#### Mobile/Desktop (PKCE Client-Side)

For mobile and desktop applications, PKCE flow with client-side token exchange is used:

```rust
// Enable mobile feature in Cargo.toml:
// [dependencies]
// dxauth0 = { workspace = true, features = ["mobile"] }

use dxauth0::client::{use_auth_provider, use_auth, pkce};

#[component]
pub fn App() -> Element {
    use_auth_provider();
    
    rsx! {
        Router::<Route> {}
    }
}

// In your callback route handler:
#[component]
fn Callback() -> Element {
    let auth = use_auth();
    
    use_effect(move || {
        spawn(async move {
            // Extract code from URL
            if let Some(code) = get_query_param("code") {
                // Client-side token exchange using stored PKCE verifier
                auth.handle_callback.call(code);
            }
        });
    });
    
    rsx! {
        div { "Processing login..." }
    }
}
```

**Flow:**
1. User clicks login → Client generates PKCE challenge and verifier
2. Client stores verifier in LocalStorage
3. Client redirects to Auth0 with `code_challenge`
4. Auth0 redirects to client `/callback` with authorization code
5. Client exchanges code + `code_verifier` for tokens
6. Client stores tokens and sets Authorization header
7. All requests include `Authorization: Bearer <token>` header

**Note**: This flow is preserved and fully implemented but not yet tested on native platforms. It will be used when mobile/desktop builds are added to the project.

### Server-Side Setup

```rust
use dxauth0::{Auth0Config, server::{oauth_callback, logout, auth_me, CookieLayer, extractors::AuthState}};
use dioxus::prelude::*;
use axum::{routing::get, Extension};
use std::sync::Arc;

#[cfg(feature = "server")]
pub fn get_router(app: fn() -> Element) -> Result<axum::routing::Router, anyhow::Error> {
    // 1. Load Auth0 configuration
    let auth0_config = Auth0Config::from_env_server_or_panic();
    let auth0_config = Arc::new(auth0_config);
    
    // 2. Initialize authentication state
    let auth_state = AuthState::new((*auth0_config).clone());
    
    // 3. Create callback router (handles OAuth flow)
    let callback_router = axum::Router::new()
        .route("/callback", get(oauth_callback))  // OAuth callback handler
        .route("/logout", get(logout))            // Logout handler
        .with_state(auth0_config);
    
    // 4. Create main Dioxus router
    let dioxus_router = dioxus::server::router(app)
        .route("/api/auth/me", get(auth_me))     // Auth status check
        .layer(Extension(auth_state));
    
    // 5. Merge routers and add cookie layer
    let router = axum::Router::new()
        .merge(callback_router)
        .merge(dioxus_router)
        .layer(CookieLayer::default());
    
    Ok(router)
}

// Use in protected endpoints
#[get("/api/user/profile", user: AuthenticatedUser)]
pub async fn get_user_profile() -> Result<UserProfile> {
    tracing::info!("Request from user: {}", user.0.id);
    
    Ok(UserProfile {
        id: user.0.id.clone(),
        email: user.0.email.clone(),
        name: user.0.name.clone(),
    })
}

// The AuthenticatedUser extractor:
// - Reads token from Cookie header (HttpOnly cookie) OR Authorization header (Bearer token)
// - Validates JWT signature and claims
// - Returns 401 Unauthorized if authentication fails
```

## Environment Variables

### Client (Compile-time)

```bash
# Auth0 Application Settings
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your_client_id
AUTH0_AUDIENCE=https://your-api-identifier
```

### Server (Runtime)

```bash
# Auth0 API Settings (Required)
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your_client_id
AUTH0_CLIENT_SECRET=your_client_secret  # Required for server-side OAuth flow
AUTH0_AUDIENCE=https://your-api-identifier

# Application Settings (Optional)
APP_BASE_URL=http://localhost:8080  # Used for OAuth redirect_uri construction
```

**Important Notes:**
- Client variables are embedded at compile-time
- Server variables are loaded at runtime
- `AUTH0_CLIENT_SECRET` is **required** for web builds (server-side OAuth callback)
- Auth0 Application must be configured as "Regular Web Application" (not SPA)
- Allowed Callback URLs in Auth0 must include `{APP_BASE_URL}/callback`

## Architecture

### Shared Types

Available in all contexts (client, server, WASM, native):

- `Auth0Config` - Auth0 tenant configuration (domain, audience, client_id)
- `User` - User profile structure (id, email, name, picture)

### Client Module (`client`)

WASM-compatible utilities for browser-based authentication:

```
dxauth0::client
├── http_client   - Token exchange with Auth0
├── jwt           - ID token decoding
├── pkce          - PKCE challenge generation
└── token_storage - Secure LocalStorage persistence
```

### Server Module (`server`)

Native-only utilities for backend authentication:

```
dxauth0::server
├── claims       - JWT claims structure
├── extractors   - Axum extractors (BearerToken, AuthenticatedUser, AuthState)
├── jwks         - JWKS fetching and caching
└── validation   - JWT signature and claims validation
```

## Platform Compatibility

| Component | WASM (Browser) | Native (Server) |
|-----------|----------------|-----------------|
| Shared types (`Auth0Config`, `User`) | ✅ | ✅ |
| Client module | ✅ | ✅ (for testing) |
| Server module | ❌ | ✅ |

The server module is automatically excluded from WASM builds through:
1. **Target-specific dependencies** in `Cargo.toml`
2. **Platform guards** in module declarations: `cfg(all(feature = "server", not(target_arch = "wasm32")))`

This ensures workspace feature unification doesn't break WASM builds.

## Security Considerations

### Web Builds (Cookie-Based Auth)

- ✅ HttpOnly cookies prevent XSS access to tokens
- ✅ Secure flag ensures HTTPS-only transmission (production)
- ✅ SameSite=Lax provides CSRF protection
- ✅ Server-side token exchange uses `client_secret`
- ✅ Cookies automatically included in WebSocket upgrades
- ✅ State parameter validation prevents CSRF on OAuth flow
- ⚠️ Requires proper session management (use short-lived tokens)

### Mobile/Desktop Builds (PKCE)

- ✅ Uses PKCE (RFC 7636) for authorization code flow
- ✅ Tokens stored in secure platform storage
- ✅ No client_secret exposure (public client)
- ⚠️ Token security depends on platform's secure storage

### Server-Side

- ✅ JWT signature validation using JWKS
- ✅ Claims validation (issuer, audience, expiration)
- ✅ JWKS caching with configurable TTL
- ✅ Type-safe extractors prevent bypassing authentication
- ✅ Automatic 401 responses for invalid tokens
- ✅ Supports both Cookie and Authorization header authentication

## Testing

Run tests for specific features:

```bash
# Web client tests (WASM-compatible)
cargo test --package dxauth0 --features web

# Mobile client tests
cargo test --package dxauth0 --features mobile

# Server tests (native only)
cargo test --package dxauth0 --features server

# All tests
cargo test --package dxauth0 --all-features
```

## Examples

See the parent project's implementation for complete examples:

- `client/src/hooks/use_auth.rs` - Full client authentication flow
- `server/src/lib.rs` - Server setup with authentication state
- `server/src/handlers/*.rs` - Protected endpoint examples

## Contributing

This crate is part of the Tolkien project. See the main repository for contribution guidelines.

## License

MIT

## Related Documentation

- [Auth0 Documentation](https://auth0.com/docs)
- [OAuth 2.0 PKCE (RFC 7636)](https://tools.ietf.org/html/rfc7636)
- [JWT (RFC 7519)](https://tools.ietf.org/html/rfc7519)
- [Dioxus Fullstack Guide](https://dioxuslabs.com/learn/0.7/essentials/fullstack)