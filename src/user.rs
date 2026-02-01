//! User profile data structures for authenticated users.
//!
//! This module defines the `User` struct that represents an authenticated user's
//! profile information, typically extracted from Auth0 ID tokens or JWT claims.
//!
//! This is a shared module used by both client and server crates.

use serde::{Deserialize, Serialize};

/// Represents an authenticated user's profile information.
///
/// This struct contains the core user profile fields extracted from Auth0 ID tokens.
/// The fields correspond to standard OpenID Connect claims.
///
/// Used on both client (from ID token) and server (from validated JWT claims).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Unique user identifier (subject claim from JWT).
    ///
    /// This is typically in the format `auth0|<user_id>` or `<provider>|<user_id>`.
    pub id: String,

    /// User's email address.
    ///
    /// This field may be `None` if the user hasn't verified their email
    /// or if email scope wasn't requested during authentication.
    pub email: Option<String>,

    /// User's display name.
    ///
    /// This is typically the user's full name or chosen display name.
    /// May be `None` if the user hasn't set a name.
    pub name: Option<String>,

    /// URL to the user's profile picture.
    ///
    /// This is typically provided by the authentication provider (Auth0, Google, etc.).
    /// May be `None` if no picture is available.
    pub picture: Option<String>,
}

impl User {
    /// Creates a new User with the given ID.
    ///
    /// All optional fields are set to `None`.
    ///
    /// # Example
    ///
    /// ```
    /// # use dxauth0::User;
    /// let user = User::new("auth0|123456".to_string());
    /// assert_eq!(user.id, "auth0|123456");
    /// assert!(user.email.is_none());
    /// ```
    pub fn new(id: String) -> Self {
        Self {
            id,
            email: None,
            name: None,
            picture: None,
        }
    }

    /// Creates a new User with all fields specified.
    ///
    /// # Example
    ///
    /// ```
    /// # use dxauth0::User;
    /// let user = User::with_details(
    ///     "auth0|123456".to_string(),
    ///     Some("user@example.com".to_string()),
    ///     Some("John Doe".to_string()),
    ///     Some("https://example.com/avatar.jpg".to_string()),
    /// );
    /// assert_eq!(user.email.as_deref(), Some("user@example.com"));
    /// ```
    pub fn with_details(
        id: String,
        email: Option<String>,
        name: Option<String>,
        picture: Option<String>,
    ) -> Self {
        Self {
            id,
            email,
            name,
            picture,
        }
    }

    /// Returns a display name for the user.
    ///
    /// Prefers the user's name if available, falls back to email,
    /// and finally to the user ID.
    ///
    /// # Example
    ///
    /// ```
    /// # use dxauth0::User;
    /// let user = User::with_details(
    ///     "auth0|123456".to_string(),
    ///     Some("user@example.com".to_string()),
    ///     Some("John Doe".to_string()),
    ///     None,
    /// );
    /// assert_eq!(user.display_name(), "John Doe");
    /// ```
    pub fn display_name(&self) -> &str {
        self.name
            .as_deref()
            .or(self.email.as_deref())
            .unwrap_or(&self.id)
    }

    /// Returns the user's initials for avatar display.
    ///
    /// If the user has a name, returns the first letter of the first two words.
    /// Otherwise, returns the first two characters of the email or ID.
    ///
    /// # Example
    ///
    /// ```
    /// # use dxauth0::User;
    /// let user = User::with_details(
    ///     "auth0|123456".to_string(),
    ///     None,
    ///     Some("John Doe".to_string()),
    ///     None,
    /// );
    /// assert_eq!(user.initials(), "JD");
    /// ```
    pub fn initials(&self) -> String {
        if let Some(name) = &self.name {
            let parts: Vec<&str> = name.split_whitespace().collect();
            match parts.len() {
                0 => "??".to_string(),
                1 => parts[0].chars().take(2).collect::<String>().to_uppercase(),
                _ => {
                    let first = parts[0].chars().next().unwrap_or('?');
                    let second = parts[1].chars().next().unwrap_or('?');
                    format!("{}{}", first, second).to_uppercase()
                }
            }
        } else if let Some(email) = &self.email {
            email.chars().take(2).collect::<String>().to_uppercase()
        } else {
            self.id.chars().take(2).collect::<String>().to_uppercase()
        }
    }

    /// Checks if the user has verified their email.
    ///
    /// Returns `true` if an email is present, `false` otherwise.
    /// Note: This doesn't check the actual verification status,
    /// just whether an email is available.
    pub fn has_email(&self) -> bool {
        self.email.is_some()
    }

    /// Checks if the user has a profile picture.
    pub fn has_picture(&self) -> bool {
        self.picture.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_new() {
        let user = User::new("auth0|123456".to_string());
        assert_eq!(user.id, "auth0|123456");
        assert!(user.email.is_none());
        assert!(user.name.is_none());
        assert!(user.picture.is_none());
    }

    #[test]
    fn test_user_with_details() {
        let user = User::with_details(
            "auth0|123456".to_string(),
            Some("user@example.com".to_string()),
            Some("John Doe".to_string()),
            Some("https://example.com/avatar.jpg".to_string()),
        );

        assert_eq!(user.id, "auth0|123456");
        assert_eq!(user.email.as_deref(), Some("user@example.com"));
        assert_eq!(user.name.as_deref(), Some("John Doe"));
        assert_eq!(
            user.picture.as_deref(),
            Some("https://example.com/avatar.jpg")
        );
    }

    #[test]
    fn test_display_name_with_name() {
        let user = User::with_details(
            "auth0|123456".to_string(),
            Some("user@example.com".to_string()),
            Some("John Doe".to_string()),
            None,
        );
        assert_eq!(user.display_name(), "John Doe");
    }

    #[test]
    fn test_display_name_with_email_only() {
        let user = User::with_details(
            "auth0|123456".to_string(),
            Some("user@example.com".to_string()),
            None,
            None,
        );
        assert_eq!(user.display_name(), "user@example.com");
    }

    #[test]
    fn test_display_name_with_id_only() {
        let user = User::new("auth0|123456".to_string());
        assert_eq!(user.display_name(), "auth0|123456");
    }

    #[test]
    fn test_initials_from_full_name() {
        let user = User::with_details(
            "auth0|123456".to_string(),
            None,
            Some("John Doe".to_string()),
            None,
        );
        assert_eq!(user.initials(), "JD");
    }

    #[test]
    fn test_initials_from_single_name() {
        let user = User::with_details(
            "auth0|123456".to_string(),
            None,
            Some("Madonna".to_string()),
            None,
        );
        assert_eq!(user.initials(), "MA");
    }

    #[test]
    fn test_initials_from_email() {
        let user = User::with_details(
            "auth0|123456".to_string(),
            Some("john@example.com".to_string()),
            None,
            None,
        );
        assert_eq!(user.initials(), "JO");
    }

    #[test]
    fn test_initials_from_id() {
        let user = User::new("auth0|123456".to_string());
        assert_eq!(user.initials(), "AU");
    }

    #[test]
    fn test_initials_three_word_name() {
        let user = User::with_details(
            "auth0|123456".to_string(),
            None,
            Some("John Paul Smith".to_string()),
            None,
        );
        // Should only use first two words
        assert_eq!(user.initials(), "JP");
    }

    #[test]
    fn test_has_email_true() {
        let user = User::with_details(
            "auth0|123456".to_string(),
            Some("user@example.com".to_string()),
            None,
            None,
        );
        assert!(user.has_email());
    }

    #[test]
    fn test_has_email_false() {
        let user = User::new("auth0|123456".to_string());
        assert!(!user.has_email());
    }

    #[test]
    fn test_has_picture_true() {
        let user = User::with_details(
            "auth0|123456".to_string(),
            None,
            None,
            Some("https://example.com/avatar.jpg".to_string()),
        );
        assert!(user.has_picture());
    }

    #[test]
    fn test_has_picture_false() {
        let user = User::new("auth0|123456".to_string());
        assert!(!user.has_picture());
    }

    #[test]
    fn test_clone() {
        let user1 = User::with_details(
            "auth0|123456".to_string(),
            Some("user@example.com".to_string()),
            Some("John Doe".to_string()),
            Some("https://example.com/avatar.jpg".to_string()),
        );

        let user2 = user1.clone();
        assert_eq!(user1, user2);
    }

    #[test]
    fn test_serialization() {
        let user = User::with_details(
            "auth0|123456".to_string(),
            Some("user@example.com".to_string()),
            Some("John Doe".to_string()),
            Some("https://example.com/avatar.jpg".to_string()),
        );

        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("auth0|123456"));
        assert!(json.contains("user@example.com"));
        assert!(json.contains("John Doe"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "id": "auth0|123456",
            "email": "user@example.com",
            "name": "John Doe",
            "picture": "https://example.com/avatar.jpg"
        }"#;

        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.id, "auth0|123456");
        assert_eq!(user.email.as_deref(), Some("user@example.com"));
        assert_eq!(user.name.as_deref(), Some("John Doe"));
        assert_eq!(
            user.picture.as_deref(),
            Some("https://example.com/avatar.jpg")
        );
    }

    #[test]
    fn test_deserialization_with_nulls() {
        let json = r#"{
            "id": "auth0|123456",
            "email": null,
            "name": null,
            "picture": null
        }"#;

        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.id, "auth0|123456");
        assert!(user.email.is_none());
        assert!(user.name.is_none());
        assert!(user.picture.is_none());
    }

    #[test]
    fn test_equality() {
        let user1 = User::with_details(
            "auth0|123456".to_string(),
            Some("user@example.com".to_string()),
            Some("John Doe".to_string()),
            None,
        );

        let user2 = User::with_details(
            "auth0|123456".to_string(),
            Some("user@example.com".to_string()),
            Some("John Doe".to_string()),
            None,
        );

        assert_eq!(user1, user2);
    }

    #[test]
    fn test_inequality() {
        let user1 = User::new("auth0|123456".to_string());
        let user2 = User::new("auth0|654321".to_string());

        assert_ne!(user1, user2);
    }
}
