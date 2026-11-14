//! Username rules, shared so clients can validate before the server does.
//!
//! 3-24 characters of `a-z 0-9 _`, case-insensitive (stored lowercase), no leading,
//! trailing or doubled underscores, and not on the reserved list.

pub const MIN_LEN: usize = 3;
pub const MAX_LEN: usize = 24;

/// Names that could be mistaken for staff or system accounts.
const RESERVED: &[&str] = &[
    "admin",
    "administrator",
    "root",
    "system",
    "support",
    "security",
    "abuse",
    "postmaster",
    "noreply",
    "yappitron",
    "yap",
    "help",
    "staff",
    "moderator",
    "null",
    "undefined",
];

#[derive(Debug, PartialEq, Eq)]
pub enum UsernameError {
    TooShort,
    TooLong,
    InvalidCharacter,
    BadUnderscore,
    Reserved,
}

impl UsernameError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::TooShort => "username must be at least 3 characters",
            Self::TooLong => "username must be at most 24 characters",
            Self::InvalidCharacter => "username may only contain letters, digits and underscores",
            Self::BadUnderscore => "username cannot start or end with an underscore or contain __",
            Self::Reserved => "that username is reserved",
        }
    }
}

impl std::fmt::Display for UsernameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for UsernameError {}

/// Validate `input` and return its canonical (lowercase) form.
pub fn canonicalize(input: &str) -> Result<String, UsernameError> {
    let name = input.to_ascii_lowercase();
    if name.len() < MIN_LEN {
        return Err(UsernameError::TooShort);
    }
    if name.len() > MAX_LEN {
        return Err(UsernameError::TooLong);
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(UsernameError::InvalidCharacter);
    }
    if name.starts_with('_') || name.ends_with('_') || name.contains("__") {
        return Err(UsernameError::BadUnderscore);
    }
    if RESERVED.contains(&name.as_str()) {
        return Err(UsernameError::Reserved);
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercases() {
        assert_eq!(canonicalize("Alice_99").unwrap(), "alice_99");
    }

    #[test]
    fn length_limits() {
        assert_eq!(canonicalize("ab"), Err(UsernameError::TooShort));
        assert!(canonicalize(&"a".repeat(24)).is_ok());
        assert_eq!(canonicalize(&"a".repeat(25)), Err(UsernameError::TooLong));
    }

    #[test]
    fn rejects_bad_characters() {
        for bad in ["bob smith", "bob-smith", "bób", "bob@x", "bob.x", "bob😀"] {
            assert_eq!(
                canonicalize(bad),
                Err(UsernameError::InvalidCharacter),
                "{bad}"
            );
        }
    }

    #[test]
    fn underscore_rules() {
        for bad in ["_bob", "bob_", "bo__b"] {
            assert_eq!(
                canonicalize(bad),
                Err(UsernameError::BadUnderscore),
                "{bad}"
            );
        }
        assert!(canonicalize("bo_b").is_ok());
    }

    #[test]
    fn reserved_names_blocked_case_insensitively() {
        assert_eq!(canonicalize("Admin"), Err(UsernameError::Reserved));
        assert_eq!(canonicalize("ROOT"), Err(UsernameError::Reserved));
    }
}
