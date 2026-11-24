// ascii format
pub fn validate_email(email: &str) -> Result<(), &'static str> {
    if email.len() > 254 || !email.is_ascii() {
        return Err("Wpisz poprawny adres e-mail (maks. 254 znaki ASCII).");
    }
    let mut parts = email.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._+-".contains(&c))
        || !domain.contains('.')
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err("Wpisz poprawny adres e-mail, np. anna@example.com.");
    }
    Ok(())
}

pub fn validate_password_strength(password: &str) -> Result<(), String> {
    // Match HTML maxlength and JavaScript length, including Unicode passwords.
    if !(8..=128).contains(&password.encode_utf16().count()) {
        return Err("Password must be 8-128 characters long".to_string());
    }

    let has_letter = password.chars().any(|ch| ch.is_ascii_alphabetic());
    let has_digit = password.chars().any(|ch| ch.is_ascii_digit());

    if !has_letter || !has_digit {
        return Err("Password must contain at least one letter and one digit".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_password_strength;

    #[test]
    fn password_length_matches_browser_limits_for_unicode() {
        assert!(validate_password_strength("a1ąąą").is_err());
        assert!(validate_password_strength("a1ąąąąąą").is_ok());
        assert!(validate_password_strength(&format!("a1{}", "ą".repeat(126))).is_ok());
        assert!(validate_password_strength(&format!("a1{}", "ą".repeat(127))).is_err());
        assert!(validate_password_strength(&format!("a1{}", "😀".repeat(63))).is_ok());
        assert!(validate_password_strength(&format!("a1{}", "😀".repeat(64))).is_err());
    }
}
