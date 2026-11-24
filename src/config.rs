// just email verification flag

pub const REQUIRE_EMAIL_VERIFICATION: bool = false;

pub fn verification_required() -> Result<bool, String> {
    match std::env::var("REQUIRE_EMAIL_VERIFICATION") {
        Ok(value) => match value.as_str() {
            "" => Ok(REQUIRE_EMAIL_VERIFICATION),
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err("REQUIRE_EMAIL_VERIFICATION must be true or false".into()),
        },
        Err(std::env::VarError::NotPresent) => Ok(REQUIRE_EMAIL_VERIFICATION),
        Err(_) => Err("Invalid REQUIRE_EMAIL_VERIFICATION".into()),
    }
}
