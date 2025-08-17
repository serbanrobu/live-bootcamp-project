use std::fmt;

use serde::Serialize;
use validator::ValidateEmail;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Self, String> {
        if !email.validate_email() {
            return Err(format!("{email} is not a valid email"));
        }

        Ok(Self(email))
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<Email> for String {
    fn from(value: Email) -> Self {
        value.0
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use fake::{faker::internet::en::FreeEmail, Fake};
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    use super::*;

    #[quickcheck]
    fn should_parse_valid_email() -> bool {
        let email = FreeEmail().fake();
        Email::parse(email).is_ok()
    }

    #[quickcheck]
    fn should_fail_to_parse_invalid_email(email: String) -> TestResult {
        if email.validate_email() {
            return TestResult::discard();
        }

        TestResult::from_bool(Email::parse(email).is_err())
    }
}
