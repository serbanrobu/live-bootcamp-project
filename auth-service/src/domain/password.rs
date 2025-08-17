use std::fmt;

use validator::ValidateLength;

#[derive(Clone, Debug, PartialEq)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Self, String> {
        if !password.validate_length(Some(8), Some(64), None) {
            return Err(format!("{password} is not a valid password"));
        }

        Ok(Self(password))
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Default for Password {
    fn default() -> Self {
        Self("\0\0\0\0\0\0\0\0".to_owned())
    }
}

impl From<Password> for String {
    fn from(value: Password) -> Self {
        value.0
    }
}

impl fmt::Display for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use fake::{faker::internet::en::Password, Fake};
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    use super::*;

    #[quickcheck]
    fn should_parse_valid_password() -> bool {
        let email = Password(8..65).fake();
        Password::parse(email).is_ok()
    }

    #[quickcheck]
    fn should_fail_to_parse_invalid_password(password: String) -> TestResult {
        if password.validate_length(Some(8), Some(64), None) {
            return TestResult::discard();
        }

        TestResult::from_bool(Password::parse(password).is_err())
    }

    #[test]
    fn should_parse_default_password() {
        assert!(Password::parse(Password::default().into()).is_ok())
    }
}
