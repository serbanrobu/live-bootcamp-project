use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, SecretString};
use validator::ValidateLength;

#[derive(Clone, Debug)]
pub struct Password(SecretString);

impl Password {
    pub fn parse(password: SecretString) -> Result<Self> {
        if !password
            .expose_secret()
            .validate_length(Some(8), Some(64), None)
        {
            return Err(eyre!("Failed to parse string to a Password type"));
        }

        Ok(Self(password))
    }
}

impl AsRef<SecretString> for Password {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

impl Default for Password {
    fn default() -> Self {
        Self("\0\0\0\0\0\0\0\0".into())
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
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
        let email: String = Password(8..65).fake();
        Password::parse(email.into()).is_ok()
    }

    #[quickcheck]
    fn should_fail_to_parse_invalid_password(password: String) -> TestResult {
        if password.validate_length(Some(8), Some(64), None) {
            return TestResult::discard();
        }

        TestResult::from_bool(Password::parse(password.into()).is_err())
    }

    #[test]
    fn should_parse_default_password() {
        assert!(Password::parse(Password::default().as_ref().to_owned()).is_ok())
    }
}
