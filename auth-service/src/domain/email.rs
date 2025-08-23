use std::hash::Hash;

use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, SecretString};
use validator::ValidateEmail;

#[derive(Clone, Debug)]
pub struct Email(SecretString);

impl Email {
    pub fn parse(email: SecretString) -> Result<Self> {
        if !email.expose_secret().validate_email() {
            return Err(eyre!("{} is not a valid email", email.expose_secret()));
        }

        Ok(Self(email))
    }
}

impl AsRef<SecretString> for Email {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state)
    }
}

impl Eq for Email {}

#[cfg(test)]
mod tests {
    use fake::{faker::internet::en::FreeEmail, Fake};
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    use super::*;

    #[quickcheck]
    fn should_parse_valid_email() -> bool {
        let email: String = FreeEmail().fake();
        Email::parse(email.into()).is_ok()
    }

    #[quickcheck]
    fn should_fail_to_parse_invalid_email(email: String) -> TestResult {
        if email.validate_email() {
            return TestResult::discard();
        }

        TestResult::from_bool(Email::parse(email.into()).is_err())
    }
}
