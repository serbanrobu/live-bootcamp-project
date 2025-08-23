use async_trait::async_trait;
use color_eyre::eyre::{eyre, Context, Report, Result};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use uuid::Uuid;

use super::{Email, Password, User};

#[async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;

    async fn validate_user(&self, email: &Email, password: &Password)
        -> Result<(), UserStoreError>;
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait]
pub trait BannedTokenStore {
    async fn add_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login Attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone)]
pub struct LoginAttemptId(SecretString);

impl LoginAttemptId {
    pub fn parse(id: SecretString) -> Result<Self> {
        Uuid::parse_str(id.expose_secret()).wrap_err("Invalid login attempt id")?;
        Ok(Self(id))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        Self(Uuid::new_v4().to_string().into())
    }
}

impl AsRef<SecretString> for LoginAttemptId {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

#[derive(Clone, Debug)]
pub struct TwoFACode(SecretString);

impl TwoFACode {
    pub fn parse(code: SecretString) -> Result<Self> {
        if code.expose_secret().len() != 6
            || !code.expose_secret().chars().all(|c| c.is_ascii_digit())
        {
            return Err(eyre!("Invalid 2FA code"));
        }

        Ok(Self(code))
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        Self(format!("{:06}", rand::random_range(0..=999999)).into())
    }
}

impl AsRef<SecretString> for TwoFACode {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}
