use std::error::Error;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};

use async_trait::async_trait;
use sqlx::PgPool;
use tokio::task;

use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    Email, Password, User,
};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserStore for PostgresUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let password_hash = compute_password_hash(user.password.into())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        sqlx::query!(
            "INSERT INTO users VALUES ($1, $2, $3)",
            user.email.as_ref(),
            password_hash,
            user.requires_2fa,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(e)
                if e.code().is_some_and(|c| c == UNIQUE_VIOLATION_ERROR_CODE) =>
            {
                UserStoreError::UserAlreadyExists
            }
            _ => UserStoreError::UnexpectedError,
        })?;

        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let requires_2fa = sqlx::query_scalar!(
            "SELECT requires_2fa FROM users WHERE email = $1",
            email.as_ref(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?
        .ok_or(UserStoreError::UserNotFound)?;

        Ok(User::new(email.clone(), Default::default(), requires_2fa))
    }

    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        let password_hash = sqlx::query_scalar!(
            "SELECT password_hash FROM users WHERE email = $1",
            email.as_ref(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?
        .ok_or(UserStoreError::UserNotFound)?;

        verify_password_hash(password_hash, password.to_string())
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}

async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    task::spawn_blocking(move || {
        let expected_password_hash = PasswordHash::new(&expected_password_hash)?;

        Argon2::default()
            .verify_password(password_candidate.as_bytes(), &expected_password_hash)?;

        Ok(())
    })
    .await?
}

async fn compute_password_hash(password: String) -> Result<String, Box<dyn Error + Send + Sync>> {
    task::spawn_blocking(move || {
        let salt: SaltString = SaltString::generate(&mut OsRng);

        let password_hash = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None)?,
        )
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

        Ok(password_hash)
    })
    .await?
}

const UNIQUE_VIOLATION_ERROR_CODE: &str = "23505";
