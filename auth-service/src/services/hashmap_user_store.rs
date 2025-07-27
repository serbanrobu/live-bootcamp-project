use std::collections::HashMap;

use axum::async_trait;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }

        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        let user = self.users.get(email).ok_or(UserStoreError::UserNotFound)?;

        if user.password != *password {
            return Err(UserStoreError::InvalidCredentials);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        assert!(store.users.is_empty());
        let user = new_example_user();
        store.add_user(user.clone()).await.expect("should add user");
        assert_eq!(store.users.get(&user.email), Some(&user));
    }

    #[tokio::test]
    async fn test_get_user() {
        let user = new_example_user();

        let store = HashmapUserStore {
            users: HashMap::from([(user.email.clone(), user.clone())]),
        };

        let actual = store.get_user(&user.email).await.expect("should get user");
        assert_eq!(actual, user);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let user = new_example_user();

        let store = HashmapUserStore {
            users: HashMap::from([(user.email.clone(), user.clone())]),
        };

        store
            .validate_user(&user.email, &user.password)
            .await
            .expect("should validate user");

        store
            .validate_user(
                &user.email,
                &Password::parse("12345678".to_owned()).unwrap(),
            )
            .await
            .expect_err("should not validate user");

        store
            .validate_user(
                &Email::parse("john@example.com".to_owned()).unwrap(),
                &user.password,
            )
            .await
            .expect_err("should not validate user");

        store
            .validate_user(
                &Email::parse("doe@example.com".to_owned()).unwrap(),
                &Password::parse("87654321".to_owned()).unwrap(),
            )
            .await
            .expect_err("should not validate user");
    }

    fn new_example_user() -> User {
        User {
            email: Email::parse("john.doe@example.com".to_owned()).unwrap(),
            password: Password::parse("********".to_owned()).unwrap(),
            requires_2fa: true,
        }
    }
}
