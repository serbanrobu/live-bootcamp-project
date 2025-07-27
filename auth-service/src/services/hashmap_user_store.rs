use std::collections::HashMap;

use crate::domain::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }

        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        let user = self.users.get(email).ok_or(UserStoreError::UserNotFound)?;

        if user.password != password {
            return Err(UserStoreError::InvalidCredentials);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_user() {
        let mut store = HashmapUserStore::default();
        assert!(store.users.is_empty());
        let user = new_example_user();
        store.add_user(user.clone()).expect("should add user");
        assert_eq!(store.users.get(&user.email), Some(&user));
    }

    #[test]
    fn test_get_user() {
        let user = new_example_user();

        let store = HashmapUserStore {
            users: HashMap::from([(user.email.clone(), user.clone())]),
        };

        let actual = store.get_user(&user.email).expect("should get user");
        assert_eq!(actual, user);
    }

    #[test]
    fn test_validate_user() {
        let user = new_example_user();

        let store = HashmapUserStore {
            users: HashMap::from([(user.email.clone(), user.clone())]),
        };

        store
            .validate_user(&user.email, &user.password)
            .expect("should validate user");
        store
            .validate_user(&user.email, "12345678")
            .expect_err("should not validate user");
        store
            .validate_user("john@example.com", &user.password)
            .expect_err("should not validate user");
        store
            .validate_user("doe@example.com", "87654321")
            .expect_err("should not validate user");
    }

    fn new_example_user() -> User {
        User {
            email: "john.doe@example.com".to_owned(),
            password: "********".to_owned(),
            requires_2fa: true,
        }
    }
}
