use std::collections::HashSet;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

impl<const N: usize> From<[String; N]> for HashsetBannedTokenStore {
    fn from(value: [String; N]) -> Self {
        Self {
            tokens: value.into(),
        }
    }
}

#[async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token.expose_secret().to_string());
        Ok(())
    }

    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_insert_token() {
        let token: SecretString = "qwerty".into();
        let mut store = HashsetBannedTokenStore::default();
        assert!(store.tokens.is_empty());

        store
            .add_token(token.clone())
            .await
            .expect("should insert token");

        assert!(store.tokens.contains(token.expose_secret()));
    }

    #[tokio::test]
    async fn test_contains_token() {
        let token: SecretString = "1234567890".into();

        let store = HashsetBannedTokenStore {
            tokens: HashSet::from([token.expose_secret().into()]),
        };

        assert!(!store
            .contains_token(&"0987654321".into())
            .await
            .expect("should check if the store contains the token"));

        assert!(store
            .contains_token(&token)
            .await
            .expect("should check if the store contains the token"));
    }
}
