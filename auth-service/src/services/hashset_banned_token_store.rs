use std::collections::HashSet;

use async_trait::async_trait;

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
    async fn insert_token(&mut self, token: String) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.insert(token))
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_insert_token() {
        let token = "qwerty".to_owned();
        let mut store = HashsetBannedTokenStore::default();
        assert!(store.tokens.is_empty());

        assert!(store
            .insert_token(token.clone())
            .await
            .expect("should insert token"));

        assert!(store.tokens.contains(&token));
    }

    #[tokio::test]
    async fn test_contains_token() {
        let token = "1234567890".to_owned();

        let store = HashsetBannedTokenStore {
            tokens: HashSet::from([token.clone()]),
        };

        assert!(!store
            .contains_token("0987654321")
            .await
            .expect("should check if the store contains the token"));

        assert!(store
            .contains_token(&token)
            .await
            .expect("should check if the store contains the token"));
    }
}
