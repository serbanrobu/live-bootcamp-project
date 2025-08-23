use std::collections::HashMap;

use async_trait::async_trait;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email);
        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.codes
            .get(email)
            .cloned()
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
    }
}

#[cfg(test)]
mod tests {
    use fake::{faker::internet::en::FreeEmail, Fake};

    use super::*;

    #[tokio::test]
    async fn test_add_code() {
        let mut store = HashmapTwoFACodeStore::default();
        assert!(store.codes.is_empty());
        let email = Email::parse(FreeEmail().fake::<String>().into()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .expect("should add code");

        assert_eq!(store.codes.get(&email), Some(&(login_attempt_id, code)));
    }

    #[tokio::test]
    async fn test_remove_code() {
        let email = Email::parse(FreeEmail().fake::<String>().into()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        let mut store = HashmapTwoFACodeStore {
            codes: HashMap::from([(email.clone(), (login_attempt_id.clone(), code.clone()))]),
        };

        store.remove_code(&email).await.expect("should remove code");
        assert!(store.codes.is_empty());
    }

    #[tokio::test]
    async fn test_get_code() {
        let email = Email::parse(FreeEmail().fake::<String>().into()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        let store = HashmapTwoFACodeStore {
            codes: HashMap::from([(email.clone(), (login_attempt_id.clone(), code.clone()))]),
        };

        let actual = store.get_code(&email).await.expect("should get code");
        assert_eq!(actual, (login_attempt_id, code));
    }
}
