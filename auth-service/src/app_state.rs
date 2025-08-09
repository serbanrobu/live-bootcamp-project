use std::sync::Arc;

use tokio::sync::RwLock;

pub type UserStoreType<UserStoreImpl> = Arc<RwLock<UserStoreImpl>>;

pub type BannedTokenStoreType<BannedTokenStoreImpl> = Arc<RwLock<BannedTokenStoreImpl>>;

pub type TwoFACodeStoreType<TwoFACodeStoreImpl> = Arc<RwLock<TwoFACodeStoreImpl>>;

pub type EmailClientType<EmailClientImpl> = Arc<EmailClientImpl>;

pub struct AppState<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl, EmailClientImpl> {
    pub user_store: UserStoreType<UserStoreImpl>,
    pub banned_token_store: BannedTokenStoreType<BannedTokenStoreImpl>,
    pub two_fa_code_store: TwoFACodeStoreType<TwoFACodeStoreImpl>,
    pub email_client: EmailClientType<EmailClientImpl>,
}

impl<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl, EmailClientImpl> Clone
    for AppState<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl, EmailClientImpl>
{
    fn clone(&self) -> Self {
        Self {
            user_store: self.user_store.clone(),
            banned_token_store: self.banned_token_store.clone(),
            two_fa_code_store: self.two_fa_code_store.clone(),
            email_client: self.email_client.clone(),
        }
    }
}

impl<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl, EmailClientImpl>
    AppState<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl, EmailClientImpl>
{
    pub fn new(
        user_store: UserStoreType<UserStoreImpl>,
        banned_token_store: BannedTokenStoreType<BannedTokenStoreImpl>,
        two_fa_code_store: TwoFACodeStoreType<TwoFACodeStoreImpl>,
        email_client: EmailClientType<EmailClientImpl>,
    ) -> Self {
        Self {
            user_store,
            banned_token_store,
            two_fa_code_store,
            email_client,
        }
    }
}
