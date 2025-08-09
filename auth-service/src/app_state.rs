use std::sync::Arc;

use tokio::sync::RwLock;

pub type UserStoreType<UserStoreImpl> = Arc<RwLock<UserStoreImpl>>;

pub type BannedTokenStoreType<BannedTokenStoreImpl> = Arc<RwLock<BannedTokenStoreImpl>>;

pub type TwoFACodeStoreType<TwoFACodeStoreImpl> = Arc<RwLock<TwoFACodeStoreImpl>>;

pub struct AppState<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl> {
    pub user_store: UserStoreType<UserStoreImpl>,
    pub banned_token_store: BannedTokenStoreType<BannedTokenStoreImpl>,
    pub two_fa_code_store: TwoFACodeStoreType<TwoFACodeStoreImpl>,
}

impl<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl> Clone
    for AppState<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl>
{
    fn clone(&self) -> Self {
        Self {
            user_store: self.user_store.clone(),
            banned_token_store: self.banned_token_store.clone(),
            two_fa_code_store: self.two_fa_code_store.clone(),
        }
    }
}

impl<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl>
    AppState<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl>
{
    pub fn new(
        user_store: UserStoreType<UserStoreImpl>,
        banned_token_store: BannedTokenStoreType<BannedTokenStoreImpl>,
        two_fa_code_store: TwoFACodeStoreType<TwoFACodeStoreImpl>,
    ) -> Self {
        Self {
            user_store,
            banned_token_store,
            two_fa_code_store,
        }
    }
}
