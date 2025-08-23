use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;

use crate::{
    domain::{AuthAPIError, BannedTokenStore},
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
    AppState,
};

#[tracing::instrument(name = "Logout", skip_all)]
pub async fn logout<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl, EmailClientImpl>(
    State(state): State<
        AppState<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl, EmailClientImpl>,
    >,
    jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError>
where
    BannedTokenStoreImpl: BannedTokenStore,
{
    let cookie = jar.get(JWT_COOKIE_NAME).ok_or(AuthAPIError::MissingToken)?;
    let token = cookie.value().to_owned();

    validate_token(&token, &state.banned_token_store)
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    let updated_jar = jar.remove(JWT_COOKIE_NAME);
    let mut banned_token_store = state.banned_token_store.write().await;

    banned_token_store
        .add_token(token)
        .await
        .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;

    drop(banned_token_store);

    Ok((updated_jar, StatusCode::OK))
}
