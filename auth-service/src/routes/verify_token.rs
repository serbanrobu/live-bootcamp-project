use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use secrecy::SecretString;
use serde::Deserialize;

use crate::{
    domain::{AuthAPIError, BannedTokenStore},
    utils::auth::validate_token,
    AppState,
};

#[tracing::instrument(name = "Verify token", skip_all)]
pub async fn verify_token<
    UserStoreImpl,
    BannedTokenStoreImpl,
    TwoFACodeStoreImpl,
    EmailClientImpl,
>(
    State(state): State<
        AppState<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl, EmailClientImpl>,
    >,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError>
where
    BannedTokenStoreImpl: BannedTokenStore,
{
    validate_token(&request.token, &state.banned_token_store)
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: SecretString,
}
