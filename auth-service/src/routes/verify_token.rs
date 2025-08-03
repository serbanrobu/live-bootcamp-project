use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{
    domain::{AuthAPIError, BannedTokenStore},
    utils::auth::validate_token,
    AppState,
};

pub async fn verify_token<UserStoreImpl, BannedTokenStoreImpl>(
    State(state): State<AppState<UserStoreImpl, BannedTokenStoreImpl>>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError>
where
    BannedTokenStoreImpl: BannedTokenStore,
{
    validate_token(&request.token, state.banned_token_store.clone())
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}
