use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{domain::AuthAPIError, utils::auth::validate_token};

pub async fn verify_token(
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    validate_token(&request.token)
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}
