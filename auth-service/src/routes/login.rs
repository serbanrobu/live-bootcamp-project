use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::TwoFACodeStoreType,
    domain::{
        data_stores::LoginAttemptId, AuthAPIError, Email, Password, TwoFACode, TwoFACodeStore,
        UserStore,
    },
    utils::auth::generate_auth_cookie,
    AppState,
};

pub async fn login<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl>(
    State(state): State<AppState<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl>>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<(StatusCode, CookieJar, Json<LoginResponse>), AuthAPIError>
where
    UserStoreImpl: UserStore,
    TwoFACodeStoreImpl: TwoFACodeStore,
{
    let email = Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let password =
        Password::parse(request.password).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = state.user_store.read().await;

    user_store
        .validate_user(&email, &password)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    let user = user_store
        .get_user(&email)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    drop(user_store);

    if user.requires_2fa {
        handle_2fa(user.email, &state.two_fa_code_store, jar).await
    } else {
        handle_no_2fa(&user.email, jar).await
    }
}

async fn handle_2fa<TwoFACodeStoreImpl>(
    email: Email,
    two_fa_code_store: &TwoFACodeStoreType<TwoFACodeStoreImpl>,
    jar: CookieJar,
) -> Result<(StatusCode, CookieJar, Json<LoginResponse>), AuthAPIError>
where
    TwoFACodeStoreImpl: TwoFACodeStore,
{
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();
    let mut lock = two_fa_code_store.write().await;

    lock.add_code(email, login_attempt_id.clone(), two_fa_code)
        .await
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    drop(lock);

    Ok((
        StatusCode::PARTIAL_CONTENT,
        jar,
        Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
            message: "2FA required".to_owned(),
            login_attempt_id: login_attempt_id.into(),
        })),
    ))
}

async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> Result<(StatusCode, CookieJar, Json<LoginResponse>), AuthAPIError> {
    let auth_cookie = generate_auth_cookie(email).map_err(|_| AuthAPIError::UnexpectedError)?;
    let updated_jar = jar.add(auth_cookie);

    Ok((
        StatusCode::OK,
        updated_jar,
        Json(LoginResponse::RegularAuth),
    ))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}
