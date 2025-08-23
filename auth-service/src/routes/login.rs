use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::CookieJar;
use color_eyre::eyre::eyre;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::{EmailClientType, TwoFACodeStoreType},
    domain::{
        data_stores::LoginAttemptId, AuthAPIError, Email, EmailClient, Password, TwoFACode,
        TwoFACodeStore, UserStore,
    },
    utils::auth::generate_auth_cookie,
    AppState,
};

#[tracing::instrument(name = "Login", skip_all)]
pub async fn login<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl, EmailClientImpl>(
    State(state): State<
        AppState<UserStoreImpl, BannedTokenStoreImpl, TwoFACodeStoreImpl, EmailClientImpl>,
    >,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<(StatusCode, CookieJar, Json<LoginResponse>), AuthAPIError>
where
    UserStoreImpl: UserStore,
    TwoFACodeStoreImpl: TwoFACodeStore,
    EmailClientImpl: EmailClient,
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
        handle_2fa(
            &user.email,
            &state.two_fa_code_store,
            &state.email_client,
            jar,
        )
        .await
    } else {
        handle_no_2fa(&user.email, jar).await
    }
}

#[tracing::instrument(name = "Handle 2FA", skip_all)]
async fn handle_2fa<TwoFACodeStoreImpl, EmailClientImpl>(
    email: &Email,
    two_fa_code_store: &TwoFACodeStoreType<TwoFACodeStoreImpl>,
    email_client: &EmailClientType<EmailClientImpl>,
    jar: CookieJar,
) -> Result<(StatusCode, CookieJar, Json<LoginResponse>), AuthAPIError>
where
    TwoFACodeStoreImpl: TwoFACodeStore,
    EmailClientImpl: EmailClient,
{
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();
    let mut lock = two_fa_code_store.write().await;

    lock.add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
        .await
        .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;

    drop(lock);

    email_client
        .send_email(
            email,
            "Two FA code",
            &format!(
                "Your two FA code is `{}`.",
                two_fa_code.as_ref().expose_secret()
            ),
        )
        .await
        .map_err(|e| AuthAPIError::UnexpectedError(eyre!(e)))?;

    Ok((
        StatusCode::PARTIAL_CONTENT,
        jar,
        Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
            message: "2FA required".to_owned(),
            login_attempt_id: login_attempt_id.as_ref().expose_secret().to_string(),
        })),
    ))
}

#[tracing::instrument(name = "Handle no 2FA", skip_all)]
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> Result<(StatusCode, CookieJar, Json<LoginResponse>), AuthAPIError> {
    let auth_cookie = generate_auth_cookie(email).map_err(AuthAPIError::UnexpectedError)?;
    let updated_jar = jar.add(auth_cookie);

    Ok((
        StatusCode::OK,
        updated_jar,
        Json(LoginResponse::RegularAuth),
    ))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: SecretString,
    pub password: SecretString,
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
