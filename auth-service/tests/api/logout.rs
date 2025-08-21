use auth_service::{
    domain::{BannedTokenStore, Email},
    utils::{
        auth::{create_auth_cookie, generate_auth_cookie, generate_auth_token},
        constants::JWT_COOKIE_NAME,
    },
    ErrorResponse,
};
use fake::{faker::internet::en::FreeEmail, Fake};
use reqwest::Url;
use test_context::test_context;

use crate::helpers::TestApp;

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie(app: &mut TestApp) {
    let token = generate_auth_token(&Email::parse(FreeEmail().fake()).unwrap()).unwrap();

    let cookie = create_auth_cookie(token.clone());

    app.cookie_jar.add_cookie_str(
        &format!("{cookie}; HttpOnly; SameSite=Lax; Secure; Path=/"),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200);
    let banned_token_store = app.banned_token_store.read().await;
    assert!(banned_token_store.contains_token(&token).await.unwrap());
}

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row(app: &mut TestApp) {
    let cookie = generate_auth_cookie(&Email::parse(FreeEmail().fake()).unwrap()).unwrap();

    app.cookie_jar.add_cookie_str(
        &format!("{cookie}; HttpOnly; SameSite=Lax; Secure; Path=/"),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    app.post_logout().await;
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Missing token".to_owned()
    );
}

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing(app: &mut TestApp) {
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Missing token".to_owned()
    );
}

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_401_if_invalid_token(app: &mut TestApp) {
    app.cookie_jar.add_cookie_str(
        &format!("{JWT_COOKIE_NAME}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/"),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid token".to_owned()
    );
}
