use auth_service::{
    domain::{BannedTokenStore, Email},
    utils::auth::generate_auth_token,
    ErrorResponse,
};
use fake::{faker::internet::en::FreeEmail, Fake};
use test_context::test_context;

use crate::helpers::TestApp;

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_200_valid_token(app: &mut TestApp) {
    let token = generate_auth_token(&Email::parse(FreeEmail().fake()).unwrap()).unwrap();

    let verify_token_body = serde_json::json!({
        "token": token,
    });

    let response = app.post_verify_token(&verify_token_body).await;
    assert_eq!(response.status().as_u16(), 200);
}

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_401_if_banned_token(app: &mut TestApp) {
    let token = generate_auth_token(&Email::parse(FreeEmail().fake()).unwrap()).unwrap();

    let mut banned_token_store = app.banned_token_store.write().await;

    banned_token_store.add_token(token.clone()).await.unwrap();

    drop(banned_token_store);

    let verify_token_body = serde_json::json!({
        "token": token,
    });

    let response = app.post_verify_token(&verify_token_body).await;
    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid auth token".to_owned()
    );
}

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_401_if_invalid_token(app: &mut TestApp) {
    let verify_token_body = serde_json::json!({
        "token": "invalid token",
    });

    let response = app.post_verify_token(&verify_token_body).await;
    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid auth token".to_owned()
    );
}

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_422_if_malformed_input(app: &mut TestApp) {
    let test_cases = [
        serde_json::json!({}),
        serde_json::json!({ "token": 1234567890 }),
        serde_json::json!({ "tok": "qwertyuiopasdfghjklzxcvbnm" }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_token(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {test_case:?}"
        );
    }
}
