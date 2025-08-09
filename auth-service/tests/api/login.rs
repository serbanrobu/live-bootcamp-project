use auth_service::{
    domain::{Email, TwoFACodeStore},
    routes::TwoFactorAuthResponse,
    utils::constants::JWT_COOKIE_NAME,
    ErrorResponse,
};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let app = TestApp::new().await;
    let random_email = Email::parse(get_random_email()).unwrap();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());

    let two_fa_code_store = app.two_fa_code_store.read().await;

    let (login_attempt_id, _) = two_fa_code_store
        .get_code(&random_email)
        .await
        .expect("should get code");

    drop(two_fa_code_store);

    assert_eq!(json_body.login_attempt_id, login_attempt_id.as_ref());
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let input = [
        serde_json::json!({
            "password": "********",
            "email": "",
        }),
        serde_json::json!({
            "password": "qwertyui",
            "email": "email.without.commercial.at",
        }),
        serde_json::json!({
            "password": "short",
            "email": get_random_email(),
        }),
    ];

    for i in input.iter() {
        let response = app.post_login(i).await;
        assert_eq!(response.status().as_u16(), 400, "Failed for input: {i:?}");

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

    let input = serde_json::json!({
        "password": "password123",
        "email": get_random_email(),
    });

    app.post_login(&input).await;
    let response = app.post_login(&input).await;

    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Incorrect credentials".to_owned()
    );
}

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "password": "password123",
        }),
        serde_json::json!({
            "email": random_email,
        }),
        serde_json::json!({}),
        serde_json::json!({
            "password": 123,
            "email": random_email,
        }),
        serde_json::json!({
            "password": "qwertyuiop",
            "email": true,
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {test_case:?}"
        );
    }
}
