use auth_service::{
    domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore},
    utils::constants::JWT_COOKIE_NAME,
    ErrorResponse,
};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let app = TestApp::new().await;
    let email = Email::parse(get_random_email()).unwrap();
    let password = "password123";

    let signup_body = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": true,
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": email,
        "password": password,
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    let two_fa_code_store = app.two_fa_code_store.read().await;

    let (login_attempt_id, two_fa_code) = two_fa_code_store
        .get_code(&email)
        .await
        .expect("should get code");

    drop(two_fa_code_store);

    let input = serde_json::json!({
        "email": email,
        "loginAttemptId": login_attempt_id,
        "2FACode": two_fa_code,
    });

    let response = app.post_verify_2fa(&input).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    let login_attempt_id = LoginAttemptId::default();
    let code = TwoFACode::default();

    let input = [
        serde_json::json!({
            "email": "",
            "loginAttemptId": login_attempt_id,
            "2FACode": code,
        }),
        serde_json::json!({
            "email": "email.without.commercial.at",
            "loginAttemptId": login_attempt_id,
            "2FACode": code,
        }),
        serde_json::json!({
            "email": get_random_email(),
            "loginAttemptId": "23f6b037-0ea5-4404-a712",
            "2FACode": code,
        }),
        serde_json::json!({
            "email": get_random_email(),
            "loginAttemptId": login_attempt_id,
            "2FACode": "12345",
        }),
    ];

    for i in input.iter() {
        let response = app.post_verify_2fa(i).await;
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
    let email = get_random_email();
    let login_attempt_id = LoginAttemptId::default();
    let code = TwoFACode::default();

    let input = serde_json::json!({
        "email": email,
        "loginAttemptId": login_attempt_id,
        "2FACode": code,
    });

    let response = app.post_verify_2fa(&input).await;

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
async fn should_return_401_if_old_code() {
    let app = TestApp::new().await;
    let email = Email::parse(get_random_email()).unwrap();
    let password = "password123";

    let signup_body = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": true,
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": email,
        "password": password,
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    let two_fa_code_store = app.two_fa_code_store.read().await;

    let (login_attempt_id, two_fa_code) = two_fa_code_store
        .get_code(&email)
        .await
        .expect("should get code");

    drop(two_fa_code_store);

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    let input = serde_json::json!({
        "email": email,
        "loginAttemptId": login_attempt_id,
        "2FACode": two_fa_code,
    });

    app.post_verify_2fa(&input).await;
    let response = app.post_verify_2fa(&input).await;

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
async fn should_return_401_if_same_code_twice() {
    let app = TestApp::new().await;
    let email = Email::parse(get_random_email()).unwrap();
    let password = "password123";

    let signup_body = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": true,
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": email,
        "password": password,
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    let two_fa_code_store = app.two_fa_code_store.read().await;

    let (login_attempt_id, two_fa_code) = two_fa_code_store
        .get_code(&email)
        .await
        .expect("should get code");

    drop(two_fa_code_store);

    let input = serde_json::json!({
        "email": email,
        "loginAttemptId": login_attempt_id,
        "2FACode": two_fa_code,
    });

    let response = app.post_verify_2fa(&input).await;
    assert_eq!(response.status().as_u16(), 200);

    let response = app.post_verify_2fa(&input).await;
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
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let email = get_random_email();
    let login_attempt_id = LoginAttemptId::default();
    let code = TwoFACode::default();

    let test_cases = [
        serde_json::json!({
            "loginAttemptId": login_attempt_id,
            "2FACode": code,
        }),
        serde_json::json!({
            "email": email,
            "2FACode": code,
        }),
        serde_json::json!({
            "email": email,
            "loginAttemptId": login_attempt_id,
        }),
        serde_json::json!({}),
        serde_json::json!({
            "email": email,
            "loginAttemptId": 123,
            "2FACode": code,
        }),
        serde_json::json!({
            "email": email,
            "loginAttemptId": login_attempt_id,
            "2FACode": 123456,
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {test_case:?}"
        );
    }
}
