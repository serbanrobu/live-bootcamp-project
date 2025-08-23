use auth_service::{
    domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore},
    utils::constants::JWT_COOKIE_NAME,
    ErrorResponse,
};
use secrecy::ExposeSecret;
use test_context::test_context;
use wiremock::{
    matchers::{method, path},
    Mock, ResponseTemplate,
};

use crate::helpers::{get_random_email, TestApp};

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_200_if_correct_code(app: &mut TestApp) {
    let email = Email::parse(get_random_email().into()).unwrap();
    let password = "password123";

    let signup_body = serde_json::json!({
        "email": email.as_ref().expose_secret(),
        "password": password,
        "requires2FA": true,
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_body = serde_json::json!({
        "email": email.as_ref().expose_secret(),
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
        "email": email.as_ref().expose_secret(),
        "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
        "2FACode": two_fa_code.as_ref().expose_secret(),
    });

    let response = app.post_verify_2fa(&input).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_400_if_invalid_input(app: &mut TestApp) {
    let login_attempt_id = LoginAttemptId::default();
    let code = TwoFACode::default();

    let input = [
        serde_json::json!({
            "email": "",
            "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
            "2FACode": code.as_ref().expose_secret(),
        }),
        serde_json::json!({
            "email": "email.without.commercial.at",
            "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
            "2FACode": code.as_ref().expose_secret(),
        }),
        serde_json::json!({
            "email": get_random_email(),
            "loginAttemptId": "23f6b037-0ea5-4404-a712",
            "2FACode": code.as_ref().expose_secret(),
        }),
        serde_json::json!({
            "email": get_random_email(),
            "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
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

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_401_if_incorrect_credentials(app: &mut TestApp) {
    let email = get_random_email();
    let login_attempt_id = LoginAttemptId::default();
    let code = TwoFACode::default();

    let input = serde_json::json!({
        "email": email,
        "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
        "2FACode": code.as_ref().expose_secret(),
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

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_401_if_old_code(app: &mut TestApp) {
    let email = Email::parse(get_random_email().into()).unwrap();
    let password = "password123";

    let signup_body = serde_json::json!({
        "email": email.as_ref().expose_secret(),
        "password": password,
        "requires2FA": true,
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&app.email_server)
        .await;

    let login_body = serde_json::json!({
        "email": email.as_ref().expose_secret(),
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
        "email": email.as_ref().expose_secret(),
        "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
        "2FACode": two_fa_code.as_ref().expose_secret(),
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

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_401_if_same_code_twice(app: &mut TestApp) {
    let email = Email::parse(get_random_email().into()).unwrap();
    let password = "password123";

    let signup_body = serde_json::json!({
        "email": email.as_ref().expose_secret(),
        "password": password,
        "requires2FA": true,
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_body = serde_json::json!({
        "email": email.as_ref().expose_secret(),
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
        "email": email.as_ref().expose_secret(),
        "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
        "2FACode": two_fa_code.as_ref().expose_secret(),
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

#[test_context(TestApp)]
#[tokio::test]
async fn should_return_422_if_malformed_input(app: &mut TestApp) {
    let email = get_random_email();
    let login_attempt_id = LoginAttemptId::default();
    let code = TwoFACode::default();

    let test_cases = [
        serde_json::json!({
            "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
            "2FACode": code.as_ref().expose_secret(),
        }),
        serde_json::json!({
            "email": email,
            "2FACode": code.as_ref().expose_secret(),
        }),
        serde_json::json!({
            "email": email,
            "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
        }),
        serde_json::json!({}),
        serde_json::json!({
            "email": email,
            "loginAttemptId": 123,
            "2FACode": code.as_ref().expose_secret(),
        }),
        serde_json::json!({
            "email": email,
            "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
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
