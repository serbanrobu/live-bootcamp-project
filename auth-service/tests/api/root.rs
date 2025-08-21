use test_context::test_context;

use crate::helpers::TestApp;

#[test_context(TestApp)]
#[tokio::test]
async fn root_returns_auth_ui(app: &mut TestApp) {
    let response = app.get_root().await;

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
}
