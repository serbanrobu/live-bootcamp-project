use axum::response::IntoResponse;
use http::StatusCode;

pub async fn login() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
