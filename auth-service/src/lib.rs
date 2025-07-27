use std::{error::Error, sync::Arc};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use domain::{AuthAPIError, UserStore};
use routes::{login, logout, signup, verify_2fa, verify_token};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::services::ServeDir;

mod domain;
pub mod routes;
pub mod services;

pub type UserStoreType<UserStoreImpl> = Arc<RwLock<UserStoreImpl>>;

pub struct AppState<UserStoreImpl> {
    pub user_store: UserStoreType<UserStoreImpl>,
}

impl<UserStoreImpl> Clone for AppState<UserStoreImpl> {
    fn clone(&self) -> Self {
        Self {
            user_store: self.user_store.clone(),
        }
    }
}

impl<UserStoreImpl> AppState<UserStoreImpl> {
    pub fn new(user_store: UserStoreType<UserStoreImpl>) -> Self {
        Self { user_store }
    }
}

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build<UserStoreImpl>(
        app_state: AppState<UserStoreImpl>,
        address: &str,
    ) -> Result<Self, Box<dyn Error>>
    where
        UserStoreImpl: UserStore + Send + Sync + 'static,
    {
        let router = Router::new()
            .nest_service("/", ServeDir::new("assets"))
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/verify-2fa", post(verify_2fa))
            .route("/logout", post(logout))
            .route("/verify-token", post(verify_token))
            .with_state(app_state);

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);
        Ok(Self { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}
