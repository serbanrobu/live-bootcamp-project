use std::{error::Error, sync::Arc};

use axum::{
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use domain::{AuthAPIError, BannedTokenStore, UserStore};
use routes::{login, logout, signup, verify_2fa, verify_token};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::RwLock};
use tower_http::{cors::CorsLayer, services::ServeDir};
use utils::constants::AUTH_SERVICE_IP;

pub mod domain;
pub mod routes;
pub mod services;
pub mod utils;

pub type UserStoreType<UserStoreImpl> = Arc<RwLock<UserStoreImpl>>;

pub type BannedTokenStoreType<BannedTokenStoreImpl> = Arc<RwLock<BannedTokenStoreImpl>>;

pub struct AppState<UserStoreImpl, BannedTokenStoreImpl> {
    pub user_store: UserStoreType<UserStoreImpl>,
    pub banned_token_store: BannedTokenStoreType<BannedTokenStoreImpl>,
}

impl<UserStoreImpl, BannedTokenStoreImpl> Clone for AppState<UserStoreImpl, BannedTokenStoreImpl> {
    fn clone(&self) -> Self {
        Self {
            user_store: self.user_store.clone(),
            banned_token_store: self.banned_token_store.clone(),
        }
    }
}

impl<UserStoreImpl, BannedTokenStoreImpl> AppState<UserStoreImpl, BannedTokenStoreImpl> {
    pub fn new(
        user_store: UserStoreType<UserStoreImpl>,
        banned_token_store: BannedTokenStoreType<BannedTokenStoreImpl>,
    ) -> Self {
        Self {
            user_store,
            banned_token_store,
        }
    }
}

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build<UserStoreImpl, BannedTokenStoreImpl>(
        app_state: AppState<UserStoreImpl, BannedTokenStoreImpl>,
        address: &str,
    ) -> Result<Self, Box<dyn Error>>
    where
        UserStoreImpl: UserStore + Send + Sync + 'static,
        BannedTokenStoreImpl: BannedTokenStore + Send + Sync + 'static,
    {
        let allowed_origins = [
            "http://localhost:8000".parse()?,
            format!("http://{}:8000", AUTH_SERVICE_IP.as_str()).parse()?,
        ];

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_credentials(true)
            .allow_origin(allowed_origins);

        let router = Router::new()
            .fallback_service(ServeDir::new("assets"))
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/verify-2fa", post(verify_2fa))
            .route("/logout", post(logout))
            .route("/verify-token", post(verify_token))
            .with_state(app_state)
            .layer(cors);

        let listener = TcpListener::bind(address).await?;
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
            AuthAPIError::IncorrectCredentials => {
                (StatusCode::UNAUTHORIZED, "Incorrect credentials")
            }
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "Missing token"),
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}
