use std::sync::Arc;

use auth_service::{
    app_state::AppState,
    domain::Email,
    get_postgres_pool, get_redis_client,
    services::{
        data_stores::{
            postgres_user_store::PostgresUserStore, RedisBannedTokenStore, RedisTwoFACodeStore,
        },
        postmark_email_client::PostmarkEmailClient,
    },
    utils::{
        constants::{prod, DATABASE_URL, POSTMARK_AUTH_TOKEN, REDIS_HOST_NAME},
        tracing::init_tracing,
    },
    Application,
};
use reqwest::Client;
use sqlx::PgPool;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    color_eyre::install().expect("Failed to install color_eyre");
    init_tracing().expect("Failed to initialize tracing");

    let pg_pool = configure_postgresql().await;
    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    let redis_conn = Arc::new(RwLock::new(configure_redis()));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(redis_conn.clone())));
    let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new(redis_conn)));
    let email_client = Arc::new(configure_postmark_email_client());

    let app_state = AppState::new(
        user_store,
        banned_token_store,
        two_fa_code_store,
        email_client,
    );

    let _pg_pool = configure_postgresql().await;

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn configure_postgresql() -> PgPool {
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}

fn configure_postmark_email_client() -> PostmarkEmailClient {
    let http_client = Client::builder()
        .timeout(prod::email_client::TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    PostmarkEmailClient::new(
        prod::email_client::BASE_URL.to_owned(),
        Email::parse(prod::email_client::SENDER.to_owned().into()).unwrap(),
        POSTMARK_AUTH_TOKEN.to_owned(),
        http_client,
    )
}
