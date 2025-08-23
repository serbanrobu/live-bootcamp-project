use dotenvy::dotenv;
use lazy_static::lazy_static;
use secrecy::SecretString;
use std::env as std_env;

lazy_static! {
    pub static ref AUTH_SERVICE_IP: String = set_auth_service_ip();
    pub static ref JWT_SECRET: SecretString = set_token();
    pub static ref DATABASE_URL: SecretString = set_database_url();
    pub static ref REDIS_HOST_NAME: String = set_redis_host();
}

fn set_auth_service_ip() -> String {
    dotenv().ok();
    let secret = std_env::var(env::AUTH_SERVICE_IP_ENV_VAR).expect("AUTH_SERVICE_IP must be set.");

    if secret.is_empty() {
        panic!("AUTH_SERVICE_IP must not be empty.");
    }

    secret
}

fn set_token() -> SecretString {
    dotenv().ok();
    let secret = std_env::var(env::JWT_SECRET_ENV_VAR).expect("JWT_SECRET must be set.");

    if secret.is_empty() {
        panic!("JWT_SECRET must not be empty.");
    }

    secret.into()
}

fn set_database_url() -> SecretString {
    dotenv().ok();
    let secret = std_env::var(env::DATABASE_URL_ENV_VAR).expect("DATABASE_URL must be set.");

    if secret.is_empty() {
        panic!("DATABASE_URL must not be empty.");
    }

    secret.into()
}

fn set_redis_host() -> String {
    dotenv().ok();
    std_env::var(env::REDIS_HOST_NAME_ENV_VAR).unwrap_or(DEFAULT_REDIS_HOSTNAME.to_owned())
}

pub mod env {
    pub const AUTH_SERVICE_IP_ENV_VAR: &str = "AUTH_SERVICE_IP";
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
    pub const DATABASE_URL_ENV_VAR: &str = "DATABASE_URL";
    pub const REDIS_HOST_NAME_ENV_VAR: &str = "REDIS_HOST_NAME";
}

pub const JWT_COOKIE_NAME: &str = "jwt";
pub const DEFAULT_REDIS_HOSTNAME: &str = "127.0.0.1";

pub mod prod {
    pub const APP_ADDRESS: &str = "0.0.0.0:3000";
}

pub mod test {
    pub const APP_ADDRESS: &str = "127.0.0.1:0";
}
