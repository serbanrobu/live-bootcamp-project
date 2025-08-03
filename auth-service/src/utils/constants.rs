use dotenvy::dotenv;
use lazy_static::lazy_static;
use std::env as std_env;

lazy_static! {
    pub static ref AUTH_SERVICE_IP: String = set_auth_service_ip();
    pub static ref JWT_SECRET: String = set_token();
}

fn set_auth_service_ip() -> String {
    dotenv().ok();
    let secret = std_env::var(env::AUTH_SERVICE_IP_ENV_VAR).expect("AUTH_SERVICE_IP must be set.");

    if secret.is_empty() {
        panic!("AUTH_SERVICE_IP must not be empty.");
    }

    secret
}

fn set_token() -> String {
    dotenv().ok();
    let secret = std_env::var(env::JWT_SECRET_ENV_VAR).expect("JWT_SECRET must be set.");

    if secret.is_empty() {
        panic!("JWT_SECRET must not be empty.");
    }

    secret
}

pub mod env {
    pub const AUTH_SERVICE_IP_ENV_VAR: &str = "AUTH_SERVICE_IP";
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
}

pub const JWT_COOKIE_NAME: &str = "jwt";

pub mod prod {
    pub const APP_ADDRESS: &str = "0.0.0.0:3000";
}

pub mod test {
    pub const APP_ADDRESS: &str = "127.0.0.1:0";
}
