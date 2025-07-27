use std::sync::Arc;

use auth_service::{services::hashmap_user_store::HashmapUserStore, AppState, Application};

#[tokio::main]
async fn main() {
    let user_store = HashmapUserStore::default();
    let app_state = AppState::new(Arc::new(user_store.into()));

    let app = Application::build(app_state, "0.0.0.0:3000")
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
