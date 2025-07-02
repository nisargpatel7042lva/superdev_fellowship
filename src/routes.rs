use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::CorsLayer;

use crate::handlers::*;

pub fn create_application_router() -> Router {
    let cors = CorsLayer::permissive();

    Router::new()
        .route("/health", get(health_check))
        .route("/", get(health_check))
        .route("/keypair", post(create_new_keypair))
        .route("/token/create", post(create_token_mint_instruction))
        .route("/token/account", post(get_associated_token_account))
        .route("/sign", post(sign_message))
        .route("/verify", post(verify_signature))
        .route("/send/sol", post(send_sol_instruction))
        .route("/send/token", post(send_token_v2_instruction))
        .route("/token/mint", post(mint_token_instruction))
        .route("/message/sign", post(message_sign))
        .route("/message/verify", post(message_verify))
        .layer(cors)
} 