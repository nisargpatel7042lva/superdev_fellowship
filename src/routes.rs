use axum::{
    routing::{post, get},
    Router,
};
use tower_http::cors::CorsLayer;

use crate::handlers::*;

pub fn create_application_router() -> Router {
    let cors = CorsLayer::permissive();

    Router::new()
        .route("/", get(check_server_health))
        .route("/keypair", post(create_new_keypair))
        .route("/token/create", post(create_token_mint_instruction))
        .route("/token/mint", post(create_mint_token_instruction))
        .route("/message/sign", post(sign_message_with_private_key))
        .route("/message/verify", post(verify_signed_message))
        .route("/send/sol", post(create_sol_transfer_instruction))
        .route("/send/token", post(create_token_transfer_instruction))
        .layer(cors)
} 