use base58::ToBase58;
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_sdk::signer::Signer;
use solana_sdk::signer::keypair::Keypair;
use vercel_runtime::{Body, Error, Request, Response, StatusCode, run};

#[derive(Serialize, Deserialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(handler).await
}

pub async fn handler(req: Request) -> Result<Response<Body>, Error> {
    if req.method() != "POST" {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "success": false,
                    "error": "Method not allowed"
                })
                .to_string()
                .into(),
            )?);
    }

    match generate_keypair().await {
        Ok(response) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "success": true,
                    "data": response
                })
                .to_string()
                .into(),
            )?),
        Err(error_msg) => Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "success": false,
                    "error": error_msg
                })
                .to_string()
                .into(),
            )?),
    }
}

async fn generate_keypair() -> Result<KeypairResponse, String> {
    let keypair = Keypair::new();

    let mut secret_bytes = [0u8; 64];
    secret_bytes[..32].copy_from_slice(keypair.secret_bytes());
    secret_bytes[32..].copy_from_slice(&keypair.pubkey().to_bytes());

    let response = KeypairResponse {
        pubkey: keypair.pubkey().to_bytes().to_base58(),
        secret: secret_bytes.to_base58(),
    };

    Ok(response)
}
