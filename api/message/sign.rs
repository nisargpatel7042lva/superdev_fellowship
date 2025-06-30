use base58::FromBase58;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_sdk::signer::Signer;
use solana_sdk::signer::keypair::Keypair;
use vercel_runtime::{Body, Error, Request, Response, StatusCode, run};

#[derive(Deserialize)]
struct SignRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignResponse {
    signature: String,
    public_key: String,
    message: String,
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

    let body_string = match req.body() {
        Body::Text(text) => text.clone(),
        Body::Binary(bytes) => String::from_utf8_lossy(bytes).to_string(),
        _ => String::new(),
    };

    let sign_request: SignRequest = match serde_json::from_str(&body_string) {
        Ok(req) => req,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .body(
                    json!({
                        "success": false,
                        "error": "Missing required fields"
                    })
                    .to_string()
                    .into(),
                )?);
        }
    };

    match sign_message(sign_request).await {
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

async fn sign_message(request: SignRequest) -> Result<SignResponse, String> {
    // Decode the base58 secret key
    let secret_bytes = request
        .secret
        .from_base58()
        .map_err(|_| "Invalid secret key format")?;

    if secret_bytes.len() != 64 {
        return Err("Invalid secret key length".to_string());
    }

    // Convert to array
    let secret_array: [u8; 64] = secret_bytes
        .try_into()
        .map_err(|_| "Invalid secret key length")?;

    // Create keypair from the secret bytes
    let keypair = Keypair::try_from(&secret_array[..]).map_err(|_| "Invalid keypair")?;

    // Sign the message
    let message_bytes = request.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let response = SignResponse {
        signature: BASE64.encode(signature.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: request.message,
    };

    Ok(response)
}
