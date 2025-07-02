use base58::{FromBase58, ToBase58};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_sdk::signer::Signer;
use solana_sdk::signer::keypair::Keypair;
use vercel_runtime::{Body, Error, Request, Response, StatusCode, run};

#[derive(Deserialize)]
struct SignRequest {
    message: String,
    secret: Value,
}

#[derive(Serialize)]
struct SignResponse {
    signature: String,
    pubkey: String,
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
    // Handle both string and array formats for secret key
    let secret_bytes = match &request.secret {
        Value::String(s) => {
            // If it's a string, try to decode as base58
            s.from_base58().map_err(|_| "Invalid secret key format")?
        }
        Value::Array(arr) => {
            // If it's an array, convert each element to u8
            let mut bytes = Vec::new();
            for val in arr {
                if let Value::Number(n) = val {
                    if let Some(byte) = n.as_u64() {
                        if byte <= 255 {
                            bytes.push(byte as u8);
                        } else {
                            return Err("Invalid byte value in secret key".to_string());
                        }
                    } else {
                        return Err("Invalid number in secret key".to_string());
                    }
                } else {
                    return Err("Invalid secret key format".to_string());
                }
            }
            bytes
        }
        _ => return Err("Invalid secret key format".to_string()),
    };

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
        signature: signature.as_ref().to_base58(),
        pubkey: keypair.pubkey().to_string(),
        message: request.message,
    };

    Ok(response)
}
