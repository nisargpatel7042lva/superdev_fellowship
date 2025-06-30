use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::system_instruction;
use std::str::FromStr;
use vercel_runtime::{Body, Error, Request, Response, StatusCode, run};

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
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

    let send_request: SendSolRequest = match serde_json::from_str(&body_string) {
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

    match send_sol(send_request).await {
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

async fn send_sol(payload: SendSolRequest) -> Result<SendSolResponse, String> {
    // Validate inputs
    if payload.lamports == 0 {
        return Err("Amount must be greater than 0".to_string());
    }

    let from_pubkey =
        parse_pubkey(&payload.from).map_err(|e| format!("Invalid from address: {}", e))?;

    let to_pubkey = parse_pubkey(&payload.to).map_err(|e| format!("Invalid to address: {}", e))?;

    // Create transfer instruction
    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);

    let accounts = vec![from_pubkey.to_string(), to_pubkey.to_string()];

    let response = SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: BASE64.encode(&instruction.data),
    };

    Ok(response)
}

fn parse_pubkey(pubkey_str: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(pubkey_str).map_err(|e| format!("Invalid pubkey format: {}", e))
}
