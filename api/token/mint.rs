use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_sdk::pubkey::Pubkey;
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction::mint_to;
use std::str::FromStr;
use vercel_runtime::{Body, Error, Request, Response, StatusCode, run};

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct InstructionAccount {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct MintTokenResponse {
    program_id: String,
    accounts: Vec<InstructionAccount>,
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

    let mint_request: MintTokenRequest = match serde_json::from_str(&body_string) {
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

    match mint_token(mint_request).await {
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

async fn mint_token(payload: MintTokenRequest) -> Result<MintTokenResponse, String> {
    let mint = parse_pubkey(&payload.mint).map_err(|e| format!("Invalid mint: {}", e))?;

    let destination =
        parse_pubkey(&payload.destination).map_err(|e| format!("Invalid destination: {}", e))?;

    let authority =
        parse_pubkey(&payload.authority).map_err(|e| format!("Invalid authority: {}", e))?;

    // Get the associated token account for the destination
    let destination_token_account = get_associated_token_address(&destination, &mint);

    let instruction = mint_to(
        &spl_token::id(),
        &mint,
        &destination_token_account,
        &authority,
        &[],
        payload.amount,
    )
    .map_err(|e| {
        eprintln!("Failed to create mint_to instruction: {}", e);
        "Failed to create mint_to instruction".to_string()
    })?;

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| InstructionAccount {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let response = MintTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: BASE64.encode(&instruction.data),
    };

    Ok(response)
}

fn parse_pubkey(pubkey_str: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(pubkey_str).map_err(|e| format!("Invalid pubkey format: {}", e))
}
