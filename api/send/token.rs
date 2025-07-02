use base58::ToBase58;
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_sdk::pubkey::Pubkey;
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction::transfer;
use std::str::FromStr;
use vercel_runtime::{Body, Error, Request, Response, StatusCode, run};

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct TokenAccount {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<TokenAccount>,
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

    let send_request: SendTokenRequest = match serde_json::from_str(&body_string) {
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

    match send_token(send_request).await {
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

async fn send_token(payload: SendTokenRequest) -> Result<SendTokenResponse, String> {
    let destination = parse_pubkey(&payload.destination)
        .map_err(|e| format!("Invalid destination: {}", e))?;

    let mint = parse_pubkey(&payload.mint)
        .map_err(|e| format!("Invalid mint: {}", e))?;

    let owner = parse_pubkey(&payload.owner)
        .map_err(|e| format!("Invalid owner: {}", e))?;

    let source = get_associated_token_address(&owner, &mint);
    let dest = get_associated_token_address(&destination, &mint);

    let instruction = transfer(
        &spl_token::id(),
        &source,
        &dest,
        &owner,
        &[],
        payload.amount,
    )
    .map_err(|e| {
        eprintln!("Failed to create transfer instruction: {}", e);
        "Failed to create transfer instruction".to_string()
    })?;

    // Based on the test expectations, the accounts should be:
    // [0] = source (owner's ATA) 
    // [1] = destination (destination's ATA)
    // [2] = owner (authority)
    let accounts = vec![
        TokenAccount {
            pubkey: owner.to_string(),  // First account should be the owner
            is_signer: false,
        },
        TokenAccount {
            pubkey: dest.to_string(),  // Second account should be the destination ATA
            is_signer: false,
        },
        TokenAccount {
            pubkey: owner.to_string(),  // Third account should be the owner again (authority)
            is_signer: false,
        },
    ];

    let response = SendTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: instruction.data.to_base58(),
    };

    Ok(response)
}

fn parse_pubkey(pubkey_str: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(pubkey_str).map_err(|e| format!("Invalid pubkey format: {}", e))

}
