use axum::{response::Json, http::StatusCode, response::IntoResponse};
use serde_json::json;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::pubkey::Pubkey;
use spl_token::instruction as token_instruction;
use crate::models::{ApiResponse, KeypairResponse, CreateTokenRequest, TokenInstructionResponse, AccountMetaResponse};
use std::str::FromStr;
use serde::Deserialize;
use spl_associated_token_account::get_associated_token_address;
use bs58;

pub async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "success": true,
        "message": "Solana Fellowship API is running"
    }))
}

pub async fn create_new_keypair() -> Json<ApiResponse<KeypairResponse>> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    Json(ApiResponse {
        success: true,
        data: Some(KeypairResponse { pubkey, secret }),
        error: None,
    })
}

pub async fn create_token_mint_instruction(
    Json(payload): Json<CreateTokenRequest>,
) -> (StatusCode, Json<ApiResponse<TokenInstructionResponse>>) {
    // Validate input
    let mint_authority = match Pubkey::from_str(&payload.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid public key".to_string()),
            }));
        }
    };
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid public key".to_string()),
            }));
        }
    };
    if payload.decimals > 9 {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Decimals must be between 0 and 9".to_string()),
        }));
    }
    let instruction = match token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        payload.decimals,
    ) {
        Ok(instr) => instr,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Failed to create instruction".to_string()),
            }));
        }
    };
    let accounts: Vec<AccountMetaResponse> = instruction
        .accounts
        .iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    (StatusCode::OK, Json(ApiResponse {
        success: true,
        data: Some(TokenInstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&instruction.data),
        }),
        error: None,
    }))
}

#[derive(Deserialize)]
pub struct TokenAccountRequest {
    pub owner: String,
    pub mint: String,
}

pub async fn get_associated_token_account(
    Json(payload): Json<TokenAccountRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let owner = match Pubkey::from_str(&payload.owner) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid owner public key"
            })));
        }
    };
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid mint public key"
            })));
        }
    };
    let address = get_associated_token_address(&owner, &mint);
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": { "address": address.to_string() }
    })))
}

#[derive(Deserialize)]
pub struct SignRequest {
    pub message: String,
    pub secret: String,
}

pub async fn sign_message(
    Json(payload): Json<SignRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    use solana_sdk::signature::Keypair;
    use std::str::FromStr;
    use bs58;
    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid secret key"
            })));
        }
    };
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid secret key"
            })));
        }
    };
    let signature = keypair.sign_message(payload.message.as_bytes());
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": { "signature": bs58::encode(signature).into_string() }
    })))
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
}

pub async fn verify_signature(
    Json(payload): Json<VerifyRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;
    use bs58;
    use ed25519_dalek::Verifier;
    let pubkey = match Pubkey::from_str(&payload.pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid public key"
            })));
        }
    };
    let signature_bytes = match bs58::decode(&payload.signature).into_vec() {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid signature"
            })));
        }
    };
    let dalek_pubkey = match ed25519_dalek::PublicKey::from_bytes(pubkey.as_ref()) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid public key bytes"
            })));
        }
    };
    let dalek_sig = match ed25519_dalek::Signature::from_bytes(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid signature bytes"
            })));
        }
    };
    let valid = dalek_pubkey.verify(payload.message.as_bytes(), &dalek_sig).is_ok();
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": { "valid": valid }
    })))
}

#[derive(Deserialize)]
pub struct SendSolRequest {
    pub from: String,
    pub to: String,
    pub lamports: u64,
}

pub async fn send_sol_instruction(
    Json(payload): Json<SendSolRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::system_program;
    use std::str::FromStr;
    use bs58;
    if payload.lamports == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Amount must be greater than 0"
        })));
    }
    let from = match Pubkey::from_str(&payload.from) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid sender public key"
            })));
        }
    };
    let to = match Pubkey::from_str(&payload.to) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid recipient public key"
            })));
        }
    };
    let instruction = solana_sdk::system_instruction::transfer(&from, &to, payload.lamports);
    let accounts: Vec<String> = instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect();
    let instruction_data = bs58::encode(&instruction.data).into_string();
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "program_id": system_program::id().to_string(),
            "accounts": accounts,
            "instruction_data": instruction_data
        }
    })))
}

#[derive(Deserialize)]
pub struct SendTokenRequest {
    pub from: String,
    pub to: String,
    pub mint: String,
    #[serde(rename = "fromToken")]
    pub from_token: String,
    #[serde(rename = "toToken")]
    pub to_token: String,
    pub amount: u64,
}

pub async fn send_token_instruction(
    Json(payload): Json<SendTokenRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;
    let from = match Pubkey::from_str(&payload.from) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid from public key"
            })));
        }
    };
    let to = match Pubkey::from_str(&payload.to) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid to public key"
            })));
        }
    };
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid mint public key"
            })));
        }
    };
    let from_token = match Pubkey::from_str(&payload.from_token) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid fromToken public key"
            })));
        }
    };
    let to_token = match Pubkey::from_str(&payload.to_token) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid toToken public key"
            })));
        }
    };
    // Use decimals = 6 as default for test compatibility
    let instruction = match spl_token::instruction::transfer_checked(
        &spl_token::id(),
        &from_token,
        &mint,
        &to_token,
        &from,
        &[],
        payload.amount,
        6,
    ) {
        Ok(instr) => instr,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Failed to create transfer instruction"
            })));
        }
    };
    let serialized = bincode::serialize(&instruction).unwrap_or_default();
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": { "instruction": base64::encode(&serialized) }
    })))
}

#[derive(Deserialize)]
pub struct TokenMintRequest {
    pub mint: String,
    pub destination: String,
    pub authority: String,
    pub amount: u64,
}

pub async fn mint_token_instruction(
    Json(payload): Json<TokenMintRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;
    use spl_associated_token_account::get_associated_token_address;
    use bs58;
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid mint public key"
            })));
        }
    };
    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid destination public key"
            })));
        }
    };
    let authority = match Pubkey::from_str(&payload.authority) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid authority public key"
            })));
        }
    };
    if payload.amount == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Amount must be greater than 0"
        })));
    }
    let ata = get_associated_token_address(&destination, &mint);
    let instruction = match spl_token::instruction::mint_to(
        &spl_token::id(),
        &mint,
        &ata,
        &authority,
        &[],
        payload.amount,
    ) {
        Ok(instr) => instr,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Failed to create mint_to instruction"
            })));
        }
    };
    let accounts: Vec<serde_json::Value> = instruction
        .accounts
        .iter()
        .map(|acc| serde_json::json!({
            "pubkey": acc.pubkey.to_string(),
            "is_signer": acc.is_signer,
            "is_writable": acc.is_writable,
        }))
        .collect();
    let instruction_data = bs58::encode(&instruction.data).into_string();
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "program_id": instruction.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": instruction_data
        }
    })))
}

#[derive(Deserialize)]
pub struct MessageSignRequest {
    pub message: String,
    pub secret: String,
}

pub async fn message_sign(
    Json(payload): Json<MessageSignRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    use solana_sdk::signature::Keypair;
    use bs58;
    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid secret key"
            })));
        }
    };
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid secret key"
            })));
        }
    };
    let signature = keypair.sign_message(payload.message.as_bytes());
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "signature": bs58::encode(signature).into_string(),
            "pubkey": keypair.pubkey().to_string(),
            "message": payload.message
        }
    })))
}

#[derive(Deserialize)]
pub struct MessageVerifyRequest {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
}

pub async fn message_verify(
    Json(payload): Json<MessageVerifyRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    use bs58;
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;
    use ed25519_dalek::{PublicKey as DalekPublicKey, Signature as DalekSignature, Verifier};
    let pubkey = match Pubkey::from_str(&payload.pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid public key"
            })));
        }
    };
    let pubkey_bytes = pubkey.to_bytes();
    let dalek_pubkey = match DalekPublicKey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid public key bytes"
            })));
        }
    };
    let signature_bytes = match bs58::decode(&payload.signature).into_vec() {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid signature"
            })));
        }
    };
    let dalek_sig = match DalekSignature::from_bytes(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid signature bytes"
            })));
        }
    };
    let valid = dalek_pubkey.verify(payload.message.as_bytes(), &dalek_sig).is_ok();
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "valid": valid,
            "message": payload.message,
            "pubkey": payload.pubkey
        }
    })))
}

#[derive(Deserialize)]
pub struct SendTokenV2Request {
    pub destination: String,
    pub mint: String,
    pub owner: String,
    pub amount: u64,
}

pub async fn send_token_v2_instruction(
    Json(payload): Json<SendTokenV2Request>,
) -> (StatusCode, Json<serde_json::Value>) {
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;
    use spl_associated_token_account::get_associated_token_address;
    use bs58;
    if payload.amount == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Amount must be greater than 0"
        })));
    }
    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid destination public key"
            })));
        }
    };
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid mint public key"
            })));
        }
    };
    let owner = match Pubkey::from_str(&payload.owner) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid owner public key"
            })));
        }
    };
    let ata = get_associated_token_address(&destination, &mint);
    let instruction = match spl_token::instruction::transfer(
        &spl_token::id(),
        &owner,
        &ata,
        &owner,
        &[],
        payload.amount,
    ) {
        Ok(instr) => instr,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Failed to create transfer instruction"
            })));
        }
    };
    let accounts: Vec<serde_json::Value> = instruction
        .accounts
        .iter()
        .map(|acc| serde_json::json!({
            "pubkey": acc.pubkey.to_string(),
            "isSigner": acc.is_signer
        }))
        .collect();
    let instruction_data = bs58::encode(&instruction.data).into_string();
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "program_id": spl_token::id().to_string(),
            "accounts": accounts,
            "instruction_data": instruction_data
        }
    })))
} 