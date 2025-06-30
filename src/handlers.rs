use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as JsonResponse,
};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
};
use spl_token::instruction as token_instruction;
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose};
use bs58;
use std::convert::TryFrom;
use serde::Serialize;
use serde_json;

use crate::models::*;

pub async fn check_server_health() -> JsonResponse<ApiResponse<String>> {
    JsonResponse(ApiResponse {
        success: true,
        data: Some("Solana Blockchain Server is running and ready to process requests".to_string()),
        error: None,
    })
}

pub async fn create_new_keypair() -> JsonResponse<ApiResponse<KeypairResponse>> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    JsonResponse(ApiResponse {
        success: true,
        data: Some(KeypairResponse { pubkey, secret }),
        error: None,
    })
}

pub async fn create_token_mint_instruction(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<JsonResponse<ApiResponse<InstructionResponse>>, StatusCode> {
    let mint_authority = Pubkey::from_str(&payload.mint_authority)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let mint = Pubkey::from_str(&payload.mint)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if payload.decimals > 9 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        payload.decimals,
    ).map_err(|_| StatusCode::BAD_REQUEST)?;

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    Ok(JsonResponse(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        }),
        error: None,
    }))
}

pub async fn create_mint_token_instruction(
    Json(payload): Json<MintTokenRequest>,
) -> Result<JsonResponse<ApiResponse<InstructionResponse>>, StatusCode> {
    let mint = Pubkey::from_str(&payload.mint)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let destination = Pubkey::from_str(&payload.destination)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let authority = Pubkey::from_str(&payload.authority)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if payload.amount == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let instruction = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    ).map_err(|_| StatusCode::BAD_REQUEST)?;

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    Ok(JsonResponse(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        }),
        error: None,
    }))
}

pub async fn sign_message_with_private_key(
    Json(payload): Json<SignMessageRequest>,
) -> Result<JsonResponse<ApiResponse<SignMessageResponse>>, StatusCode> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Ok(JsonResponse(ApiResponse {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        }));
    }

    let secret_bytes = bs58::decode(&payload.secret)
        .into_vec()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if secret_bytes.len() != 64 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let keypair = Keypair::from_bytes(&secret_bytes)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());

    Ok(JsonResponse(ApiResponse {
        success: true,
        data: Some(SignMessageResponse {
            signature: signature_b64,
            public_key: keypair.pubkey().to_string(),
            message: payload.message,
        }),
        error: None,
    }))
}

pub async fn verify_signed_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<JsonResponse<ApiResponse<VerifyMessageResponse>>, StatusCode> {
    let pubkey = Pubkey::from_str(&payload.pubkey)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let signature_bytes = general_purpose::STANDARD.decode(&payload.signature)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if signature_bytes.len() != 64 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let signature = solana_sdk::signature::Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let message_bytes = payload.message.as_bytes();
    let valid = signature.verify(pubkey.as_ref(), message_bytes);

    Ok(JsonResponse(ApiResponse {
        success: true,
        data: Some(VerifyMessageResponse {
            valid,
            message: payload.message,
            pubkey: payload.pubkey,
        }),
        error: None,
    }))
}

pub async fn create_sol_transfer_instruction(
    Json(payload): Json<SendSolRequest>,
) -> Result<JsonResponse<ApiResponse<InstructionResponse>>, StatusCode> {
    let from = Pubkey::from_str(&payload.from)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let to = Pubkey::from_str(&payload.to)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if payload.lamports == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let instruction = system_instruction::transfer(&from, &to, payload.lamports);

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    Ok(JsonResponse(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        }),
        error: None,
    }))
}

pub async fn create_token_transfer_instruction(
    Json(payload): Json<SendTokenRequest>,
) -> Result<JsonResponse<ApiResponse<InstructionResponse>>, StatusCode> {
    let destination = Pubkey::from_str(&payload.destination)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let mint = Pubkey::from_str(&payload.mint)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let owner = Pubkey::from_str(&payload.owner)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if payload.amount == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let source = spl_associated_token_account::get_associated_token_address(&owner, &mint);

    let instruction = token_instruction::transfer(
        &spl_token::id(),
        &source,
        &destination,
        &owner,
        &[],
        payload.amount,
    ).map_err(|_| StatusCode::BAD_REQUEST)?;

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    Ok(JsonResponse(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        }),
        error: None,
    }))
} 