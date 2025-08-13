pub mod types;

use axum::{
    http::StatusCode, response::{IntoResponse}, routing::{get, post}, Json, Router
};
use solana_keypair::keypair_from_seed;
use solana_sdk::{pubkey::Pubkey, signature::Signature, signer::Signer, system_instruction::transfer};
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction::{initialize_mint, mint_to, transfer as transfer_token};
use spl_token::ID as TOKEN_PROGRAM_ID;

use std::{net::SocketAddr, str::FromStr};
use serde_json::{self, json};

use crate::types::{AccountMetaResponse, CreateTokenRequest, SendSOLRequest, SendTokenRequest, SignMsgRequest, TokenAccount, TokenCreateErrorResponse, TokenCreateSuccessResponse, TokenData, TokenMintRequest, VerifyMsgRequest};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(token_create))
        .route("/token/mint", post(token_mint))
        .route("/message/sign", post(sign_msg))
        .route("/message/verify", post(verify_msg))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> &'static str {
    "gm Dharmin!"
}

async fn generate_keypair() -> impl IntoResponse {
    let keypair = solana_sdk::signature::Keypair::new();
    let pub_key = keypair.pubkey();
    let secret_key = keypair.to_base58_string();

    if secret_key.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": "Failed to generate keypair"
            })),
        );
    } else {
        return (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "data": {
                "pubkey": pub_key.to_string(),
                "secret": secret_key
            }
        })));
    }
}

async fn token_create(Json(payload): Json<CreateTokenRequest>) -> impl IntoResponse {
    if payload.mintAuthority.is_none() || payload.mint.is_none() {
        let error_response = TokenCreateErrorResponse {
            success: false,
            error: "Missing required fields: mintAuthority or mint".to_string(),
        };
        return (StatusCode::BAD_REQUEST, Json(error_response)).into_response();
    }
    
    let CreateTokenRequest { mintAuthority, mint, decimals } = payload;

    let mintAuthority = mintAuthority.unwrap();
    let mint = mint.unwrap();

    let mint_pubkey = match Pubkey::from_str(&mint) {
        Ok(key) => key,
        Err(_) => {
            let error_response = TokenCreateErrorResponse {
                success: false,
                error: "Invalid mint public key format".to_string(),
            };
            return (StatusCode::BAD_REQUEST, Json(error_response)).into_response();
        }
    };
    
    let mint_authority_pubkey = match Pubkey::from_str(&mintAuthority) {
        Ok(key) => key,
        Err(_) => {
            let error_response = TokenCreateErrorResponse {
                success: false,
                error: "Invalid mint authority public key format".to_string(),
            };
            return (StatusCode::BAD_REQUEST, Json(error_response)).into_response();
        }
    };
    
    let initialize_mint_ix = initialize_mint(
        &TOKEN_PROGRAM_ID,
        &mint_pubkey,
        &mint_authority_pubkey,
        Some(&mint_authority_pubkey),
        decimals,
    );

    match initialize_mint_ix {
        Ok(ix) => {
            let accounts: Vec<AccountMetaResponse> = ix.accounts.iter().map(|account| {
                AccountMetaResponse {
                    pubkey: account.pubkey.to_string(),
                    is_signer: account.is_signer,
                    is_writable: account.is_writable,
                }
            }).collect();

            let response = TokenCreateSuccessResponse {
                success: true,
                data: TokenData {
                    program_id: ix.program_id.to_string(),
                    accounts,
                    instruction_data: bs58::encode(&ix.data).into_string(),
                },
            };

            return (StatusCode::OK, Json(response)).into_response()
        },
        Err(_) => {
            let error_response = TokenCreateErrorResponse {
                success: false,
                error: String::from("Failed to create mint instruction"),
            };
            return (StatusCode::BAD_REQUEST, Json(error_response)).into_response();
        }
    }
    
    
}

async fn token_mint(Json(payload): Json<TokenMintRequest>) -> impl IntoResponse {
    if payload.mint.is_none() || payload.destination.is_none() || payload.authority.is_none() || payload.amount.is_none() {
        let error_response = TokenCreateErrorResponse {
            success: false,
            error: "Missing required fields: mint, destination, authority, or amount".to_string(),
        };
        return (StatusCode::BAD_REQUEST, Json(error_response)).into_response();
    }

    let TokenMintRequest { mint, destination, authority, amount } = payload;

    let mint = mint.unwrap();
    let destination = destination.unwrap();
    let authority = authority.unwrap();
    let amount = amount.unwrap();

    let mint_pubkey = match Pubkey::from_str(&mint) {
        Ok(key) => key,
        Err(_) => {
            let error_response = TokenCreateErrorResponse {
                success: false,
                error: "Invalid mint public key format".to_string(),
            };
            return (StatusCode::BAD_REQUEST, Json(error_response)).into_response();
        }
    };

    let destination_pubkey = match Pubkey::from_str(&destination) {
        Ok(key) => key,
        Err(_) => {
            let error_response = TokenCreateErrorResponse {
                success: false,
                error: "Invalid destination public key format".to_string(),
            };
            return (StatusCode::BAD_REQUEST, Json(error_response)).into_response();
        }
    };

    let authority_pubkey = match Pubkey::from_str(&authority) {
        Ok(key) => key,
        Err(_) => {
            let error_response = TokenCreateErrorResponse {
                success: false,
                error: "Invalid authority public key format".to_string(),
            };
            return (StatusCode::BAD_REQUEST, Json(error_response)).into_response();
        }
    };

    let associated_token_account =
        get_associated_token_address(&destination_pubkey, &mint_pubkey);

    let mint_to_ix = mint_to(
        &TOKEN_PROGRAM_ID,
        &mint_pubkey,
        &associated_token_account,
        &authority_pubkey,
        &[],
        amount,
    );

    match mint_to_ix {
        Ok(ix) => {
            let accounts: Vec<AccountMetaResponse> = ix.accounts.iter().map(|account| {
                AccountMetaResponse {
                    pubkey: account.pubkey.to_string(),
                    is_signer: account.is_signer,
                    is_writable: account.is_writable,
                }
            }).collect();

            let response = TokenCreateSuccessResponse {
                success: true,
                data: TokenData {
                    program_id: TOKEN_PROGRAM_ID.to_string(),
                    accounts,
                    instruction_data: bs58::encode(&ix.data).into_string(),
                },
            };
            return (StatusCode::OK, Json(response)).into_response();
        }
        Err(_) => {
            let error_response = TokenCreateErrorResponse {
                success: false,
                error: String::from("Failed to create mint instruction"),
            };

            return (StatusCode::OK, Json(error_response)).into_response();
        }
    }
}

async fn sign_msg(Json(payload): Json<SignMsgRequest>) -> impl IntoResponse {
    let SignMsgRequest { message, secret } = payload;

    if message.is_empty() || secret.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }))).into_response();
    }

    let secret_bytes = match bs58::decode(secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid secret key format"
            }))).into_response();
        }
    };
    let keypair = match keypair_from_seed(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Failed to create keypair from seed"
            }))).into_response();
        }
    };

    let signature = keypair.sign_message(message.as_bytes());

    let response = serde_json::json!({
        "success": true,
        "data": {
            "signature": signature.to_string(),
            "pubkey": keypair.pubkey().to_string(),
            "message": message
        }
    });

    (StatusCode::OK, Json(response)).into_response()
}

async fn verify_msg(Json(payload): Json<VerifyMsgRequest>) -> impl IntoResponse {
    let VerifyMsgRequest { message, signature, pubkey } = payload;

    if message.is_empty() || signature.is_empty() || pubkey.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }))).into_response();
    }
    let public_key = Pubkey::from_str(&pubkey).unwrap();

    let signature_bytes = match bs58::decode(signature.as_str()).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid signature format"
            }))).into_response();
        }
    };

    if signature_bytes.len() != 64 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Signature must be 64 bytes long"
        }))).into_response();
    }

    let signature_array: [u8; 64] = signature_bytes.try_into().unwrap();

    let signature = Signature::from(signature_array);

    let is_valid_signature = signature.verify(&public_key.to_bytes(), message.as_bytes());

    if !is_valid_signature {
        let error_response = json!({
            "success": false,
            "error": "Invalid signature"
        });
        
        return (StatusCode::BAD_REQUEST, Json(error_response)).into_response();
    }
    
    let response = json!({
        "success": true,
        "data": {
            "valid": is_valid_signature,
            "pubkey": &pubkey,
            "message": message
        }
    });

    return (StatusCode::OK, Json(response)).into_response()
}

async fn send_sol(Json(payload): Json<SendSOLRequest>) -> impl IntoResponse {
    let SendSOLRequest { from, to, lamports } = payload;

    if lamports == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Amount must be greater than 0"
        }))).into_response();
    }

    let from_pubkey = match Pubkey::from_str(&from) {
        Ok(key) => key,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid sender public key"
            }))).into_response();
        }
    };

    let to_pubkey = match Pubkey::from_str(&to) {
        Ok(key) => key,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid to public key format"
            }))).into_response();
        }
    };

    let transfer_ix = transfer(
        &from_pubkey,
        &to_pubkey,
        lamports,
    );

    let response = json!({
        "success": true,
        "data": {
            "program_id": transfer_ix.program_id.to_string(),
            "accounts": [
                transfer_ix.accounts[0].pubkey.to_string(),
                transfer_ix.accounts[1].pubkey.to_string()
            ],
            "instruction_data": bs58::encode(&transfer_ix.data).into_string(),
        }
    });

    (StatusCode::OK, Json(response)).into_response()
}

async fn send_token(Json(payload): Json<SendTokenRequest>) -> impl IntoResponse {
    if payload.destination.is_none() || payload.mint.is_none() || payload.owner.is_none() || payload.amount.is_none() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Missing required fields: destination, mint, owner, or amount"
        }))).into_response();
    }

    let SendTokenRequest { destination, mint, owner, amount } = payload;

    let destination = destination.unwrap();
    let mint = mint.unwrap();
    let owner = owner.unwrap();
    let amount = amount.unwrap();

    let destination_pubkey = match Pubkey::from_str(&destination) {
        Ok(key) => key,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid destination public key format"
            }))).into_response();
        }
    };

    let mint_pubkey = match Pubkey::from_str(&mint) {
        Ok(key) => key,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid mint public key format"
            }))).into_response();
        }
    };

    let owner_pubkey = match Pubkey::from_str(&owner) {
        Ok(key) => key,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid owner public key format"
            }))).into_response();
        }
    };

    let destination_token_account =
        get_associated_token_address(&destination_pubkey, &mint_pubkey);
    let sender_token_account =
        get_associated_token_address(&owner_pubkey, &mint_pubkey);

    let transfer_ix = transfer_token(
        &TOKEN_PROGRAM_ID,
        &sender_token_account,
        &destination_token_account,
        &owner_pubkey,
        &[],
        amount
    );
    match transfer_ix {
        Ok(ix) => {
            let accounts = vec![
                TokenAccount {
                    pubkey: owner_pubkey.to_string(),
                    isSigner: false,
                },
                TokenAccount {
                    pubkey: destination_token_account.to_string(),
                    isSigner: false,
                },
                TokenAccount {
                    pubkey: owner_pubkey.to_string(),
                    isSigner: false,
                },
           ];

            let response = json!({
                "success": true,
                "data": {
                    "program_id": ix.program_id.to_string(),
                    "accounts": accounts,
                    "instruction_data": bs58::encode(&ix.data).into_string(),
                }
            });
            return (StatusCode::OK, Json(response)).into_response();
        },
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": String::from("Failed to create transfer instruction: ")
            }))).into_response();
        }
    };
}