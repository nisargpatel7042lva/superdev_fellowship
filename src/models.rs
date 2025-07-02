// Models for request/response types will go here. 

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct KeypairResponse {
    pub pubkey: String,
    pub secret: String,
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    pub mint_authority: String,
    pub mint: String,
    pub decimals: u8,
}

#[derive(Serialize)]
pub struct AccountMetaResponse {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Serialize)]
pub struct InstructionResponse<T> {
    pub program_id: String,
    pub accounts: T,
    pub instruction_data: String,
}

pub type TokenInstructionResponse = InstructionResponse<Vec<AccountMetaResponse>>; 