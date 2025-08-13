use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateTokenRequest {
    pub mintAuthority: Option<String>,
    pub mint: Option<String>,
    pub decimals: u8,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccountMetaResponse {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}
#[derive(Serialize, Deserialize)]
pub struct TokenData {
    pub program_id: String,
    pub accounts: Vec<AccountMetaResponse>,
    pub instruction_data: String
}


#[derive(Serialize, Deserialize)]
pub struct TokenCreateSuccessResponse {
    pub success: bool,
    pub data: TokenData,
}

#[derive(Serialize, Deserialize)]
pub struct TokenCreateErrorResponse {
    pub success: bool,
    pub error: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenMintRequest {
    pub mint: Option<String>,
    pub destination: Option<String>,
    pub authority: Option<String>,
    pub amount: Option<u64>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignMsgRequest {
    pub message: String,
    pub secret: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyMsgRequest {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyMsgData {
    pub signature: String,
    pub pubkey: String,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyMsgResponse {
    pub success: bool,
    pub error: Option<String>,
    pub data: Option<VerifyMsgData>,
}

#[derive(Serialize, Deserialize)]
pub struct SendSOLRequest {
    pub from: String,
    pub to: String,
    pub lamports: u64,
}

#[derive(Serialize, Deserialize)]
pub struct SendTokenRequest {
    pub destination: Option<String>,
    pub mint: Option<String>,
    pub owner: Option<String>,
    pub amount: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct SendTokenResponse {
    pub success: bool,
    pub data: TokenAccount
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenAccount {
    pub pubkey: String,
    pub isSigner: bool,
}