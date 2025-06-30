# Solana Fellowship Assignment – Rust HTTP Server

## Overview

Build a **Rust-based HTTP server** exposing **Solana-related endpoints**. The server provides functionality to generate keypairs, handle SPL tokens, sign/verify messages, and construct valid on-chain instructions.

## HTTP-URL

```
https://superdev-fellowship.vercel.app/api
```

## Response Format

All endpoints return JSON responses in the following format:

### Success Response (Status 200)

```json
{
  "success": true,
  "data": { /* endpoint-specific result */ }
}

```

### Error Response ( Status: 400)

```json
{
  "success": false,
  "error": "Description of error"
}

```

## Endpoints Specification

### 1. Generate Keypair

Generate a new Solana keypair.

**Endpoint:** `POST /keypair`

**Response:**

```json
{
  "success": true,
  "data": {
    "pubkey": "base58-encoded-public-key",
    "secret": "base58-encoded-secret-key"
  }
}
```

### 2. Create Token

Create a new SPL token initialise mint instruction.

**Endpoint:** `POST /token/create`

**Request:**

```json
{
  "mintAuthority": "base58-encoded-public-key",
  "mint": "base58-encoded-public-key"
  "decimals": 6
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "program_id": "string",
    "accounts": {
	    pubkey: "pubkey", 
	    is_signer: boolean, 
	    is_writable: boolean
    }...,
    "instruction_data": "base64-encoded-data"
  }
}
```

### 3. Mint Token

Create a mint-to instruction for SPL tokens.

**Endpoint:** `POST /token/mint`

**Request:**

```json
{
  "mint": "mint-address",
  "destination": "destination-user-address",
  "authority": "authority-address",
  "amount": 1000000,
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "program_id": "string",
    "accounts": [
      {
        "pubkey": "pubkey",
        "is_signer": false,
        "is_writable": true
      }...,
    ],
    "instruction_data": "base64-encoded-data"
  }
}

```

### 4. Sign Message

Sign a message using a private key.

**Endpoint:** `POST /message/sign`

**Request:**

```json
{
  "message": "Hello, Solana!",
  "secret": "base58-encoded-secret-key"
}

```

**Response:**

```json
{
  "success": true,
  "data": {
    "signature": "base64-encoded-signature",
    "public_key": "base58-encoded-public-key",
    "message": "Hello, Solana!"
  }
}

```

**Error Response (Missing Fields):**

```json
{
  "success": false,
  "error": "Missing required fields"
}

```

### 5. Verify Message

Verify a signed message.

**Endpoint:** `POST /message/verify`

**Request:**

```json
{
  "message": "Hello, Solana!",
  "signature": "base64-encoded-signature",
  "pubkey": "base58-encoded-public-key"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "valid": true,
    "message": "Hello, Solana!",
    "pubkey": "base58-encoded-public-key"
  }
}

```

### 6. Send SOL

Create a SOL transfer instruction. Should only process valid inputs, figure out what we mean when we say valid inputs

**Endpoint:** `POST /send/sol`

**Request:**

```json
{
  "from": "sender-address",
  "to": "recipient-address",
  "lamports": 100000,
}

```

**Response:**

```json
{
  "success": true,
  "data": {
    "program_id": "respective program id",
    "accounts": [
      "address of first account",
      "address of second account"
    ],
    "instruction_data": "instruction_data"
  }
}

```

### 7. Send Token

Create an SPL token transfer instruction.

**Endpoint:** `POST /send/token`

**Request:**

```json
{
  "destination": "destination-user-address",
  "mint": "mint-address",
  "owner": "owner-address",
  "amount": 100000,
}

```

**Response:**

```json
{
  "success": true,
  "data": {
    "program_id": "respective program id",
    "accounts": [
	    {
		    pubkey: "pubkey", 
		    isSigner: boolean,
	    }
    ],
    "instruction_data": "instruction_data"
  }
}

```

## Technical Details

### Signature Implementation

- Uses Ed25519 for signing/verification
- Base58 encoding for public/private keys
- Base64 encoding for signatures

### Error Handling

- All endpoints return HTTP 200 with success flag
- Detailed error messages in response
- Proper validation of all input fields
- Consistent error message format

### Security Considerations

- No private keys stored on server
- All cryptographic operations use standard libraries
- Input validation for all endpoints
- Proper error handling to avoid information leakage
