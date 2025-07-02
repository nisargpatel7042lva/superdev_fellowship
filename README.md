# Solana Fellowship API

This project is a Rust-based HTTP server exposing Solana-related endpoints, designed for the Superteam Fellowship. The server provides endpoints for:

- Keypair generation
- SPL token operations (mint, transfer, create)
- Message signing and verification
- SOL and token transfer instruction generation

The API is built with [Axum](https://github.com/tokio-rs/axum) and is designed to pass a comprehensive Jest test suite (21 tests) that validates all endpoints and error handling.

## Main Task

**Build a Rust HTTP server that exposes Solana blockchain-related endpoints, including keypair generation, SPL token operations, message signing/verification, and SOL/token transfer instruction generation. The server must pass a provided Jest test suite with 21 test cases.**

## Endpoints

- `POST /keypair` — Generate a new Solana keypair
- `POST /token/create` — Create SPL token mint instruction
- `POST /token/account` — Get associated token account address
- `POST /token/mint` — Mint SPL tokens instruction
- `POST /send/sol` — Create SOL transfer instruction
- `POST /send/token` — Create SPL token transfer instruction
- `POST /message/sign` — Sign a message with a secret key
- `POST /message/verify` — Verify a signed message
- `GET /health` — Health check

## Setup

### Prerequisites
- Rust (https://rustup.rs/)
- Node.js & npm (for running tests)

### Install Rust dependencies
```sh
cargo build
```

### Install Node.js dependencies
```sh
npm install
```

## Running the Server
```sh
cargo run
```
The server will start on `http://localhost:3000`.

## Running the Tests
Make sure the server is running, then in another terminal:
```sh
npx jest solana.test.js
```
All 21 tests should pass if the server is implemented correctly.

## Notes
- The server is stateless and only generates instructions or signatures; it does not submit transactions to the Solana blockchain.
- All keypairs and secrets are handled in-memory and not persisted.
- Error handling is implemented to match the test suite's requirements (e.g., 400 for bad input, correct error messages).

---

**Superteam Fellowship — Solana API Challenge** 