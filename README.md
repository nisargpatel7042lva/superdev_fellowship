# Solana Blockchain Server

A Rust-based HTTP server that provides Solana blockchain operations including keypair generation, token operations, message signing/verification, and SOL/token transfers.

## Features

- Generate Solana keypairs
- Create and mint SPL tokens
- Sign and verify messages using Ed25519
- Send SOL and SPL token transfers
- Input validation and error handling
- CORS enabled for web applications

## Project Structure

The project is organized into modular components:

- `src/main.rs` - Application entry point and server startup
- `src/models.rs` - Data structures and request/response types
- `src/handlers.rs` - HTTP endpoint handlers with business logic
- `src/routes.rs` - Route definitions and application router setup

## Quick Start

### Prerequisites

- Rust (latest stable version)
- Cargo package manager

### Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd solana-http-server
```

2. Build the project:
```bash
cargo build --release
```

3. Run the server:
```bash
cargo run --release
```

The server will start on `http://localhost:3000`

## API Endpoints

### Health Check
- **GET** `/` - Check if server is running

### Keypair Generation
- **POST** `/keypair` - Generate a new Solana keypair

### Token Operations
- **POST** `/token/create` - Create a new SPL token mint instruction
- **POST** `/token/mint` - Create a mint-to instruction for SPL tokens

### Message Operations
- **POST** `/message/sign` - Sign a message using a private key
- **POST** `/message/verify` - Verify a signed message

### Transfer Operations
- **POST** `/send/sol` - Create a SOL transfer instruction
- **POST** `/send/token` - Create an SPL token transfer instruction

## Example Usage

### Generate Keypair
```bash
curl -X POST http://localhost:3000/keypair
```

### Sign Message
```bash
curl -X POST http://localhost:3000/message/sign \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Hello, Solana!",
    "secret": "your-base58-encoded-secret-key"
  }'
```

### Create Token
```bash
curl -X POST http://localhost:3000/token/create \
  -H "Content-Type: application/json" \
  -d '{
    "mint_authority": "your-mint-authority-pubkey",
    "mint": "your-mint-pubkey",
    "decimals": 6
  }'
```

## Deployment with ngrok

### 1. Install ngrok
```bash
# Download ngrok
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz
tar xvzf ngrok-v3-stable-linux-amd64.tgz

# Or use snap
sudo snap install ngrok
```

### 2. Start the Rust server
```bash
cargo run --release
```

### 3. In another terminal, start ngrok
```bash
ngrok http 3000
```

### 4. Use the ngrok URL
ngrok will provide you with a public URL like `https://abc123.ngrok.io` that you can use to access your server from anywhere.

## Response Format

All endpoints return JSON responses in the following format:

### Success Response (Status 200)
```json
{
  "success": true,
  "data": { /* endpoint-specific result */ }
}
```

### Error Response (Status 400)
```json
{
  "success": false,
  "error": "Description of error"
}
```

## Security Considerations

- No private keys are stored on the server
- All cryptographic operations use standard libraries
- Input validation for all endpoints
- Proper error handling to avoid information leakage
- CORS is enabled for web application integration

## Development

### Running in Development Mode
```bash
cargo run
```

### Running Tests
```bash
cargo test
```

### Testing the Server
```bash
./test_server.sh
```

### Building for Production
```bash
cargo build --release
```

## Dependencies

- **axum** - Web framework
- **tokio** - Async runtime
- **solana-sdk** - Solana SDK for blockchain operations
- **spl-token** - SPL token program integration
- **serde** - Serialization/deserialization
- **tower-http** - HTTP middleware (CORS)

## License

MIT License 