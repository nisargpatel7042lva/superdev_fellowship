const axios = require("axios");
const nacl = require('tweetnacl');
const { PublicKey, Keypair } = require('@solana/web3.js');
const bs58 = require('bs58').default;
const { getAssociatedTokenAddress } = require("@solana/spl-token");

const HTTP_URL = process.env.HTTP_URL || "http://localhost:3000";

const ERROR_CODE = 400;
const NOT_FOUND_CODE = 404;
const SUCCESS_CODE = 200;

const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

describe("Solana Fellowship API", () => {
  let generatedKeypair = null;

  test("POST /keypair should generate a valid keypair", async () => {
    const res = await axios.post(`${HTTP_URL}/keypair`);
    expect(res.status).toBe(SUCCESS_CODE);
    expect(res.data.success).toBe(true);
    expect(res.data.data.pubkey).toBeDefined();
    expect(res.data.data.secret).toBeDefined();
    generatedKeypair = res.data.data;
  });

  test("POST /keypair should generate a valid keypair", async () => {
    const res = await axios.post(`${HTTP_URL}/keypair`);    
    const { pubkey, secret } = res.data.data;
    
    // Validate public key format (should be base58 encoded, 32 bytes when decoded)
    expect(() => new PublicKey(pubkey)).not.toThrow();
    const pubkeyBytes = bs58.decode(pubkey);
    expect(pubkeyBytes.length).toBe(32);
    
    // Validate secret key format
    let secretBytes;
    if (Array.isArray(secret)) {
        // If secret is returned as byte array
        expect(secret.length).toBe(64);
        secretBytes = new Uint8Array(secret);
    } else if (typeof secret === 'string') {
        // If secret is returned as base58 string
        secretBytes = bs58.decode(secret);
        expect(secretBytes.length).toBe(64);
    } else {
        throw new Error('Secret key format not recognized');
    }
    
    // Verify the keypair relationship - derive public key from secret key
    const keypairFromSecret = Keypair.fromSecretKey(secretBytes);
    expect(keypairFromSecret.publicKey.toBase58()).toBe(pubkey);
    
    // Additional validation: ensure public key is on the ed25519 curve
    expect(PublicKey.isOnCurve(pubkey)).toBe(true);
    
    generatedKeypair = res.data.data;
  });

  test("POST /token/create should have atleast the right program id returned", async () => {
    let mintKeypair = Keypair.generate();
    const res = await axios.post(`${HTTP_URL}/token/create`, {
      mintAuthority: generatedKeypair.pubkey,
      mint: mintKeypair.publicKey,
      decimals: 6
    });
    expect(res.data.data.program_id).toBe(TOKEN_PROGRAM_ID)
    expect(res.status).toBe(SUCCESS_CODE)
  });

  test("POST /token/create should return valid instruction", async () => {
    let mintKeypair = Keypair.generate();
    const res = await axios.post(`${HTTP_URL}/token/create`, {
      mintAuthority: generatedKeypair.pubkey,
      mint: mintKeypair.publicKey,
      decimals: 6
    });

    expect(res.status).toBe(SUCCESS_CODE);
    expect(res.data.data.accounts?.length).toBe(2);
    expect(res.data.data.accounts[0].is_signer).toBe(false);
    expect(res.data.data.accounts[0].is_writable).toBe(true);
    expect(res.data.data.accounts[0].pubkey).toBe(mintKeypair.publicKey.toString());

    expect(res.data.data.accounts[1].is_signer).toBe(false);
    expect(res.data.data.accounts[1].is_writable).toBe(false);
    
  });
  
  test("POST /token/create should fail if incorrect public key is passed", async () => {
    const res = await axios.post(`${HTTP_URL}/token/create`, {
      mintAuthority: "askdjkadsjkdsajkdajadkjk",
      mint: "asdadsdas",
      decimals: 6
    }, {
      validateStatus: () => true // Don't throw on any status code
    });

    expect(res.status).toBe(400);
    expect(res.data.success).toBe(false);
  });

  test("POST /token/create should fail if inputs are missing", async () => {
    const res = await axios.post(`${HTTP_URL}/token/create`, {
      mint: "asdadsdas",
      decimals: 6
    }, {
      validateStatus: () => true // Don't throw on any status code
    });

    expect(res.status).toBe(400);
    expect(res.data.success).toBe(false);
    expect(res.data.error).toBeDefined()
    
  });

  test("POST /token/mint should return valid mint_to instruction", async () => {
    let mintKeypair = Keypair.generate();
    let userKeypair = Keypair.generate();

    const res = await axios.post(`${HTTP_URL}/token/mint`, {
      mint: mintKeypair.publicKey.toString(),
      destination: userKeypair.publicKey.toString(),
      authority: generatedKeypair.pubkey,
      amount: 1000000,
    });

    let ata = await getAssociatedTokenAddress(mintKeypair.publicKey, userKeypair.publicKey);
    expect(res.data.success).toBe(true);
    expect(res.data.data.program_id).toBe(TOKEN_PROGRAM_ID);
    expect(res.data.data.accounts?.length).toBe(3);
    expect(res.data.data.instruction_data).toBeDefined();
    expect(res.data.data.accounts[0].pubkey).toBe(mintKeypair.publicKey.toString());
    expect(res.data.data.accounts[1].pubkey).toBe(ata.toString());
    expect(res.data.data.accounts[2].pubkey).toBe(generatedKeypair.pubkey.toString());
  });

  test("POST /token/mint should fail if mint is not a valid public key", async () => {
    const res = await axios.post(`${HTTP_URL}/token/mint`, {
      mint: "Adsasd",
      destination: "Asdads",
      authority: "asdadsads",
      amount: 1000000,
    }, {
      validateStatus: () => true // Don't throw on any status code
    });

    expect(res.status).toBe(400);
    expect(res.data.success).toBe(false);
    expect(res.data.error).toBeDefined()
  });

  test("POST /token/mint should fail if inputs are missing", async () => {
    let mintKeypair = Keypair.generate();
    let userKeypair = Keypair.generate();

    const res = await axios.post(`${HTTP_URL}/token/mint`, {
      destination: userKeypair.publicKey.toString(),
      authority: generatedKeypair.pubkey,
      amount: 1000000,
    }, {
      validateStatus: () => true // Don't throw on any status code
    });

    expect(res.status).toBe(400);
    expect(res.data.success).toBe(false);
    expect(res.data.error).toBeDefined()
  });

  test("POST /message/sign should return valid signature", async () => {
    const message = "Hello, Solana!";
    
    const res = await axios.post(`${HTTP_URL}/message/sign`, {
      message: message,
      secret: generatedKeypair.secret
    });

    expect(res.status).toBe(200);
    expect(res.data.success).toBe(true);
    expect(res.data.data.signature).toBeDefined();
    expect(res.data.data.message).toBe(message);
    expect(res.data.data.pubkey).toBe(generatedKeypair.pubkey);

    // Verify the signature is actually valid
    const signatureBytes = bs58.decode(res.data.data.signature);
    const messageBytes = new TextEncoder().encode(message);
    const pubkeyBytes = bs58.decode(res.data.data.pubkey);
    
    // Verify signature using nacl
    const isValid = nacl.sign.detached.verify(
      messageBytes,
      signatureBytes,
      pubkeyBytes
    );
    
    expect(isValid).toBe(true);
  });

  test("POST /message/sign should handle invalid secret key", async () => {
    const res = await axios.post(`${HTTP_URL}/message/sign`, {
      message: "Hello, Solana!",
      secret: "secret"
    }, {
      validateStatus: () => true // Don't throw on any status code
    });

    expect(res.status).toBe(400);
    expect(res.data.success).toBe(false);
    expect(res.data.error).toBeDefined();
  });

  test("POST /message/sign with different messages should produce different signatures", async () => {
    const message1 = "Hello, Solana!";
    const message2 = "Goodbye, Solana!";
    
    const res1 = await axios.post(`${HTTP_URL}/message/sign`, {
      message: message1,
      secret: generatedKeypair.secret
    });
    
    const res2 = await axios.post(`${HTTP_URL}/message/sign`, {
      message: message2,
      secret: generatedKeypair.secret
    });

    expect(res1.data.success).toBe(true);
    expect(res2.data.success).toBe(true);
    expect(res1.data.data.signature).not.toBe(res2.data.data.signature);
    
    // Verify both signatures are valid
    const sig1Bytes = bs58.decode(res1.data.data.signature);
    const sig2Bytes = bs58.decode(res2.data.data.signature);
    const msg1Bytes = new TextEncoder().encode(message1);
    const msg2Bytes = new TextEncoder().encode(message2);
    const pubkeyBytes = bs58.decode(generatedKeypair.pubkey);
    
    const isValid1 = nacl.sign.detached.verify(msg1Bytes, sig1Bytes, pubkeyBytes);
    const isValid2 = nacl.sign.detached.verify(msg2Bytes, sig2Bytes, pubkeyBytes);
    
    expect(isValid1).toBe(true);
    expect(isValid2).toBe(true);
  });

  test("POST /message/sign signature should NOT verify with wrong message", async () => {
    const originalMessage = "Hello, Solana!";
    const tamperedMessage = "Hello, Bitcoin!";
    
    const res = await axios.post(`${HTTP_URL}/message/sign`, {
      message: originalMessage,
      secret: generatedKeypair.secret
    });

    expect(res.data.success).toBe(true);
    
    // Try to verify the signature with a different message
    const signatureBytes = bs58.decode(res.data.data.signature);
    const tamperedMessageBytes = new TextEncoder().encode(tamperedMessage);
    const pubkeyBytes = bs58.decode(res.data.data.pubkey);
    
    const isValid = nacl.sign.detached.verify(
      tamperedMessageBytes,
      signatureBytes,
      pubkeyBytes
    );
    
    // Should be false because the message was tampered with
    expect(isValid).toBe(false);
  });

  test("POST /message/verify should verify valid signature", async () => {
    const message = "Hello, Solana!";
    
    // First, sign a message
    const signRes = await axios.post(`${HTTP_URL}/message/sign`, {
      message: message,
      secret: generatedKeypair.secret
    });

    expect(signRes.data.success).toBe(true);

    // Then verify the signature
    const verifyRes = await axios.post(`${HTTP_URL}/message/verify`, {
      message: message,
      signature: signRes.data.data.signature,
      pubkey: signRes.data.data.pubkey
    });

    expect(verifyRes.status).toBe(200);
    expect(verifyRes.data.success).toBe(true);
    expect(verifyRes.data.data.valid).toBe(true);
    expect(verifyRes.data.data.message).toBe(message);
    expect(verifyRes.data.data.pubkey).toBe(generatedKeypair.pubkey);
  });

  test("POST /send/sol should create valid SOL transfer instruction", async () => {
    const senderKeypair = Keypair.generate();
    const recipientKeypair = Keypair.generate();
    const lamports = 1000000; // 0.001 SOL

    const res = await axios.post(`${HTTP_URL}/send/sol`, {
      from: senderKeypair.publicKey.toString(),
      to: recipientKeypair.publicKey.toString(),
      lamports: lamports,
    });

    expect(res.status).toBe(200);
    expect(res.data.success).toBe(true);
    expect(res.data.data.program_id).toBe("11111111111111111111111111111111");
    expect(res.data.data.accounts).toBeDefined();
    expect(Array.isArray(res.data.data.accounts)).toBe(true);
    expect(res.data.data.accounts.length).toBe(2);
    expect(res.data.data.instruction_data).toBeDefined();

    // Verify account structure
    const accounts = res.data.data.accounts;
    expect(accounts[0]).toBe(senderKeypair.publicKey.toString());
    expect(accounts[1]).toBe(recipientKeypair.publicKey.toString());
  });

  test("POST /send/sol should reject zero lamports", async () => {
    const senderKeypair = Keypair.generate();
    const recipientKeypair = Keypair.generate();

    const res = await axios.post(`${HTTP_URL}/send/sol`, {
      from: senderKeypair.publicKey.toString(),
      to: recipientKeypair.publicKey.toString(),
      lamports: 0
    }, {
      validateStatus: () => true // Don't throw on any status code
    });

    expect(res.status).toBe(400);
    expect(res.data.success).toBe(false);
    expect(res.data.error).toBe("Amount must be greater than 0");
  });

  test("POST /send/sol should reject invalid sender address", async () => {
    const recipientKeypair = Keypair.generate();

    const res = await axios.post(`${HTTP_URL}/send/sol`, {
      from: "sender",
      to: bs58.encode(recipientKeypair.publicKey.toBytes()),
      lamports: 1000000
    }, {
      validateStatus: () => true // Don't throw on any status code
    });

    expect(res.status).toBe(400);
    expect(res.data.success).toBe(false);
    expect(res.data.error).toBe("Invalid sender public key");
  });

  test("POST /send/sol instruction data should be consistent", async () => {
    const senderKeypair = Keypair.generate();
    const recipientKeypair = Keypair.generate();
    const lamports = 1000000;

    // Make multiple requests with same parameters
    const requests = await Promise.all([
      axios.post(`${HTTP_URL}/send/sol`, {
        from: bs58.encode(senderKeypair.publicKey.toBytes()),
        to: bs58.encode(recipientKeypair.publicKey.toBytes()),
        lamports: lamports
      }),
      axios.post(`${HTTP_URL}/send/sol`, {
        from: bs58.encode(senderKeypair.publicKey.toBytes()),
        to: bs58.encode(recipientKeypair.publicKey.toBytes()),
        lamports: lamports
      })
    ]);

    expect(requests[0].data.data.instruction_data).toBe(requests[1].data.data.instruction_data);
    expect(requests[0].data.data.program_id).toBe(requests[1].data.data.program_id);
  });

  test("POST /send/sol instruction should decode properly", async () => {
    const senderKeypair = Keypair.generate();
    const recipientKeypair = Keypair.generate();
    const lamports = 200;

    const res = await axios.post(`${HTTP_URL}/send/sol`, {
      from: senderKeypair.publicKey.toString(),
      to: recipientKeypair.publicKey.toString(),
      lamports: lamports
    });

    expect(res.data.success).toBe(true);

    // Decode and verify instruction data
    const instructionData = bs58.decode(res.data.data.instruction_data);
    expect(instructionData).toBeDefined();
    expect(instructionData.length).toBeGreaterThan(0);
    
    // First 4 bytes should be the instruction discriminator for transfer
    // SOL transfer instruction has discriminator [2, 0, 0, 0]
    expect(instructionData[0]).toBe(2);
    expect(instructionData[1]).toBe(0);
    expect(instructionData[2]).toBe(0);
    expect(instructionData[3]).toBe(0);
    // check if amount is correct after this
    expect(instructionData[4]).toBe(lamports);
  });

  test("POST /send/token should create valid SPL token transfer instruction", async () => {
    const destinationKeypair = Keypair.generate();
    const mintKeypair = Keypair.generate();
    const ownerKeypair = Keypair.generate();
    const amount = 1000000;

    const res = await axios.post(`${HTTP_URL}/send/token`, {
      destination: bs58.encode(destinationKeypair.publicKey.toBytes()),
      mint: bs58.encode(mintKeypair.publicKey.toBytes()),
      owner: bs58.encode(ownerKeypair.publicKey.toBytes()),
      amount: amount,
    });

    let ata = await getAssociatedTokenAddress(mintKeypair.publicKey, destinationKeypair.publicKey);

    expect(res.status).toBe(200);
    expect(res.data.success).toBe(true);
    expect(res.data.data.program_id).toBe("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    expect(res.data.data.accounts).toBeDefined();
    expect(Array.isArray(res.data.data.accounts)).toBe(true);
    expect(res.data.data.accounts.length).toBe(3); // source, destination, owner
    expect(res.data.data.instruction_data).toBeDefined();

    // Verify account structure
    const accounts = res.data.data.accounts;
    expect(accounts[0].pubkey).toBe(ownerKeypair.publicKey.toString());
    expect(accounts[1].pubkey).toBe(ata.toString());
    expect(accounts[2].pubkey).toBe(ownerKeypair.publicKey.toString());
    
    // Check account permissions
    expect(accounts[0].isSigner).toBe(false);  // source (writable)
    expect(accounts[1].isSigner).toBe(false);  // destination (writable)

    expect(accounts[0].is_writable).not.toBeDefined();
    expect(accounts[1].is_writable).not.toBeDefined();
    expect(accounts[2].is_writable).not.toBeDefined();

    expect(accounts[0].is_signer).not.toBeDefined();
    expect(accounts[1].is_signer).not.toBeDefined();
    expect(accounts[2].is_signer).not.toBeDefined();
  });

  test("POST /send/token should fail if wrong inputs are provided", async () => {
    const destinationKeypair = Keypair.generate();
    const ownerKeypair = Keypair.generate();
    const amount = 1000000;

    const res = await axios.post(`${HTTP_URL}/send/token`, {
      destination: bs58.encode(destinationKeypair.publicKey.toBytes()),
      owner: bs58.encode(ownerKeypair.publicKey.toBytes()),
      amount: amount,
    }, {
      validateStatus: () => true // Don't throw on any status code
    });

    expect(res.status).toBe(400);
    expect(res.data.success).toBe(false);
  });
});