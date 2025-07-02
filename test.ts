import { test, expect, describe } from "bun:test";
import { PublicKey, Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { getAssociatedTokenAddress } from "@solana/spl-token";

const HTTP_URL = "https://superdev-fellowship.vercel.app/api";

const SUCCESS_CODE = 200;

const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
}

interface KeypairData {
  pubkey: string;
  secret: string | number[];
}

let generatedKeypair: KeypairData | null = null;

describe("Solana Fellowship API", () => {
  test("POST /keypair should generate a valid keypair", async () => {
    const response = await fetch(`${HTTP_URL}/keypair`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });

    expect(response.status).toBe(SUCCESS_CODE);

    const data = (await response.json()) as ApiResponse<KeypairData>;
    expect(data.success).toBe(true);
    expect(data.data?.pubkey).toBeDefined();
    expect(data.data?.secret).toBeDefined();

    generatedKeypair = data.data!;
  });

  test("POST /keypair should generate a valid keypair with proper validation", async () => {
    const response = await fetch(`${HTTP_URL}/keypair`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });

    const data = (await response.json()) as ApiResponse<KeypairData>;
    const { pubkey, secret } = data.data!;

    // Validate public key format (should be base58 encoded, 32 bytes when decoded)
    expect(() => new PublicKey(pubkey)).not.toThrow();
    const pubkeyBytes = bs58.decode(pubkey);
    expect(pubkeyBytes.length).toBe(32);

    // Validate secret key format
    let secretBytes: Uint8Array;
    if (Array.isArray(secret)) {
      // If secret is returned as byte array
      expect(secret.length).toBe(64);
      secretBytes = new Uint8Array(secret);
    } else if (typeof secret === "string") {
      // If secret is returned as base58 string
      secretBytes = bs58.decode(secret);
      expect(secretBytes.length).toBe(64);
    } else {
      throw new Error("Secret key format not recognized");
    }

    // Verify the keypair relationship - derive public key from secret key
    const keypairFromSecret = Keypair.fromSecretKey(secretBytes);
    expect(keypairFromSecret.publicKey.toBase58()).toBe(pubkey);

    // Additional validation: ensure public key is on the ed25519 curve
    expect(PublicKey.isOnCurve(pubkey)).toBe(true);

    generatedKeypair = data.data!;
  });

  test("POST /token/create should have at least the right program id returned", async () => {
    const mintKeypair = Keypair.generate();
    const response = await fetch(`${HTTP_URL}/token/create`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mintAuthority: generatedKeypair!.pubkey,
        mint: mintKeypair.publicKey.toString(),
        decimals: 6,
      }),
    });

    const data = (await response.json()) as ApiResponse;
    expect(data.data.program_id).toBe(TOKEN_PROGRAM_ID);
    expect(response.status).toBe(SUCCESS_CODE);
  });

  test("POST /token/create should return valid instruction", async () => {
    const mintKeypair = Keypair.generate();
    const response = await fetch(`${HTTP_URL}/token/create`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mintAuthority: generatedKeypair!.pubkey,
        mint: mintKeypair.publicKey.toString(),
        decimals: 6,
      }),
    });

    expect(response.status).toBe(SUCCESS_CODE);
    const data = (await response.json()) as ApiResponse;
    expect(data.data.accounts?.length).toBe(2);
    expect(data.data.accounts[0].is_signer).toBe(false);
    expect(data.data.accounts[0].is_writable).toBe(true);
    expect(data.data.accounts[0].pubkey).toBe(mintKeypair.publicKey.toString());

    expect(data.data.accounts[1].is_signer).toBe(false);
    expect(data.data.accounts[1].is_writable).toBe(false);
  });

  test("POST /token/create should fail if incorrect public key is passed", async () => {
    const response = await fetch(`${HTTP_URL}/token/create`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mintAuthority: "askdjkadsjkdsajkdajadkjk",
        mint: "asdadsdas",
        decimals: 6,
      }),
    });

    expect(response.status).toBe(400);
    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(false);
  });

  test("POST /token/create should fail if inputs are missing", async () => {
    const response = await fetch(`${HTTP_URL}/token/create`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mint: "asdadsdas",
        decimals: 6,
      }),
    });

    expect(response.status).toBe(400);
    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(false);
    expect(data.error).toBeDefined();
  });

  test("POST /token/mint should return valid mint_to instruction", async () => {
    const mintKeypair = Keypair.generate();
    const userKeypair = Keypair.generate();

    const response = await fetch(`${HTTP_URL}/token/mint`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mint: mintKeypair.publicKey.toString(),
        destination: userKeypair.publicKey.toString(),
        authority: generatedKeypair!.pubkey,
        amount: 1000000,
      }),
    });

    const ata = await getAssociatedTokenAddress(
      mintKeypair.publicKey,
      userKeypair.publicKey
    );
    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(true);
    expect(data.data.program_id).toBe(TOKEN_PROGRAM_ID);
    expect(data.data.accounts?.length).toBe(3);
    expect(data.data.instruction_data).toBeDefined();
    expect(data.data.accounts[0].pubkey).toBe(mintKeypair.publicKey.toString());
    expect(data.data.accounts[1].pubkey).toBe(ata.toString());
    expect(data.data.accounts[2].pubkey).toBe(
      generatedKeypair!.pubkey.toString()
    );
  });

  test("POST /token/mint should fail if mint is not a valid public key", async () => {
    const response = await fetch(`${HTTP_URL}/token/mint`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mint: "Adsasd",
        destination: "Asdads",
        authority: "asdadsads",
        amount: 1000000,
      }),
    });

    expect(response.status).toBe(400);
    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(false);
    expect(data.error).toBeDefined();
  });

  test("POST /token/mint should fail if inputs are missing", async () => {
    const userKeypair = Keypair.generate();

    const response = await fetch(`${HTTP_URL}/token/mint`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        destination: userKeypair.publicKey.toString(),
        authority: generatedKeypair!.pubkey,
        amount: 1000000,
      }),
    });

    expect(response.status).toBe(400);
    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(false);
    expect(data.error).toBeDefined();
  });

  test("POST /message/sign should return valid signature", async () => {
    const message = "Hello, Solana!";

    const response = await fetch(`${HTTP_URL}/message/sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: message,
        secret: generatedKeypair!.secret,
      }),
    });

    expect(response.status).toBe(200);
    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(true);
    expect(data.data.signature).toBeDefined();
    expect(data.data.message).toBe(message);
    expect(data.data.pubkey).toBe(generatedKeypair!.pubkey);

    // Verify the signature is actually valid
    const signatureBytes = bs58.decode(data.data.signature);
    const messageBytes = new TextEncoder().encode(message);
    const pubkeyBytes = bs58.decode(data.data.pubkey);

    // Verify signature using nacl
    const isValid = nacl.sign.detached.verify(
      messageBytes,
      signatureBytes,
      pubkeyBytes
    );

    expect(isValid).toBe(true);
  });

  test("POST /message/sign should handle invalid secret key", async () => {
    const response = await fetch(`${HTTP_URL}/message/sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: "Hello, Solana!",
        secret: "secret",
      }),
    });

    expect(response.status).toBe(400);
    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(false);
    expect(data.error).toBeDefined();
  });

  test("POST /message/sign with different messages should produce different signatures", async () => {
    const message1 = "Hello, Solana!";
    const message2 = "Goodbye, Solana!";

    const res1 = await fetch(`${HTTP_URL}/message/sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: message1,
        secret: generatedKeypair!.secret,
      }),
    });

    const res2 = await fetch(`${HTTP_URL}/message/sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: message2,
        secret: generatedKeypair!.secret,
      }),
    });

    const data1 = (await res1.json()) as ApiResponse;
    const data2 = (await res2.json()) as ApiResponse;

    expect(data1.success).toBe(true);
    expect(data2.success).toBe(true);
    expect(data1.data.signature).not.toBe(data2.data.signature);

    // Verify both signatures are valid
    const sig1Bytes = bs58.decode(data1.data.signature);
    const sig2Bytes = bs58.decode(data2.data.signature);
    const msg1Bytes = new TextEncoder().encode(message1);
    const msg2Bytes = new TextEncoder().encode(message2);
    const pubkeyBytes = bs58.decode(generatedKeypair!.pubkey);

    const isValid1 = nacl.sign.detached.verify(
      msg1Bytes,
      sig1Bytes,
      pubkeyBytes
    );
    const isValid2 = nacl.sign.detached.verify(
      msg2Bytes,
      sig2Bytes,
      pubkeyBytes
    );

    expect(isValid1).toBe(true);
    expect(isValid2).toBe(true);
  });

  test("POST /message/sign signature should NOT verify with wrong message", async () => {
    const originalMessage = "Hello, Solana!";
    const tamperedMessage = "Hello, Bitcoin!";

    const response = await fetch(`${HTTP_URL}/message/sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: originalMessage,
        secret: generatedKeypair!.secret,
      }),
    });

    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(true);

    // Try to verify the signature with a different message
    const signatureBytes = bs58.decode(data.data.signature);
    const tamperedMessageBytes = new TextEncoder().encode(tamperedMessage);
    const pubkeyBytes = bs58.decode(data.data.pubkey);

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
    const signRes = await fetch(`${HTTP_URL}/message/sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: message,
        secret: generatedKeypair!.secret,
      }),
    });

    const signData = (await signRes.json()) as ApiResponse;
    expect(signData.success).toBe(true);

    // Then verify the signature
    const verifyRes = await fetch(`${HTTP_URL}/message/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: message,
        signature: signData.data.signature,
        pubkey: signData.data.pubkey,
      }),
    });

    expect(verifyRes.status).toBe(200);
    const verifyData = (await verifyRes.json()) as ApiResponse;
    expect(verifyData.success).toBe(true);
    expect(verifyData.data.valid).toBe(true);
    expect(verifyData.data.message).toBe(message);
    expect(verifyData.data.pubkey).toBe(generatedKeypair!.pubkey);
  });

  test("POST /send/sol should create valid SOL transfer instruction", async () => {
    const senderKeypair = Keypair.generate();
    const recipientKeypair = Keypair.generate();
    const lamports = 1000000; // 0.001 SOL

    const response = await fetch(`${HTTP_URL}/send/sol`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        from: senderKeypair.publicKey.toString(),
        to: recipientKeypair.publicKey.toString(),
        lamports: lamports,
      }),
    });

    expect(response.status).toBe(200);
    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(true);
    expect(data.data.program_id).toBe("11111111111111111111111111111111");
    expect(data.data.accounts).toBeDefined();
    expect(Array.isArray(data.data.accounts)).toBe(true);
    expect(data.data.accounts.length).toBe(2);
    expect(data.data.instruction_data).toBeDefined();

    // Verify account structure
    const accounts = data.data.accounts;
    expect(accounts[0]).toBe(senderKeypair.publicKey.toString());
    expect(accounts[1]).toBe(recipientKeypair.publicKey.toString());
  });

  test("POST /send/sol should reject zero lamports", async () => {
    const senderKeypair = Keypair.generate();
    const recipientKeypair = Keypair.generate();

    const response = await fetch(`${HTTP_URL}/send/sol`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        from: senderKeypair.publicKey.toString(),
        to: recipientKeypair.publicKey.toString(),
        lamports: 0,
      }),
    });

    expect(response.status).toBe(400);
    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(false);
    expect(data.error).toBe("Amount must be greater than 0");
  });

  test("POST /send/sol should reject invalid sender address", async () => {
    const recipientKeypair = Keypair.generate();

    const response = await fetch(`${HTTP_URL}/send/sol`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        from: "sender",
        to: bs58.encode(recipientKeypair.publicKey.toBytes()),
        lamports: 1000000,
      }),
    });

    expect(response.status).toBe(400);
    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(false);
    expect(data.error).toBe("Invalid sender public key");
  });

  test("POST /send/sol instruction data should be consistent", async () => {
    const senderKeypair = Keypair.generate();
    const recipientKeypair = Keypair.generate();
    const lamports = 1000000;

    // Make multiple requests with same parameters
    const requests = await Promise.all([
      fetch(`${HTTP_URL}/send/sol`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          from: bs58.encode(senderKeypair.publicKey.toBytes()),
          to: bs58.encode(recipientKeypair.publicKey.toBytes()),
          lamports: lamports,
        }),
      }),
      fetch(`${HTTP_URL}/send/sol`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          from: bs58.encode(senderKeypair.publicKey.toBytes()),
          to: bs58.encode(recipientKeypair.publicKey.toBytes()),
          lamports: lamports,
        }),
      }),
    ]);

    const data1 = (await requests[0].json()) as ApiResponse;
    const data2 = (await requests[1].json()) as ApiResponse;

    expect(data1.data.instruction_data).toBe(data2.data.instruction_data);
    expect(data1.data.program_id).toBe(data2.data.program_id);
  });

  test("POST /send/sol instruction should decode properly", async () => {
    const senderKeypair = Keypair.generate();
    const recipientKeypair = Keypair.generate();
    const lamports = 200;

    const response = await fetch(`${HTTP_URL}/send/sol`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        from: senderKeypair.publicKey.toString(),
        to: recipientKeypair.publicKey.toString(),
        lamports: lamports,
      }),
    });

    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(true);

    // Decode and verify instruction data
    const instructionData = bs58.decode(data.data.instruction_data);
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

    const response = await fetch(`${HTTP_URL}/send/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        destination: bs58.encode(destinationKeypair.publicKey.toBytes()),
        mint: bs58.encode(mintKeypair.publicKey.toBytes()),
        owner: bs58.encode(ownerKeypair.publicKey.toBytes()),
        amount: amount,
      }),
    });

    const ata = await getAssociatedTokenAddress(
      mintKeypair.publicKey,
      destinationKeypair.publicKey
    );

    expect(response.status).toBe(200);
    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(true);
    expect(data.data.program_id).toBe(
      "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    );
    expect(data.data.accounts).toBeDefined();
    expect(Array.isArray(data.data.accounts)).toBe(true);
    expect(data.data.accounts.length).toBe(3); // source, destination, owner
    expect(data.data.instruction_data).toBeDefined();

    // Verify account structure
    const accounts = data.data.accounts;
    expect(accounts[0].pubkey).toBe(ownerKeypair.publicKey.toString());
    expect(accounts[1].pubkey).toBe(ata.toString());
    expect(accounts[2].pubkey).toBe(ownerKeypair.publicKey.toString());

    // Check account permissions
    expect(accounts[0].isSigner).toBe(false); // source (writable)
    expect(accounts[1].isSigner).toBe(false); // destination (writable)

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

    const response = await fetch(`${HTTP_URL}/send/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        destination: bs58.encode(destinationKeypair.publicKey.toBytes()),
        owner: bs58.encode(ownerKeypair.publicKey.toBytes()),
        amount: amount,
      }),
    });

    expect(response.status).toBe(400);
    const data = (await response.json()) as ApiResponse;
    expect(data.success).toBe(false);
  });
});

console.log(`\n🧪 Running tests against: ${HTTP_URL}`);
