import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SlhDsaClient,
  canonicalTransactionHash,
  bytesToHex,
  hexToBytes,
  bytesToBase64Url,
  base64UrlToBytes
} from '../dist/index.js';

test('SLH-DSA SDK: Hex and Base64Url Serialization Round-Trip', () => {
  const bytes = new Uint8Array([0x00, 0xde, 0xad, 0xbe, 0xef, 0xff]);
  const hex = bytesToHex(bytes);
  assert.equal(hex, '00deadbeefff');
  assert.deepEqual(hexToBytes(hex), bytes);
  assert.deepEqual(hexToBytes('0x00deadbeefff'), bytes);

  const b64 = bytesToBase64Url(bytes);
  assert.deepEqual(base64UrlToBytes(b64), bytes);

  assert.throws(() => hexToBytes('123'), /INVALID_HEX_STRING/);
});

test('SLH-DSA SDK: Canonical Transaction Hash Determinism', () => {
  const tx1 = {
    chainId: 'arbitrum-one',
    nonce: 10,
    fromAddress: '0xAlice',
    toAddress: '0xBob',
    value: '1000000000000000000',
    payloadHex: '0x1234',
    contextString: 'ARBITRUM_FIPS205_V1'
  };

  const tx2 = {
    ...tx1,
    fromAddress: '0xALICE', // casing normalization
    payloadHex: '1234'      // prefix normalization
  };

  const hash1 = canonicalTransactionHash(tx1);
  const hash2 = canonicalTransactionHash(tx2);

  assert.equal(bytesToHex(hash1), bytesToHex(hash2));
});

test('SLH-DSA SDK: Client Pure Message Signing & Verification', () => {
  const client = new SlhDsaClient();
  const alice = client.createKeyPair('SLH-DSA-SHA2-128f');

  assert.equal(typeof alice.publicKeyHex, 'string');
  assert.equal(typeof alice.secretKeyHex, 'string');

  const msg = new TextEncoder().encode('Sovereign Web4 Stateless Hash Root');
  const sig = client.signMessage(msg, alice.secretKeyHex, 'SLH-DSA-SHA2-128f');

  assert.equal(typeof sig.signatureHex, 'string');

  const isValid = client.verifySignature(sig.signatureHex, msg, alice.publicKeyHex, 'SLH-DSA-SHA2-128f');
  assert.equal(isValid, true);
});

test('SLH-DSA SDK: Web4 Transaction Authorization Envelope Signing & Verification', () => {
  const client = new SlhDsaClient();
  const alice = client.createKeyPair('SLH-DSA-SHA2-128f');

  const tx = {
    chainId: '42161',
    nonce: 1,
    fromAddress: '0xAlice',
    toAddress: '0xVault',
    value: '5000000000000000000',
    payloadHex: '0xabcdef',
    contextString: 'QMOOSA_CHAIN_42161'
  };

  const envelope = client.signTransaction(tx, alice.secretKeyHex, alice.publicKeyHex, 'SLH-DSA-SHA2-128f');
  assert.equal(envelope.chainId, '42161');
  assert.equal(envelope.nonce, 1);
  assert.equal(typeof envelope.signatureHex, 'string');

  const isVerified = client.verifyTransaction(envelope);
  assert.equal(isVerified, true, 'Genuine transaction envelope must verify successfully');
});

test('SLH-DSA SDK: Adversarial Negative Control - Altered Amount Rejection', () => {
  const client = new SlhDsaClient();
  const alice = client.createKeyPair('SLH-DSA-SHA2-128f');

  const tx = {
    chainId: '42161',
    nonce: 1,
    fromAddress: '0xAlice',
    toAddress: '0xVault',
    value: '5000000000000000000',
    payloadHex: '0xabcdef',
    contextString: 'QMOOSA_CHAIN_42161'
  };

  const envelope = client.signTransaction(tx, alice.secretKeyHex, alice.publicKeyHex, 'SLH-DSA-SHA2-128f');

  // Attacker inflates value
  const forgedEnvelope = {
    ...envelope,
    value: '9999999999999999999'
  };

  assert.equal(client.verifyTransaction(forgedEnvelope), false, 'Tampered amount must fail verification');
});

test('SLH-DSA SDK: Adversarial Negative Control - Replay on Altered Chain ID Rejection', () => {
  const client = new SlhDsaClient();
  const alice = client.createKeyPair('SLH-DSA-SHA2-128f');

  const tx = {
    chainId: '42161',
    nonce: 1,
    fromAddress: '0xAlice',
    toAddress: '0xVault',
    value: '1000',
    payloadHex: '0x',
    contextString: 'QMOOSA_CHAIN_42161'
  };

  const envelope = client.signTransaction(tx, alice.secretKeyHex, alice.publicKeyHex, 'SLH-DSA-SHA2-128f');

  // Attacker tries to replay envelope on another chain (e.g. Ethereum Mainnet 1)
  const replayedEnvelope = {
    ...envelope,
    chainId: '1',
    contextString: 'QMOOSA_CHAIN_1'
  };

  assert.equal(client.verifyTransaction(replayedEnvelope), false, 'Cross-chain replayed envelope must fail verification');
});
