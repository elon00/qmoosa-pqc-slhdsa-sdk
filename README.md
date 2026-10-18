# @qmoosa/pqc-slhdsa-sdk

[![CI Gate](https://github.com/elon00/qmoosa-pqc-slhdsa-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/elon00/qmoosa-pqc-slhdsa-sdk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> QMOOSA Post-Quantum Cryptography Suite — NIST FIPS 205 SLH-DSA TypeScript SDK & Web4 Transaction Signer.

## Overview

`@qmoosa/pqc-slhdsa-sdk` provides an ergonomic, strongly-typed TypeScript SDK for quantum-safe digital signatures using NIST FIPS 205 (SLH-DSA). It integrates key management, canonical Web4 transaction serialization, domain-separated cryptographic envelopes, and multi-tier verification.

## Features

- **Ergonomic Client:** `SlhDsaClient` for generating keys, signing payloads, and verifying signatures.
- **Web4 Transaction Envelopes:** High-level `signTransaction` and `verifyTransaction` abstractions binding chain IDs, nonces, payloads, and domain context strings.
- **Deterministic Canonical Hashing:** Strict JSON key ordering and address normalization.
- **Hex and Base64Url Utilities:** Safe encoding and decoding for cross-network transmission.

## Quick Start

```typescript
import { SlhDsaClient } from '@qmoosa/pqc-slhdsa-sdk';

const client = new SlhDsaClient();
const alice = client.createKeyPair('SLH-DSA-SHA2-128s');

const tx = {
  chainId: '42161',
  nonce: 1,
  fromAddress: '0xAlice',
  toAddress: '0xVault',
  value: '1000000000000000000',
  payloadHex: '0x',
  contextString: 'QMOOSA_CHAIN_42161'
};

const envelope = client.signTransaction(tx, alice.secretKeyHex, alice.publicKeyHex, 'SLH-DSA-SHA2-128s');
const isValid = client.verifyTransaction(envelope);
console.log('Verified:', isValid);
```

## Installation & Tests

```bash
npm install
npm run build
npm test
npm run lint
```

## Reality Gate Status

- Production Deployment Status: **LOCKED (0 / 1,000 certified)**
- Local Reality-Gate Verification: **ACTIVE**
