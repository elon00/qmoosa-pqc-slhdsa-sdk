/**
 * QMOOSA Post-Quantum Cryptography — NIST FIPS 205 SLH-DSA TypeScript SDK
 *
 * Provides client abstractions, transaction authorization envelope creation,
 * canonical transaction serialization, and stateless hash-based signing utilities.
 */

import { createHash } from 'node:crypto';
import {
  SLH_DSA_SHA2_128S,
  SLH_DSA_SHA2_128F,
  SLH_DSA_SHA2_192S,
  SLH_DSA_SHA2_256S,
  SLH_DSA_SHAKE_128S,
  getSlhDsaParameters,
  constantTimeEqual,
  type SlhDsaParameterName,
  type SlhDsaParameters,
  type SlhDsaKeyPair,
  type SlhDsaSignatureResult,
  type Web4SignedTransactionEnvelope
} from '@qmoosa/pqc-slhdsa-protocol';
import {
  SlhDsaEngine,
  type KeyGenOptions,
  type SignOptions,
  type VerifyOptions
} from '@qmoosa/pqc-slhdsa-engine';

export * from '@qmoosa/pqc-slhdsa-protocol';
export * from '@qmoosa/pqc-slhdsa-engine';

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error('INVALID_HEX_STRING: Length must be even');
  }
  return new Uint8Array(Buffer.from(clean, 'hex'));
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function base64UrlToBytes(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, 'base64url'));
}

export interface SerializedSlhDsaKeyPair {
  readonly publicKeyHex: string;
  readonly secretKeyHex: string;
  readonly parameterSet: SlhDsaParameterName;
}

export interface SerializedSlhDsaSignature {
  readonly signatureHex: string;
  readonly parameterSet: SlhDsaParameterName;
}

export interface UnsignedTransaction {
  readonly chainId: string;
  readonly nonce: number;
  readonly fromAddress: string;
  readonly toAddress: string;
  readonly value: string;
  readonly payloadHex: string;
  readonly contextString: string;
}

/**
 * Computes canonical SHA-256 hash of an unsigned transaction payload.
 * Guarantees deterministic field ordering for cross-platform signing.
 */
export function canonicalTransactionHash(tx: UnsignedTransaction): Uint8Array {
  const canonicalString = JSON.stringify({
    chainId: tx.chainId,
    contextString: tx.contextString,
    fromAddress: tx.fromAddress.toLowerCase(),
    nonce: tx.nonce,
    payloadHex: tx.payloadHex.toLowerCase().replace(/^0x/, ''),
    toAddress: tx.toAddress.toLowerCase(),
    value: tx.value
  });

  return new Uint8Array(createHash('sha256').update(canonicalString, 'utf8').digest());
}

export class SlhDsaClient {
  private readonly engine: SlhDsaEngine;

  constructor(engine?: SlhDsaEngine) {
    this.engine = engine ?? new SlhDsaEngine();
  }

  public createKeyPair(
    paramName: SlhDsaParameterName = SLH_DSA_SHA2_128S.name,
    options?: KeyGenOptions
  ): SerializedSlhDsaKeyPair {
    const kp = this.engine.generateKeyPair(paramName, options);
    return Object.freeze({
      publicKeyHex: bytesToHex(kp.publicKey),
      secretKeyHex: bytesToHex(kp.secretKey),
      parameterSet: paramName
    });
  }

  public signMessage(
    messageBytes: Uint8Array,
    secretKeyHex: string,
    paramName: SlhDsaParameterName = SLH_DSA_SHA2_128S.name,
    options?: SignOptions
  ): SerializedSlhDsaSignature {
    const sk = hexToBytes(secretKeyHex);
    const res = this.engine.sign(messageBytes, sk, paramName, options);
    return Object.freeze({
      signatureHex: bytesToHex(res.signature),
      parameterSet: paramName
    });
  }

  public verifySignature(
    signatureHex: string,
    messageBytes: Uint8Array,
    publicKeyHex: string,
    paramName: SlhDsaParameterName = SLH_DSA_SHA2_128S.name,
    options?: VerifyOptions
  ): boolean {
    const sig = hexToBytes(signatureHex);
    const pk = hexToBytes(publicKeyHex);
    return this.engine.verify(sig, messageBytes, pk, paramName, options);
  }

  /**
   * Signs a Web4 transaction and bundles it into an immutable authorization envelope.
   */
  public signTransaction(
    tx: UnsignedTransaction,
    secretKeyHex: string,
    publicKeyHex: string,
    paramName: SlhDsaParameterName = SLH_DSA_SHA2_128S.name,
    timestamp = Date.now()
  ): Web4SignedTransactionEnvelope {
    const txHash = canonicalTransactionHash(tx);
    const sig = this.signMessage(txHash, secretKeyHex, paramName, {
      context: tx.contextString
    });

    return Object.freeze({
      chainId: tx.chainId,
      nonce: tx.nonce,
      fromAddress: tx.fromAddress,
      toAddress: tx.toAddress,
      value: tx.value,
      payloadHex: tx.payloadHex,
      contextString: tx.contextString,
      parameterSet: paramName,
      publicKeyHex,
      signatureHex: sig.signatureHex,
      timestamp
    });
  }

  /**
   * Verifies an immutable Web4 transaction envelope against its post-quantum signature.
   */
  public verifyTransaction(envelope: Web4SignedTransactionEnvelope): boolean {
    const unsignedTx: UnsignedTransaction = {
      chainId: envelope.chainId,
      nonce: envelope.nonce,
      fromAddress: envelope.fromAddress,
      toAddress: envelope.toAddress,
      value: envelope.value,
      payloadHex: envelope.payloadHex,
      contextString: envelope.contextString
    };

    const txHash = canonicalTransactionHash(unsignedTx);
    return this.verifySignature(
      envelope.signatureHex,
      txHash,
      envelope.publicKeyHex,
      envelope.parameterSet,
      { context: envelope.contextString }
    );
  }
}
