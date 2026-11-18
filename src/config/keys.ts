import crypto, { KeyObject } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { JwkRsaPublicKey, JwksDocument } from '../types/index.js';
import { env } from './env.js';

export interface ActiveSigningKeyPair {
  kid: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
  privateKeyPem: string;
  publicKeyPem: string;
  jwk: JwkRsaPublicKey;
}

interface KeyStoreState {
  active: ActiveSigningKeyPair;
  verificationKeysByKid: Map<string, KeyObject>;
  jwks: JwksDocument;
}

let keyStore: KeyStoreState | null = null;

/**
 * Computes an RFC 7638 compliant SHA-256 JWK thumbprint to serve as deterministic `kid`.
 */
export function computeRsaJwkThumbprint(n: string, e: string): string {
  const canonicalJwk = JSON.stringify({ e, kty: 'RSA', n });
  return crypto.createHash('sha256').update(canonicalJwk, 'utf8').digest('base64url');
}

/**
 * Converts a Node KeyObject RSA public key into a public JWKS entry.
 */
export function exportPublicKeyToJwk(publicKey: KeyObject, explicitKid?: string): JwkRsaPublicKey {
  if (publicKey.asymmetricKeyType !== 'rsa') {
    throw new Error('Asymmetric key must be of type RSA for RS256 signing.');
  }

  const modulusLength = publicKey.asymmetricKeyDetails?.modulusLength ?? 0;
  if (modulusLength < 2048) {
    throw new Error(`RSA modulus length must be at least 2048 bits (got ${modulusLength}).`);
  }

  const exported = publicKey.export({ format: 'jwk' });
  if (!exported.n || !exported.e) {
    throw new Error('Failed to export RSA modulus (n) and exponent (e) to JWK.');
  }

  const kid = explicitKid && explicitKid.trim().length > 0
    ? explicitKid.trim()
    : computeRsaJwkThumbprint(exported.n, exported.e);

  return {
    kty: 'RSA',
    use: 'sig',
    alg: 'RS256',
    kid,
    n: exported.n,
    e: exported.e,
  };
}

function normalizePem(raw: string): string {
  return raw.replace(/\\n/g, '\n').trim();
}

function resolveRawKeyPairFromEnv(): { privatePem: string; publicPem: string } | null {
  if (env.RSA_PRIVATE_KEY_BASE64 && env.RSA_PUBLIC_KEY_BASE64) {
    return {
      privatePem: Buffer.from(env.RSA_PRIVATE_KEY_BASE64, 'base64').toString('utf8').trim(),
      publicPem: Buffer.from(env.RSA_PUBLIC_KEY_BASE64, 'base64').toString('utf8').trim(),
    };
  }

  if (env.RSA_PRIVATE_KEY && env.RSA_PUBLIC_KEY) {
    return {
      privatePem: normalizePem(env.RSA_PRIVATE_KEY),
      publicPem: normalizePem(env.RSA_PUBLIC_KEY),
    };
  }

  if (env.RSA_PRIVATE_KEY_PATH && env.RSA_PUBLIC_KEY_PATH) {
    const privPath = path.resolve(process.cwd(), env.RSA_PRIVATE_KEY_PATH);
    const pubPath = path.resolve(process.cwd(), env.RSA_PUBLIC_KEY_PATH);
    if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
      return {
        privatePem: fs.readFileSync(privPath, 'utf8').trim(),
        publicPem: fs.readFileSync(pubPath, 'utf8').trim(),
      };
    }
  }

  return null;
}

/**
 * Generates an ephemeral 2048-bit RSA keypair strictly for non-production / test environments
 * when explicit PEM files have not yet been generated.
 */
export function generateRsaKeyPairPem(): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  return { privatePem: privateKey, publicPem: publicKey };
}

/**
 * Initializes and validates the RS256 key store and JWKS document.
 */
export function initializeKeyStore(customPem?: {
  privatePem: string;
  publicPem: string;
  kid?: string;
  previousPublicPems?: string[];
}): KeyStoreState {
  let resolved = customPem
    ? { privatePem: customPem.privatePem, publicPem: customPem.publicPem }
    : resolveRawKeyPairFromEnv();

  if (!resolved) {
    if (env.NODE_ENV === 'production') {
      throw new Error(
        'CRITICAL: RS256 RSA keypair not configured in production. Set RSA_PRIVATE_KEY_BASE64 & RSA_PUBLIC_KEY_BASE64 or mount key files.',
      );
    }
    resolved = generateRsaKeyPairPem();
  }

  const privateKey = crypto.createPrivateKey(resolved.privatePem);
  const publicKey = crypto.createPublicKey(resolved.publicPem);

  // Cryptographically verify that privateKey and publicKey form a valid pair
  const derivedPublicJwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
  const providedPublicJwk = publicKey.export({ format: 'jwk' });
  if (derivedPublicJwk.n !== providedPublicJwk.n || derivedPublicJwk.e !== providedPublicJwk.e) {
    throw new Error('Configured RSA_PRIVATE_KEY and RSA_PUBLIC_KEY do not match.');
  }

  const activeJwk = exportPublicKeyToJwk(publicKey, customPem?.kid ?? env.RSA_KEY_ID);

  const verificationKeysByKid = new Map<string, KeyObject>();
  verificationKeysByKid.set(activeJwk.kid, publicKey);

  const jwksKeys: JwkRsaPublicKey[] = [activeJwk];

  const previousPems =
    customPem?.previousPublicPems ??
    env.RSA_PREVIOUS_PUBLIC_KEYS_BASE64.map((b64) =>
      Buffer.from(b64, 'base64').toString('utf8').trim(),
    );

  for (const prevPem of previousPems) {
    const prevPubKey = crypto.createPublicKey(prevPem);
    const prevJwk = exportPublicKeyToJwk(prevPubKey);
    if (!verificationKeysByKid.has(prevJwk.kid)) {
      verificationKeysByKid.set(prevJwk.kid, prevPubKey);
      jwksKeys.push(prevJwk);
    }
  }

  keyStore = {
    active: {
      kid: activeJwk.kid,
      privateKey,
      publicKey,
      privateKeyPem: resolved.privatePem,
      publicKeyPem: resolved.publicPem,
      jwk: activeJwk,
    },
    verificationKeysByKid,
    jwks: { keys: jwksKeys },
  };

  return keyStore;
}

export function getKeyStore(): KeyStoreState {
  if (!keyStore) {
    return initializeKeyStore();
  }
  return keyStore;
}
