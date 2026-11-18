import crypto from 'node:crypto';
import argon2 from 'argon2';

const ARGON2_OPTIONS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MiB
  timeCost: 3,
  parallelism: 4,
};

export async function hashSecret(plainText: string): Promise<string> {
  return argon2.hash(plainText, ARGON2_OPTIONS);
}

export async function verifySecret(hash: string, plainText: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plainText);
  } catch {
    return false;
  }
}

export function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

export function sha256Base64Url(input: string): string {
  return crypto.createHash('sha256').update(input, 'ascii').digest('base64url');
}

export function generateRandomToken(byteLength = 32): string {
  return crypto.randomBytes(byteLength).toString('base64url');
}

export function generateClientId(): string {
  return `cl_${crypto.randomBytes(16).toString('hex')}`;
}

export function generateClientSecret(): string {
  return `cs_${crypto.randomBytes(32).toString('base64url')}`;
}

/**
 * Constant-time string comparison immune to length-oracle timing leaks.
 */
export function safeCompareStrings(a: string, b: string): boolean {
  const digestA = crypto.createHash('sha256').update(a, 'utf8').digest();
  const digestB = crypto.createHash('sha256').update(b, 'utf8').digest();
  const digestsMatch = crypto.timingSafeEqual(digestA, digestB);
  return digestsMatch && a.length === b.length;
}
