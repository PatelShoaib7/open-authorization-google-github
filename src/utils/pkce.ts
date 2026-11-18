import { generateRandomToken, safeCompareStrings, sha256Base64Url } from './crypto.js';

/**
 * RFC 7636 Section 4.1: code_verifier must be 43..128 chars from [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
 */
const PKCE_TOKEN_REGEX = /^[A-Za-z0-9\-._~]{43,128}$/;

export function isValidPkceString(value: string): boolean {
  return PKCE_TOKEN_REGEX.test(value);
}

export function generateCodeVerifier(): string {
  // 32 bytes -> 43 base64url chars; 48 bytes -> 64 base64url chars
  return generateRandomToken(48);
}

/**
 * Computes S256 PKCE code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
 */
export function computeS256CodeChallenge(codeVerifier: string): string {
  if (!isValidPkceString(codeVerifier)) {
    throw new Error('Invalid PKCE code_verifier format (RFC 7636).');
  }
  return sha256Base64Url(codeVerifier);
}

/**
 * Verifies an OAuth 2.1 S256 PKCE challenge in constant time.
 * Note: 'plain' method is intentionally rejected under OAuth 2.1 security baseline.
 */
export function verifyPkceS256(codeVerifier: string, storedCodeChallenge: string): boolean {
  if (!isValidPkceString(codeVerifier) || !isValidPkceString(storedCodeChallenge)) {
    return false;
  }
  const computedChallenge = sha256Base64Url(codeVerifier);
  return safeCompareStrings(computedChallenge, storedCodeChallenge);
}
