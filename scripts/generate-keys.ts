import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * Generates a production-grade 2048-bit RSA keypair for RS256 JWT signing & JWKS verification,
 * writing `./keys/private.pem` and `./keys/public.pem` and printing Base64 env strings.
 */
function main(): void {
  const keysDir = path.resolve(process.cwd(), 'keys');
  fs.mkdirSync(keysDir, { recursive: true });

  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const privPath = path.join(keysDir, 'private.pem');
  const pubPath = path.join(keysDir, 'public.pem');

  fs.writeFileSync(privPath, privateKey, { encoding: 'utf8', mode: 0o600 });
  fs.writeFileSync(pubPath, publicKey, { encoding: 'utf8', mode: 0o644 });

  const pubKeyObj = crypto.createPublicKey(publicKey);
  const exported = pubKeyObj.export({ format: 'jwk' });
  const kid = crypto
    .createHash('sha256')
    .update(JSON.stringify({ e: exported.e, kty: 'RSA', n: exported.n }), 'utf8')
    .digest('base64url');

  const privB64 = Buffer.from(privateKey, 'utf8').toString('base64');
  const pubB64 = Buffer.from(publicKey, 'utf8').toString('base64');

  process.stdout.write(`Generated 2048-bit RSA Keypair for RS256 Signing:\n`);
  process.stdout.write(`  Private Key : ${privPath}\n`);
  process.stdout.write(`  Public Key  : ${pubPath}\n`);
  process.stdout.write(`  Key ID (kid): ${kid}\n\n`);
  process.stdout.write(`For cloud secret managers (.env / Kubernetes / Render / Railway):\n`);
  process.stdout.write(`RSA_KEY_ID=${kid}\n`);
  process.stdout.write(`RSA_PRIVATE_KEY_BASE64=${privB64}\n`);
  process.stdout.write(`RSA_PUBLIC_KEY_BASE64=${pubB64}\n`);
}

main();
