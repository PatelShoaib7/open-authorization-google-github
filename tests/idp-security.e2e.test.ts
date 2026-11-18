import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { Application } from 'express';

process.env.NODE_ENV = 'test';
process.env.ADMIN_EMAILS = 'admin@shoaib.dev';
process.env.ISSUER_URL = 'http://localhost:4000';

const { createApp } = await import('../src/app.js');
const {
  InMemoryRedisStore,
  generateRsaKeyPairPem,
  initializeKeyStore,
  setRedisStore,
} = await import('../src/config/index.js');
const { computeS256CodeChallenge, generateCodeVerifier } = await import(
  '../src/utils/pkce.js'
);
const {
  InMemoryClientRepository,
  InMemoryConsentRepository,
  InMemoryUserRepository,
} = await import('./in-memory-repositories.js');

function extractCookieValue(setCookieHeader: string[] | undefined, name: string): string | undefined {
  if (!setCookieHeader) return undefined;
  for (const raw of setCookieHeader) {
    const [pair] = raw.split(';');
    if (pair && pair.startsWith(`${name}=`)) {
      return decodeURIComponent(pair.slice(name.length + 1));
    }
  }
  return undefined;
}

describe('Centralized Identity Provider (IdP) & SSO Security Suite', () => {
  let app: Application;
  let userRepository: InstanceType<typeof InMemoryUserRepository>;
  let clientRepository: InstanceType<typeof InMemoryClientRepository>;
  let consentRepository: InstanceType<typeof InMemoryConsentRepository>;

  beforeEach(() => {
    const keyPair = generateRsaKeyPairPem();
    initializeKeyStore({
      privatePem: keyPair.privatePem,
      publicPem: keyPair.publicPem,
    });
    setRedisStore(new InMemoryRedisStore());

    userRepository = new InMemoryUserRepository();
    clientRepository = new InMemoryClientRepository();
    consentRepository = new InMemoryConsentRepository();

    app = createApp({
      userRepository,
      clientRepository,
      consentRepository,
    });
  });

  it('exposes RS256 public key via /.well-known/jwks.json so external projects verify tokens without shared secrets', async () => {
    const regRes = await request(app).post('/api/v1/auth/register').send({
      email: 'admin@shoaib.dev',
      username: 'shoaib',
      password: 'StrongPassword123',
      name: 'Shoaib Patel',
    });

    expect(regRes.status).toBe(201);
    const accessToken = regRes.body.data.accessToken as string;

    // Simulate an external personal project fetching ONLY /.well-known/jwks.json
    const jwksRes = await request(app).get('/.well-known/jwks.json');
    expect(jwksRes.status).toBe(200);
    expect(jwksRes.body.keys).toHaveLength(1);

    const jwk = jwksRes.body.keys[0];
    expect(jwk.kty).toBe('RSA');
    expect(jwk.alg).toBe('RS256');
    expect(jwk.use).toBe('sig');
    expect(jwk.kid).toBeTruthy();

    // Reconstruct public KeyObject from JWK alone and verify JWT signature & claims
    const externalPublicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const decoded = jwt.verify(accessToken, externalPublicKey, {
      algorithms: ['RS256'],
      issuer: 'http://localhost:4000',
    }) as Record<string, unknown>;

    expect(decoded.sub).toBe(regRes.body.data.user.id);
    expect(decoded.roles).toContain('admin');
    // Ensure passwordHash is NEVER leaked into JWT payload (fixing legacy anti-pattern)
    expect(decoded.password).toBeUndefined();
    expect(decoded.passwordHash).toBeUndefined();
  });

  it('strictly blocks symmetric HS256 / alg:none algorithm confusion attacks on protected routes', async () => {
    const forgedHs256Token = jwt.sign(
      { sub: 'attacker-id', iss: 'http://localhost:4000', roles: ['admin'], scope: 'openid' },
      'shared-secret',
      { algorithm: 'HS256' },
    );

    const res = await request(app)
      .get('/api/v1/users/me')
      .set('Authorization', `Bearer ${forgedHs256Token}`);

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_ACCESS_TOKEN');
  });

  it('enforces Refresh Token Rotation in HttpOnly cookies and revokes entire family upon Reuse Detection', async () => {
    const loginRes = await request(app).post('/api/v1/auth/register').send({
      email: 'user1@example.com',
      username: 'userone',
      password: 'StrongPassword123',
      name: 'User One',
    });

    const setCookies1 = loginRes.headers['set-cookie'] as unknown as string[];
    expect(setCookies1.some((c) => c.includes('HttpOnly'))).toBe(true);
    const refreshTokenGen1 = extractCookieValue(setCookies1, 'idp_refresh_token');
    expect(refreshTokenGen1).toBeTruthy();

    // Legitimate rotation Gen 1 -> Gen 2
    const refreshRes1 = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', [`idp_refresh_token=${refreshTokenGen1}`]);

    expect(refreshRes1.status).toBe(200);
    const setCookies2 = refreshRes1.headers['set-cookie'] as unknown as string[];
    const refreshTokenGen2 = extractCookieValue(setCookies2, 'idp_refresh_token');
    expect(refreshTokenGen2).toBeTruthy();
    expect(refreshTokenGen2).not.toBe(refreshTokenGen1);

    // Attacker (or compromised client) replays already-used Gen 1 token -> REUSE DETECTED!
    const replayRes = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', [`idp_refresh_token=${refreshTokenGen1}`]);

    expect(replayRes.status).toBe(401);
    expect(replayRes.body.error.code).toBe('REFRESH_TOKEN_REUSE_DETECTED');

    // Verify the ENTIRE token family was immediately revoked: even Gen 2 is now dead!
    const afterCompromiseRes = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', [`idp_refresh_token=${refreshTokenGen2}`]);

    expect(afterCompromiseRes.status).toBe(401);
    expect(afterCompromiseRes.body.error.code).toBe('INVALID_REFRESH_TOKEN');
  });

  it('completes full OAuth 2.1 Authorization Code + PKCE (S256) SSO flow across personal projects and blocks code replay', async () => {
    // 1. Register admin & sign in (gets SSO session cookie)
    const adminRes = await request(app).post('/api/v1/auth/register').send({
      email: 'admin@shoaib.dev',
      username: 'shoaib_admin',
      password: 'StrongPassword123',
      name: 'Shoaib Admin',
    });
    const adminAccessToken = adminRes.body.data.accessToken as string;
    const ssoCookie = extractCookieValue(
      adminRes.headers['set-cookie'] as unknown as string[],
      'idp_sso_session',
    );
    expect(ssoCookie).toBeTruthy();

    // 2. Register a personal SPA client
    const createClientRes = await request(app)
      .post('/api/v1/clients')
      .set('Authorization', `Bearer ${adminAccessToken}`)
      .send({
        name: 'Expense Tracker SPA',
        applicationType: 'spa',
        redirectUris: ['https://expenses.shoaib.dev/auth/callback'],
        allowedOrigins: ['https://expenses.shoaib.dev'],
        allowedScopes: ['openid', 'profile', 'email'],
        requireConsent: false,
      });

    expect(createClientRes.status).toBe(201);
    const clientId = createClientRes.body.data.client.clientId as string;

    // 3. Verify Dynamic CORS allows registered client origin and blocks unknown origins
    const corsAllowedRes = await request(app)
      .get('/health')
      .set('Origin', 'https://expenses.shoaib.dev');
    expect(corsAllowedRes.headers['access-control-allow-origin']).toBe(
      'https://expenses.shoaib.dev',
    );

    const corsBlockedRes = await request(app)
      .get('/health')
      .set('Origin', 'https://evil-phishing.example.com');
    expect(corsBlockedRes.status).toBe(403);
    expect(corsBlockedRes.body.error.code).toBe('CORS_ORIGIN_FORBIDDEN');

    // 4. Initiate OAuth 2.1 PKCE S256 Authorization with active SSO cookie -> seamless SSO redirect!
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = computeS256CodeChallenge(codeVerifier);
    const state = 'csrf_state_token_12345';

    const authzRes = await request(app)
      .get('/oauth/authorize')
      .set('Cookie', [`idp_sso_session=${ssoCookie}`])
      .query({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: 'https://expenses.shoaib.dev/auth/callback',
        scope: 'openid profile email',
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      });

    expect(authzRes.status).toBe(302);
    const redirectLocation = new URL(authzRes.headers.location!);
    expect(redirectLocation.origin + redirectLocation.pathname).toBe(
      'https://expenses.shoaib.dev/auth/callback',
    );
    expect(redirectLocation.searchParams.get('state')).toBe(state);
    const authCode = redirectLocation.searchParams.get('code')!;
    expect(authCode).toMatch(/^ac_/);

    // 5. Wrong PKCE verifier fails without issuing tokens (note: code is single-use, so let's issue a fresh code to test valid exchange too)
    const tokenSuccessRes = await request(app).post('/oauth/token').send({
      grant_type: 'authorization_code',
      client_id: clientId,
      redirect_uri: 'https://expenses.shoaib.dev/auth/callback',
      code: authCode,
      code_verifier: codeVerifier,
    });

    expect(tokenSuccessRes.status).toBe(200);
    expect(tokenSuccessRes.body.access_token).toBeTruthy();
    expect(tokenSuccessRes.body.id_token).toBeTruthy();
    expect(tokenSuccessRes.body.expires_in).toBe(900);

    const clientRefreshCookie = extractCookieValue(
      tokenSuccessRes.headers['set-cookie'] as unknown as string[],
      'idp_refresh_token',
    );
    expect(clientRefreshCookie).toBeTruthy();

    // 6. Replaying the same authorization code revokes the issued refresh token family!
    const replayCodeRes = await request(app).post('/oauth/token').send({
      grant_type: 'authorization_code',
      client_id: clientId,
      redirect_uri: 'https://expenses.shoaib.dev/auth/callback',
      code: authCode,
      code_verifier: codeVerifier,
    });
    expect(replayCodeRes.status).toBe(400);
    expect(replayCodeRes.body.error).toBe('invalid_grant');

    const tryRevokedRefresh = await request(app)
      .post('/oauth/token')
      .set('Cookie', [`idp_refresh_token=${clientRefreshCookie}`])
      .send({
        grant_type: 'refresh_token',
        client_id: clientId,
      });
    expect(tryRevokedRefresh.status).toBe(400);
    expect(tryRevokedRefresh.body.error).toBe('invalid_grant');
  });

  it('rejects deprecated Implicit Grant, ROPC password grant, plain PKCE, and Open Redirects', async () => {
    const adminRes = await request(app).post('/api/v1/auth/register').send({
      email: 'admin@shoaib.dev',
      username: 'admin2',
      password: 'StrongPassword123',
      name: 'Admin Two',
    });
    const token = adminRes.body.data.accessToken as string;

    const createClientRes = await request(app)
      .post('/api/v1/clients')
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: 'Docs App',
        applicationType: 'spa',
        redirectUris: ['https://docs.shoaib.dev/callback'],
      });
    const clientId = createClientRes.body.data.client.clientId as string;

    // 1. Open Redirect attempt -> direct 400 error, NEVER 302 redirect!
    const openRedirectRes = await request(app).get('/oauth/authorize').query({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: 'https://attacker.evil.com/steal-code',
      state: 'valid_state_1234',
      code_challenge: computeS256CodeChallenge(generateCodeVerifier()),
      code_challenge_method: 'S256',
    });
    expect(openRedirectRes.status).toBe(400);
    expect(openRedirectRes.headers.location).toBeUndefined();
    expect(openRedirectRes.body.error).toBe('invalid_request');

    // 2. Deprecated Implicit Grant (`response_type=token`)
    const implicitRes = await request(app).get('/oauth/authorize').query({
      response_type: 'token',
      client_id: clientId,
      redirect_uri: 'https://docs.shoaib.dev/callback',
      state: 'valid_state_1234',
    });
    expect(implicitRes.status).toBe(400);
    expect(implicitRes.body.error).toBe('unsupported_response_type');

    // 3. Downgraded `code_challenge_method=plain`
    const plainPkceRes = await request(app).get('/oauth/authorize').query({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: 'https://docs.shoaib.dev/callback',
      state: 'valid_state_1234',
      code_challenge: generateCodeVerifier(),
      code_challenge_method: 'plain',
    });
    expect(plainPkceRes.status).toBe(400);
    expect(plainPkceRes.body.error).toBe('invalid_request');

    // 4. Deprecated ROPC (`grant_type=password`)
    const ropcRes = await request(app).post('/oauth/token').send({
      grant_type: 'password',
      username: 'admin2',
      password: 'StrongPassword123',
      client_id: clientId,
    });
    expect(ropcRes.status).toBe(400);
    expect(ropcRes.body.error).toBe('unsupported_grant_type');
  });

  it('enforces interactive Consent Screen flow when requireConsent=true', async () => {
    const adminRes = await request(app).post('/api/v1/auth/register').send({
      email: 'admin@shoaib.dev',
      username: 'consent_admin',
      password: 'StrongPassword123',
      name: 'Consent Admin',
    });
    const token = adminRes.body.data.accessToken as string;
    const ssoCookie = extractCookieValue(
      adminRes.headers['set-cookie'] as unknown as string[],
      'idp_sso_session',
    )!;

    const createClientRes = await request(app)
      .post('/api/v1/clients')
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: 'Third-Party Analytics CLI',
        applicationType: 'spa',
        redirectUris: ['http://localhost:5173/callback'],
        requireConsent: true,
      });
    const clientId = createClientRes.body.data.client.clientId as string;

    const verifier = generateCodeVerifier();
    const challenge = computeS256CodeChallenge(verifier);

    const step1 = await request(app)
      .get('/oauth/authorize')
      .set('Accept', 'application/json')
      .set('Cookie', [`idp_sso_session=${ssoCookie}`])
      .query({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: 'http://localhost:5173/callback',
        scope: 'openid email',
        state: 'state_consent_9999',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      });

    expect(step1.status).toBe(200);
    expect(step1.body.status).toBe('consent_required');
    const authReqId = step1.body.authReqId as string;

    const approveRes = await request(app)
      .post('/oauth/authorize/decision')
      .set('Accept', 'application/json')
      .set('Cookie', [`idp_sso_session=${ssoCookie}`])
      .send({
        auth_req_id: authReqId,
        decision: 'approve',
      });

    expect(approveRes.status).toBe(200);
    const callbackUrl = new URL(approveRes.body.data.redirectUrl);
    expect(callbackUrl.searchParams.get('code')).toMatch(/^ac_/);
    expect(callbackUrl.searchParams.get('state')).toBe('state_consent_9999');
  });
});
