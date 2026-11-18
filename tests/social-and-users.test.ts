import request from 'supertest';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

process.env.NODE_ENV = 'test';
process.env.ADMIN_EMAILS = 'admin@shoaib.dev';
process.env.ISSUER_URL = 'http://localhost:4000';
process.env.GOOGLE_CLIENT_ID = 'test-google-client-id';
process.env.GOOGLE_CLIENT_SECRET = 'test-google-client-secret';
process.env.GITHUB_CLIENT_ID = 'test-github-client-id';
process.env.GITHUB_CLIENT_SECRET = 'test-github-client-secret';

const { createApp } = await import('../src/app.js');
const {
  InMemoryRedisStore,
  generateRsaKeyPairPem,
  initializeKeyStore,
  setRedisStore,
} = await import('../src/config/index.js');
const {
  InMemoryClientRepository,
  InMemoryConsentRepository,
  InMemoryUserRepository,
} = await import('./in-memory-repositories.js');

function extractCookieValue(
  setCookieHeader: string[] | undefined,
  name: string,
): string | undefined {
  if (!setCookieHeader) return undefined;
  for (const raw of setCookieHeader) {
    const [pair] = raw.split(';');
    if (pair && pair.startsWith(`${name}=`)) {
      return decodeURIComponent(pair.slice(name.length + 1));
    }
  }
  return undefined;
}

describe('Social OAuth CSRF Hardening, Confidential Clients & RBAC Suite', () => {
  let app: Application;

  beforeEach(() => {
    vi.restoreAllMocks();
    const keyPair = generateRsaKeyPairPem();
    initializeKeyStore({
      privatePem: keyPair.privatePem,
      publicPem: keyPair.publicPem,
    });
    setRedisStore(new InMemoryRedisStore());

    app = createApp({
      userRepository: new InMemoryUserRepository(),
      clientRepository: new InMemoryClientRepository(),
      consentRepository: new InMemoryConsentRepository(),
    });
  });

  it('enforces single-use Redis state & PKCE on Google/GitHub Social OAuth and safely resolves private GitHub emails', async () => {
    const initRes = await request(app).get('/api/v1/auth/github');
    expect(initRes.status).toBe(302);

    const ghUrl = new URL(initRes.headers.location!);
    expect(ghUrl.origin).toBe('https://github.com');
    expect(ghUrl.searchParams.get('code_challenge_method')).toBe('S256');
    expect(ghUrl.searchParams.get('code_challenge')).toBeTruthy();
    const validState = ghUrl.searchParams.get('state')!;
    expect(validState.length).toBeGreaterThanOrEqual(32);

    // Reject forged state parameter (CSRF defense)
    const csrfRes = await request(app).get('/api/v1/auth/github/callback').query({
      code: 'some_code',
      state: 'forged_attacker_state_value',
    });
    expect(csrfRes.status).toBe(400);
    expect(csrfRes.body.error.code).toBe('INVALID_OAUTH_STATE');

    // Mock upstream GitHub API responses (simulating private profile email + verified /user/emails)
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('github.com/login/oauth/access_token')) {
        return new Response(JSON.stringify({ access_token: 'gho_upstream_secret_token' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url.endsWith('/user')) {
        return new Response(
          JSON.stringify({
            id: 987654,
            login: 'shoaib-mushtak-kf',
            name: 'Shoaib Patel',
            email: null, // Private email on GitHub profile!
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url.endsWith('/user/emails')) {
        return new Response(
          JSON.stringify([
            { email: 'patelshoaib125@gmail.com', primary: true, verified: true },
          ]),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('Not found', { status: 404 });
    });

    const callbackRes = await request(app).get('/api/v1/auth/github/callback').query({
      code: 'valid_gh_code',
      state: validState,
    });

    expect(callbackRes.status).toBe(200);
    expect(callbackRes.body.data.user.email).toBe('patelshoaib125@gmail.com');
    expect(callbackRes.body.data.user.linkedProviders).toContain('github');
    // Upstream GitHub token is NEVER leaked in response
    expect(JSON.stringify(callbackRes.body)).not.toContain('gho_upstream_secret_token');

    // Replaying the same state parameter fails immediately (atomic consumeOnce)
    const replayStateRes = await request(app).get('/api/v1/auth/github/callback').query({
      code: 'valid_gh_code',
      state: validState,
    });
    expect(replayStateRes.status).toBe(400);
    expect(replayStateRes.body.error.code).toBe('INVALID_OAUTH_STATE');
  });

  it('enforces RBAC on /api/v1/clients, confidential client secret rotation, and revokes all sessions on password change', async () => {
    // Standard non-admin user cannot register OAuth clients
    const stdUserRes = await request(app).post('/api/v1/auth/register').send({
      email: 'member@example.com',
      username: 'stdmember',
      password: 'StrongPassword123',
      name: 'Standard Member',
    });
    const stdToken = stdUserRes.body.data.accessToken as string;
    const stdRefreshCookie = extractCookieValue(
      stdUserRes.headers['set-cookie'] as unknown as string[],
      'idp_refresh_token',
    )!;

    const forbiddenClientRes = await request(app)
      .post('/api/v1/clients')
      .set('Authorization', `Bearer ${stdToken}`)
      .send({
        name: 'Unauthorized App',
        applicationType: 'spa',
        redirectUris: ['http://localhost:3000/cb'],
      });
    expect(forbiddenClientRes.status).toBe(403);

    // Admin registers a confidential backend web client and rotates its secret
    const adminRes = await request(app).post('/api/v1/auth/register').send({
      email: 'admin@shoaib.dev',
      username: 'superadmin',
      password: 'StrongPassword123',
      name: 'Super Admin',
    });
    const adminToken = adminRes.body.data.accessToken as string;

    const confClientRes = await request(app)
      .post('/api/v1/clients')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: 'Backend Order Microservice',
        applicationType: 'web',
        redirectUris: ['https://orders.shoaib.dev/oauth/callback'],
      });

    expect(confClientRes.status).toBe(201);
    expect(confClientRes.body.data.client.isConfidential).toBe(true);
    expect(confClientRes.body.data.clientSecret).toMatch(/^cs_/);

    const rotateRes = await request(app)
      .post(`/api/v1/clients/${confClientRes.body.data.client.clientId}/rotate-secret`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(rotateRes.status).toBe(200);
    expect(rotateRes.body.data.clientSecret).toMatch(/^cs_/);
    expect(rotateRes.body.data.clientSecret).not.toBe(
      confClientRes.body.data.clientSecret,
    );

    // Standard user changes password -> existing refresh token family is immediately invalidated
    const pwChangeRes = await request(app)
      .post('/api/v1/users/me/password')
      .set('Authorization', `Bearer ${stdToken}`)
      .send({
        currentPassword: 'StrongPassword123',
        newPassword: 'EvenStrongerPassword456',
      });
    expect(pwChangeRes.status).toBe(200);

    const oldSessionRefresh = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', [`idp_refresh_token=${stdRefreshCookie}`]);
    expect(oldSessionRefresh.status).toBe(401);
  });
});
