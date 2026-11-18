function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Verify your unique identity across connected applications',
  profile: 'Read your basic profile details (name, username, avatar)',
  email: 'Read your primary email address and verification status',
  offline_access: 'Maintain signed-in session using rotating HttpOnly refresh tokens',
};

export function renderSsoLoginHtml(params: {
  authReqId: string;
  clientName: string;
}): string {
  const safeClientName = escapeHtml(params.clientName);
  const safeAuthReqId = escapeHtml(params.authReqId);
  const encodedAuthReqId = encodeURIComponent(params.authReqId);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Sign In — Centralized SSO Identity Provider</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0a0a0a;
      color: #f4f4f5;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .card {
      width: 100%;
      max-width: 400px;
      background: #141417;
      border: 1px solid #27272a;
      border-radius: 12px;
      padding: 32px;
    }
    .badge {
      display: inline-block;
      font-size: 11px;
      font-family: monospace;
      color: #a1a1aa;
      background: #1f1f23;
      border: 1px solid #27272a;
      padding: 4px 8px;
      border-radius: 6px;
      margin-bottom: 16px;
    }
    h1 { font-size: 20px; font-weight: 600; margin-bottom: 8px; }
    p.sub { font-size: 14px; color: #a1a1aa; margin-bottom: 24px; line-height: 1.5; }
    label { display: block; font-size: 13px; color: #d4d4d8; margin-bottom: 6px; }
    input {
      width: 100%;
      padding: 10px 12px;
      background: #0a0a0a;
      border: 1px solid #27272a;
      border-radius: 8px;
      color: #f4f4f5;
      font-size: 14px;
      margin-bottom: 16px;
    }
    input:focus { outline: none; border-color: #52525b; }
    button.primary {
      width: 100%;
      padding: 10px 16px;
      background: #f4f4f5;
      color: #09090b;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
    }
    .divider {
      text-align: center;
      font-size: 12px;
      color: #71717a;
      margin: 20px 0;
    }
    .social-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    a.social-btn {
      text-align: center;
      text-decoration: none;
      padding: 9px 12px;
      background: #18181b;
      border: 1px solid #27272a;
      border-radius: 8px;
      color: #e4e4e7;
      font-size: 13px;
      font-weight: 500;
    }
  </style>
</head>
<body>
  <main class="card">
    <span class="badge">OAUTH 2.1 + PKCE SSO</span>
    <h1>Sign in to continue</h1>
    <p class="sub">Authenticating for <strong>${safeClientName}</strong></p>
    <form method="POST" action="/api/v1/auth/login">
      <input type="hidden" name="authReqId" value="${safeAuthReqId}" />
      <label for="identifier">Email or Username</label>
      <input id="identifier" name="identifier" type="text" required autocomplete="username" />
      <label for="password">Password</label>
      <input id="password" name="password" type="password" required autocomplete="current-password" />
      <button type="submit" class="primary">Continue</button>
    </form>
    <div class="divider">or continue with</div>
    <div class="social-grid">
      <a class="social-btn" href="/api/v1/auth/google?auth_req_id=${encodedAuthReqId}">Google</a>
      <a class="social-btn" href="/api/v1/auth/github?auth_req_id=${encodedAuthReqId}">GitHub</a>
    </div>
  </main>
</body>
</html>`;
}

export function renderConsentScreenHtml(params: {
  authReqId: string;
  clientName: string;
  userEmail: string;
  scopes: string[];
}): string {
  const safeClientName = escapeHtml(params.clientName);
  const safeUserEmail = escapeHtml(params.userEmail);
  const safeAuthReqId = escapeHtml(params.authReqId);

  const scopeItems = params.scopes
    .map((scope) => {
      const desc =
        SCOPE_DESCRIPTIONS[scope] ?? `Access permission scope: ${scope}`;
      return `<li><code>${escapeHtml(scope)}</code><span>${escapeHtml(desc)}</span></li>`;
    })
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Authorize Application — Centralized SSO</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0a0a0a;
      color: #f4f4f5;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .card {
      width: 100%;
      max-width: 440px;
      background: #141417;
      border: 1px solid #27272a;
      border-radius: 12px;
      padding: 32px;
    }
    h1 { font-size: 20px; font-weight: 600; margin-bottom: 6px; }
    p.sub { font-size: 13px; color: #a1a1aa; margin-bottom: 20px; }
    ul { list-style: none; border-top: 1px solid #27272a; margin-bottom: 24px; }
    li {
      padding: 12px 0;
      border-bottom: 1px solid #27272a;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    code { font-size: 12px; color: #e4e4e7; font-weight: 600; }
    li span { font-size: 13px; color: #a1a1aa; }
    .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    button {
      padding: 10px 16px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
    }
    button.deny { background: transparent; border: 1px solid #3f3f46; color: #d4d4d8; }
    button.approve { background: #f4f4f5; border: none; color: #09090b; }
  </style>
</head>
<body>
  <main class="card">
    <h1>Authorize ${safeClientName}</h1>
    <p class="sub">Signed in as <strong>${safeUserEmail}</strong>. This application requests the following permissions:</p>
    <ul>${scopeItems}</ul>
    <form method="POST" action="/oauth/authorize/decision" class="actions">
      <input type="hidden" name="auth_req_id" value="${safeAuthReqId}" />
      <button type="submit" name="decision" value="deny" class="deny">Deny</button>
      <button type="submit" name="decision" value="approve" class="approve">Authorize</button>
    </form>
  </main>
</body>
</html>`;
}
