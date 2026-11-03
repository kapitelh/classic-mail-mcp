import { OAuthProxy, OAuthProxyError, type AuthorizationParams } from 'fastmcp/auth';
import type { FastMCP } from 'fastmcp';
import type { IncomingMessage } from 'node:http';
import type { Database } from './store.js';
import type { Secrets } from './config.js';
import { FirestoreTokenStore, rateLimit } from './store.js';
import { createHash } from 'node:crypto';
import { SignJWT, jwtVerify, decodeJwt } from 'jose';

export type Session = { email: string; sub: string };
export const SCOPES = ['openid', 'email'];
export const CHATGPT_CALLBACK = 'https://chatgpt.com/connector_platform_oauth_redirect';

/** Native Codex returns to a temporary loopback listener, never an arbitrary web host. */
export function isAllowedCallback(uri: unknown): uri is string {
  if (uri === CHATGPT_CALLBACK) return true;
  if (typeof uri !== 'string') return false;
  const match =
    /^http:\/\/(?:127\.0\.0\.1|localhost):([1-9]\d{0,4})\/callback(?:\/[A-Za-z0-9_-]{1,128})?$/.exec(
      uri,
    );
  return Boolean(match && Number(match[1]) <= 65535);
}

export function createProxy(baseUrl: string, secrets: Secrets, db: Database) {
  return new OAuthProxy({
    baseUrl,
    upstreamAuthorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    upstreamTokenEndpoint: 'https://oauth2.googleapis.com/token',
    upstreamClientId: secrets.googleClientId,
    upstreamClientSecret: secrets.googleClientSecret,
    upstreamTokenEndpointAuthMethod: 'client_secret_post',
    // Generate an independent upstream challenge/verifier pair. In FastMCP,
    // forwardPkce:true omits the Google challenge but still sends a verifier.
    forwardPkce: false,
    allowPlainPkce: false,
    consentRequired: true,
    authorizationResponseIss: true,
    enableCimd: false,
    // Globs only support transport matching. Routes below enforce the exact native shape
    // before registration/authorization; registered redirect URIs remain exact-match bound.
    allowedRedirectUriPatterns: [
      CHATGPT_CALLBACK,
      'http://127.0.0.1:*/callback*',
      'http://localhost:*/callback*',
    ],
    extraAuthorizationParams: { access_type: 'offline', prompt: 'consent' },
    accessTokenTtl: 900,
    refreshTokenTtl: 7 * 24 * 3600,
    authorizationCodeTtl: 120,
    jwtSigningKey: secrets.jwtSigningKey,
    encryptionKey: secrets.encryptionKey,
    consentSigningKey: secrets.consentSigningKey,
    customClaimsPassthrough: false,
    tokenStorage: new FirestoreTokenStore(db),
    scopes: SCOPES,
  });
}

export function allowIdentity(identity: unknown, allowedEmails: string[]): Session {
  const u = identity as { email?: unknown; email_verified?: unknown; sub?: unknown };
  if (
    !u ||
    u.email_verified !== true ||
    typeof u.email !== 'string' ||
    typeof u.sub !== 'string' ||
    !allowedEmails.map((x) => x.toLowerCase()).includes(u.email.toLowerCase())
  )
    throw new Error('Access denied');
  return { email: u.email.toLowerCase(), sub: u.sub };
}

export function authenticate(proxy: OAuthProxy, secrets: Secrets, db: Database, baseUrl: string) {
  return async (req: IncomingMessage): Promise<Session | undefined> => {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ') || header.length > 16000) return undefined;
    let stage = 'token_verification';
    const denied = () => {
      console.info(JSON.stringify({ event: 'mcp_auth_rejected', stage }));
      return undefined;
    };
    try {
      const { payload } = await jwtVerify(
        header.slice(7),
        new TextEncoder().encode(secrets.jwtSigningKey),
        {
          algorithms: ['HS256'],
          issuer: baseUrl,
          audience: baseUrl,
          requiredClaims: ['exp', 'iat', 'jti', 'scope', 'token_use'],
        },
      );
      if (payload.token_use !== 'access') return denied();
      // FastMCP JWTs use arrays; other compatible issuers use space-separated strings.
      // Google may return the canonical userinfo.email URL for the requested email scope.
      stage = 'identity_scopes';
      const scopes = typeof payload.scope === 'string' ? payload.scope.split(/\s+/) : payload.scope;
      if (!Array.isArray(scopes) || !scopes.every((s) => typeof s === 'string')) return denied();
      const identityScopes = new Set(
        scopes.map((s) => (s === 'https://www.googleapis.com/auth/userinfo.email' ? 'email' : s)),
      );
      if (!SCOPES.every((s) => identityScopes.has(s))) return denied();
      stage = 'token_kind';
      if (!(await new FirestoreTokenStore(db).get('issued-access:' + header.slice(7))))
        return denied();
      stage = 'token_mapping';
      const tokens = await proxy.loadUpstreamTokens(header.slice(7));
      if (!tokens) return denied();
      // Google userinfo validates the upstream token. Never trust decoded, unverified ID-token claims.
      stage = 'google_identity';
      const response = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
        headers: { Authorization: `Bearer ${tokens.accessToken}` },
        signal: AbortSignal.timeout(8000),
        redirect: 'error',
      });
      if (!response.ok) return denied();
      stage = 'owner_allowlist';
      const session = allowIdentity(await response.json(), secrets.allowedEmails);
      stage = 'rate_limit';
      await rateLimit(db, session.sub, 'mcp', 120, 60);
      return session;
    } catch {
      return denied();
    }
  };
}

export function validateOAuthRequest(params: URLSearchParams, baseUrl: string, authorize: boolean) {
  if (
    authorize &&
    (params.getAll('redirect_uri').length !== 1 || !isAllowedCallback(params.get('redirect_uri')))
  )
    throw new OAuthProxyError(
      'invalid_redirect_uri',
      'Use the ChatGPT callback or a native loopback callback',
    );
  const resources = params.getAll('resource');
  if (resources.some((x) => x !== baseUrl) || resources.length > 1)
    throw new OAuthProxyError('invalid_target', 'Resource does not match this server');
  const scope = params.get('scope');
  if (scope && scope.split(' ').some((s) => !SCOPES.includes(s)))
    throw new OAuthProxyError('invalid_scope', 'Unsupported scope');
  if (
    authorize &&
    (params.get('code_challenge_method') !== 'S256' ||
      !/^[A-Za-z0-9_-]{43}$/.test(params.get('code_challenge') ?? ''))
  )
    throw new OAuthProxyError('invalid_request', 'S256 PKCE is required');
}

/** Reject ambiguous credentials before any authorization code or token is consumed. */
export function tokenCredentials(params: URLSearchParams, authorization?: string) {
  for (const name of [
    'client_id',
    'client_secret',
    'grant_type',
    'code',
    'code_verifier',
    'refresh_token',
    'redirect_uri',
    'scope',
  ]) {
    if (params.getAll(name).length > 1)
      throw new OAuthProxyError('invalid_request', 'Duplicate OAuth parameter');
  }
  let client_id = params.get('client_id') ?? '';
  let client_secret = params.get('client_secret') ?? undefined;
  if (authorization !== undefined) {
    if (params.has('client_id') || params.has('client_secret'))
      throw new OAuthProxyError('invalid_request', 'Use one client authentication method');
    const match = /^Basic ([A-Za-z0-9+/]+={0,2})$/i.exec(authorization);
    if (!match) throw new OAuthProxyError('invalid_client', 'Invalid client authentication');
    try {
      const decoded = new TextDecoder('utf-8', { fatal: true }).decode(
        Buffer.from(match[1], 'base64'),
      );
      const separator = decoded.indexOf(':');
      if (separator < 1) throw Error();
      client_id = decodeURIComponent(decoded.slice(0, separator).replace(/\+/g, ' '));
      client_secret = decodeURIComponent(decoded.slice(separator + 1).replace(/\+/g, ' '));
    } catch {
      throw new OAuthProxyError('invalid_client', 'Invalid client authentication');
    }
  }
  if (!client_id) throw new OAuthProxyError('invalid_client', 'Client ID is required');
  return { client_id, client_secret };
}

/** Use the library's OAuth implementation, preserving cookies and HTTP headers through Cloud Run. */
export function authRoutes(
  server: FastMCP<Session>,
  proxy: OAuthProxy,
  baseUrl: string,
  db: Database,
  consentKey: string,
  accessMode: 'read-only' | 'read-write' = 'read-write',
) {
  const app = server.getApp();
  app.onError((e, c) =>
    c.json(e instanceof OAuthProxyError ? e.toJSON() : { error: 'server_error' }, 400),
  );
  const signingKey = new TextEncoder().encode(consentKey);
  const codeBindings = new FirestoreTokenStore(db);
  const cookieName = '__Host-classic_mail_oauth';
  async function rememberTokens(
    tokens: { access_token: string; refresh_token?: string },
    clientId: string,
  ) {
    for (const [kind, token] of [
      ['access', tokens.access_token],
      ['refresh', tokens.refresh_token],
    ]) {
      if (!token) continue;
      const payload = decodeJwt(token),
        ttl = Number(payload.exp) - Math.floor(Date.now() / 1000);
      if (!Number.isFinite(ttl) || ttl <= 0)
        throw new OAuthProxyError('server_error', 'Invalid token expiration');
      await codeBindings.save('issued-' + kind + ':' + token, { clientId }, ttl);
    }
  }
  async function binding(req: Request, transaction: string | null) {
    const cookie = req.headers
      .get('cookie')
      ?.split(';')
      .map((x) => x.trim())
      .find((x) => x.startsWith(cookieName + '='))
      ?.slice(cookieName.length + 1);
    if (!cookie || !transaction)
      throw new OAuthProxyError('invalid_request', 'Restart sign-in in this browser');
    try {
      const { payload } = await jwtVerify(cookie, signingKey, {
        algorithms: ['HS256'],
        issuer: baseUrl,
        audience: 'oauth-browser',
      });
      if (payload.transaction !== transaction) throw new Error('Mismatch');
      return payload;
    } catch {
      throw new OAuthProxyError('invalid_request', 'Browser binding mismatch; restart sign-in');
    }
  }
  app.use('/oauth/*', async (c, next) => {
    c.header('Cache-Control', 'no-store');
    c.header('Pragma', 'no-cache');
    c.header('Referrer-Policy', 'same-origin');
    c.header('X-Content-Type-Options', 'nosniff');
    try {
      await next();
    } catch (e) {
      return c.json(e instanceof OAuthProxyError ? e.toJSON() : { error: 'server_error' }, 400);
    }
  });
  app.post('/oauth/register', async (c) => {
    await rateLimit(db, 'public', 'dcr', 20, 3600);
    const body = await c.req.json();
    if (
      !Array.isArray(body.redirect_uris) ||
      body.redirect_uris.length < 1 ||
      body.redirect_uris.length > 5 ||
      !body.redirect_uris.every(isAllowedCallback)
    )
      return c.json(
        {
          error: 'invalid_redirect_uri',
          error_description: 'Use the ChatGPT callback or a native loopback callback',
        },
        400,
      );
    // No caller-controlled remote logos/links on the consent page.
    const request = {
      redirect_uris: body.redirect_uris,
      client_name: 'Classic Mail MCP',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: body.token_endpoint_auth_method ?? 'none',
      scope: SCOPES.join(' '),
    };
    if (
      !['none', 'client_secret_post', 'client_secret_basic'].includes(
        request.token_endpoint_auth_method,
      )
    )
      return c.json({ error: 'invalid_client_metadata' }, 400);
    return c.json(await proxy.registerClient(request), 201);
  });
  app.get('/oauth/authorize', async (c) => {
    const params = new URL(c.req.url).searchParams;
    validateOAuthRequest(params, baseUrl, true);
    await rateLimit(db, 'public', 'authorize', 100, 3600);
    const response = await proxy.authorize(
      Object.fromEntries(params) as unknown as AuthorizationParams,
    );
    const body = await response.text();
    const transaction = body.match(/name="transaction_id" value="([^"]+)"/)?.[1];
    if (!transaction) throw new OAuthProxyError('server_error', 'Consent transaction missing');
    const cookie = await new SignJWT({
      transaction,
      redirectUri: params.get('redirect_uri'),
      clientId: params.get('client_id'),
      challenge: params.get('code_challenge'),
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(baseUrl)
      .setAudience('oauth-browser')
      .setIssuedAt()
      .setExpirationTime('10m')
      .sign(signingKey);
    const headers = new Headers(response.headers);
    headers.set('Referrer-Policy', 'same-origin');
    headers.set(
      'Set-Cookie',
      `${cookieName}=${cookie}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
    );
    // Make the actual mail permissions explicit; identity scopes alone do not describe tool powers.
    const permissions =
      accessMode === 'read-write'
        ? 'Read mail and attachments, send replies and forwards, manage drafts and folders, and delete messages when you explicitly authorize the action.'
        : 'Read mail and attachments and check connections. Sending, deletion and other write tools are disabled.';
    const consent = body.replace(
      '<h3>This will allow the app to:</h3>',
      '<h3>Access to all configured mailboxes</h3><p>' +
        permissions +
        ' This instance belongs to one operator. Continue only if you trust this client.</p><h3>Google sign-in permissions:</h3>',
    );
    return new Response(consent, { status: response.status, headers });
  });
  app.get('/oauth/callback', async (c) => {
    const bound = await binding(c.req.raw, new URL(c.req.url).searchParams.get('state'));
    const response = await proxy.handleCallback(c.req.raw);
    const location = response.headers.get('location');
    if (location) {
      const callback = new URL(location),
        code = callback.searchParams.get('code');
      if (code) {
        if (
          callback.origin + callback.pathname !== bound.redirectUri ||
          !isAllowedCallback(bound.redirectUri)
        )
          throw new OAuthProxyError('invalid_grant', 'Callback binding mismatch');
        // Extra binding is needed because the library does not check redirect_uri at exchange.
        // Only non-secret metadata is stored here; the document key hashes the authorization code.
        await codeBindings.save(
          'callback-binding:' + code,
          { redirectUri: bound.redirectUri, clientId: bound.clientId, challenge: bound.challenge },
          120,
        );
      }
    }
    response.headers.set(
      'Set-Cookie',
      `${cookieName}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    );
    return response;
  });
  app.post('/oauth/consent', async (c) => {
    if (c.req.header('origin') !== baseUrl)
      throw new OAuthProxyError('invalid_request', 'Invalid consent origin');
    const form = await c.req.raw.clone().formData();
    await binding(c.req.raw, form.get('transaction_id') as string | null);
    return proxy.handleConsent(c.req.raw);
  });
  app.post('/oauth/token', async (c) => {
    const params = new URLSearchParams(await c.req.text());
    validateOAuthRequest(params, baseUrl, false);
    const { client_id, client_secret } = tokenCredentials(params, c.req.header('authorization'));
    const grant = params.get('grant_type');
    if (grant === 'authorization_code') {
      const code = params.get('code') ?? '',
        verifier = params.get('code_verifier') ?? '';
      const bound = (await codeBindings.get('callback-binding:' + code)) as {
        redirectUri: string;
        clientId: string;
        challenge: string;
      } | null;
      if (
        !bound ||
        bound.clientId !== client_id ||
        params.getAll('redirect_uri').length !== 1 ||
        bound.redirectUri !== params.get('redirect_uri') ||
        !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) ||
        createHash('sha256').update(verifier).digest('base64url') !== bound.challenge
      )
        throw new OAuthProxyError('invalid_grant', 'Authorization code binding or PKCE mismatch');
      const tokens = await proxy.exchangeAuthorizationCode({
        client_id,
        client_secret,
        grant_type: grant,
        code,
        redirect_uri: bound.redirectUri,
        code_verifier: verifier,
      });
      await rememberTokens(tokens, client_id);
      await codeBindings.delete('callback-binding:' + code);
      return c.json(tokens);
    }
    if (grant === 'refresh_token') {
      const token = params.get('refresh_token') ?? '';
      const record = (await codeBindings.get('issued-refresh:' + token)) as {
        clientId: string;
      } | null;
      if (!record || record.clientId !== client_id)
        throw new OAuthProxyError('invalid_grant', 'Refresh token binding mismatch');
      // The library atomically consumes its mapping, so concurrent replays cannot both succeed.
      const tokens = await proxy.exchangeRefreshToken({
        client_id,
        client_secret,
        grant_type: grant,
        refresh_token: token,
        scope: params.get('scope') ?? undefined,
      });
      await rememberTokens(tokens, client_id);
      await codeBindings.delete('issued-refresh:' + token);
      return c.json(tokens);
    }
    return c.json({ error: 'unsupported_grant_type' }, 400);
  });
}
