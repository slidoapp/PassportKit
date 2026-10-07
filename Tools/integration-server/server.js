// Local OAuth 2.0 authorization server for PassportKit integration tests. See README.md.
import http from 'node:http';
import Provider, { errors } from 'oidc-provider';
import MemoryAdapter, { resetAdapters } from './memory-adapter.js';
import { approveDevice } from './device-approval.js';

const port = Number(process.env.PORT ?? 9400);
const issuer = process.env.ISSUER ?? `http://localhost:${port}`;
const seconds = (name, fallback) => Number(process.env[name] ?? fallback);
const accessTokenTtl = seconds('ACCESS_TOKEN_TTL', 600);
const resourcePrefix = 'https://api.example.com/';
const accountId = 'test-user';
const tokenExchangeGrant = 'urn:ietf:params:oauth:grant-type:token-exchange';
const tokenTypes = {
  accessToken: 'urn:ietf:params:oauth:token-type:access_token',
  refreshToken: 'urn:ietf:params:oauth:token-type:refresh_token',
};
const isDenied = (resource) => resource.includes('/denied/');

const nativeDefaults = { application_type: 'native', token_endpoint_auth_method: 'none' };
const clients = [
  {
    ...nativeDefaults,
    client_id: 'public-native',
    grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code', tokenExchangeGrant],
    response_types: ['code'],
    // Loopback redirects ignore the port (RFC 8252 section 7.3) natively in oidc-provider.
    redirect_uris: ['http://127.0.0.1/callback', 'com.example.app:/callback'],
  },
  {
    ...nativeDefaults,
    client_id: 'audience-client',
    grant_types: ['refresh_token'],
    response_types: [],
  },
  {
    client_id: 'confidential-service',
    client_secret: 'integration-secret',
    token_endpoint_auth_method: 'client_secret_basic',
    grant_types: ['client_credentials'],
    response_types: [],
  },
];

const configuration = {
  adapter: MemoryAdapter,
  clients,
  scopes: ['openid', 'offline_access', 'profile', 'email', 'api:read', 'api:write'],
  claims: { profile: ['name'], email: ['email', 'email_verified'] },
  cookies: { keys: ['passportkit-integration-key'] },
  clientAuthMethods: ['none', 'client_secret_basic', 'client_secret_post'],
  pkce: { required: () => true, methods: ['S256'] },
  rotateRefreshToken: true,
  ttl: {
    AccessToken: accessTokenTtl,
    ClientCredentials: accessTokenTtl,
    RefreshToken: seconds('REFRESH_TOKEN_TTL', 86400),
    AuthorizationCode: seconds('AUTHORIZATION_CODE_TTL', 60),
    DeviceCode: seconds('DEVICE_CODE_TTL', 600),
    Grant: 86400,
    Interaction: 600,
    Session: 86400,
  },
  interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
  findAccount: async (_ctx, id) => ({
    accountId: id,
    claims: async () => ({ sub: id, name: 'Test User', email: 'test-user@example.com', email_verified: true }),
  }),
  features: {
    devInteractions: { enabled: false },
    deviceFlow: { enabled: true },
    revocation: { enabled: true },
    introspection: { enabled: false },
    clientCredentials: { enabled: true },
    resourceIndicators: {
      enabled: true,
      defaultResource: async () => undefined,
      getResourceServerInfo: async (ctx, resource) => {
        if (!resource.startsWith(resourcePrefix)) throw new errors.InvalidTarget();
        // Simulated "underscoped 200": on refresh, a /denied/ resource gets a token without resource scopes.
        const narrowed = isDenied(resource) && ctx.oidc.route === 'token' && ctx.oidc.params.grant_type === 'refresh_token';
        return {
          scope: narrowed ? 'api:none' : 'api:read api:write',
          audience: resource,
          accessTokenTTL: accessTokenTtl,
          accessTokenFormat: 'opaque',
        };
      },
    },
  },
};

const provider = new Provider(issuer, configuration);

const need = (condition, error) => {
  if (!condition) throw error;
};

async function revokeGrant(grantId) {
  await Promise.all([
    provider.AccessToken.revokeByGrantId(grantId),
    provider.RefreshToken.revokeByGrantId(grantId),
    provider.Grant.adapter.destroy(grantId),
  ]);
}

function responseFor({ token, issuedTokenType, refreshToken, scope }) {
  return {
    access_token: token.value,
    issued_token_type: issuedTokenType,
    token_type: issuedTokenType === tokenTypes.accessToken ? 'Bearer' : 'N_A',
    expires_in: token.expiration,
    ...(refreshToken ? { refresh_token: refreshToken } : {}),
    ...(scope ? { scope } : {}),
  };
}

async function exchangeAccessToken(ctx) {
  const { subject_token: value, resource, scope: requestedScope } = ctx.oidc.params;
  const client = ctx.oidc.client;
  const subject = await provider.AccessToken.find(value);
  need(subject && subject.clientId === client.clientId, new errors.InvalidGrant('subject token invalid'));
  need(resource, new errors.InvalidRequest('resource is required for access token subjects'));
  if (isDenied(resource)) {
    ctx.status = 401;
    ctx.body = { error: 'access_denied' };
    return;
  }
  const info = await configuration.features.resourceIndicators.getResourceServerInfo(ctx, resource);
  const allowed = new Set(info.scope.split(' '));
  const wanted = (requestedScope ?? subject.scope ?? '').split(' ').filter(Boolean);
  const scope = wanted.filter((entry) => allowed.has(entry)).join(' ');
  const token = new provider.AccessToken({
    accountId: subject.accountId,
    client,
    grantId: subject.grantId,
    gty: 'token-exchange',
    scope: scope || undefined,
    sessionUid: subject.sessionUid,
    sid: subject.sid,
  });
  token.resourceServer = new provider.ResourceServer(resource, info);
  token.value = await token.save();
  ctx.body = responseFor({ token, issuedTokenType: tokenTypes.accessToken, scope });
}

async function exchangeRefreshToken(ctx) {
  const { subject_token: value, audience } = ctx.oidc.params;
  const client = ctx.oidc.client;
  const subject = await provider.RefreshToken.find(value, { ignoreExpiration: true });
  need(subject && subject.clientId === client.clientId, new errors.InvalidGrant('subject token invalid'));
  need(!subject.isExpired, new errors.InvalidGrant('subject token expired'));
  if (subject.consumed) {
    await revokeGrant(subject.grantId);
    throw new errors.InvalidGrant('refresh token already used');
  }
  const target = audience ? await provider.Client.find(audience) : undefined;
  need(!audience || target, new errors.InvalidTarget('unknown audience'));

  // Rotate the subject refresh token exactly like the refresh_token grant does.
  await subject.consume();
  const rotated = new provider.RefreshToken({
    accountId: subject.accountId,
    acr: subject.acr,
    amr: subject.amr,
    authTime: subject.authTime,
    claims: subject.claims,
    client,
    expiresWithSession: subject.expiresWithSession,
    iiat: subject.iiat,
    grantId: subject.grantId,
    gty: subject.gty,
    nonce: subject.nonce,
    resource: subject.resource,
    rotations: (subject.rotations ?? 0) + 1,
    scope: subject.scope,
    sessionUid: subject.sessionUid,
    sid: subject.sid,
  });
  const rotatedValue = await rotated.save();
  if (!target) {
    // No audience: behave like a refresh of the same client, but as a token exchange response.
    const token = new provider.AccessToken({ accountId: subject.accountId, client, grantId: subject.grantId, gty: 'token-exchange', scope: subject.scope, sessionUid: subject.sessionUid, sid: subject.sid });
    token.value = await token.save();
    ctx.body = responseFor({ token, issuedTokenType: tokenTypes.accessToken, refreshToken: rotatedValue, scope: subject.scope });
    return;
  }

  const grant = new provider.Grant({ accountId: subject.accountId, clientId: target.clientId });
  grant.addOIDCScope(subject.scope.split(' ').filter((entry) => !entry.startsWith('api:')).join(' '));
  const grantId = await grant.save();
  const issued = new provider.RefreshToken({
    accountId: subject.accountId,
    authTime: subject.authTime,
    client: target,
    grantId,
    gty: 'token-exchange',
    rotations: 0,
    scope: grant.getOIDCScope(),
    sessionUid: subject.sessionUid,
    sid: subject.sid,
  });
  const issuedValue = await issued.save();
  ctx.body = responseFor({
    token: { value: issuedValue, expiration: issued.expiration },
    issuedTokenType: tokenTypes.refreshToken,
    refreshToken: rotatedValue,
    scope: issued.scope,
  });
}

provider.registerGrantType(
  tokenExchangeGrant,
  async (ctx) => {
    const { subject_token_type: type } = ctx.oidc.params;
    if (type === tokenTypes.accessToken) return exchangeAccessToken(ctx);
    if (type === tokenTypes.refreshToken) return exchangeRefreshToken(ctx);
    throw new errors.InvalidRequest('unsupported subject_token_type');
  },
  ['subject_token', 'subject_token_type', 'requested_token_type', 'audience', 'resource', 'scope'],
);

async function autoInteraction(ctx) {
  const details = await provider.interactionDetails(ctx.req, ctx.res);
  const { prompt, params, session, grantId } = details;
  const result = {};
  if (prompt.name === 'login') {
    result.login = { accountId };
  } else {
    const grant = grantId
      ? await provider.Grant.find(grantId)
      : new provider.Grant({ accountId: session.accountId, clientId: params.client_id });
    const { missingOIDCScope, missingOIDCClaims, missingResourceScopes } = prompt.details;
    if (missingOIDCScope) grant.addOIDCScope(missingOIDCScope.join(' '));
    if (missingOIDCClaims) grant.addOIDCClaims(missingOIDCClaims);
    for (const [indicator, scopes] of Object.entries(missingResourceScopes ?? {})) {
      grant.addResourceScope(indicator, scopes.join(' '));
    }
    result.consent = { grantId: await grant.save() };
  }
  ctx.redirect(await provider.interactionResult(ctx.req, ctx.res, result, { mergeWithLastSubmission: true }));
}

async function readJson(ctx) {
  const chunks = [];
  for await (const chunk of ctx.req) chunks.push(chunk);
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
}

async function handleTestRoute(ctx) {
  if (ctx.method !== 'POST') return false;
  if (ctx.path === '/test/reset') {
    resetAdapters();
    ctx.body = { ok: true };
  } else if (ctx.path === '/test/device/approve' || ctx.path === '/test/device/deny') {
    const { user_code: userCode } = await readJson(ctx);
    need(userCode, new errors.InvalidRequest('user_code required'));
    const outcome = await approveDevice({ issuer, userCode, decision: ctx.path.endsWith('approve') ? 'approve' : 'deny' });
    ctx.status = outcome.ok ? 200 : 400;
    ctx.body = outcome;
  } else {
    return false;
  }
  return true;
}

provider.use(async (ctx, next) => {
  // Logs method, path and status only: queries and bodies carry codes and tokens.
  const logRequest = () => console.log(`${ctx.method} ${ctx.path} ${ctx.status}`);
  try {
    if (ctx.path === '/.well-known/oauth-authorization-server') {
      ctx.path = '/.well-known/openid-configuration'; // RFC 8414 alias, same document
      ctx.state.originalPath = '/.well-known/oauth-authorization-server';
    } else if (ctx.method === 'GET' && ctx.path.startsWith('/interaction/')) {
      await autoInteraction(ctx);
      return;
    } else if (ctx.path.startsWith('/test/') && await handleTestRoute(ctx)) {
      return;
    }
    await next();
  } catch (error) {
    ctx.status = error.statusCode ?? error.status ?? 500;
    ctx.body = { error: error.error ?? 'server_error', error_description: error.error_description ?? error.message };
  } finally {
    logRequest();
  }
});

http.createServer(provider.callback()).listen(port, '127.0.0.1', () => {
  console.log(`integration server listening on ${issuer}`);
});
