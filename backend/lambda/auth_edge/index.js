'use strict';

const https = require('https');
const crypto = require('crypto');

const REGION = 'us-east-1';
const USER_POOL_ID = 'us-east-1_b2D0V3E1k';
const CLIENT_ID = '6q607dk3liirhtecgps7hifmlk';
const COGNITO_DOMAIN = 'https://enceladus-status-356364570033.auth.us-east-1.amazoncognito.com';
const REDIRECT_URI = 'https://jreese.net/enceladus/callback';
const COOKIE_NAME = 'enceladus_id_token';
const SCOPE = 'openid email profile';

const ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;
const JWKS_URL = `${ISSUER}/.well-known/jwks.json`;

let jwksCache = null;
let jwksFetchedAt = 0;
const JWKS_TTL_MS = 60 * 60 * 1000;

function parseCookies(headers) {
  const cookieHeader = headers.cookie && headers.cookie[0] && headers.cookie[0].value;
  if (!cookieHeader) return {};
  const out = {};
  cookieHeader.split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i > 0) {
      const key = part.slice(0, i).trim();
      const val = part.slice(i + 1).trim();
      out[key] = decodeURIComponent(val);
    }
  });
  return out;
}

function b64urlToBuffer(input) {
  const pad = '='.repeat((4 - (input.length % 4)) % 4);
  const base64 = (input + pad).replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(base64, 'base64');
}

function b64urlDecodeJson(input) {
  return JSON.parse(b64urlToBuffer(input).toString('utf8'));
}

function httpsRequest(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function getJwks() {
  if (jwksCache && Date.now() - jwksFetchedAt < JWKS_TTL_MS) {
    return jwksCache;
  }
  const url = new URL(JWKS_URL);
  const res = await httpsRequest({ hostname: url.hostname, path: url.pathname, method: 'GET' });
  if (res.statusCode !== 200) throw new Error(`JWKS fetch failed: ${res.statusCode}`);
  const parsed = JSON.parse(res.body);
  jwksCache = parsed.keys || [];
  jwksFetchedAt = Date.now();
  return jwksCache;
}

async function verifyIdToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT');

  const header = b64urlDecodeJson(parts[0]);
  const payload = b64urlDecodeJson(parts[1]);

  if (payload.iss !== ISSUER) throw new Error('Invalid issuer');
  if (payload.aud !== CLIENT_ID) throw new Error('Invalid audience');
  if (payload.token_use !== 'id') throw new Error('Invalid token use');
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');

  const jwks = await getJwks();
  const jwk = jwks.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('Signing key not found');

  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const signingInput = `${parts[0]}.${parts[1]}`;
  const signature = b64urlToBuffer(parts[2]);

  const ok = crypto.verify('RSA-SHA256', Buffer.from(signingInput), publicKey, signature);
  if (!ok) throw new Error('Invalid signature');

  return payload;
}

function isXhrRequest(headers) {
  // Detect fetch/XHR calls from the PWA so we return 401 JSON instead of
  // a 302 redirect (which fetch() silently follows and returns HTML, causing
  // JSON parse failures that blank the app).
  const accept = headers.accept && headers.accept[0] && headers.accept[0].value || '';
  const xrw = headers['x-requested-with'] && headers['x-requested-with'][0] && headers['x-requested-with'][0].value || '';
  const purpose = headers['purpose'] && headers['purpose'][0] && headers['purpose'][0].value || '';
  const secFetch = headers['sec-fetch-dest'] && headers['sec-fetch-dest'][0] && headers['sec-fetch-dest'][0].value || '';

  // sec-fetch-dest=empty is set by fetch() API calls (not navigations)
  if (secFetch === 'empty') return true;
  // Explicit XHR header
  if (xrw.toLowerCase() === 'xmlhttprequest') return true;
  // prefetch/preload hint
  if (purpose === 'prefetch') return true;
  // Accept header prefers JSON over HTML
  if (accept.includes('application/json') && !accept.includes('text/html')) return true;
  return false;
}

function redirectToLogin(request) {
  // For XHR/fetch calls, return 401 so the PWA can handle the error
  // instead of silently following the redirect to HTML.
  if (isXhrRequest(request.headers || {})) {
    return {
      status: '401',
      statusDescription: 'Unauthorized',
      headers: {
        'content-type': [{ key: 'Content-Type', value: 'application/json' }],
        'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
      },
      body: JSON.stringify({ error: 'unauthenticated' }),
    };
  }

  const originalUri = request.querystring ? `${request.uri}?${request.querystring}` : request.uri;
  const state = Buffer.from(originalUri, 'utf8').toString('base64url');

  const loginUrl =
    `${COGNITO_DOMAIN}/oauth2/authorize` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=${encodeURIComponent(SCOPE)}` +
    `&state=${encodeURIComponent(state)}`;

  return {
    status: '302',
    statusDescription: 'Found',
    headers: {
      location: [{ key: 'Location', value: loginUrl }],
      'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
    },
  };
}

function redirectToPath(path, idToken, refreshToken) {
  const cookies = [
    {
      key: 'Set-Cookie',
      // SameSite=None;Secure is required so the cookie is included on
      // cross-origin subresource fetch() calls (e.g. PWA fetching
      // /mobile/v1/*.json via JavaScript), which SameSite=Lax blocks.
      value: `${COOKIE_NAME}=${encodeURIComponent(idToken)}; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=3600`,
    },
    {
      key: 'Set-Cookie',
      // Session timestamp: non-HttpOnly so PWA JavaScript can read it for
      // the client-side 60-minute session timer. Path-scoped to /enceladus.
      value: `enceladus_session_at=${Date.now()}; Path=/enceladus; Secure; SameSite=None; Max-Age=3600`,
    },
  ];

  // Store refresh token if provided. Path=/ ensures the cookie is sent on
  // all requests to jreese.net, including POST /api/v1/auth/refresh (which
  // the PWA calls to silently refresh credentials). Previously Path was
  // /api/v1/auth, but the cookie was never reaching the auth-refresh Lambda
  // (DVP-ISS-015). HttpOnly + SameSite=None + Secure keeps it safe.
  if (refreshToken) {
    cookies.push({
      key: 'Set-Cookie',
      value: `enceladus_refresh_token=${encodeURIComponent(refreshToken)}; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=2592000`,
    });
  }

  return {
    status: '302',
    statusDescription: 'Found',
    headers: {
      location: [{ key: 'Location', value: path }],
      'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
      'set-cookie': cookies,
    },
  };
}

function normalizePostLoginTarget(target) {
  if (!target || !target.startsWith('/')) return '/enceladus/';
  if (target === '/enceladus') return '/enceladus/';
  if (target.startsWith('/enceladus/callback')) return '/enceladus/';
  return target;
}

function shouldRewriteToEnceladusIndex(uri) {
  if (!uri.startsWith('/enceladus')) return false;
  if (uri.startsWith('/enceladus/callback')) return false;
  if (uri === '/enceladus' || uri === '/enceladus/') return true;

  const suffix = uri.replace(/^\/enceladus\/?/, '');
  if (!suffix) return true;

  // Keep static asset and file requests untouched.
  return !suffix.includes('.');
}

async function handleCallback(request) {
  const params = new URLSearchParams(request.querystring || '');
  const code = params.get('code');
  const state = params.get('state');
  if (!code) return { status: '400', statusDescription: 'Bad Request', body: 'Missing code' };

  const tokenBody = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    code,
    redirect_uri: REDIRECT_URI,
  }).toString();

  const tokenUrl = new URL(`${COGNITO_DOMAIN}/oauth2/token`);
  const tokenRes = await httpsRequest(
    {
      hostname: tokenUrl.hostname,
      path: tokenUrl.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(tokenBody),
      },
    },
    tokenBody,
  );

  if (tokenRes.statusCode !== 200) {
    return { status: '401', statusDescription: 'Unauthorized', body: 'Token exchange failed' };
  }

  const tokenJson = JSON.parse(tokenRes.body);
  const idToken = tokenJson.id_token;
  const refreshToken = tokenJson.refresh_token || null;
  // Diagnostic logging for DVP-ISS-015 — confirm refresh_token presence
  console.log(`callback token exchange: id_token=${idToken ? 'present' : 'MISSING'}, refresh_token=${refreshToken ? 'present' : 'MISSING'}`);
  if (!idToken) return { status: '401', statusDescription: 'Unauthorized', body: 'Missing id_token' };

  await verifyIdToken(idToken);

  let target = '/enceladus/';
  if (state) {
    try {
      target = Buffer.from(state, 'base64url').toString('utf8');
    } catch (_e) {}
  }
  target = normalizePostLoginTarget(target);

  return redirectToPath(target, idToken, refreshToken);
}

exports.handler = async (event) => {
  try {
    const request = event.Records[0].cf.request;
    const uri = request.uri || '/';

    const protectedPath = uri.startsWith('/enceladus') || uri.startsWith('/mobile/v1');
    if (!protectedPath) return request;

    if (uri.startsWith('/enceladus/callback')) {
      return await handleCallback(request);
    }

    const cookies = parseCookies(request.headers || {});
    const token = cookies[COOKIE_NAME];

    if (token) {
      try {
        await verifyIdToken(token);
        if (shouldRewriteToEnceladusIndex(uri)) {
          request.uri = '/enceladus/index.html';
        }
        return request;
      } catch (_e) {
        // fall through to login redirect
      }
    }

    return redirectToLogin(request);
  } catch (_err) {
    return { status: '500', statusDescription: 'Internal Server Error', body: 'Auth handler error' };
  }
};
