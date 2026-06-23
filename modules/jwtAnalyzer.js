// modules/jwtAnalyzer.js
// Decodes JWT structure (header/payload) for inspection and flags common
// misconfigurations. This is passive decoding of base64url segments —
// it does not attempt to crack signatures or forge tokens.

function b64urlDecode(str) {
  try {
    const padded = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
    const decoded = atob(padded + pad);
    // handle UTF-8
    return decodeURIComponent(
      decoded.split('').map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
    );
  } catch (e) {
    return null;
  }
}

const JWT_RE = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.([A-Za-z0-9_-]*)$/;

/**
 * Parse and analyze a candidate JWT string.
 * @param {string} token
 * @param {object} ctx - { url, source }
 * @returns {object|null} analysis result or null if not a valid JWT shape
 */
export function analyzeJwt(token, ctx = {}) {
  if (!token || !JWT_RE.test(token.trim())) return null;
  const parts = token.trim().split('.');
  if (parts.length < 2) return null;

  const headerRaw = b64urlDecode(parts[0]);
  const payloadRaw = b64urlDecode(parts[1]);
  if (!headerRaw || !payloadRaw) return null;

  let header, payload;
  try {
    header = JSON.parse(headerRaw);
    payload = JSON.parse(payloadRaw);
  } catch (e) {
    return null;
  }

  const issues = [];
  const alg = (header.alg || '').toLowerCase();

  if (alg === 'none') {
    issues.push({ severity: 'high', note: 'alg=none — server may accept unsigned tokens' });
  }
  if (alg === 'hs256' || alg === 'hs384' || alg === 'hs512') {
    issues.push({ severity: 'info', note: `Symmetric algorithm (${header.alg}) — if the secret is weak or leaked client-side, tokens can be forged` });
  }
  if (!payload.exp) {
    issues.push({ severity: 'medium', note: 'No exp claim — token may never expire' });
  } else {
    const expDate = new Date(payload.exp * 1000);
    const lifetimeHrs = (payload.exp - (payload.iat || payload.exp)) / 3600;
    if (lifetimeHrs > 24 * 7) {
      issues.push({ severity: 'low', note: `Long lifetime (~${Math.round(lifetimeHrs)}h)` });
    }
    if (expDate.getTime() < Date.now()) {
      issues.push({ severity: 'info', note: 'Token is expired' });
    }
  }
  if (!header.kid && (alg === 'rs256' || alg === 'es256')) {
    issues.push({ severity: 'low', note: 'Asymmetric alg with no kid — key rotation/verification path unclear' });
  }
  const sensitiveKeys = ['role', 'roles', 'isAdmin', 'is_admin', 'admin', 'permissions', 'scope', 'scopes'];
  const foundClaims = sensitiveKeys.filter(k => k in payload);
  if (foundClaims.length) {
    issues.push({ severity: 'info', note: `Authorization-relevant claims present: ${foundClaims.join(', ')} — good candidates for tamper/role-replay testing` });
  }

  return {
    tokenMasked: token.slice(0, 12) + '…' + token.slice(-6),
    header,
    payload,
    claims: Object.keys(payload),
    issues,
    url: ctx.url || null,
    source: ctx.source || 'unknown',
    foundAt: Date.now(),
  };
}

/** Scan free text for JWT-shaped substrings and analyze each. */
export function scanForJwts(text, ctx = {}) {
  if (!text || typeof text !== 'string') return [];
  const matches = text.match(/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g) || [];
  const results = [];
  const seen = new Set();
  for (const m of matches) {
    if (seen.has(m)) continue;
    seen.add(m);
    const a = analyzeJwt(m, ctx);
    if (a) results.push(a);
  }
  return results;
}
