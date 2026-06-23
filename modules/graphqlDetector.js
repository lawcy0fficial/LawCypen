// modules/graphqlDetector.js
// Identifies GraphQL traffic by shape (not just URL) and extracts a
// best-effort operation map: operation name, type (query/mutation/subscription),
// and top-level field names referenced. This is a lightweight regex parser,
// not a full GraphQL grammar — good enough for recon, not for schema export.

function looksLikeGraphQL(url, body) {
  if (/graphql/i.test(url)) return true;
  if (!body) return false;
  if (typeof body === 'object' && ('query' in body || 'mutation' in body)) return true;
  if (typeof body === 'string') {
    try {
      const parsed = JSON.parse(body);
      return parsed && typeof parsed === 'object' && 'query' in parsed;
    } catch (e) {
      return /^\s*(query|mutation|subscription)\b/.test(body);
    }
  }
  return false;
}

function parseOperation(queryStr) {
  if (!queryStr || typeof queryStr !== 'string') return null;
  const opMatch = queryStr.match(/\b(query|mutation|subscription)\s+([A-Za-z0-9_]+)?/);
  const type = opMatch ? opMatch[1] : 'query';
  const name = (opMatch && opMatch[2]) || '(anonymous)';

  // crude top-level field extraction: first { ... } block's identifiers
  const fields = new Set();
  const bodyStart = queryStr.indexOf('{');
  if (bodyStart !== -1) {
    // find matching depth-1 fields by scanning until balance hits 0 once
    let depth = 0, started = false, buf = '';
    for (let i = bodyStart; i < queryStr.length; i++) {
      const ch = queryStr[i];
      if (ch === '{') { depth++; if (depth === 1) { started = true; continue; } }
      if (ch === '}') { depth--; if (depth === 0) break; }
      if (started && depth === 1) buf += ch;
    }
    const fieldMatches = buf.match(/[A-Za-z_][A-Za-z0-9_]*/g) || [];
    fieldMatches.forEach(f => fields.add(f));
  }

  return { type, name, fields: Array.from(fields) };
}

/**
 * @param {object} req - { url, method, requestBody }
 * @returns {object|null} GraphQL operation record, or null if not GraphQL
 */
export function detectGraphQL(req) {
  const { url, requestBody } = req;
  if (!looksLikeGraphQL(url, requestBody)) return null;

  let queryStr = null;
  let operationName = null;
  let variables = null;

  if (typeof requestBody === 'string') {
    try {
      const parsed = JSON.parse(requestBody);
      queryStr = parsed.query;
      operationName = parsed.operationName || null;
      variables = parsed.variables || null;
    } catch (e) {
      queryStr = requestBody;
    }
  } else if (requestBody && typeof requestBody === 'object') {
    queryStr = requestBody.query;
    operationName = requestBody.operationName || null;
    variables = requestBody.variables || null;
  }

  const parsed = parseOperation(queryStr) || { type: 'unknown', name: operationName || '(unknown)', fields: [] };

  return {
    endpoint: (() => { try { return new URL(url).pathname; } catch { return url; } })(),
    operationName: operationName || parsed.name,
    operationType: parsed.type,
    fields: parsed.fields,
    variableKeys: variables ? Object.keys(variables) : [],
    url,
    foundAt: Date.now(),
  };
}
