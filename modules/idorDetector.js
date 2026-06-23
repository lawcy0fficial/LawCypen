// modules/idorDetector.js
// Flags candidate parameters for IDOR testing. Pure pattern matching over
// already-captured requests — no automatic ID swapping or replay. You decide
// which candidate to test and fire the edited request yourself via Repeater.

function isUuid(s) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s); }
function isMongoId(s) { return /^[0-9a-f]{24}$/i.test(s); }
function isNumericId(s) { return /^[0-9]{2,}$/.test(s); }

function classify(value) {
  if (isUuid(value)) return 'uuid';
  if (isMongoId(value)) return 'mongoid';
  if (isNumericId(value)) return 'numeric';
  return null;
}

const ID_KEY_RE = /(^id$|_id$|Id$|^uid$|^uuid$|userId|accountId|orderId|customerId|invoiceId|ownerId|profileId)/;

function walkJson(obj, path, out) {
  if (obj == null) return;
  if (Array.isArray(obj)) { obj.forEach((v, i) => walkJson(v, `${path}[${i}]`, out)); return; }
  if (typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      const newPath = path ? `${path}.${k}` : k;
      if (v !== null && typeof v === 'object') { walkJson(v, newPath, out); continue; }
      const sval = String(v);
      const cls = classify(sval);
      if (cls || ID_KEY_RE.test(k)) {
        out.push({ location: 'body', detail: newPath, value: sval, pattern: cls || 'keyword-match' });
      }
    }
  }
}

/**
 * @param {object} entry - { id, method, url, requestBody }
 * @returns {Array} candidate findings, each tagged with the originating request
 */
export function detectIdorCandidates(entry) {
  const candidates = [];
  let u;
  try { u = new URL(entry.url); } catch (e) { return candidates; }

  u.pathname.split('/').filter(Boolean).forEach((seg, idx) => {
    const cls = classify(seg);
    if (cls) candidates.push({ location: 'path', detail: `segment ${idx}`, value: seg, pattern: cls });
  });

  for (const [k, v] of u.searchParams.entries()) {
    const cls = classify(v);
    if (cls || ID_KEY_RE.test(k)) candidates.push({ location: 'query', detail: k, value: v, pattern: cls || 'keyword-match' });
  }

  if (entry.requestBody) {
    try { walkJson(JSON.parse(entry.requestBody), '', candidates); } catch (e) { /* not JSON */ }
  }

  return candidates.map(c => ({
    ...c,
    method: entry.method,
    url: entry.url,
    historyId: entry.id,
    foundAt: Date.now(),
  }));
}
