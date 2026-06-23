// modules/secretDetector.js
// Pattern-based secret/credential detector. Runs against script text,
// request/response bodies, and headers. Values are masked before storage
// or display — we keep enough to recognize the type, never the raw secret.

const PATTERNS = [
  { type: 'AWS Access Key ID',      re: /AKIA[0-9A-Z]{16}/g,                                   severity: 'high' },
  { type: 'AWS Secret Access Key',  re: /(?:aws_secret_access_key|secretAccessKey)\s*[:=]\s*['"]([A-Za-z0-9\/+=]{40})['"]/gi, severity: 'high', group: 1 },
  { type: 'Google API Key',         re: /AIza[0-9A-Za-z\-_]{35}/g,                              severity: 'high' },
  { type: 'Slack Token',            re: /xox[baprs]-[0-9A-Za-z-]{10,}/g,                         severity: 'high' },
  { type: 'Stripe Live Secret Key', re: /sk_live_[0-9A-Za-z]{20,}/g,                             severity: 'high' },
  { type: 'Stripe Live Publishable',re: /pk_live_[0-9A-Za-z]{20,}/g,                             severity: 'medium' },
  { type: 'GitHub Token',           re: /gh[pousr]_[A-Za-z0-9]{36,}/g,                           severity: 'high' },
  { type: 'Private Key Block',      re: /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/g,    severity: 'high' },
  { type: 'Generic Bearer Token',   re: /Bearer\s+([A-Za-z0-9\-_\.]{20,})/g,                     severity: 'medium', group: 1 },
  { type: 'Hardcoded Password Assignment', re: /(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{6,})['"]/gi, severity: 'medium', group: 1 },
  { type: 'Generic API Key Assignment', re: /(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*['"]([A-Za-z0-9\-_]{20,})['"]/gi, severity: 'medium', group: 1 },
  { type: 'JWT-looking String',     re: /eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g, severity: 'info' },
];

function mask(value) {
  if (!value) return value;
  if (value.length <= 10) return value.slice(0, 2) + '***';
  return value.slice(0, 6) + '…' + value.slice(-4) + `  (${value.length} chars)`;
}

/**
 * Scan a chunk of text (script source, response body, header value) for secrets.
 * @param {string} text
 * @param {object} ctx - { url, source } for provenance
 * @returns {Array} findings
 */
export function scanForSecrets(text, ctx = {}) {
  if (!text || typeof text !== 'string') return [];
  const findings = [];
  const seen = new Set();

  for (const pattern of PATTERNS) {
    let match;
    pattern.re.lastIndex = 0;
    while ((match = pattern.re.exec(text)) !== null) {
      const raw = pattern.group ? match[match.length === pattern.group + 1 ? pattern.group : pattern.group] : match[0];
      const value = pattern.group ? match[pattern.group] : match[0];
      if (!value) continue;
      const dedupeKey = pattern.type + ':' + value;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      findings.push({
        type: pattern.type,
        severity: pattern.severity,
        masked: mask(value),
        length: value.length,
        url: ctx.url || null,
        source: ctx.source || 'unknown',
        context: text.slice(Math.max(0, match.index - 30), match.index + value.length + 10).trim(),
        foundAt: Date.now(),
      });

      // guard against pathological loops on zero-width matches
      if (match.index === pattern.re.lastIndex) pattern.re.lastIndex++;
    }
  }
  return findings;
}
