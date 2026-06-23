// modules/endpointExtractor.js
// Extracts candidate API endpoints from JS source text (bundles, inline
// scripts) and from observed network traffic. Purely text-pattern based —
// no execution, no probing.

const PATH_PATTERNS = [
  // fetch('/api/...'), axios.get("/v1/..."), template literals
  /['"`](\/(?:api|v[0-9]+|graphql|rest|internal|admin|service)[a-zA-Z0-9_\-\/{}.:]*)['"`]/g,
  // absolute URLs with an /api/ or version segment
  /https?:\/\/[a-zA-Z0-9.\-]+(\/(?:api|v[0-9]+|graphql|rest)[a-zA-Z0-9_\-\/{}.:]*)/g,
];

const METHOD_HINT_RE = /\.(get|post|put|patch|delete|head)\s*\(\s*['"`]([^'"`]+)['"`]/gi;

export function extractEndpointsFromText(text, ctx = {}) {
  if (!text || typeof text !== 'string') return [];
  const found = new Map(); // path -> {path, methods:Set, source, sample}

  for (const re of PATH_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const path = (m[1] || m[0]).replace(/^https?:\/\/[^/]+/, '');
      if (!path || path.length < 2 || path.length > 300) continue;
      if (!found.has(path)) {
        found.set(path, { path, methods: new Set(), source: ctx.source || 'script', url: ctx.url || null });
      }
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }

  // Pick up method hints near matched calls (best-effort correlation by proximity)
  METHOD_HINT_RE.lastIndex = 0;
  let hm;
  while ((hm = METHOD_HINT_RE.exec(text)) !== null) {
    const method = hm[1].toUpperCase();
    const candidatePath = hm[2];
    for (const [path, entry] of found) {
      if (candidatePath.includes(path) || path.includes(candidatePath)) {
        entry.methods.add(method);
      }
    }
  }

  return Array.from(found.values()).map(e => ({
    path: e.path,
    methods: Array.from(e.methods),
    source: e.source,
    url: e.url,
    foundAt: Date.now(),
  }));
}

/** Build an endpoint record directly from an observed network request. */
export function endpointFromRequest(req) {
  try {
    const u = new URL(req.url);
    return {
      path: u.pathname,
      methods: [req.method || 'GET'],
      source: 'traffic',
      url: req.url,
      status: req.status,
      foundAt: Date.now(),
    };
  } catch (e) {
    return null;
  }
}
