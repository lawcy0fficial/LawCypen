// background.js (MV3 service worker, type: module)
import { scanForSecrets } from './modules/secretDetector.js';
import { scanForJwts } from './modules/jwtAnalyzer.js';
import { extractEndpointsFromText, endpointFromRequest } from './modules/endpointExtractor.js';
import { detectGraphQL } from './modules/graphqlDetector.js';
import { isInScope } from './modules/scopeMatch.js';
import { detectIdorCandidates } from './modules/idorDetector.js';
import { extractS3Buckets } from './modules/s3Detector.js';
import { classifyCnameTarget } from './modules/takeoverDetector.js';

const MAX_HISTORY = 600;
const MAX_BODY_STORE = 8000; // chars kept per request/response body in History (Repeater results are not subject to this)
const MAX_FINDINGS = 500;
const SAVE_DEBOUNCE_MS = 400;

const TEXT_MIME_RE = /json|text|javascript|xml|graphql|html|css/i;

// ================= LOCAL STORAGE (low-frequency: targets/scope/repeater) =================

async function getLocal(keys) { return chrome.storage.local.get(keys); }
async function setLocal(obj) { return chrome.storage.local.set(obj); }

async function getTargets() {
  const { targets } = await getLocal('targets');
  return targets || [];
}
async function setTargets(targets) { await setLocal({ targets }); }

async function getScope() {
  const { scope } = await getLocal('scope');
  return scope || { includePatterns: [], excludePatterns: [] };
}
async function setScope(scope) { await setLocal({ scope }); }

async function getRepeaterItems() {
  const { repeaterItems } = await getLocal('repeaterItems');
  return repeaterItems || [];
}
async function setRepeaterItems(items) { await setLocal({ repeaterItems: items }); }

async function getManualTakeoverHosts() {
  const { manualTakeoverHosts } = await getLocal('manualTakeoverHosts');
  return manualTakeoverHosts || [];
}
async function setManualTakeoverHosts(hosts) { await setLocal({ manualTakeoverHosts: hosts }); }

// ================= IN-MEMORY CANONICAL STORE (high-frequency: traffic + findings) =================
//
// Why this exists: the previous design did read-from-storage -> mutate -> write-to-storage
// on every single captured request. Under any real page load (dozens of concurrent
// requests), those async read-modify-write cycles overlap and later writes silently
// clobber earlier ones — requests vanish from History not because they weren't
// captured, but because a write race ate them after the fact.
//
// Fix: keep one canonical JS object in memory. All mutations are synchronous (no
// `await` between reading and writing it), so within a single service worker
// lifetime there is no interleaving possible — JS execution of synchronous code
// cannot be preempted. Persistence to chrome.storage.session is a debounced
// snapshot of the whole object, purely for surviving service-worker suspension,
// not the source of truth during an active capture session.

function emptyStore() {
  return {
    history: [], secrets: [], jwts: [], endpoints: {}, graphqlOps: {},
    idorCandidates: [], s3Buckets: {}, takeoverResults: {},
  };
}

let memStore = null;
let hydrationPromise = null;

function ensureHydrated() {
  if (memStore) return Promise.resolve();
  if (!hydrationPromise) {
    hydrationPromise = (async () => {
      const result = await chrome.storage.session.get(
        ['history', 'secrets', 'jwts', 'endpoints', 'graphqlOps', 'idorCandidates', 's3Buckets', 'takeoverResults']
      );
      memStore = {
        history: result.history || [],
        secrets: result.secrets || [],
        jwts: result.jwts || [],
        endpoints: result.endpoints || {},
        graphqlOps: result.graphqlOps || {},
        idorCandidates: result.idorCandidates || [],
        s3Buckets: result.s3Buckets || {},
        takeoverResults: result.takeoverResults || {},
      };
    })();
  }
  return hydrationPromise;
}

let saveTimer = null;
function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(async () => {
    saveTimer = null;
    try { await chrome.storage.session.set({ ...memStore }); } catch (e) { /* next mutation will reschedule */ }
  }, SAVE_DEBOUNCE_MS);
}

async function clearStore() {
  await ensureHydrated();
  memStore = emptyStore();
  if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
  await chrome.storage.session.set({ ...memStore });
}

// ================= SCOPE =================

async function isUrlInScope(url) {
  const targets = await getTargets();
  const scope = await getScope();
  const includes = [...targets.map(t => t + '/*'), ...scope.includePatterns];
  return isInScope(url, includes, scope.excludePatterns);
}

// ================= MERGE HELPERS (all synchronous, mutate memStore directly) =================

function truncate(text) {
  if (!text || typeof text !== 'string') return text || '';
  return text.length > MAX_BODY_STORE ? text.slice(0, MAX_BODY_STORE) + `\n…[truncated, ${text.length} chars total]` : text;
}

function capArray(arr, max) {
  if (arr.length > max) arr.length = max;
}

function mergeEndpoint(store, ep) {
  if (!ep) return;
  const key = ep.origin ? `${ep.origin}|${ep.path}` : ep.path;
  const existing = store.endpoints[key];
  if (existing) {
    (ep.methods || []).forEach(m => { if (!existing.methods.includes(m)) existing.methods.push(m); });
    existing.lastSeen = Date.now();
    existing.seenCount = (existing.seenCount || 1) + 1;
  } else {
    store.endpoints[key] = { ...ep, methods: ep.methods || [], firstSeen: Date.now(), lastSeen: Date.now(), seenCount: 1 };
  }
}

function mergeSecret(store, finding) {
  const key = finding.type + ':' + finding.masked;
  if (store.secrets.some(s => s.type + ':' + s.masked === key)) return;
  store.secrets.unshift(finding);
  capArray(store.secrets, MAX_FINDINGS);
}

function mergeJwt(store, jwtRecord) {
  if (store.jwts.some(j => j.tokenMasked === jwtRecord.tokenMasked)) return;
  store.jwts.unshift(jwtRecord);
  capArray(store.jwts, MAX_FINDINGS);
}

function mergeGraphQL(store, gqlRecord) {
  if (!gqlRecord) return;
  const key = gqlRecord.operationName + '|' + gqlRecord.operationType;
  const existing = store.graphqlOps[key];
  if (existing) {
    gqlRecord.fields.forEach(f => { if (!existing.fields.includes(f)) existing.fields.push(f); });
    existing.count = (existing.count || 1) + 1;
    existing.lastSeen = Date.now();
  } else {
    store.graphqlOps[key] = { ...gqlRecord, count: 1, firstSeen: Date.now(), lastSeen: Date.now() };
  }
}

function mergeIdorCandidate(store, c) {
  const key = `${c.url}|${c.location}|${c.detail}`;
  if (store.idorCandidates.some(x => `${x.url}|${x.location}|${x.detail}` === key)) return;
  store.idorCandidates.unshift(c);
  capArray(store.idorCandidates, MAX_FINDINGS);
}

function mergeS3Bucket(store, b) {
  if (!b) return;
  const existing = store.s3Buckets[b.bucket];
  if (existing) {
    existing.lastSeen = Date.now();
    existing.seenCount = (existing.seenCount || 1) + 1;
  } else {
    store.s3Buckets[b.bucket] = { ...b, firstSeen: Date.now(), lastSeen: Date.now(), seenCount: 1, checkResult: null };
  }
}

// ================= TRAFFIC PROCESSING =================

async function processDevtoolsTraffic(payload) {
  if (!(await isUrlInScope(payload.url))) return;
  await ensureHydrated();
  const store = memStore;

  const origin = (() => { try { return new URL(payload.url).origin; } catch { return null; } })();
  const isText = TEXT_MIME_RE.test(payload.mimeType || '');

  const entry = {
    id: `h_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    method: payload.method,
    url: payload.url,
    origin,
    status: payload.status,
    statusText: payload.statusText,
    mimeType: payload.mimeType,
    sizeBytes: payload.sizeBytes,
    timeMs: Math.round(payload.timeMs || 0),
    timestamp: payload.timestamp || Date.now(),
    requestHeaders: payload.requestHeaders || {},
    requestBody: truncate(payload.requestBody),
    responseHeaders: payload.responseHeaders || {},
    responseBody: isText ? truncate(payload.responseBody) : `[${payload.mimeType || 'binary'}, ${payload.sizeBytes || 0} bytes — not stored]`,
  };

  store.history.unshift(entry);
  capArray(store.history, MAX_HISTORY);

  const epBase = endpointFromRequest(payload);
  if (epBase) mergeEndpoint(store, { ...epBase, origin });

  const gql = detectGraphQL(payload);
  if (gql) mergeGraphQL(store, gql);

  detectIdorCandidates(entry).forEach(c => mergeIdorCandidate(store, c));

  if (isText) {
    const scanText = [payload.requestBody, payload.responseBody].filter(Boolean).join('\n');
    scanForSecrets(scanText, { url: payload.url, source: 'traffic' }).forEach(f => mergeSecret(store, f));
    scanForJwts(scanText, { url: payload.url, source: 'traffic' }).forEach(j => mergeJwt(store, j));
    extractS3Buckets(scanText, { url: payload.url, source: 'traffic' }).forEach(b => mergeS3Bucket(store, b));
  }
  scanForSecrets(JSON.stringify(payload.requestHeaders || {}), { url: payload.url, source: 'headers' }).forEach(f => mergeSecret(store, f));
  scanForJwts(JSON.stringify(payload.requestHeaders || {}), { url: payload.url, source: 'headers' }).forEach(j => mergeJwt(store, j));

  scheduleSave();
}

async function processWsTraffic(origin, payload) {
  const wsUrlAsHttp = payload.url.replace(/^ws/i, 'http');
  if (!(await isUrlInScope(wsUrlAsHttp))) return;
  await ensureHydrated();
  const store = memStore;

  store.history.unshift({
    id: `h_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    method: payload.method,
    url: payload.url,
    origin,
    status: null,
    statusText: payload.kind,
    mimeType: 'websocket',
    sizeBytes: (payload.requestBody || payload.responseBody || '').length,
    timeMs: 0,
    timestamp: Date.now(),
    requestHeaders: {},
    requestBody: truncate(payload.requestBody),
    responseHeaders: {},
    responseBody: truncate(payload.responseBody),
  });
  capArray(store.history, MAX_HISTORY);

  const text = [payload.requestBody, payload.responseBody].filter(Boolean).join('\n');
  scanForSecrets(text, { url: payload.url, source: 'websocket' }).forEach(f => mergeSecret(store, f));
  scanForJwts(text, { url: payload.url, source: 'websocket' }).forEach(j => mergeJwt(store, j));

  scheduleSave();
}

async function processScriptScan(origin, payload) {
  if (!(await isUrlInScope(payload.url))) return;
  await ensureHydrated();
  const store = memStore;
  const { text, url } = payload;

  extractEndpointsFromText(text, { url, source: 'script' }).forEach(ep => mergeEndpoint(store, { ...ep, origin }));
  scanForSecrets(text, { url, source: 'script' }).forEach(f => mergeSecret(store, f));
  scanForJwts(text, { url, source: 'script' }).forEach(j => mergeJwt(store, j));
  extractS3Buckets(text, { url, source: 'script' }).forEach(b => mergeS3Bucket(store, b));

  scheduleSave();
}

// ================= TARGET / SCOPE MANAGEMENT =================

function originPattern(origin) { return origin + '/*'; }

async function registerScriptsForOrigin(origin) {
  const id = 'lawcypen-' + origin.replace(/[^a-zA-Z0-9]/g, '_');
  try { await chrome.scripting.unregisterContentScripts({ ids: [id + '-main', id + '-isolated'] }); } catch (e) {}
  await chrome.scripting.registerContentScripts([
    { id: id + '-main', matches: [originPattern(origin)], js: ['injected.js'], runAt: 'document_start', world: 'MAIN' },
    { id: id + '-isolated', matches: [originPattern(origin)], js: ['content-script.js'], runAt: 'document_start', world: 'ISOLATED' },
  ]);
}

async function unregisterScriptsForOrigin(origin) {
  const id = 'lawcypen-' + origin.replace(/[^a-zA-Z0-9]/g, '_');
  try { await chrome.scripting.unregisterContentScripts({ ids: [id + '-main', id + '-isolated'] }); } catch (e) {}
}

async function addTarget(origin) {
  const targets = await getTargets();
  if (!targets.includes(origin)) {
    targets.push(origin);
    await setTargets(targets);
  }
  await registerScriptsForOrigin(origin);
}

async function removeTarget(origin) {
  const targets = (await getTargets()).filter(t => t !== origin);
  await setTargets(targets);
  await unregisterScriptsForOrigin(origin);
  await chrome.permissions.remove({ origins: [originPattern(origin)] }).catch(() => {});
}

// ================= REPEATER =================

const FORBIDDEN_HEADERS = new Set([
  'accept-charset', 'accept-encoding', 'access-control-request-headers', 'access-control-request-method',
  'connection', 'content-length', 'cookie', 'cookie2', 'date', 'dnt', 'expect', 'host', 'keep-alive',
  'origin', 'referer', 'set-cookie', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'via',
]);

function stripForbiddenHeaders(headers) {
  const clean = {};
  const removed = [];
  for (const [k, v] of Object.entries(headers || {})) {
    const lower = k.toLowerCase();
    if (FORBIDDEN_HEADERS.has(lower) || lower.startsWith('proxy-') || lower.startsWith('sec-')) {
      removed.push(k);
    } else {
      clean[k] = v;
    }
  }
  return { clean, removed };
}

async function repeaterSend({ url, method, headers, body }) {
  const { clean, removed } = stripForbiddenHeaders(headers);
  const fetchHeaders = new Headers();
  for (const [k, v] of Object.entries(clean)) {
    try { fetchHeaders.append(k, v); } catch (e) { /* invalid header value, skip */ }
  }

  const init = { method: method || 'GET', headers: fetchHeaders, credentials: 'include' };
  if (body && !['GET', 'HEAD'].includes((method || 'GET').toUpperCase())) init.body = body;

  const start = Date.now();
  let res;
  try {
    res = await fetch(url, init);
  } catch (e) {
    return {
      ok: false,
      error: e.message + ' — if this is a cross-origin target, make sure it is authorized in Scope first.',
      removedHeaders: removed,
    };
  }
  const timeMs = Date.now() - start;
  const resHeaders = {};
  res.headers.forEach((v, k) => { resHeaders[k] = v; });

  let bodyText = '';
  try { bodyText = await res.text(); } catch (e) { bodyText = '[unreadable response body]'; }

  return {
    ok: true,
    status: res.status,
    statusText: res.statusText,
    headers: resHeaders,
    body: bodyText.slice(0, 2_000_000),
    timeMs,
    removedHeaders: removed,
  };
}

// ================= S3 / TAKEOVER CHECKS =================

async function checkS3Bucket(bucket) {
  const url = `https://s3.amazonaws.com/${bucket}`;
  let res;
  try {
    res = await fetch(url);
  } catch (e) {
    return { ok: false, error: e.message };
  }
  const text = await res.text();

  let verdict = 'unknown';
  if (res.status === 200 && /<ListBucketResult/i.test(text)) verdict = 'public-listing';
  else if (res.status === 403 && /AccessDenied/i.test(text)) verdict = 'private';
  else if (res.status === 404 && /NoSuchBucket/i.test(text)) verdict = 'not-found-possible-takeover';

  let keys = [];
  if (verdict === 'public-listing') {
    keys = Array.from(text.matchAll(/<Key>(.*?)<\/Key>/g)).map(m => m[1]).slice(0, 200);
  }

  return {
    ok: true,
    status: res.status,
    verdict,
    keyCount: keys.length,
    keys,
    rawSnippet: text.slice(0, 4000),
    checkedAt: Date.now(),
  };
}

async function checkTakeover(hostname) {
  let cname = null;
  try {
    const dnsRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=CNAME`);
    const data = await dnsRes.json();
    if (data.Answer && data.Answer.length) {
      cname = data.Answer[data.Answer.length - 1].data.replace(/\.$/, '');
    }
  } catch (e) {
    return { ok: false, error: 'DNS lookup failed: ' + e.message };
  }

  if (!cname) {
    return { ok: true, cname: null, verdict: 'no-cname', checkedAt: Date.now() };
  }

  const svc = classifyCnameTarget(cname);
  if (!svc) {
    return { ok: true, cname, verdict: 'cname-not-watched', checkedAt: Date.now() };
  }

  let verdict = 'manual-check-needed';
  let bodySnippet = '';
  try {
    const pageRes = await fetch(`https://${hostname}/`, { redirect: 'follow' });
    const text = await pageRes.text();
    bodySnippet = text.slice(0, 2000);
    if (svc.fingerprint) verdict = svc.fingerprint.test(text) ? 'vulnerable' : 'claimed-or-active';
  } catch (e) {
    verdict = 'fetch-failed';
    bodySnippet = e.message;
  }

  return { ok: true, cname, service: svc.name, confidence: svc.confidence, verdict, bodySnippet, checkedAt: Date.now() };
}

// ================= MESSAGE ROUTER =================

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case 'DEVTOOLS_TRAFFIC':
          await processDevtoolsTraffic(msg.payload);
          sendResponse({ ok: true });
          break;
        case 'WS_TRAFFIC':
          await processWsTraffic(msg.origin, msg.payload);
          sendResponse({ ok: true });
          break;
        case 'SCRIPT_SCAN':
          await processScriptScan(msg.origin, msg.payload);
          sendResponse({ ok: true });
          break;

        case 'ADD_TARGET':
          await addTarget(msg.origin);
          sendResponse({ ok: true, targets: await getTargets() });
          break;
        case 'REMOVE_TARGET':
          await removeTarget(msg.origin);
          sendResponse({ ok: true, targets: await getTargets() });
          break;
        case 'GET_TARGETS':
          sendResponse({ ok: true, targets: await getTargets() });
          break;

        case 'GET_SCOPE':
          sendResponse({ ok: true, scope: await getScope() });
          break;
        case 'SET_SCOPE':
          await setScope(msg.scope);
          sendResponse({ ok: true });
          break;

        case 'GET_HISTORY': {
          await ensureHydrated();
          sendResponse({ ok: true, history: memStore.history });
          break;
        }
        case 'GET_ANALYSIS': {
          await ensureHydrated();
          sendResponse({
            ok: true,
            secrets: memStore.secrets,
            jwts: memStore.jwts,
            endpoints: memStore.endpoints,
            graphqlOps: memStore.graphqlOps,
            idorCandidates: memStore.idorCandidates,
            s3Buckets: memStore.s3Buckets,
          });
          break;
        }
        case 'CLEAR_DATA': {
          await clearStore();
          sendResponse({ ok: true });
          break;
        }

        case 'CHECK_S3_BUCKET': {
          const result = await checkS3Bucket(msg.bucket);
          await ensureHydrated();
          if (memStore.s3Buckets[msg.bucket]) memStore.s3Buckets[msg.bucket].checkResult = result;
          scheduleSave();
          sendResponse({ ok: true, result });
          break;
        }

        case 'CHECK_TAKEOVER': {
          const result = await checkTakeover(msg.hostname);
          await ensureHydrated();
          memStore.takeoverResults[msg.hostname] = result;
          scheduleSave();
          sendResponse({ ok: true, result });
          break;
        }
        case 'GET_TAKEOVER_HOSTS': {
          await ensureHydrated();
          const fromHistory = Array.from(new Set(
            memStore.history.map(h => h.origin).filter(Boolean)
              .map(o => { try { return new URL(o).host; } catch { return null; } }).filter(Boolean)
          ));
          const manual = await getManualTakeoverHosts();
          const hosts = Array.from(new Set([...fromHistory, ...manual]));
          sendResponse({ ok: true, hosts, results: memStore.takeoverResults });
          break;
        }
        case 'ADD_TAKEOVER_HOST': {
          const hosts = await getManualTakeoverHosts();
          if (!hosts.includes(msg.hostname)) hosts.push(msg.hostname);
          await setManualTakeoverHosts(hosts);
          sendResponse({ ok: true, hosts });
          break;
        }

        case 'REPEATER_SEND': {
          const result = await repeaterSend(msg.request);
          sendResponse({ ok: true, result });
          break;
        }
        case 'GET_REPEATER_ITEMS':
          sendResponse({ ok: true, items: await getRepeaterItems() });
          break;
        case 'SAVE_REPEATER_ITEM': {
          const items = await getRepeaterItems();
          const idx = items.findIndex(i => i.id === msg.item.id);
          if (idx >= 0) items[idx] = msg.item; else items.push(msg.item);
          await setRepeaterItems(items);
          sendResponse({ ok: true, items });
          break;
        }
        case 'DELETE_REPEATER_ITEM': {
          const items = (await getRepeaterItems()).filter(i => i.id !== msg.id);
          await setRepeaterItems(items);
          sendResponse({ ok: true, items });
          break;
        }

        default:
          sendResponse({ ok: false, error: 'unknown message type: ' + msg.type });
      }
    } catch (err) {
      sendResponse({ ok: false, error: err.message });
    }
  })();
  return true;
});
