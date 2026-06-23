// panel/panel.js

const state = {
  history: [],
  selectedHistoryId: null,
  filterText: '',
  analysis: { secrets: [], jwts: [], endpoints: {}, graphqlOps: {}, idorCandidates: [], s3Buckets: {} },
  takeoverHosts: [],
  takeoverResults: {},
  targets: [],
  scope: { includePatterns: [], excludePatterns: [] },
  repeaterItems: [],
  selectedRepeaterId: null,
};

function uid(prefix) { return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`; }
function esc(str) { return (str ?? '').toString().replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

function tryPretty(text) {
  if (!text) return '';
  const trimmed = text.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try { return JSON.stringify(JSON.parse(trimmed), null, 2); } catch (e) { /* not JSON */ }
  }
  return text;
}

function statusClass(status) {
  if (!status) return 'status-none';
  return 'status-' + Math.floor(status / 100);
}

function fmtTime(ms) {
  if (ms == null) return '';
  if (ms < 1000) return ms + 'ms';
  return (ms / 1000).toFixed(2) + 's';
}

function fmtSize(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

async function openInBrowser(contentType, body) {
  const id = uid('v');
  await chrome.storage.session.set({ [`view:${id}`]: { contentType: contentType || 'text/plain', body: body || '' } });
  chrome.tabs.create({ url: chrome.runtime.getURL('viewer/viewer.html') + '?id=' + id });
}

function send(msg) { return chrome.runtime.sendMessage(msg); }

// ================= RAW HTTP MESSAGE HELPERS (Repeater) =================
//
// Repeater edits one raw HTTP message, the same model Burp uses, instead of
// separate method/url/headers/body fields. Scheme is tracked alongside
// since a raw request line ("GET /path HTTP/1.1") has no scheme in it —
// that comes from the Host header + an explicit https/http toggle.

function buildRawRequest(method, url, headers, body) {
  let u = null;
  try { u = new URL(url); } catch (e) { /* relative/invalid, fall through */ }
  const path = u ? (u.pathname + (u.search || '')) : (url || '/');
  const host = u ? u.host : '';

  const headerEntries = Object.entries(headers || {});
  const hasHost = headerEntries.some(([k]) => k.toLowerCase() === 'host');
  const lines = [`${(method || 'GET').toUpperCase()} ${path} HTTP/1.1`];
  if (!hasHost && host) lines.push(`Host: ${host}`);
  headerEntries.forEach(([k, v]) => lines.push(`${k}: ${v}`));

  return body ? `${lines.join('\n')}\n\n${body}` : `${lines.join('\n')}\n\n`;
}

function parseRawRequest(text) {
  const normalized = (text || '').replace(/\r\n/g, '\n');
  const splitIdx = normalized.indexOf('\n\n');
  const head = splitIdx === -1 ? normalized : normalized.slice(0, splitIdx);
  const body = splitIdx === -1 ? '' : normalized.slice(splitIdx + 2);
  const lines = head.split('\n');
  const requestLine = lines[0] || '';
  const [method, path] = requestLine.split(' ');
  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const idx = lines[i].indexOf(':');
    if (idx === -1) continue;
    headers[lines[i].slice(0, idx).trim()] = lines[i].slice(idx + 1).trim();
  }
  return { method: (method || 'GET').toUpperCase(), path: path || '/', headers, body };
}

function rawRequestToFetchTarget(item) {
  const parsed = parseRawRequest(item.rawRequest);
  const hostKey = Object.keys(parsed.headers).find(k => k.toLowerCase() === 'host');
  const host = hostKey ? parsed.headers[hostKey] : null;
  if (!host) return { error: 'No Host header — add one, e.g. "Host: example.com"' };
  return {
    url: `${item.scheme || 'https'}://${host}${parsed.path}`,
    method: parsed.method,
    headers: parsed.headers,
    body: parsed.body,
  };
}

// ================= TAB SWITCHING =================

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('panel-' + tab.dataset.tab).classList.add('active');
  });
});

document.querySelectorAll('.subtab').forEach(st => {
  st.addEventListener('click', () => {
    document.querySelectorAll('.subtab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.subpanel').forEach(p => p.classList.remove('active'));
    st.classList.add('active');
    document.getElementById('sub-' + st.dataset.subtab).classList.add('active');
  });
});

// ================= HTTP HISTORY =================

function filteredHistory() {
  const f = state.filterText.trim().toLowerCase();
  if (!f) return state.history;
  return state.history.filter(h =>
    (h.method || '').toLowerCase().includes(f) ||
    (h.url || '').toLowerCase().includes(f) ||
    String(h.status || '').includes(f) ||
    (h.mimeType || '').toLowerCase().includes(f)
  );
}

function renderHistoryTable() {
  const tbody = document.getElementById('historyTbody');
  const rows = filteredHistory();
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-msg">No traffic captured yet. Authorize a target in Scope, then browse it with DevTools open.</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map((h, i) => {
    let host = '', path = h.url;
    try { const u = new URL(h.url); host = u.host; path = u.pathname + (u.search || ''); } catch (e) {}
    const selected = h.id === state.selectedHistoryId ? 'selected' : '';
    return `
      <tr class="${selected}" data-id="${esc(h.id)}">
        <td class="col-num">${i + 1}</td>
        <td class="col-method"><span class="method ${esc(h.method)}">${esc(h.method)}</span></td>
        <td class="col-host">${esc(host)}</td>
        <td class="col-path">${esc(path)}</td>
        <td class="col-status"><span class="status-code ${statusClass(h.status)}">${h.status ?? '—'}</span></td>
        <td class="col-type">${esc((h.mimeType || '').split(';')[0])}</td>
        <td class="col-size">${fmtSize(h.sizeBytes)}</td>
        <td class="col-time">${fmtTime(h.timeMs)}</td>
      </tr>
    `;
  }).join('');

  tbody.querySelectorAll('tr[data-id]').forEach(tr => {
    tr.addEventListener('click', () => {
      state.selectedHistoryId = tr.dataset.id;
      renderHistoryTable();
      renderHistoryDetail();
    });
  });
}

// Generalized parameter extraction — every query/body param, not just
// IDOR-shaped ones, so any value can be pushed to Repeater for testing.
function extractAllParams(entry) {
  const params = [];
  let u;
  try { u = new URL(entry.url); } catch (e) { return params; }

  for (const [k, v] of u.searchParams.entries()) {
    params.push({ location: 'query', name: k, value: v });
  }

  if (entry.requestBody) {
    try {
      walkJsonParams(JSON.parse(entry.requestBody), '', params);
    } catch (e) { /* not JSON body, skip */ }
  }
  return params;
}

function walkJsonParams(obj, path, out) {
  if (obj == null) return;
  if (Array.isArray(obj)) { obj.forEach((v, i) => walkJsonParams(v, `${path}[${i}]`, out)); return; }
  if (typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      const newPath = path ? `${path}.${k}` : k;
      if (v !== null && typeof v === 'object') { walkJsonParams(v, newPath, out); continue; }
      out.push({ location: 'body', name: newPath, value: String(v) });
    }
  }
}

function renderParamsSection(entry) {
  const params = extractAllParams(entry);
  if (!params.length) return '';
  return `
    <div class="params-section">
      <div class="editor-section-label" style="padding-left:0;">Parameters</div>
      <table class="params-table">
        <thead><tr><th>Location</th><th>Name</th><th>Value</th><th></th></tr></thead>
        <tbody>
          ${params.map((p, i) => `
            <tr>
              <td><span class="param-loc-badge">${esc(p.location)}</span></td>
              <td>${esc(p.name)}</td>
              <td>${esc(p.value)}</td>
              <td class="param-actions"><button class="param-send-btn" data-idx="${i}">→ Repeater</button></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderHistoryDetail() {
  const el = document.getElementById('historyDetail');
  const entry = state.history.find(h => h.id === state.selectedHistoryId);
  if (!entry) {
    el.innerHTML = '<div class="empty-msg">Select a request above to view its full request and response.</div>';
    return;
  }
  const params = extractAllParams(entry);

  el.innerHTML = `
    <div class="detail-toolbar">
      <button id="sendToRepeaterBtn" class="btn btn-primary">Send to Repeater</button>
      <button id="openInBrowserBtn" class="btn btn-ghost">Open response in browser</button>
      <span>${esc(entry.method)} · ${entry.status ?? '—'} ${esc(entry.statusText || '')} · ${fmtSize(entry.sizeBytes)} · ${fmtTime(entry.timeMs)}</span>
    </div>
    ${renderParamsSection(entry)}
    <div class="detail-cols">
      <div class="detail-pane">
        <div class="detail-pane-head">Request</div>
        <div class="detail-pane-body"><span class="status-line">${esc(entry.method)} ${esc(entry.url)}</span>${
          Object.entries(entry.requestHeaders || {}).map(([k, v]) => `<span class="header-line">${esc(k)}: <span class="h-val">${esc(v)}</span></span>`).join('\n')
        }${entry.requestBody ? '\n\n' + esc(tryPretty(entry.requestBody)) : ''}</div>
      </div>
      <div class="detail-pane">
        <div class="detail-pane-head">Response</div>
        <div class="detail-pane-body"><span class="status-line ${statusClass(entry.status)}">HTTP ${entry.status ?? ''} ${esc(entry.statusText || '')}</span>${
          Object.entries(entry.responseHeaders || {}).map(([k, v]) => `<span class="header-line">${esc(k)}: <span class="h-val">${esc(v)}</span></span>`).join('\n')
        }${entry.responseBody ? '\n\n' + esc(tryPretty(entry.responseBody)) : ''}</div>
      </div>
    </div>
  `;

  document.getElementById('sendToRepeaterBtn').addEventListener('click', () => sendHistoryToRepeater(entry));
  document.getElementById('openInBrowserBtn').addEventListener('click', () => {
    const ct = entry.responseHeaders?.['content-type'] || entry.responseHeaders?.['Content-Type'] || entry.mimeType || 'text/plain';
    openInBrowser(ct, entry.responseBody);
  });
  el.querySelectorAll('.param-send-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const p = params[Number(btn.dataset.idx)];
      sendHistoryToRepeater(entry, p?.value);
    });
  });
}

document.getElementById('filterInput').addEventListener('input', (e) => {
  state.filterText = e.target.value;
  renderHistoryTable();
});

document.getElementById('clearBtn').addEventListener('click', async () => {
  await send({ type: 'CLEAR_DATA' });
  state.history = [];
  state.analysis = { secrets: [], jwts: [], endpoints: {}, graphqlOps: {}, idorCandidates: [], s3Buckets: {} };
  state.selectedHistoryId = null;
  renderHistoryTable();
  renderHistoryDetail();
  renderAnalysis();
});

// ================= RESIZABLE HISTORY LAYOUT =================

function setupResizer() {
  const resizer = document.getElementById('historyResizer');
  const tableWrap = document.querySelector('.history-table-wrap');
  const container = document.querySelector('.history-layout');
  let dragging = false;

  resizer.addEventListener('mousedown', (e) => {
    dragging = true;
    resizer.classList.add('dragging');
    document.body.style.cursor = 'row-resize';
    e.preventDefault();
  });
  window.addEventListener('mousemove', (e) => {
    if (!dragging) return;
    const rect = container.getBoundingClientRect();
    let pct = ((e.clientY - rect.top) / rect.height) * 100;
    pct = Math.max(15, Math.min(80, pct));
    tableWrap.style.flex = `0 0 ${pct}%`;
  });
  window.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false;
    resizer.classList.remove('dragging');
    document.body.style.cursor = '';
  });
}

// ================= REPEATER =================

function sendHistoryToRepeater(entry, highlightValue) {
  const item = {
    id: uid('rep'),
    name: 'R' + (state.repeaterItems.length + 1),
    scheme: entry.url.startsWith('http://') ? 'http' : 'https',
    rawRequest: buildRawRequest(entry.method, entry.url, entry.requestHeaders, entry.requestBody || ''),
    lastResponse: null,
    respView: 'pretty',
  };
  state.repeaterItems.push(item);
  state.selectedRepeaterId = item.id;
  if (highlightValue) pendingHighlight = { id: item.id, value: highlightValue };
  persistRepeaterItem(item);
  document.querySelector('.tab[data-tab="repeater"]').click();
  renderRepeaterTabs();
  renderRepeaterBody();
}

let pendingHighlight = null;

function renderRepeaterTabs() {
  const el = document.getElementById('repeaterTabs');
  el.innerHTML = state.repeaterItems.map(item => `
    <div class="repeater-chip ${item.id === state.selectedRepeaterId ? 'active' : ''}" data-id="${esc(item.id)}">
      <span class="chip-label">${esc(item.name)}</span>
      <span class="close-x" data-close="${esc(item.id)}">✕</span>
    </div>
  `).join('');

  el.querySelectorAll('.repeater-chip').forEach(chip => {
    chip.addEventListener('click', (e) => {
      if (e.target.dataset.close) return;
      state.selectedRepeaterId = chip.dataset.id;
      renderRepeaterTabs();
      renderRepeaterBody();
    });
  });
  el.querySelectorAll('.close-x').forEach(x => {
    x.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = e.target.dataset.close;
      state.repeaterItems = state.repeaterItems.filter(i => i.id !== id);
      if (state.selectedRepeaterId === id) {
        state.selectedRepeaterId = state.repeaterItems[0]?.id || null;
      }
      await send({ type: 'DELETE_REPEATER_ITEM', id });
      renderRepeaterTabs();
      renderRepeaterBody();
    });
  });
}

function buildRawResponseText(resp, view) {
  if (!resp) return '';
  if (!resp.ok) return resp.error || 'Request failed';
  const statusLine = `HTTP ${resp.status} ${resp.statusText}`;
  const headerLines = Object.entries(resp.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
  let body = resp.body || '';
  if (view !== 'raw') body = tryPretty(body);
  const removedNote = resp.removedHeaders?.length
    ? `\n[note: browser-controlled headers not sent as typed: ${resp.removedHeaders.join(', ')}]`
    : '';
  return `${statusLine}\n${headerLines}${removedNote}\n\n${body}`;
}

function renderRepeaterBody() {
  const el = document.getElementById('repeaterBody');
  const item = state.repeaterItems.find(i => i.id === state.selectedRepeaterId);
  if (!item) {
    el.innerHTML = '<div class="empty-msg">Send a request here from HTTP History, or click "+ New" to start one from scratch.</div>';
    return;
  }

  const target = rawRequestToFetchTarget(item);
  const urlPreviewHtml = target.error ? `<span style="color:var(--red)">${esc(target.error)}</span>` : esc(target.url);

  el.innerHTML = `
    <div class="repeater-editor">
      <div class="repeater-editor-head">
        <select class="method-select" id="rep-scheme">
          <option value="https" ${item.scheme !== 'http' ? 'selected' : ''}>https://</option>
          <option value="http" ${item.scheme === 'http' ? 'selected' : ''}>http://</option>
        </select>
        <span class="url-preview mono" id="rep-url-preview">${urlPreviewHtml}</span>
        <button class="send-btn" id="rep-send">Send ▶</button>
      </div>
      <textarea class="code-area raw-area mono" id="rep-raw" spellcheck="false">${esc(item.rawRequest)}</textarea>
    </div>
    <div class="repeater-response">
      <div class="repeater-response-head">
        ${item.lastResponse
          ? (item.lastResponse.ok
              ? `<span class="status-line ${statusClass(item.lastResponse.status)}">HTTP ${item.lastResponse.status} ${esc(item.lastResponse.statusText)}</span> <span style="color:var(--muted)">· ${fmtTime(item.lastResponse.timeMs)}</span>`
              : `<span class="status-line status-5">Request failed</span>`)
          : '<span style="color:var(--muted)">No response yet</span>'}
        <div class="resp-toggle">
          <button class="btn-icon ${item.respView !== 'raw' ? 'active' : ''}" id="resp-pretty">Pretty</button>
          <button class="btn-icon ${item.respView === 'raw' ? 'active' : ''}" id="resp-raw">Raw</button>
        </div>
        <button class="btn btn-ghost" id="rep-open-browser" ${item.lastResponse && item.lastResponse.ok ? '' : 'disabled'}>Open in browser</button>
      </div>
      <pre class="repeater-response-body" id="rep-response-body">${esc(buildRawResponseText(item.lastResponse, item.respView))}</pre>
    </div>
  `;

  const textarea = document.getElementById('rep-raw');
  const urlPreviewEl = document.getElementById('rep-url-preview');

  function refreshPreview() {
    const t = rawRequestToFetchTarget(item);
    urlPreviewEl.innerHTML = t.error ? `<span style="color:var(--red)">${esc(t.error)}</span>` : esc(t.url);
  }

  if (pendingHighlight && pendingHighlight.id === item.id) {
    const idx = item.rawRequest.indexOf(pendingHighlight.value);
    if (idx !== -1) {
      textarea.focus();
      textarea.setSelectionRange(idx, idx + pendingHighlight.value.length);
    }
    pendingHighlight = null;
  }

  textarea.addEventListener('input', () => { item.rawRequest = textarea.value; refreshPreview(); });
  textarea.addEventListener('blur', () => persistRepeaterItem(item));
  document.getElementById('rep-scheme').addEventListener('change', (e) => {
    item.scheme = e.target.value;
    refreshPreview();
    persistRepeaterItem(item);
  });

  document.getElementById('rep-send').addEventListener('click', async () => {
    item.rawRequest = textarea.value;
    const t = rawRequestToFetchTarget(item);
    if (t.error) { refreshPreview(); return; }

    const sendBtn = document.getElementById('rep-send');
    sendBtn.disabled = true;
    sendBtn.textContent = 'Sending…';

    const res = await send({ type: 'REPEATER_SEND', request: t });
    item.lastResponse = res?.result || { ok: false, error: 'No response from background worker' };
    await persistRepeaterItem(item);
    renderRepeaterBody();
  });

  document.getElementById('resp-pretty').addEventListener('click', () => { item.respView = 'pretty'; renderRepeaterBody(); });
  document.getElementById('resp-raw').addEventListener('click', () => { item.respView = 'raw'; renderRepeaterBody(); });

  const openBtn = document.getElementById('rep-open-browser');
  if (openBtn) {
    openBtn.addEventListener('click', () => {
      const ct = item.lastResponse?.headers?.['content-type'] || 'text/plain';
      openInBrowser(ct, item.lastResponse?.body || '');
    });
  }
}

async function persistRepeaterItem(item) {
  await send({ type: 'SAVE_REPEATER_ITEM', item });
}

document.getElementById('newRepeaterBtn').addEventListener('click', () => {
  const item = {
    id: uid('rep'),
    name: 'R' + (state.repeaterItems.length + 1),
    scheme: 'https',
    rawRequest: 'GET / HTTP/1.1\nHost: \n\n',
    lastResponse: null,
    respView: 'pretty',
  };
  state.repeaterItems.push(item);
  state.selectedRepeaterId = item.id;
  persistRepeaterItem(item);
  renderRepeaterTabs();
  renderRepeaterBody();
});

// ================= SCOPE =================

function renderScope() {
  const targetList = document.getElementById('targetList');
  targetList.innerHTML = state.targets.map(t => `
    <li class="scope-item"><span>${esc(t)}</span><button class="remove-btn" data-origin="${esc(t)}">Remove</button></li>
  `).join('') || '<li class="scope-item" style="color:var(--muted);font-style:italic;">None yet</li>';
  targetList.querySelectorAll('.remove-btn').forEach(b => b.addEventListener('click', async () => {
    await send({ type: 'REMOVE_TARGET', origin: b.dataset.origin });
    await loadScope();
  }));

  const incList = document.getElementById('includeList');
  incList.innerHTML = state.scope.includePatterns.map(p => `
    <li class="scope-item"><span>${esc(p)}</span><button class="remove-btn" data-p="${esc(p)}" data-kind="include">Remove</button></li>
  `).join('') || '<li class="scope-item" style="color:var(--muted);font-style:italic;">None</li>';

  const excList = document.getElementById('excludeList');
  excList.innerHTML = state.scope.excludePatterns.map(p => `
    <li class="scope-item"><span>${esc(p)}</span><button class="remove-btn" data-p="${esc(p)}" data-kind="exclude">Remove</button></li>
  `).join('') || '<li class="scope-item" style="color:var(--muted);font-style:italic;">None</li>';

  document.querySelectorAll('#includeList .remove-btn, #excludeList .remove-btn').forEach(b => {
    b.addEventListener('click', async () => {
      const kind = b.dataset.kind;
      const key = kind === 'include' ? 'includePatterns' : 'excludePatterns';
      state.scope[key] = state.scope[key].filter(p => p !== b.dataset.p);
      await send({ type: 'SET_SCOPE', scope: state.scope });
      renderScope();
    });
  });
}

function deriveOrigin(input) {
  let str = input.trim();
  if (!/^https?:\/\//i.test(str)) str = 'https://' + str;
  try { return new URL(str).origin; } catch (e) { return null; }
}

document.getElementById('addTargetBtn').addEventListener('click', async () => {
  const input = document.getElementById('newTargetInput');
  const origin = deriveOrigin(input.value);
  if (!origin) return;
  const granted = await chrome.permissions.request({ origins: [origin + '/*'] });
  if (!granted) return;
  await send({ type: 'ADD_TARGET', origin });
  input.value = '';
  await loadScope();
});

document.getElementById('addIncludeBtn').addEventListener('click', async () => {
  const input = document.getElementById('newIncludeInput');
  if (!input.value.trim()) return;
  state.scope.includePatterns.push(input.value.trim());
  await send({ type: 'SET_SCOPE', scope: state.scope });
  input.value = '';
  renderScope();
});

document.getElementById('addExcludeBtn').addEventListener('click', async () => {
  const input = document.getElementById('newExcludeInput');
  if (!input.value.trim()) return;
  state.scope.excludePatterns.push(input.value.trim());
  await send({ type: 'SET_SCOPE', scope: state.scope });
  input.value = '';
  renderScope();
});

// ================= ANALYSIS =================

function renderS3Row(b) {
  const r = b.checkResult;
  let statusHtml = '<span style="color:var(--muted)">not checked yet</span>';
  let openBtn = '';
  if (r) {
    if (!r.ok) {
      statusHtml = `<span class="badge medium">error</span> ${esc(r.error)}`;
    } else if (r.verdict === 'public-listing') {
      statusHtml = `<span class="badge high">publicly listable</span> ${r.keyCount} object key(s) visible`;
      openBtn = `<button class="btn btn-ghost s3-open-btn" data-raw="${esc(r.rawSnippet)}">Open listing in browser</button>`;
    } else if (r.verdict === 'not-found-possible-takeover') {
      statusHtml = `<span class="badge high">bucket doesn't exist — possible takeover</span>`;
    } else if (r.verdict === 'private') {
      statusHtml = `<span class="badge info">private (properly secured)</span>`;
    } else {
      statusHtml = `<span class="badge low">unknown (HTTP ${r.status})</span>`;
    }
  }
  return `
    <div class="row">
      <div class="row-top"><span class="url">${esc(b.bucket)}</span><button class="btn btn-ghost s3-check-btn" data-bucket="${esc(b.bucket)}">Check</button></div>
      <div class="detail">first seen via ${esc(b.source)} ${b.sourceUrl ? '· ' + esc(b.sourceUrl) : ''}</div>
      <div class="detail">${statusHtml}</div>
      ${openBtn}
    </div>
  `;
}

function renderAnalysis() {
  const endpoints = Object.values(state.analysis.endpoints || {}).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
  document.getElementById('count-endpoints').textContent = endpoints.length || '';
  document.getElementById('sub-endpoints').innerHTML = endpoints.length ? endpoints.map(e => `
    <div class="row">
      <div class="row-top">${(e.methods || []).map(m => `<span class="method ${esc(m)}">${esc(m)}</span>`).join('')}<span class="url">${esc(e.path)}</span></div>
      <div class="detail">${esc(e.origin || '')} · source: ${esc(e.source)} · seen ${e.seenCount || 1}×</div>
    </div>
  `).join('') : '<div class="empty-msg">No endpoints discovered yet.</div>';

  const ops = Object.values(state.analysis.graphqlOps || {}).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
  document.getElementById('count-graphql').textContent = ops.length || '';
  document.getElementById('sub-graphql').innerHTML = ops.length ? ops.map(o => `
    <div class="row">
      <div class="row-top"><span class="method POST">${esc(o.operationType)}</span><span class="url">${esc(o.operationName)}</span></div>
      <div class="detail">endpoint: ${esc(o.endpoint)}\nfields: ${esc((o.fields || []).slice(0, 25).join(', '))}\nseen ${o.count}×</div>
    </div>
  `).join('') : '<div class="empty-msg">No GraphQL operations detected yet.</div>';

  const secrets = state.analysis.secrets || [];
  document.getElementById('count-secrets').textContent = secrets.length || '';
  document.getElementById('sub-secrets').innerHTML = secrets.length ? secrets.map(s => `
    <div class="row">
      <div class="row-top"><span class="badge ${esc(s.severity)}">${esc(s.severity)}</span><span class="url">${esc(s.type)}</span></div>
      <div class="detail">${esc(s.masked)}\n${s.url ? 'in: ' + esc(s.url) : ''} (${esc(s.source)})</div>
    </div>
  `).join('') : '<div class="empty-msg">No secrets/credentials detected yet.</div>';

  const jwts = state.analysis.jwts || [];
  document.getElementById('count-jwts').textContent = jwts.length || '';
  document.getElementById('sub-jwts').innerHTML = jwts.length ? jwts.map(j => `
    <div class="row">
      <div class="row-top"><span class="url">${esc(j.tokenMasked)}</span><span style="color:var(--muted)">alg=${esc(j.header?.alg)}</span></div>
      <div class="detail">claims: ${esc(j.claims.join(', '))}\n${(j.issues || []).map(i => `⚠ ${esc(i.note)}`).join('\n')}</div>
    </div>
  `).join('') : '<div class="empty-msg">No JWTs detected yet.</div>';

  const idor = state.analysis.idorCandidates || [];
  document.getElementById('count-idor').textContent = idor.length || '';
  document.getElementById('sub-idor').innerHTML = idor.length ? idor.map((c, i) => `
    <div class="row">
      <div class="row-top"><span class="method ${esc(c.method)}">${esc(c.method)}</span><span class="badge ${c.pattern === 'keyword-match' ? 'low' : 'medium'}">${esc(c.pattern)}</span><span class="url">${esc(c.location)}: ${esc(c.detail)} = ${esc(c.value)}</span></div>
      <div class="detail">${esc(c.url)}</div>
      <button class="btn btn-ghost idor-send-btn" data-idx="${i}" style="margin-top:6px;">Send to Repeater</button>
    </div>
  `).join('') : '<div class="empty-msg">No IDOR candidates flagged yet.</div>';
  document.querySelectorAll('.idor-send-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const c = idor[Number(btn.dataset.idx)];
      const entry = state.history.find(h => h.id === c.historyId);
      if (entry) sendHistoryToRepeater(entry, c.value);
    });
  });

  const buckets = Object.values(state.analysis.s3Buckets || {}).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
  document.getElementById('count-s3').textContent = buckets.length || '';
  document.getElementById('sub-s3').innerHTML = buckets.length ? buckets.map(b => renderS3Row(b)).join('') : '<div class="empty-msg">No S3 bucket references discovered yet.</div>';
  document.querySelectorAll('.s3-check-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      btn.disabled = true; btn.textContent = 'Checking…';
      const res = await send({ type: 'CHECK_S3_BUCKET', bucket: btn.dataset.bucket });
      if (state.analysis.s3Buckets[btn.dataset.bucket]) state.analysis.s3Buckets[btn.dataset.bucket].checkResult = res?.result;
      renderAnalysis();
    });
  });
  document.querySelectorAll('.s3-open-btn').forEach(btn => {
    btn.addEventListener('click', () => openInBrowser('application/xml', btn.dataset.raw));
  });
}

// ================= TAKEOVER =================

async function loadTakeoverHosts() {
  const res = await send({ type: 'GET_TAKEOVER_HOSTS' });
  state.takeoverHosts = res?.hosts || [];
  state.takeoverResults = res?.results || {};
  renderTakeover();
}

function renderTakeover() {
  document.getElementById('count-takeover').textContent = state.takeoverHosts.length || '';
  const el = document.getElementById('takeoverList');
  if (!state.takeoverHosts.length) {
    el.innerHTML = '<div class="empty-msg">No hostnames yet — browse an authorized target or add one above.</div>';
    return;
  }
  el.innerHTML = state.takeoverHosts.map(host => {
    const r = state.takeoverResults[host];
    let statusHtml = '<span style="color:var(--muted)">not checked</span>';
    if (r) {
      if (!r.ok) statusHtml = `<span class="badge medium">error</span> ${esc(r.error)}`;
      else if (r.verdict === 'no-cname') statusHtml = '<span class="badge info">no CNAME record</span>';
      else if (r.verdict === 'cname-not-watched') statusHtml = `<span class="badge info">CNAME → ${esc(r.cname)} (not a watched suffix)</span>`;
      else if (r.verdict === 'vulnerable') statusHtml = `<span class="badge high">looks unclaimed on ${esc(r.service)} — possible takeover</span>`;
      else if (r.verdict === 'claimed-or-active') statusHtml = `<span class="badge info">CNAME → ${esc(r.cname)} (${esc(r.service)}), appears claimed</span>`;
      else if (r.verdict === 'manual-check-needed') statusHtml = `<span class="badge medium">CNAME → ${esc(r.cname)} (${esc(r.service)}) — no verified fingerprint, check manually</span>`;
      else statusHtml = `<span class="badge low">${esc(r.verdict)}</span>`;
    }
    return `
      <div class="row">
        <div class="row-top"><span class="url">${esc(host)}</span><button class="btn btn-ghost takeover-check-btn" data-host="${esc(host)}">Check</button></div>
        <div class="detail">${statusHtml}</div>
      </div>
    `;
  }).join('');

  el.querySelectorAll('.takeover-check-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const host = btn.dataset.host;
      btn.disabled = true; btn.textContent = 'Checking…';
      const granted = await chrome.permissions.request({ origins: [`https://${host}/*`] });
      if (!granted) { btn.disabled = false; btn.textContent = 'Check'; return; }
      const res = await send({ type: 'CHECK_TAKEOVER', hostname: host });
      state.takeoverResults[host] = res?.result;
      renderTakeover();
    });
  });
}

document.getElementById('addTakeoverHostBtn').addEventListener('click', async () => {
  const input = document.getElementById('newTakeoverHostInput');
  const host = input.value.trim();
  if (!host) return;
  await send({ type: 'ADD_TAKEOVER_HOST', hostname: host });
  input.value = '';
  await loadTakeoverHosts();
});

document.querySelector('.subtab[data-subtab="takeover"]').addEventListener('click', loadTakeoverHosts);

// ================= DATA LOADING =================

async function loadHistoryAndAnalysis() {
  const [hRes, aRes] = await Promise.all([send({ type: 'GET_HISTORY' }), send({ type: 'GET_ANALYSIS' })]);
  state.history = hRes?.history || [];
  state.analysis = {
    secrets: aRes?.secrets || [],
    jwts: aRes?.jwts || [],
    endpoints: aRes?.endpoints || {},
    graphqlOps: aRes?.graphqlOps || {},
    idorCandidates: aRes?.idorCandidates || [],
    s3Buckets: aRes?.s3Buckets || {},
  };
  renderHistoryTable();
  renderHistoryDetail();
  renderAnalysis();
}

async function loadScope() {
  const [tRes, sRes] = await Promise.all([send({ type: 'GET_TARGETS' }), send({ type: 'GET_SCOPE' })]);
  state.targets = tRes?.targets || [];
  state.scope = sRes?.scope || { includePatterns: [], excludePatterns: [] };
  renderScope();
}

async function loadRepeaterItems() {
  const res = await send({ type: 'GET_REPEATER_ITEMS' });
  state.repeaterItems = (res?.items || []).map(i => ({ respView: 'pretty', ...i }));
  if (!state.selectedRepeaterId && state.repeaterItems.length) state.selectedRepeaterId = state.repeaterItems[0].id;
  renderRepeaterTabs();
  renderRepeaterBody();
}

(async function init() {
  setupResizer();
  await loadHistoryAndAnalysis();
  await loadScope();
  await loadRepeaterItems();
  setInterval(loadHistoryAndAnalysis, 2000);
})();
