// viewer/viewer.js
const params = new URLSearchParams(location.search);
const id = params.get('id');
const metaEl = document.getElementById('meta');
const mainEl = document.getElementById('main');
const warnEl = document.getElementById('warn');
const btnRendered = document.getElementById('btn-rendered');
const btnRaw = document.getElementById('btn-raw');

let record = null;
let mode = 'rendered';

function escapeHtml(str) {
  return (str ?? '').toString().replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function isHtml(ct) { return /html/i.test(ct || ''); }
function isJson(ct, body) {
  if (/json/i.test(ct || '')) return true;
  const t = (body || '').trim();
  return (t.startsWith('{') || t.startsWith('[')) && (() => { try { JSON.parse(t); return true; } catch { return false; } })();
}

function render() {
  if (!record) {
    mainEl.innerHTML = '<pre>Nothing found for this view — the data may have expired (it only lives for this browser session).</pre>';
    return;
  }
  const { contentType, body } = record;

  if (mode === 'raw' || !isHtml(contentType)) {
    let display = body;
    if (isJson(contentType, body)) {
      try { display = JSON.stringify(JSON.parse(body), null, 2); } catch (e) {}
    }
    mainEl.innerHTML = `<pre>${escapeHtml(display)}</pre>`;
    warnEl.style.display = 'none';
    return;
  }

  // rendered HTML mode — sandboxed, no allow-same-origin, so it executes in
  // a unique opaque origin with no access to the real site's cookies/storage.
  warnEl.style.display = 'block';
  mainEl.innerHTML = '';
  const iframe = document.createElement('iframe');
  iframe.setAttribute('sandbox', 'allow-scripts');
  iframe.srcdoc = body;
  mainEl.appendChild(iframe);
}

btnRendered.addEventListener('click', () => {
  mode = 'rendered';
  btnRendered.classList.add('active'); btnRaw.classList.remove('active');
  render();
});
btnRaw.addEventListener('click', () => {
  mode = 'raw';
  btnRaw.classList.add('active'); btnRendered.classList.remove('active');
  render();
});

(async function init() {
  if (!id) { metaEl.textContent = 'no id provided'; return; }
  try {
    const result = await chrome.storage.session.get(`view:${id}`);
    record = result[`view:${id}`] || null;
  } catch (e) {
    record = null;
  }
  metaEl.textContent = record ? (record.contentType || 'text/plain') + ` · ${(record.body || '').length} chars` : 'not found';
  if (!isHtml(record?.contentType)) {
    btnRendered.style.display = 'none';
    mode = 'raw';
    btnRaw.classList.add('active');
  }
  render();
})();
