// content-script.js — isolated world. Relays WebSocket frame events from
// injected.js, and scrapes inline + same-origin script content for static
// analysis (endpoints/secrets/JWTs the script-scanner can find even before
// any matching network request fires).

const MARKER = '__LAWCYPEN_WS_EVENT__';
const origin = location.origin;

window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data || data.marker !== MARKER) return;

  chrome.runtime.sendMessage({
    type: 'WS_TRAFFIC',
    origin,
    payload: data.payload,
  }).catch(() => {});
});

// ---- script scraping ----

const scannedUrls = new Set();

async function scanInlineScripts() {
  const scripts = document.querySelectorAll('script:not([src])');
  for (const s of scripts) {
    const text = s.textContent;
    if (text && text.length > 20) {
      chrome.runtime.sendMessage({
        type: 'SCRIPT_SCAN',
        origin,
        payload: { text, url: location.href },
      }).catch(() => {});
    }
  }
}

async function scanExternalScripts() {
  const scripts = document.querySelectorAll('script[src]');
  for (const s of scripts) {
    const src = s.src;
    if (!src || scannedUrls.has(src)) continue;
    scannedUrls.add(src);
    try {
      const u = new URL(src);
      if (u.origin !== origin) continue;
      const res = await fetch(src, { credentials: 'omit' });
      const text = await res.text();
      chrome.runtime.sendMessage({
        type: 'SCRIPT_SCAN',
        origin,
        payload: { text, url: src },
      }).catch(() => {});
    } catch (e) { /* unreachable or CORS-blocked, skip */ }
  }
}

function runScan() {
  scanInlineScripts();
  scanExternalScripts();
}

if (document.readyState === 'complete' || document.readyState === 'interactive') {
  runScan();
} else {
  document.addEventListener('DOMContentLoaded', runScan, { once: true });
}

let debounceTimer = null;
const observer = new MutationObserver(() => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(runScan, 1500);
});
observer.observe(document.documentElement, { childList: true, subtree: true });
