// devtools/devtools.js
// Runs in the special DevTools page context. Forwards every finished
// request to the background worker. Two correctness fixes over the first
// version:
//   1. getContent() is wrapped with a timeout — if it never calls back
//      (happens for cancelled/redirected/odd responses), we still send the
//      request's metadata instead of silently dropping it from History.
//   2. The `encoding` argument from getContent() is now checked — some
//      responses come back base64-encoded even for text mime types, and
//      storing that as-is produced garbled, "inaccurate" bodies.

chrome.devtools.panels.create('lawCYpen', 'icons/icon48.png', 'panel/panel.html');

const inspectedTabId = chrome.devtools.inspectedWindow.tabId;

function headerArrayToObject(headers) {
  const obj = {};
  (headers || []).forEach(h => { obj[h.name] = h.value; });
  return obj;
}

function getContentSafe(request, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (content, encoding) => {
      if (done) return;
      done = true;
      resolve({ content: content || '', encoding: encoding || '' });
    };
    const timer = setTimeout(() => finish('', ''), timeoutMs);
    try {
      request.getContent((content, encoding) => {
        clearTimeout(timer);
        finish(content, encoding);
      });
    } catch (e) {
      clearTimeout(timer);
      finish('', '');
    }
  });
}

function decodeBody(content, encoding) {
  if (!content) return '';
  if (encoding === 'base64') {
    try { return atob(content); } catch (e) { return '[base64-encoded content, could not decode as text]'; }
  }
  return content;
}

chrome.devtools.network.onRequestFinished.addListener((request) => {
  (async () => {
    try {
      const req = request.request || {};
      const res = request.response || {};
      const url = req.url;
      if (!url || !/^https?:\/\//i.test(url)) return;

      const method = req.method;
      const requestHeaders = headerArrayToObject(req.headers);
      const requestBody = (req.postData && req.postData.text) || null;

      const status = res.status;
      const statusText = res.statusText;
      const responseHeaders = headerArrayToObject(res.headers);
      const mimeType = (res.content && res.content.mimeType) || '';
      const sizeBytes = (res.content && res.content.size) || 0;
      const timeMs = request.time || 0;

      const { content, encoding } = await getContentSafe(request);
      const responseBody = decodeBody(content, encoding);

      chrome.runtime.sendMessage({
        type: 'DEVTOOLS_TRAFFIC',
        tabId: inspectedTabId,
        payload: {
          url, method, status, statusText, mimeType, sizeBytes, timeMs,
          requestHeaders, requestBody,
          responseHeaders, responseBody,
          timestamp: Date.now(),
        },
      }).catch(() => {});
    } catch (e) {
      // a single malformed entry shouldn't break capture of everything else
    }
  })();
});
