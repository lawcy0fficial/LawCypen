// injected.js — MAIN world. DevTools network capture now handles fetch/XHR
// with full accuracy (real status codes, all resource types), so this file
// only needs to cover what chrome.devtools.network doesn't expose well:
// WebSocket frame-level messages.
(function () {
  if (window.__lawcypenWsInstalled) return;
  window.__lawcypenWsInstalled = true;

  const MARKER = '__LAWCYPEN_WS_EVENT__';
  let counter = 0;
  const nextId = () => `ws_${Date.now()}_${counter++}`;

  function post(payload) {
    window.postMessage({ marker: MARKER, payload }, '*');
  }

  const OrigWS = window.WebSocket;
  function PatchedWS(url, protocols) {
    const ws = protocols !== undefined ? new OrigWS(url, protocols) : new OrigWS(url);
    const id = nextId();
    post({ kind: 'websocket-open', id, url, method: 'WS' });

    ws.addEventListener('message', (evt) => {
      post({
        kind: 'websocket', id, url, method: 'WS-IN', status: null,
        requestBody: null,
        responseBody: typeof evt.data === 'string' ? evt.data.slice(0, 8000) : '[binary]',
      });
    });

    const origWsSend = ws.send.bind(ws);
    ws.send = function (data) {
      post({
        kind: 'websocket', id, url, method: 'WS-OUT', status: null,
        requestBody: typeof data === 'string' ? data.slice(0, 8000) : '[binary]',
        responseBody: null,
      });
      return origWsSend(data);
    };
    return ws;
  }
  PatchedWS.prototype = OrigWS.prototype;
  window.WebSocket = PatchedWS;
})();
