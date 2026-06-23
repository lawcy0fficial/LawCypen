// popup/popup.js
const currentOriginEl = document.getElementById('currentOrigin');
const authorizeBtn = document.getElementById('authorizeBtn');
const targetListEl = document.getElementById('targetList');
const emptyStateEl = document.getElementById('emptyState');

let currentOrigin = null;

function originPattern(origin) { return origin + '/*'; }

async function getActiveTabOrigin() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return null;
  try {
    const u = new URL(tab.url);
    if (!['http:', 'https:'].includes(u.protocol)) return null;
    return u.origin;
  } catch (e) {
    return null;
  }
}

async function refreshTargetList() {
  const res = await chrome.runtime.sendMessage({ type: 'GET_TARGETS' });
  const targets = (res && res.targets) || [];
  targetListEl.innerHTML = '';
  emptyStateEl.style.display = targets.length ? 'none' : 'block';

  for (const origin of targets) {
    const li = document.createElement('li');
    li.className = 'target-item';
    const span = document.createElement('span');
    span.textContent = origin;
    const btn = document.createElement('button');
    btn.className = 'remove-btn';
    btn.textContent = 'Remove';
    btn.onclick = async () => {
      await chrome.runtime.sendMessage({ type: 'REMOVE_TARGET', origin });
      refreshTargetList();
    };
    li.appendChild(span);
    li.appendChild(btn);
    targetListEl.appendChild(li);
  }
  updateAuthorizeButton(targets);
}

function updateAuthorizeButton(targets) {
  if (!currentOrigin) {
    authorizeBtn.disabled = true;
    authorizeBtn.textContent = 'No HTTP(S) page active';
    return;
  }
  authorizeBtn.disabled = false;
  authorizeBtn.textContent = targets.includes(currentOrigin)
    ? 'Already monitoring this site'
    : 'Authorize & monitor this site';
}

authorizeBtn.addEventListener('click', async () => {
  if (!currentOrigin) return;
  const granted = await chrome.permissions.request({ origins: [originPattern(currentOrigin)] });
  if (!granted) return;
  await chrome.runtime.sendMessage({ type: 'ADD_TARGET', origin: currentOrigin });
  await refreshTargetList();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab) chrome.tabs.reload(tab.id);
});

(async function init() {
  currentOrigin = await getActiveTabOrigin();
  currentOriginEl.textContent = currentOrigin || '(not an http/https page)';
  await refreshTargetList();
})();
