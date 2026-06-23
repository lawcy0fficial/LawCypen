# lawCYpen

A Burp-style HTTP traffic console built into Chrome DevTools: full traffic capture, HTTP History, Repeater, Scope, and a growing set of passive analyzers (endpoints, secrets, JWTs, GraphQL).

## Load it

1. `chrome://extensions` → enable Developer mode → "Load unpacked" → select this folder
2. Open the extension popup on your target tab → **Authorize & monitor this site** (this is also where you'll manage scope later, in the panel itself)
3. Open DevTools (F12) on that tab → click the **lawCYpen** tab (next to Elements/Console/Network)
4. Browse the site — HTTP History fills in live

## What's where (Burp equivalents, for orientation)

| lawCYpen tab | Roughly like |
|---|---|
| HTTP History | Proxy → HTTP history |
| Repeater | Repeater |
| Scope | Target → Scope |
| Analysis | not a Burp feature — bonus passive scanners (endpoints/secrets/JWTs/GraphQL) |

## How capture actually works (and why it's accurate)

History is captured via `chrome.devtools.network.onRequestFinished` — the same API backing the real Network panel. That's why status codes, sizes, timing, and bodies are accurate for every resource type (XHR/fetch, navigations, images, fonts, everything), not just JS-initiated requests like before. **It only captures while DevTools is open**, same as the Network tab — exactly like before you opened it, the Network tab shows nothing either.

WebSocket frame-level messages aren't exposed by that API, so those still come from the injected page hook (`injected.js`), same mechanism as the previous version.

## Scope — and why it matters here specifically

`chrome.devtools.network` doesn't check host permissions — DevTools can observe whatever tab it's attached to, regardless of what you've authorized. So scope filtering is enforced in software (`background.js` checks every captured request against your target list + include/exclude patterns before it's stored). Nothing is silently logged for an origin you haven't added. Add custom include/exclude wildcard patterns in the Scope tab to cut analytics/CDN noise out of an otherwise-authorized target.

The Repeater fetch (sending edited requests) *does* require the host permission grant from Authorize — that's what lets it bypass CORS for that origin, the same way a real proxy would just send the bytes.

## Repeater — the one place this can't be 100% Burp

Repeater sends through the browser's `fetch`, not a raw socket. The browser refuses to let any page or extension manually set a handful of headers it considers its own to control: `Cookie`, `Host`, `Origin`, `Content-Length`, `Connection`, and a few others. Practical effect:

- You **can** freely edit method, path, query, custom headers, and body — full request tampering for IDOR/mass-assignment/parameter testing works fine.
- Your **actual session cookies still go out automatically** (Repeater sends with `credentials: 'include'`), so authenticated replay works exactly like clicking around the app.
- You **cannot** type a *different* literal `Cookie:` value into the header box and have it override the real one — the browser drops it. If you see a "browser-controlled headers not sent as typed" note under a response, that's why. For session-swap testing (replay as a different role/account), the upcoming Role-based replay engine will solve this properly by storing distinct captured sessions rather than fighting the header restriction.

## Open response in browser

Renders the response body in a new tab. HTML responses render inside a **sandboxed, originless iframe** (`sandbox="allow-scripts"`, no `allow-same-origin`) — scripts can run so you can see whether a payload actually executes, but that frame has zero access to the real site's cookies, storage, or session. JSON gets pretty-printed automatically.

## Architecture

```
chrome.devtools.network (DevTools page) ──┐
injected.js (WS frames, MAIN world) ───────┼──→ background.js ──→ chrome.storage (history, findings, scope, repeater items)
content-script.js (script scraping) ───────┘         ↑
                                                       │ chrome.runtime.sendMessage
panel.js (the lawCYpen DevTools panel) ────────────────┘
```

Analyzer modules (`modules/*.js`) are plain `scan(text, ctx) -> findings[]` functions called from `background.js`. Adding a new one means: write the function, call it where traffic/script text is processed, render its output in the Analysis tab.

## IDOR candidates, S3 buckets, and subdomain takeover

Three more detectors, all in the Analysis tab, all following the same rule as everything else here: **flag, don't auto-exploit.**

**IDOR candidates** — every captured request is scanned for numeric IDs, UUIDs, and Mongo-style ObjectIds in the path, query string, or JSON body (plus common id-shaped key names like `userId`/`accountId`). Each candidate links back to its original request — "Send to Repeater" pre-fills the editor so *you* swap the value and fire it.

**S3 buckets** — bucket names found in JS source or traffic (virtual-hosted, path-style, and `s3://` forms) show up with a **Check** button. Checking does exactly one GET to `https://s3.amazonaws.com/<bucket>` and reads the response:
- `200` + `<ListBucketResult>` → **publicly listable**. You'll see the object key list (the literal content of that one response) with an "Open listing in browser" link.
- `403` + `AccessDenied` → private, properly secured.
- `404` + `NoSuchBucket` → **the bucket doesn't exist at all** — its own finding: if a CNAME points here, anyone can register that exact bucket name and take over the subdomain.

What this deliberately does **not** do: bulk-download every object's contents. A public listing is enough evidence for a finding and a fix (tighten the bucket policy); mass-pulling actual file contents is a separate, deliberate decision with real data-handling stakes, and stays outside what this tool automates.

**Takeover (CNAME) detection** — lists hostnames seen in scoped traffic, plus any added manually. **Check** does a DNS-over-HTTPS CNAME lookup, and if the target matches a known dangling-service suffix, one GET to the hostname to look for an "unclaimed" fingerprint. GitHub Pages and Heroku have verified fingerprints; other common PaaS suffixes (Azure, Fastly, Netlify, Surge, Pantheon, etc.) are flagged but reported as `manual-check-needed` rather than guessed at, since fingerprint text drifts and an asserted-but-wrong verdict is worse than an honest "go look."

Nothing here registers, claims, or creates any resource. Claiming a dangling resource as a PoC/fix is a deliberate action you take yourself, outside the tool.

**New fixed permissions:** `https://dns.google/*` (CNAME lookups) and `https://s3.amazonaws.com/*` (bucket checks) — narrow, single-purpose, separate from per-target Scope grants. Checking a takeover hostname still prompts its own one-time permission grant.

## Roadmap

Not built yet:

- **Mass-assignment detector** — diff a request's JSON body shape against the response shape; manual-Repeater-replay to test if an extra field sticks.
- **OAuth flow recorder** — passive: pattern-match `state`/PKCE/`code` params already sitting in History; flag missing `state` or implicit-grant usage.
- **Role-based replay engine** — capture one session per role explicitly, then a "replay as role X" action that swaps the stored session in, properly solving the Cookie-header restriction noted above.
- **CSP bypass analyzer** — parse `Content-Security-Policy` headers already visible in History; flag known bypass-prone configs. Report only.
- **Business-logic workflow recorder** — mark a start/end range over existing History rows and name the sequence; derived view, no new capture needed.
- **AI-assisted finding correlation** — summarize relationships between findings already in Analysis.
- **Client-side source-to-sink XSS tracking** — wrap DOM sinks (`innerHTML`, `document.write`, etc.) in `injected.js`, report source→sink flow. Reporting only.
- **Hidden admin route discovery** — mine the Endpoints list + scanned JS for admin-shaped paths with no visible link.
- **OpenAPI/Swagger auto-import** — fetch + parse a spec, diff against discovered Endpoints.



## Notes

- `chrome.storage.session` (History/findings) clears when the browser closes. `chrome.storage.local` (targets, scope, Repeater items) persists.
- History is capped at 400 entries and body previews at ~8KB to stay within storage quota; Repeater "Send" results aren't subject to that cap.
- Use only on systems you have written authorization to test.
