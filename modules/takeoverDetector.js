// modules/takeoverDetector.js
// Classifies a CNAME target against known third-party hosting services that
// are common subdomain-takeover vectors when the underlying resource is
// unclaimed. Detection/fingerprinting only — never registers or claims
// anything. Fingerprints are only asserted where confidently documented;
// everything else is flagged "manual check needed" rather than guessed at.

export const KNOWN_SERVICES = [
  { suffix: 'github.io', name: 'GitHub Pages', confidence: 'high', fingerprint: /There isn't a GitHub Pages site here/i },
  { suffix: 'herokuapp.com', name: 'Heroku', confidence: 'high', fingerprint: /no such app/i },
];

// Suffixes worth flagging even without a verified fingerprint string —
// shows up as "manual check needed" rather than an asserted verdict.
const WATCH_SUFFIXES = [
  'azurewebsites.net', 'cloudfront.net', 'fastly.net', 'netlify.app',
  'surge.sh', 'bitbucket.io', 'zendesk.com', 'wordpress.com', 'tumblr.com',
  'pantheonsite.io', 'webflow.io', 'unbouncepages.com',
];

export function classifyCnameTarget(cnameTarget) {
  if (!cnameTarget) return null;
  const target = cnameTarget.toLowerCase().replace(/\.$/, '');
  const known = KNOWN_SERVICES.find(s => target.endsWith(s.suffix));
  if (known) return { ...known };
  const watched = WATCH_SUFFIXES.find(suf => target.endsWith(suf));
  if (watched) return { suffix: watched, name: watched, confidence: 'unverified', fingerprint: null };
  return null;
}
