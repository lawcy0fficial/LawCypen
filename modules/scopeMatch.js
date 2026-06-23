// modules/scopeMatch.js
// Simple glob matching for scope rules: '*' matches any run of characters.
// Patterns are matched against both the full URL and the bare origin, so
// "https://api.example.com/*" and "*.example.com" both work as expected.

function globToRegex(glob) {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp('^' + escaped + '$', 'i');
}

export function matchesPattern(pattern, url, origin) {
  if (!pattern) return false;
  const re = globToRegex(pattern.trim());
  return re.test(url) || re.test(origin) || re.test(origin + '/*'.slice(0, 0)) || re.test(origin);
}

/**
 * Decide if a URL is in scope.
 * @param {string} url
 * @param {string[]} includePatterns - if empty, nothing is in scope (deny by default)
 * @param {string[]} excludePatterns
 */
export function isInScope(url, includePatterns = [], excludePatterns = []) {
  let origin;
  try { origin = new URL(url).origin; } catch (e) { return false; }

  if (!includePatterns.length) return false;
  const included = includePatterns.some(p => matchesPattern(p, url, origin));
  if (!included) return false;

  const excluded = excludePatterns.some(p => matchesPattern(p, url, origin));
  if (excluded) return false;

  return true;
}
