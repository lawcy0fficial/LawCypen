// modules/s3Detector.js
// Finds S3 bucket references in scanned text. Detection only — the actual
// "is it public/does it even exist" check is a separate, single, explicit
// fetch triggered by the user per-bucket (see background.js checkS3Bucket),
// never an automatic loop over every bucket found.

const VHOST_RE = /([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/gi;
const PATH_RE = /s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])/gi;
const URI_RE = /s3:\/\/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])/gi;

export function extractS3Buckets(text, ctx = {}) {
  if (!text || typeof text !== 'string') return [];
  const found = new Map();

  for (const re of [VHOST_RE, PATH_RE, URI_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const bucket = m[1].toLowerCase();
      if (bucket.length < 3 || bucket.length > 63) continue;
      if (!found.has(bucket)) {
        found.set(bucket, { bucket, sourceUrl: ctx.url || null, source: ctx.source || 'unknown', foundAt: Date.now() });
      }
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return Array.from(found.values());
}
