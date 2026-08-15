/**
 * Agentborder — Web Bot Auth signature verification (RFC 9421 profile)
 *
 * Implements the "web-bot-auth" profile of HTTP Message Signatures:
 *  - Parses Signature-Input / Signature headers
 *  - Rebuilds the signature base using the RAW inner-list string from
 *    Signature-Input as the "@signature-params" line (avoids re-serialization drift)
 *  - Verifies Ed25519 signatures against JWKs (RFC 7638 thumbprint = keyid)
 *  - Enforces tag="web-bot-auth", created/expires windows
 *
 * Design constraints (must hold — see CONTRIBUTING.md):
 *  - Synchronous on the request path. Key material comes from an in-memory cache;
 *    cache misses trigger a throttled BACKGROUND refresh and this request is
 *    classified "signature-presented" (never blocked, never falsely "verified").
 *  - Fail-open: any internal error returns {status:'error'} and the caller
 *    must treat it as unverified-but-presented.
 *
 * Supported covered components: @authority, @method, @path, signature-agent,
 * and any plain request header (lowercase). Unsupported components →
 * {status:'unsupported'} (honest: we do not verify what we cannot reconstruct).
 *
 * Algorithms: Ed25519 (per the WBA architecture draft examples).
 * RSA-PSS-SHA512 is on the roadmap; HMAC is intentionally NOT supported
 * (the spec prohibits shared-key signatures).
 */

'use strict';

const crypto = require('node:crypto');

/* ── RFC 7638 JWK thumbprint (OKP/Ed25519) ───────────────────── */

function jwkThumbprint(jwk) {
  if (jwk.kty !== 'OKP') throw new Error('only OKP (Ed25519) keys supported');
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return crypto.createHash('sha256').update(canonical).digest('base64url');
}

/* ── header parsing ──────────────────────────────────────────── */

// Signature-Input: sig1=("@authority" "signature-agent");created=...;expires=...;keyid="...";tag="web-bot-auth"
function parseSignatureInput(raw) {
  const eq = raw.indexOf('=');
  if (eq < 0) return null;
  const label = raw.slice(0, eq).trim();
  const inner = raw.slice(eq + 1).trim();          // RAW string — reused verbatim in the base
  const m = inner.match(/^\(([^)]*)\)(.*)$/s);
  if (!m) return null;
  const components = (m[1].match(/"[^"]+"/g) || []).map(s => s.slice(1, -1));
  const params = {};
  for (const pm of m[2].matchAll(/;\s*([a-zA-Z0-9_-]+)(?:="([^"]*)"|=([0-9]+))?/g)) {
    params[pm[1]] = pm[2] !== undefined ? pm[2] : (pm[3] !== undefined ? Number(pm[3]) : true);
  }
  return { label, inner, components, params };
}

// Signature: sig1=:BASE64:
function parseSignature(raw, label) {
  const m = raw.match(new RegExp(`(?:^|,)\\s*${label}=:([A-Za-z0-9+/=]+):`));
  return m ? Buffer.from(m[1], 'base64') : null;
}

/* ── signature base ──────────────────────────────────────────── */

function componentValue(name, req) {
  if (name === '@authority') return String(req.headers.host || '').toLowerCase();
  if (name === '@method') return String(req.method || '').toUpperCase();
  if (name === '@path') return String(req.url || '').split('?')[0];
  if (name.startsWith('@')) return undefined;                 // unsupported derived component
  const v = req.headers[name.toLowerCase()];
  return v === undefined ? undefined : String(v);
}

function buildBase(components, rawInner, req) {
  const lines = [];
  for (const c of components) {
    const v = componentValue(c, req);
    if (v === undefined) return { unsupported: c };
    lines.push(`"${c}": ${v}`);
  }
  lines.push(`"@signature-params": ${rawInner}`);
  return { base: lines.join('\n') };
}

/* ── key resolvers ───────────────────────────────────────────── */

/** Static resolver for tests/self-hosted trust lists. jwks: array of JWK (OKP). */
function createStaticResolver(jwks, meta = {}) {
  const map = new Map();
  for (const jwk of jwks) {
    const thumb = jwkThumbprint(jwk);
    map.set(thumb, { jwk, agent: meta[thumb] || meta[jwk.kid] || null });
    if (jwk.kid) map.set(jwk.kid, { jwk, agent: meta[jwk.kid] || null });
  }
  return {
    getKey: (keyid) => map.get(keyid) || null,
    requestRefresh: () => {},                                  // no-op
  };
}

/**
 * Directory resolver: fetches JWKS documents from vendor key directories
 * (e.g. https://<vendor>/.well-known/http-message-signatures-directory).
 * getKey() is synchronous from cache; misses schedule a throttled background fetch.
 */
function createDirectoryResolver({ directories = [], ttlMs = 6 * 3600_000, minRefreshGapMs = 60_000 } = {}) {
  const cache = new Map();      // keyid -> {jwk, agent}
  let lastRefresh = 0, refreshing = false;

  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      for (const dir of directories) {
        try {
          const res = await fetch(dir.url, { headers: { accept: 'application/http-message-signatures-directory+json, application/json' } });
          if (!res.ok) continue;
          const doc = await res.json();
          for (const jwk of (doc.keys || [])) {
            if (jwk.kty !== 'OKP') continue;
            try { cache.set(jwkThumbprint(jwk), { jwk, agent: dir.agent || null }); } catch {}
          }
        } catch { /* fail-open: directory unreachable */ }
      }
      lastRefresh = Date.now();
    } finally { refreshing = false; }
  }

  return {
    getKey: (keyid) => cache.get(keyid) || null,
    requestRefresh: () => {
      const now = Date.now();
      if (now - lastRefresh > Math.min(ttlMs, minRefreshGapMs) && !refreshing) refresh();
    },
    refresh,                                                    // manual/eager warm-up
  };
}

/* ── verifier ────────────────────────────────────────────────── */

/**
 * createVerifier({resolver, maxSkewSec=300, maxAgeSec=86400})
 * verifySync(req) → { status, keyid?, agent?, reason? }
 *   status ∈ verified | invalid | unknown-key | expired | not-wba |
 *            unsupported | malformed | none | error
 */
function createVerifier({ resolver, maxSkewSec = 300, maxAgeSec = 86_400 } = {}) {
  if (!resolver) throw new Error('createVerifier requires a resolver');

  function verifySync(req) {
    try {
      const siRaw = req.headers['signature-input'];
      const sigRaw = req.headers['signature'];
      if (!siRaw || !sigRaw) return { status: 'none' };

      const si = parseSignatureInput(String(siRaw));
      if (!si) return { status: 'malformed' };
      if (si.params.tag !== 'web-bot-auth') return { status: 'not-wba' };
      if (!si.params.keyid) return { status: 'malformed', reason: 'missing keyid' };

      const now = Math.floor(Date.now() / 1000);
      const { created, expires } = si.params;
      if (typeof created !== 'number' || created > now + maxSkewSec)
        return { status: 'malformed', reason: 'bad created' };
      if (typeof expires === 'number' ? expires < now - maxSkewSec
                                      : now - created > maxAgeSec)
        return { status: 'expired' };

      const sig = parseSignature(String(sigRaw), si.label);
      if (!sig) return { status: 'malformed', reason: 'missing signature bytes' };

      const entry = resolver.getKey(si.params.keyid);
      if (!entry) { resolver.requestRefresh(); return { status: 'unknown-key', keyid: si.params.keyid }; }

      const built = buildBase(si.components, si.inner, req);
      if (built.unsupported) return { status: 'unsupported', reason: built.unsupported };

      const keyObj = crypto.createPublicKey({ key: entry.jwk, format: 'jwk' });
      const ok = crypto.verify(null, Buffer.from(built.base, 'utf8'), keyObj, sig);
      return ok
        ? { status: 'verified', keyid: si.params.keyid, agent: entry.agent }
        : { status: 'invalid', keyid: si.params.keyid };
    } catch (err) {
      return { status: 'error', reason: String(err) };          // fail-open upstream
    }
  }

  return { verifySync };
}

module.exports = { createVerifier, createStaticResolver, createDirectoryResolver, jwkThumbprint };
