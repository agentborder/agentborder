/**
 * Agentborder — Web Bot Auth request signer (test / agent-SDK helper).
 *
 * Produces Signature-Input / Signature headers for an outgoing request using an
 * Ed25519 private key, following the same RFC 9421 "web-bot-auth" profile that
 * verify.js checks. Kept in the OSS core so the verifier is provably correct
 * (round-trip test) and so agent developers have a reference signer.
 */
'use strict';

const crypto = require('node:crypto');
const { jwkThumbprint } = require('./verify.js');

/** Generate an Ed25519 keypair as JWKs (kid = RFC 7638 thumbprint). */
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'jwk' });
  const priv = privateKey.export({ format: 'jwk' });
  const kid = jwkThumbprint(pub);
  pub.kid = kid; priv.kid = kid;
  return { publicJwk: pub, privateJwk: priv, kid };
}

/**
 * signRequest({ method, authority, path, headers?, privateJwk,
 *               components?, created?, expiresInSec?, label? })
 *  → { 'signature-input': ..., 'signature': ... }
 */
function signRequest(opts) {
  const {
    method, authority, path, headers = {}, privateJwk,
    components = ['@authority', '@method', '@path'],
    created = Math.floor(Date.now() / 1000),
    expiresInSec = 3600,
    label = 'sig1',
  } = opts;

  const expires = created + expiresInSec;
  const keyid = privateJwk.kid || jwkThumbprint(privateJwk);
  const inner = `(${components.map(c => `"${c}"`).join(' ')})` +
    `;created=${created};expires=${expires};keyid="${keyid}";tag="web-bot-auth"`;

  const lower = {};
  for (const k of Object.keys(headers)) lower[k.toLowerCase()] = headers[k];
  const req = { method, url: path, headers: { host: authority, ...lower } };

  const lines = [];
  for (const c of components) {
    let v;
    if (c === '@authority') v = String(authority).toLowerCase();
    else if (c === '@method') v = String(method).toUpperCase();
    else if (c === '@path') v = String(path).split('?')[0];
    else v = String(req.headers[c.toLowerCase()]);
    lines.push(`"${c}": ${v}`);
  }
  lines.push(`"@signature-params": ${inner}`);
  const base = lines.join('\n');

  const keyObj = crypto.createPrivateKey({ key: privateJwk, format: 'jwk' });
  const sig = crypto.sign(null, Buffer.from(base, 'utf8'), keyObj);

  return {
    'signature-input': `${label}=${inner}`,
    'signature': `${label}=:${sig.toString('base64')}:`,
  };
}

module.exports = { generateKeyPair, signRequest };
