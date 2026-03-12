/*
 * VULNERABILITY : Arbitrary File Access
 * TYPE          : Negative (safe)
 * DIFFICULTY    : Hard
 * DETECTION     : Should NOT be flagged — HMAC-signed token gates file access;
 *                 the user never controls the path directly
 * STATIC ANALYSIS VERDICT: Safe — the file path is derived entirely from an
 *                 HMAC-verified server-issued token; the raw user string (token)
 *                 is never used in path construction; only the decoded, verified
 *                 filename (which the server itself generated) reaches fs.readFile
 * ATTACK        : Attacker forges a token containing '../../../etc/passwd' as the
 *                 embedded filename
 * EFFECT        : crypto.timingSafeEqual rejects any token not signed with the
 *                 server's SECRET_KEY; a forged token fails verification before
 *                 the embedded filename is ever read
 */

'use strict';

const crypto = require('crypto');
const path   = require('path');
const fs     = require('fs');

const SECRET_KEY  = process.env.FILE_SECRET || crypto.randomBytes(32).toString('hex');
const DOCS_DIR    = path.resolve(__dirname, 'docs');

/** Issue a signed download token for a given filename (server-side only). */
function issueToken(filename) {
  const payload = Buffer.from(filename).toString('base64');
  const sig = crypto.createHmac('sha256', SECRET_KEY).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

/**
 * Serve a file referenced by a signed download token.
 * @param {string} rawToken  — untrusted token from query string
 */
function serveByToken(rawToken, callback) {
  // Split token into payload + signature
  const dotIdx = typeof rawToken === 'string' ? rawToken.lastIndexOf('.') : -1;
  if (dotIdx === -1) { callback(new Error('Malformed token')); return; }

  const payload = rawToken.slice(0, dotIdx);
  const sig     = rawToken.slice(dotIdx + 1);

  // Recompute expected signature
  const expectedSig = crypto.createHmac('sha256', SECRET_KEY).update(payload).digest('hex');

  // Constant-time comparison — prevents timing attacks
  const sigBuf      = Buffer.from(sig,         'hex');
  const expectedBuf = Buffer.from(expectedSig, 'hex');
  if (sigBuf.length !== expectedBuf.length ||
      !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    callback(new Error('Invalid token signature'));
    return;
  }

  // Token is authentic — decode the filename the server itself embedded
  const filename = Buffer.from(payload, 'base64').toString('utf8');

  // Final defence: still constrain to DOCS_DIR (defence-in-depth)
  const filePath = path.resolve(DOCS_DIR, path.basename(filename));
  if (!filePath.startsWith(DOCS_DIR + path.sep)) {
    callback(new Error('Path out of bounds'));
    return;
  }

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) { callback(new Error('File not found')); return; }
    callback(null, data);
  });
}

// --- Demo ---
const validToken = issueToken('report_2026.txt');
console.log('Issued token:', validToken.slice(0, 40) + '…');

// Attacker attempt: craft a token for '../../etc/passwd'
const forgeryPayload = Buffer.from('../../etc/passwd').toString('base64');
const forgeryToken   = `${forgeryPayload}.deadbeefdeadbeef`;  // wrong signature

serveByToken(forgeryToken, (err) => {
  console.assert(err && err.message === 'Invalid token signature',
    'SAFE: forged token rejected');
  console.log('Forgery blocked:', err.message);
});

serveByToken(validToken, (err, data) => {
  if (err) console.log('File absent (expected in test):', err.message);
  else console.log('File contents:', data.slice(0, 60));
});
