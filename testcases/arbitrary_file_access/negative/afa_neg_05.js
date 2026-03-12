/*
 * VULNERABILITY : Arbitrary File Access
 * TYPE          : Negative (safe)
 * DIFFICULTY    : Medium
 * DETECTION     : Should NOT be flagged — numeric-ID-only input is mapped to a
 *                 server-side filename template; user input never reaches the path
 * STATIC ANALYSIS VERDICT: Safe — req.params.id is validated to be a pure integer;
 *                 the file path is constructed from a server-controlled template,
 *                 not from user input directly; no user string reaches fs.readFile
 * ATTACK        : req.params.id = '../../etc/passwd' or '1; rm -rf /'
 * EFFECT        : /^\d+$/ regex rejects any non-numeric input immediately;
 *                 only a plain integer reaches Number(), which cannot encode a path
 */

'use strict';

const path = require('path');
const fs   = require('fs');

const REPORTS_DIR = path.resolve(__dirname, 'reports');

/**
 * Retrieve a report file by its numeric ID.
 * The user supplies only an ID; the path is constructed server-side.
 */
function getReport(rawId, callback) {
  // Strict numeric validation — rejects any path-like or shell-special input
  if (!/^\d+$/.test(rawId)) {
    callback(new Error('Invalid report ID'));
    return;
  }

  const reportId = Number(rawId);          // safe: purely numeric string
  if (reportId < 1 || reportId > 999999) {
    callback(new Error('Report ID out of range'));
    return;
  }

  // Server-controlled template — user input (reportId) is an integer, not a path
  const filename = `report_${String(reportId).padStart(6, '0')}.json`;
  const filePath = path.join(REPORTS_DIR, filename);

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) { callback(new Error('Report not found')); return; }
    callback(null, JSON.parse(data));
  });
}

// Test cases
getReport('42', (err, data) => {
  if (err) console.log('Error (expected if file absent):', err.message);
  else console.log('Report:', data);
});

getReport('../../etc/passwd', (err) => {
  console.assert(err && err.message === 'Invalid report ID',
    'SAFE: traversal rejected by numeric check');
  console.log('Blocked:', err.message);
});

getReport('999; DROP TABLE reports;--', (err) => {
  console.assert(err, 'SAFE: injection rejected');
  console.log('Blocked:', err.message);
});
