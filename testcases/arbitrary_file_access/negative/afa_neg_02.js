// VULNERABILITY: None — allowlist of permitted filenames
// TYPE:          negative
// DIFFICULTY:    medium
// REASON SAFE:   The user-supplied name is looked up in ALLOWED_FILES (a
//                hardcoded Set) before any file system access. Only exact
//                matches are permitted. Directory traversal sequences, absolute
//                paths, and any other strings not in the allowlist are rejected.
// ANALYSIS NOTE: The analysis must understand that the allowlist guard before
//                the readFile call makes all downstream FS access safe. Failing
//                to model the guard would produce a false positive.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE (requires modelling allowlist guard)

const fs   = require('fs');
const path = require('path');

const ALLOWED_FILES = new Set(['index.html', 'style.css', 'app.js', 'logo.png']);
const STATIC_DIR    = '/var/www/static';

function serveAllowedFile(req, res) {
  const name = req.query.file;

  if (!ALLOWED_FILES.has(name)) {
    res.status(403).send('File not allowed');
    return;
  }

  const fullPath = path.join(STATIC_DIR, name); // safe: name is allowlisted
  fs.readFile(fullPath, 'utf8', (err, data) => {
    if (err) { res.status(404).send('Not found'); return; }
    res.send(data);
  });
}

module.exports = { serveAllowedFile };
