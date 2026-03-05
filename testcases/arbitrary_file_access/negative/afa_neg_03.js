// VULNERABILITY: None — fs.realpath resolves symlinks + bounds check
// TYPE:          negative
// DIFFICULTY:    hard
// REASON SAFE:   fs.realpath resolves ALL symlinks in addition to '../'
//                sequences, returning the true canonical path. The subsequent
//                startsWith check is then performed on the canonical path,
//                preventing both directory traversal AND symlink-based escapes
//                (e.g. a symlink inside STATIC_DIR pointing to /etc).
//                This is the most robust defence against path traversal.
// ANALYSIS NOTE: Correctly suppressing the alarm requires modelling fs.realpath
//                as a sanitiser that returns the canonical absolute path, and
//                understanding that the subsequent startsWith check on the
//                canonical path constitutes a complete guard.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE (requires modelling fs.realpath semantics)

const fs   = require('fs');
const path = require('path');

const STATIC_DIR = path.resolve('/var/www/static');

function serveFileSecure(req, res) {
  const userInput = req.query.file;
  const candidate = path.join(STATIC_DIR, userInput);

  // fs.realpath resolves symlinks AND normalises; then we check containment
  fs.realpath(candidate, (err, canonical) => {
    if (err || !canonical.startsWith(STATIC_DIR + path.sep)) {
      res.status(403).send('Access denied');
      return;
    }
    fs.readFile(canonical, 'utf8', (readErr, data) => {
      if (readErr) { res.status(404).send('Not found'); return; }
      res.send(data);
    });
  });
}

module.exports = { serveFileSecure };
