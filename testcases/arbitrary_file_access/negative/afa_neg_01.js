// VULNERABILITY: None — path.resolve + startsWith guard prevents traversal
// TYPE:          negative
// DIFFICULTY:    easy
// REASON SAFE:   path.resolve collapses all '../' sequences and returns an
//                absolute path. The startsWith check then ensures the resolved
//                path remains within STATIC_DIR. Even '../../../../etc/passwd'
//                resolves to '/etc/passwd', which does not start with
//                '/var/www/static/' and is rejected.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE (requires modelling path.resolve + startsWith)

const fs   = require('fs');
const path = require('path');

const STATIC_DIR = path.resolve('/var/www/static');

function serveStaticFile(req, res) {
  const userInput = req.query.file;
  const resolved  = path.resolve(STATIC_DIR, userInput);

  // Guard: resolved path must stay inside STATIC_DIR
  if (!resolved.startsWith(STATIC_DIR + path.sep)) {
    res.status(403).send('Access denied');
    return;
  }

  fs.readFile(resolved, 'utf8', (err, data) => {
    if (err) { res.status(404).send('Not found'); return; }
    res.send(data);
  });
}

module.exports = { serveStaticFile };
