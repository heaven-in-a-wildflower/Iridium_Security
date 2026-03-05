// VULNERABILITY: Arbitrary File Read via Path Traversal (CWE-22)
// TYPE:          positive
// DIFFICULTY:    easy
// DETECTION:     Direct taint flow from req.query.name (user-controlled) to
//                fs.readFile. path.join does not neutralise '../' sequences —
//                it merely concatenates and normalises, so a leading '../'
//                chain still escapes the base directory. No bounds check is
//                performed after joining.
// STATIC ANALYSIS VERDICT: DETECTABLE
//                — the paper (ODGen) claims to detect this pattern but fails
//                  to run even this basic example in practice (see README).
//
// ATTACK:  GET /file?name=../../../../etc/passwd
// EFFECT:  Returns contents of /etc/passwd

const fs   = require('fs');
const path = require('path');

const STATIC_DIR = '/var/www/static';

function serveFile(req, res) {
  const filename = req.query.name;                      // user-controlled
  const fullPath = path.join(STATIC_DIR, filename);     // path.join does NOT strip ../
  fs.readFile(fullPath, 'utf8', (err, data) => {        // SINK
    if (err) { res.status(404).send('Not found'); return; }
    res.send(data);
  });
}

module.exports = { serveFile };
