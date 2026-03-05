// VULNERABILITY: Arbitrary File Write via Path Traversal (CWE-22)
// TYPE:          positive
// DIFFICULTY:    easy
// DETECTION:     req.body.path (user-controlled) is joined with UPLOAD_DIR
//                and passed directly to fs.writeFileSync with no bounds check.
//                An attacker can escape UPLOAD_DIR by supplying a path with
//                '../' sequences and overwrite arbitrary files (SSH keys,
//                cron jobs, etc.).
// STATIC ANALYSIS VERDICT: DETECTABLE
//
// ATTACK:  POST /upload  { path: '../../.ssh/authorized_keys', data: 'ssh-rsa ATTACKER...' }
// EFFECT:  Overwrites ~/.ssh/authorized_keys — persistent SSH backdoor

const fs   = require('fs');
const path = require('path');

const UPLOAD_DIR = '/tmp/uploads';

function handleUpload(req, res) {
  const userPath = req.body.path;   // user-controlled
  const content  = req.body.data;
  const dest = path.join(UPLOAD_DIR, userPath); // traversal not prevented
  fs.writeFileSync(dest, content);              // SINK: arbitrary write
  res.json({ saved: dest });
}

module.exports = { handleUpload };
