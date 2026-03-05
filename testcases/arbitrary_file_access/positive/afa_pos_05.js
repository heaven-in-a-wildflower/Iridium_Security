// VULNERABILITY: Command Injection via insufficiently sanitised exec (CWE-78)
// TYPE:          positive
// DIFFICULTY:    hard
// DETECTION:     User input passes through sanitizeFilename() which strips
//                leading dots but does NOT remove shell metacharacters
//                (; | & $ ` ( )). The analysis must track taint through the
//                helper function and recognise that the transformation is
//                incomplete — the output is still tainted — before flagging
//                the execSync sink.
// STATIC ANALYSIS VERDICT: DETECTABLE (inter-procedural taint through partial sanitiser)
//
// ATTACK:  processFile('report; rm -rf /')
// EFFECT:  Executes `cat report.txt; rm -rf /` — arbitrary command execution

const { execSync } = require('child_process');

// Partial sanitiser: strips leading dots but misses shell metacharacters
function sanitizeFilename(name) {
  return name.replace(/^\.+/, '') + '.txt';
}

function processFile(userFilename) {
  const safe = sanitizeFilename(userFilename); // taint survives through here
  const output = execSync(`cat ${safe}`);      // SINK: shell injection
  return output.toString();
}

module.exports = { processFile };
