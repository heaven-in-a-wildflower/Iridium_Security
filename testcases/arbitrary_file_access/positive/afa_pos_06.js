// VULNERABILITY: Arbitrary File Read — path traversal via runtime-decoded string (CWE-22)
// TYPE:          positive
// DIFFICULTY:    undecidable (conservative static analysis)
// DETECTION:     The file path is provided as a hex-encoded string and decoded
//                at runtime with Buffer.from(…, 'hex'). A conservative static
//                analysis cannot evaluate the hex decoder to discover that the
//                decoded value is '../../etc/passwd' without dynamic execution.
//                A sound analysis must either flag ALL readFile calls whose
//                argument passes through any decoder as tainted (enormous false
//                positives) or miss this instance.
//                This obfuscation pattern is used in real supply-chain attacks.
// STATIC ANALYSIS VERDICT: NOT CONSERVATIVELY DECIDABLE (encoding opacity)
//
// ATTACK:  readEncodedPath('2e2e2f2e2e2f6574632f706173737764')
//          (hex of '../../etc/passwd')
// EFFECT:  Reads /etc/passwd

const fs = require('fs');

function hexDecode(hex) {
  return Buffer.from(hex, 'hex').toString('utf8');
}

function readEncodedPath(hexPath) {
  const decodedPath = hexDecode(hexPath); // analysis cannot evaluate statically
  return fs.readFileSync(decodedPath, 'utf8'); // SINK: arbitrary read
}

module.exports = { readEncodedPath };
