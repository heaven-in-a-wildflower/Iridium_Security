// VULNERABILITY: Prototype Pollution via eval with runtime-decoded key (CWE-1321)
// TYPE:          positive
// DIFFICULTY:    undecidable (conservative static analysis)
// DETECTION:     The property name is constructed by Base64-decoding a string
//                at runtime. Conservative static analysis cannot evaluate
//                Buffer.from(…, 'base64') to discover the string '__proto__'
//                without dynamic execution. A sound analysis must either:
//                  (a) flag ALL eval-based property writes conservatively
//                      → enormous false positives on any eval usage, or
//                  (b) miss this specific instance.
//                This pattern mirrors real supply-chain obfuscation techniques.
// STATIC ANALYSIS VERDICT: NOT CONSERVATIVELY DECIDABLE (eval + encoding opacity)
//
// ATTACK:  pollute('eyJfX3Byb3RvX18iOiB7ImhhY2tlZCI6IHRydWV9fQ==')
//          (Base64 of '{"__proto__": {"hacked": true}}')
// EFFECT:  ({}).hacked === true

function pollute(encodedPayload) {
  // Decode at runtime — static analysis cannot evaluate Buffer.from
  const jsonStr = Buffer.from(encodedPayload, 'base64').toString('utf8');
  const payload = JSON.parse(jsonStr);

  // eval with a dynamically constructed string: analysis sees the template
  // but cannot know that key === '__proto__' without running the code
  for (const key of Object.keys(payload)) {
    eval(`(function(o,v){ o['${key}'] = v; })({}, payload[key])`); // SINK
  }
}

module.exports = { pollute };
