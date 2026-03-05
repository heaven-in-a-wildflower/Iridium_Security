// VULNERABILITY: Prototype Pollution from multiple input surfaces (CWE-1321)
// TYPE:          positive
// DIFFICULTY:    medium
// DETECTION:     Three functions share the same root pattern (unsanitised
//                path traversal into object assignment) but each receives
//                input from a different surface: URL query string, JSON Patch
//                document (RFC 6902), and a pre-split key array. Requires
//                inter-procedural taint tracking from each source to the sink.
// STATIC ANALYSIS VERDICT: DETECTABLE (inter-procedural taint)
//
// ATTACK (URL):   parseQuery('__proto__.admin=true')
//   → ({}).admin === true
// ATTACK (Patch): applyPatch({}, [{op:'add', path:'/__proto__/evil', value:'yes'}])
//   → ({}).evil === 'yes'
// ATTACK (array): setNested({}, ['__proto__', 'x'], 'val')
//   → ({}).x === 'val'

// Variant A: URL query string
function parseQuery(queryString) {
  const params = {};
  for (const pair of queryString.split('&')) {
    const [rawKey, rawVal] = pair.split('=');
    const keys = rawKey.split('.');
    let cur = params;
    for (let i = 0; i < keys.length - 1; i++) {
      cur[keys[i]] = cur[keys[i]] || {};
      cur = cur[keys[i]];
    }
    cur[keys[keys.length - 1]] = decodeURIComponent(rawVal || '');
  }
  return params;
}

// Variant B: JSON Patch (RFC 6902)
function applyPatch(obj, operations) {
  for (const op of operations) {
    if (op.op === 'add' || op.op === 'replace') {
      const parts = op.path.split('/').filter(Boolean);
      let cur = obj;
      for (let i = 0; i < parts.length - 1; i++) {
        cur[parts[i]] = cur[parts[i]] || {};
        cur = cur[parts[i]];
      }
      cur[parts[parts.length - 1]] = op.value; // unfiltered write
    }
  }
  return obj;
}

// Variant C: pre-split key array from API parameter
function setNested(obj, keys, value) {
  let cur = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    cur[keys[i]] = cur[keys[i]] || {};
    cur = cur[keys[i]];
  }
  cur[keys[keys.length - 1]] = value;
  return obj;
}

module.exports = { parseQuery, applyPatch, setNested };
