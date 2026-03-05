// VULNERABILITY: None — whitelist + schema validation prevents unknown keys
// TYPE:          negative
// DIFFICULTY:    hard
// REASON SAFE:   setConfigValue validates the full path string against an
//                allowlist BEFORE any traversal. Unknown paths (including any
//                containing '__proto__' or 'constructor') are rejected with an
//                error. updateUser validates against a type schema, rejecting
//                any key not explicitly listed.
// ANALYSIS NOTE: The analysis must understand that the guard at the start of
//                each function (allowlist/schema lookup) makes all downstream
//                assignments safe. Imprecise analyses may flag the writes on
//                the assignment lines without considering the early-exit guard
//                — this would be a false positive.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE (requires inter-procedural guard analysis)

const ALLOWED_PATHS = new Set([
  'user.name', 'user.email', 'settings.theme', 'settings.language', 'settings.locale'
]);

function setConfigValue(config, path, value) {
  if (!ALLOWED_PATHS.has(path)) {
    throw new Error(`Disallowed config path: ${path}`);
  }
  const keys = path.split('.');
  let current = config;
  for (let i = 0; i < keys.length - 1; i++) {
    current[keys[i]] = current[keys[i]] || {};
    current = current[keys[i]];
  }
  current[keys[keys.length - 1]] = value; // safe: path was allowlisted
  return config;
}

const USER_SCHEMA = { name: 'string', age: 'number', email: 'string' };

function updateUser(obj, updates) {
  for (const key in updates) {
    if (!Object.prototype.hasOwnProperty.call(USER_SCHEMA, key)) {
      throw new Error(`Unknown field: ${key}`);
    }
    if (typeof updates[key] !== USER_SCHEMA[key]) {
      throw new Error(`Type mismatch for ${key}`);
    }
    obj[key] = updates[key]; // safe: key is in schema
  }
  return obj;
}

module.exports = { setConfigValue, updateUser };
