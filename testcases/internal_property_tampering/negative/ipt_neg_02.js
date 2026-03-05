// VULNERABILITY: None — security-sensitive methods stored under Symbol keys
// TYPE:          negative
// DIFFICULTY:    medium
// REASON SAFE:   All internal methods are stored under Symbol keys. Symbols
//                are unique and non-enumerable by for-in. Attacker-controlled
//                string keys (including 'hasOwnProperty', 'toString', 'call')
//                cannot reach or overwrite Symbol-keyed methods because
//                Symbol keys are never produced by string-based pollution paths.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE

const _validate = Symbol('validate');
const _hasOwn   = Symbol('hasOwn');

const SecureUtils = {
  [_validate](key) {
    return typeof key === 'string' && key.length > 0 && key !== '__proto__';
  },
  [_hasOwn](obj, key) {
    // Symbol-keyed tamper-resistant replacement for obj.hasOwnProperty
    return Object.prototype.hasOwnProperty.call(obj, key);
  },
  merge(target, source) {
    for (const key of Object.keys(source)) { // own enumerable only
      if (this[_validate](key)) {
        target[key] = source[key];
      }
    }
    return target;
  }
};

module.exports = { SecureUtils, _validate, _hasOwn };
