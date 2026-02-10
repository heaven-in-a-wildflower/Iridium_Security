// Deep Merge 
function deepMerge(target, source) {
    for (let key in source) {
        if (source[key] && typeof source[key] === 'object') {
            target[key] = target[key] || {}; // If target[key] already exists, reuse it, otherwise create an empty object
            deepMerge(target[key], source[key]); // recursively merge children
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Attack: deepMerge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'))
// Result: Pollutes Object.prototype.isAdmin

// Clone
function clone(obj, options = {}) {
  const defaults = { deep: true };
  
  for (let key in options) {
    defaults[key] = options[key];
  }
  
  if (defaults.deep) {
    return JSON.parse(JSON.stringify(obj));
  }
  return { ...obj };
}


// Attack: clone({}, JSON.parse('{"__proto__": {"hacked": true}}'))
// Result: Pollutes via options parameter

// Extend
function extend(target, ...sources) {
  for (let source of sources) {
    for (let key in source) {
      if (source.hasOwnProperty(key)) {
        if (typeof source[key] === 'object' && source[key] !== null) {
          target[key] = extend({}, source[key]);
        } else {
          target[key] = source[key];
        }
      }
    }
  }
  return target;
}

// Attack: extend({}, {__proto__: {polluted: true}})
// Result: hasOwnProperty doesn't prevent __proto__ on parsed JSON