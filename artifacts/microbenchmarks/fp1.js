// Deep Merge with hasOwnProperty check
function safeMerge(target, source) {
  for (let key in source) {
    // This check prevents __proto__ from Object.create() scenarios
    if (!source.hasOwnProperty(key)) continue;
    
    // Additional safety: check if key is a dangerous property
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    
    if (source[key] && typeof source[key] === 'object') {
      target[key] = target[key] || {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Setting property with safety check
function setSecureProperty(obj, key, value) {
  // Block dangerous keys
  if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
    throw new Error('Invalid property name');
  }
  
  Object.defineProperty(obj, key, {
    value: value,
    writable: true,
    enumerable: true,
    configurable: true
  });
  
  return obj;
}

// Object.keys	enumerable string keys only
// Object.getOwnPropertyNames	all string keys
// Reflect.ownKeys	all keys (strings + symbols)

// Another method to filter out dangerous keys
function safeCopy(source) {
  const target = {};
  const keys = Reflect.ownKeys(source).filter(key => 
    typeof key === 'string' && 
    key !== '__proto__' && 
    key !== 'constructor' && 
    key !== 'prototype'
  );
  
  keys.forEach(key => {
    target[key] = source[key];
  });
  
  return target;
}

// Even though Object.keys returns own properties which do not include __proto__, 
// the attacker can still pass an object like const o = JSON.parse('{"__proto__": {"x": 1}}');
// In which case, Object.keys(o) is ["__proto__"], so we still need an additional check
function mergeUsingKeys(target, source) {
  Object.keys(source).forEach(key => {
    // Even though this looks unsafe, Object.keys won't include __proto__
    // from the prototype chain, only own properties
    if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
      target[key] = source[key];
    }
  });
  return target;
}
