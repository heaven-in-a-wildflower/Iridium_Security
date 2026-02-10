// Input type: API param
function setConfig(obj, path, value) {
  const keys = path.split('.');
  let current = obj;
  
  for (let i = 0; i < keys.length - 1; i++) {
    if (!current[keys[i]]) {
      current[keys[i]] = {};
    }
    current = current[keys[i]];
  }
  
  current[keys[keys.length - 1]] = value;

// Attack: setConfig({}, '__proto__.polluted', 'yes')
// Result: Pollutes Object.prototype.polluted

// Input type: URL string 
function parseQuery(queryString) {
  const params = {};
  const pairs = queryString.split('&');
  
  for (let pair of pairs) {
    const [key, value] = pair.split('=');
    const keys = key.split('.');
    let current = params;
    
    for (let i = 0; i < keys.length - 1; i++) {
      current[keys[i]] = current[keys[i]] || {};
      current = current[keys[i]];
    }
    
    current[keys[keys.length - 1]] = decodeURIComponent(value);
  }
  
  return params;
}

// Attack: parseQuery('__proto__.admin=true')
// Result: Pollutes Object.prototype.admin

// Input type: JSON doc
function applyPatch(obj, operations) {
  for (let op of operations) {
    if (op.op === 'add' || op.op === 'replace') {
      const path = op.path.split('/').filter(p => p);
      let current = obj;
      
      for (let i = 0; i < path.length - 1; i++) {
        current[path[i]] = current[path[i]] || {};
        current = current[path[i]];
      }
      
      current[path[path.length - 1]] = op.value;
    }
  }
  return obj;
}

// Attack: applyPatch({}, [{op: 'add', path: '/__proto__/evil', value: 'yes'}])
// Result: Pollutes Object.prototype.evil

// Use of brackets in input string
function set(object, path, value) {
  const pathArray = Array.isArray(path) ? path : path.match(/[^.[\]]+/g);
  
  pathArray.reduce((acc, key, index) => {
    if (index === pathArray.length - 1) {
      acc[key] = value;
    } else {
      acc[key] = acc[key] || {};
    }
    return acc[key];
  }, object);
  
  return object;
}

// Attack: set({}, '__proto__[polluted]', true)
// Result: Pollutes via bracket notation parsing