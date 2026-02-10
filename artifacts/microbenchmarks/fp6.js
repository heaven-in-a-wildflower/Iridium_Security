// Path traversal with whitelist
function setConfigValue(config, path, value) {
  const allowedPaths = ['user.name', 'user.email', 'settings.theme', 'settings.language'];
  
  if (!allowedPaths.includes(path)) {
    throw new Error('Invalid configuration path');
  }
  
  const keys = path.split('.');
  let current = config;
  
  for (let i = 0; i < keys.length - 1; i++) {
    if (!current[keys[i]]) {
      current[keys[i]] = {};
    }
    current = current[keys[i]];
  }
  
  current[keys[keys.length - 1]] = value;
  return config;
}

// Validating against schema
function updateWithSchema(obj, updates, schema) {
  for (let key in updates) {
    if (!schema.hasOwnProperty(key)) {
      throw new Error(`Unknown property: ${key}`);
    }
    
    if (typeof updates[key] !== schema[key]) {
      throw new Error(`Type mismatch for ${key}`);
    }
    
    obj[key] = updates[key];
  }
  return obj;
}

const userSchema = {
  name: 'string',
  age: 'number',
  email: 'string'
};