// Map objects don't have prototype pollution
function createCache() {
  const cache = new Map();
  
  return {
    set(key, value) {
      cache.set(key, value);
    },
    get(key) {
      return cache.get(key);
    }
  };
}

// WeakMap does not have prototype pollution
const privateData = new WeakMap();

function createUser(name) {
  const user = {};
  privateData.set(user, { name });
  
  return {
    getName() {
      return privateData.get(user).name;
    },
    setProperty(key, value) {
      const data = privateData.get(user);
      data[key] = value;
    }
  };
}