// Prototype is frozen, can't be modified.
Object.freeze(Object.prototype);

function unsafeLoopingMerge(target, source) {
  for (let key in source) {
    target[key] = source[key];
  }
  return target;
}