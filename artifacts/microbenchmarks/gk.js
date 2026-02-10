const sym = Symbol('s');
const obj = { a: 1 };
Object.defineProperty(obj, 'hidden', { value: 2 });
obj[sym] = 3;

Reflect.ownKeys(obj);
// ["a", "hidden", Symbol(s)]

// *******************************************

// const obj = {};
// Object.defineProperty(obj, 'hidden', {
//   value: 42,
//   enumerable: false
// });
// obj.visible = 1;

// Object.keys(obj);
// // ["visible"]

// Object.getOwnPropertyNames(obj);
// // ["hidden", "visible"]

// *******************************************


// const o = { "__proto__": { x: 1 } };

// Object.keys(o);                 // []
// Object.getOwnPropertyNames(o);  // []

// *******************************************

// const o = JSON.parse('{"__proto__": {"x": 1}}');

// Object.keys(o);                 // ["__proto__"]
// Object.getOwnPropertyNames(o);  // ["__proto__"]
