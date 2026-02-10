// Object.assign doesn't pollute prototypes
function mergeConfig(defaults, userConfig) {
  return Object.assign({}, defaults, userConfig);
}