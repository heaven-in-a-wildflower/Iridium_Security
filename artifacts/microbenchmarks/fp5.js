// Null prototype objects can't be polluted
function parseParameters(input) {
  const params = Object.create(null);
  
  for (let pair of input.split('&')) {
    const [key, value] = pair.split('=');
    params[key] = decodeURIComponent(value);
  }
  
  return params;
}