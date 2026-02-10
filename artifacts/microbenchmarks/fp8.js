// Why it's safe: JSON.parse/stringify cycle converts __proto__ to regular property, 
// then the loop copies it as regular property, not prototype access
function sanitizeInput(userInput) {
  return JSON.parse(JSON.stringify(userInput));
}

function processData(data) {
  const clean = sanitizeInput(data);
  const result = {};
  
  for (let key in clean) {
    result[key] = clean[key];
  }
  
  return result;
}

