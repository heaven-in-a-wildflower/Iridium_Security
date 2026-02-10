// Spread operator doesn't pollute
function configureOptions(...configs) {
  return { ...configs[0], ...configs[1], ...configs[2] };
}