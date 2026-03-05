// VULNERABILITY: Arbitrary File Read via dynamic require() (CWE-22 / CWE-94)
// TYPE:          positive
// DIFFICULTY:    medium
// DETECTION:     req.query.plugin flows to require(). Beyond information
//                disclosure (reading arbitrary .js files), this triggers code
//                execution if the loaded module has side effects at load time.
//                The taint path crosses a function boundary (loadPlugin →
//                require) making this harder than afa_pos_01/02 to detect
//                with purely intra-procedural analysis.
// STATIC ANALYSIS VERDICT: DETECTABLE (inter-procedural taint from query to require sink)
//
// ATTACK:  GET /plugin?name=../../../../etc/shadow
//          GET /plugin?name=/proc/self/environ
// EFFECT:  Reads or executes arbitrary files reachable from the process CWD

function loadPlugin(req, res) {
  const pluginName = req.query.plugin;    // user-controlled
  try {
    const plugin = require(pluginName);   // SINK: dynamic require with tainted path
    res.json({ loaded: true, exports: Object.keys(plugin) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

module.exports = { loadPlugin };
