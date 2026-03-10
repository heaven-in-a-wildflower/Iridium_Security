# ODGen

**Paper:** "Mining Node.js Vulnerabilities via Object Dependence Graph and Query"
**Venue:** USENIX Security 2022
**Authors:** Song Li, Mingqing Kang, Jianwei Hou, Yinzhi Cao (Johns Hopkins)
**Source:** https://github.com/Song-Li/ODGen
**Location in repo:** `artifacts/ODGen/` (git submodule)

## What it detects

ODGen builds an Object Dependence Graph (ODG) of a Node.js package and
queries it for taint paths from user-controlled inputs to dangerous sinks.

| Vulnerability | ODGen type flag |
|---|---|
| Prototype pollution | `proto_pollution` |
| Internal property tampering | `ipt` |
| OS command injection | `os_command` |
| Path traversal | `path_traversal` |
| Code execution | `code_exec` |
| XSS | `xss` |

## Detection model

ODGen's PP model requires the **two-hop property access** pattern:

```
obj = base[user_param_1]   // intermediate object resolved via tainted key
obj[user_param_2] = value  // write to a property of that intermediate object
```

It does **not** model for-in loop enumeration as a taint source for keys,
and does **not** handle destructuring assignment. See `results/evaluation_results.md`
for the documented blind spots.

## Setup

```bash
bash setup.sh
```

Requirements: Python 3.7+, Node.js 12+, npm.

## Running

```bash
# Single file
bash run.sh ../../testcases/prototype_pollution/positive/pp_pos_02.js proto_pollution

# All testcases (produces per-file DETECTED / NOT_DETECTED output)
bash run_all.sh ../../testcases
```
