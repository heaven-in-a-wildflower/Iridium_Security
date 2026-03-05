# Arbitrary File Access / Command Injection (CWE-22 / CWE-78)

Attacker-controlled strings reach file-system or shell sinks without adequate
sanitisation, allowing arbitrary file reads/writes or OS command execution.

Includes a PP-gadget variant (afa_pos_04) where prototype pollution is used
as a first stage to inject a malicious base path into a file-serving function
(Silent Spring / GHunter gadget-chain pattern).

## Positive cases (vulnerable)

| File          | Difficulty    | Sink               | Vector                                  | ODGen?      |
|---------------|---------------|--------------------|-----------------------------------------|-------------|
| afa_pos_01.js | easy          | fs.readFile        | req.query → path.join (no bounds check) | **fails**†  |
| afa_pos_02.js | easy          | fs.writeFileSync   | req.body → path.join (no bounds check)  | **fails**†  |
| afa_pos_03.js | medium        | require()          | req.query → dynamic require             | detects     |
| afa_pos_04.js | medium        | fs.readFileSync    | PP gadget (Object.prototype.base)       | partial     |
| afa_pos_05.js | hard          | execSync           | partial sanitiser bypassed              | detects     |
| afa_pos_06.js | undecidable   | fs.readFileSync    | hex-encoded path (encoding opacity)     | undecidable |

† ODGen claims to detect path traversal in the paper but fails to run even
  these basic examples in practice (observed during Iridium evaluation).

## Negative cases (safe, must not be flagged)

| File          | Difficulty | Defence mechanism                          |
|---------------|------------|--------------------------------------------|
| afa_neg_01.js | easy       | path.resolve + startsWith bounds check     |
| afa_neg_02.js | medium     | filename allowlist (Set lookup)            |
| afa_neg_03.js | hard       | fs.realpath (resolves symlinks) + check    |
