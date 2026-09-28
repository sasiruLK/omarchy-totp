// Standalone test harness for YubiKey.js. Run with: node test/yubikey.js
//
// Like the other suites, YubiKey.js is a QML JS library: `.pragma library` is
// stripped and the body evaluated, so the shipped file carries no test-only
// scaffolding.

const fs = require("fs")
const path = require("path")

const source = fs
  .readFileSync(path.join(__dirname, "..", "YubiKey.js"), "utf8")
  .replace(/^\.pragma library\s*/, "")

const Y = {}
new Function("exports", source + "\n;Object.assign(exports, {" +
  "accountId, splitName, parseAccountList, parseCodes, parseSingleCode, isTimeBased," +
  "});")(Y)

let failures = 0

function check(name, actual, expected) {
  const ok = String(actual) === String(expected)
  if (!ok) failures++
  console.log(`${ok ? "  ok  " : "FAIL  "}${name}` +
    (ok ? "" : `\n        expected ${expected}\n        actual   ${actual}`))
}

// --- names ----------------------------------------------------------------

console.log("\nName splitting")
check("issuer:name", JSON.stringify(Y.splitName("GitHub:alice")),
  JSON.stringify({ issuer: "GitHub", label: "alice" }))
check("name only", JSON.stringify(Y.splitName("alice")),
  JSON.stringify({ issuer: "", label: "alice" }))
check("extra colon kept in label", JSON.stringify(Y.splitName("a:b:c")),
  JSON.stringify({ issuer: "a", label: "b:c" }))
check("id is namespaced", Y.accountId("GitHub:alice"), "yk:GitHub:alice")

// --- account list ---------------------------------------------------------

console.log("\nAccount list (`ykman oath accounts list -o`)")
const list = Y.parseAccountList(
  "GitHub:alice, TOTP\n" +
  "My Bank:john.doe@example, TOTP\n" +
  "Legacy:ops, HOTP\n" +
  ":NoIssuer, TOTP\n" +
  "\n")
check("count", list.length, 4)
check("issuer", list[0].issuer, "GitHub")
check("label", list[0].label, "alice")
check("type from comma suffix", list[0].type, "TOTP")
check("id", list[0].id, "yk:GitHub:alice")
check("name with spaces", list[1].name, "My Bank:john.doe@example")
check("HOTP preserved", list[2].type, "HOTP")
check("empty issuer", list[3].issuer, "")
check("empty-issuer label", list[3].label, "NoIssuer")
check("period defaults to 30", list[0].period, 30)

// A comma inside the name must not be mistaken for the type separator.
const comma = Y.parseAccountList("Acme, Inc:user, TOTP\n")
check("comma in name", comma[0].name, "Acme, Inc:user")
check("comma in issuer", comma[0].issuer, "Acme, Inc")

// A name that merely ends in a number must not lose it.
const numbered = Y.parseAccountList("Backup codes 2\n")
check("numeric name survives", numbered[0].name, "Backup codes 2")
check("no type reads as TOTP", numbered[0].type, "")

// --- codes ----------------------------------------------------------------

console.log("\nBulk codes (`ykman oath accounts code`)")
// Real output pads the name to a column before the code.
const codes = Y.parseCodes(
  "GitHub:alice               123456\n" +
  "My Bank:john.doe@example    654321\n" +
  "not a code line\n" +
  "Eight:digit                 12345678\n" +
  "Leading:zero                001234\n")
check("code for plain name", codes["yk:GitHub:alice"], "123456")
check("code for name with spaces", codes["yk:My Bank:john.doe@example"], "654321")
check("eight-digit code", codes["yk:Eight:digit"], "12345678")
check("leading zero kept", codes["yk:Leading:zero"], "001234")
check("non-code line skipped", Object.keys(codes).length, 4)

console.log("\nSingle code (`ykman oath accounts code -s`)")
check("trims to the digits", Y.parseSingleCode("  123456\n"), "123456")
check("no code is empty", Y.parseSingleCode("Error: no such account"), "")

console.log("\nTime-based guard")
check("TOTP is polled", Y.isTimeBased({ type: "TOTP" }), "true")
check("empty type is polled", Y.isTimeBased({ type: "" }), "true")
check("HOTP is not polled", Y.isTimeBased({ type: "HOTP" }), "false")

console.log(failures === 0
  ? "\nAll checks passed.\n"
  : `\n${failures} check(s) FAILED.\n`)
process.exit(failures === 0 ? 0 : 1)
