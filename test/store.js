// Standalone test harness for Store.js. Run with: node test/store.js
//
// Store.js is a QML JS library: it opens with `.pragma library` and pulls in
// Totp.js with the QML `.import` directive. Both are stripped here and Totp is
// supplied as a namespace object, so the shipped files carry no test scaffolding.

const fs = require("fs")
const path = require("path")

function loadLibrary(file, exportNames, injected = {}) {
  const source = fs
    .readFileSync(path.join(__dirname, "..", file), "utf8")
    .replace(/^\.pragma library\s*/, "")
    .replace(/^\.import\s+.*$/gm, "")

  const scope = {}
  const names = Object.keys(injected)
  new Function(...names, "exports",
    source + "\n;Object.assign(exports, {" + exportNames.join(",") + "});"
  )(...names.map((n) => injected[n]), scope)
  return scope
}

const Totp = loadLibrary("Totp.js",
  ["totp", "hotp", "base32Decode", "secondsRemaining", "normalizeAlgorithm"])

const S = loadLibrary("Store.js", [
  "cleanText", "isBlank", "splitUri", "splitLabel", "parseOtpauth",
  "normalizeAccount", "newId", "toRecord", "parseIndex", "serializeIndex",
  "matches", "groupCode", "toOtpauth", "buildExport", "parseExport",
  "base64ToBytes", "bytesToBase32", "utf8Decode", "parseMigration",
  "parseOtpauthBatch"
], { Totp })

let failures = 0

function check(name, actual, expected) {
  const ok = String(actual) === String(expected)
  if (!ok) failures++
  console.log(`${ok ? "  ok  " : "FAIL  "}${name}` +
    (ok ? "" : `\n        expected ${expected}\n        actual   ${actual}`))
}

function rejects(name, fn, expectedMessage) {
  let message = null
  try { fn() } catch (e) { message = e.message }
  if (expectedMessage === undefined) {
    check(name, message === null ? "accepted" : "rejected", "rejected")
  } else {
    check(name, message, expectedMessage)
  }
}

const SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// --- otpauth:// parsing ----------------------------------------------------

console.log("\notpauth:// parsing")
{
  const a = S.parseOtpauth(
    `otpauth://totp/GitHub:sasiru?secret=${SEED}&issuer=GitHub&digits=6&period=30`)
  check("label", a.label, "sasiru")
  check("issuer", a.issuer, "GitHub")
  check("digits", a.digits, 6)
  check("period", a.period, 30)
  check("algorithm", a.algorithm, "SHA1")
  check("secret", a.secret, SEED)
}

{
  // Percent-encoded label: "ACME Co:alice@acme.com"
  const a = S.parseOtpauth(
    `otpauth://totp/ACME%20Co:alice%40acme.com?secret=${SEED}`)
  check("decodes %20 in issuer", a.issuer, "ACME Co")
  check("decodes %40 in label", a.label, "alice@acme.com")
}

{
  // No issuer= parameter: the label prefix supplies it.
  const a = S.parseOtpauth(`otpauth://totp/Proton:me?secret=${SEED}`)
  check("issuer from label prefix", a.issuer, "Proton")
  check("account after prefix", a.label, "me")
}

{
  // issuer= disagrees with the label prefix; the parameter wins.
  const a = S.parseOtpauth(`otpauth://totp/Old:me?secret=${SEED}&issuer=New`)
  check("issuer parameter wins", a.issuer, "New")
}

{
  const a = S.parseOtpauth(`otpauth://totp/BareName?secret=${SEED}`)
  check("bare label, no issuer", a.label, "BareName")
  check("issuer empty", a.issuer, "")
}

{
  const a = S.parseOtpauth(
    `otpauth://TOTP/X?secret=${SEED}&algorithm=SHA256&digits=8&period=60`)
  check("uppercase scheme type", a.algorithm, "SHA256")
  check("digits honoured", a.digits, 8)
  check("period honoured", a.period, 60)
}

// The label prefix may be padded after the colon; that space is not part of
// the account name.
check("trims space after colon",
  S.parseOtpauth(`otpauth://totp/Iss:%20name?secret=${SEED}`).label, "name")
check("trims an encoded space after the colon",
  S.parseOtpauth(`otpauth://totp/Iss:%20%20name?secret=${SEED}`).label, "name")

// The issuer/account separator may be written literally or percent-encoded.
{
  const a = S.parseOtpauth(`otpauth://totp/ACME%3Aalice?secret=${SEED}`)
  check("accepts %3A as the separator", a.issuer, "ACME")
  check("account after an encoded separator", a.label, "alice")
}

// Splitting happens on the raw path, before decoding. An encoded slash is
// therefore just a character in the account name, never a path boundary.
check("an encoded slash stays in the name",
  S.parseOtpauth(`otpauth://totp/a%2Fb?secret=${SEED}`).label, "a/b")

// Only the FIRST separator splits; later colons belong to the account name.
{
  const a = S.parseOtpauth(`otpauth://totp/Iss:a:b?secret=${SEED}`)
  check("splits on the first colon only", a.issuer, "Iss")
  check("later colons stay in the name", a.label, "a:b")
}

console.log("\notpauth:// rejection")
rejects("rejects a plain string", () => S.parseOtpauth("hello"),
  "Not an otpauth:// link")
rejects("rejects http:// links", () => S.parseOtpauth("https://example.com"),
  "Not an otpauth:// link")
rejects("rejects hotp", () => S.parseOtpauth(`otpauth://hotp/X?secret=${SEED}&counter=1`),
  "Counter-based (HOTP) codes are not supported")
rejects("rejects unknown type", () => S.parseOtpauth(`otpauth://yotp/X?secret=${SEED}`))
rejects("rejects a missing secret", () => S.parseOtpauth("otpauth://totp/X"),
  "A secret is required")
rejects("rejects a non-base32 secret", () => S.parseOtpauth("otpauth://totp/X?secret=nope!!"),
  "That secret is not valid base32")
rejects("rejects an empty name", () => S.parseOtpauth(`otpauth://totp/?secret=${SEED}`),
  "A name is required")

// A malformed percent-escape must not take the whole enrolment down with it.
check("survives a broken escape",
  S.parseOtpauth(`otpauth://totp/100%pure?secret=${SEED}`).label, "100%pure")

// --- field validation ------------------------------------------------------

console.log("\nField validation")
rejects("rejects 5 digits", () => S.normalizeAccount({ label: "x", secret: SEED, digits: 5 }),
  "Digits must be 6, 7, or 8")
rejects("rejects 9 digits", () => S.normalizeAccount({ label: "x", secret: SEED, digits: 9 }),
  "Digits must be 6, 7, or 8")
rejects("rejects period 0", () => S.normalizeAccount({ label: "x", secret: SEED, period: 0 }),
  "Period must be between 1 and 300 seconds")
rejects("rejects period 301", () => S.normalizeAccount({ label: "x", secret: SEED, period: 301 }),
  "Period must be between 1 and 300 seconds")
rejects("rejects MD5", () => S.normalizeAccount({ label: "x", secret: SEED, algorithm: "MD5" }),
  "Unsupported algorithm: MD5")
check("accepts 7 digits",
  S.normalizeAccount({ label: "x", secret: SEED, digits: 7 }).digits, 7)
check("accepts sha-512 spelling",
  S.normalizeAccount({ label: "x", secret: SEED, algorithm: "sha-512" }).algorithm, "SHA512")
check("strips spaces from a pasted secret",
  S.normalizeAccount({ label: "x", secret: "JBSW Y3DP EHPK 3PXP" }).secret, "JBSWY3DPEHPK3PXP")

// --- untrusted text --------------------------------------------------------

console.log("\nUntrusted text")
{
  // Markup is kept verbatim rather than escaped or stripped. Rendering safety
  // is the UI's job (Text.PlainText) — mangling the label here would only hide
  // the problem while leaving other sinks exposed.
  const hostile = '<img src=x onerror=alert(1)>'
  const a = S.parseOtpauth(
    `otpauth://totp/${encodeURIComponent(hostile)}?secret=${SEED}`)
  check("markup preserved verbatim", a.label, hostile)

  // Same payload in the issuer= parameter, which takes a different code path.
  const b = S.parseOtpauth(
    `otpauth://totp/name?secret=${SEED}&issuer=${encodeURIComponent(hostile)}`)
  check("markup in issuer= preserved", b.issuer, hostile)
}
check("strips newlines", S.cleanText("a\nb"), "ab")
check("strips carriage returns", S.cleanText("a\r\nb"), "ab")
check("strips NUL", S.cleanText("a\u0000b"), "ab")
check("strips DEL", S.cleanText("a\u007fb"), "ab")
check("trims surrounding space", S.cleanText("  spaced  "), "spaced")
check("caps length at 128", S.cleanText("z".repeat(500)).length, 128)
check("handles null", S.cleanText(null), "")
check("handles undefined", S.cleanText(undefined), "")
{
  // A label that is nothing but control characters cannot name an account.
  rejects("rejects an all-control label",
    () => S.normalizeAccount({ label: "\n\r ", secret: SEED }), "A name is required")
}

// --- the index file --------------------------------------------------------

console.log("\nIndex file")
{
  const account = S.normalizeAccount({ label: "GitHub", issuer: "GitHub", secret: SEED })
  const record = S.toRecord("abc123", account)
  check("record keeps the id", record.id, "abc123")
  check("record has no secret field", record.secret, "undefined")
  check("record field count", Object.keys(record).length, 6)

  const json = S.serializeIndex([Object.assign({ id: "abc123" }, account)])
  // The single most important assertion in this file.
  check("serialized index omits the secret", json.indexOf(SEED) < 0, "true")
  check("serialized index omits 'secret'", json.indexOf("secret") < 0, "true")
  check("serialized index round-trips", S.parseIndex(json).length, 1)
  check("round-trip keeps the label", S.parseIndex(json)[0].label, "GitHub")
}

console.log("\nIndex file: hostile and corrupt input")
check("corrupt JSON yields no accounts", S.parseIndex("{not json").length, 0)
check("empty string yields no accounts", S.parseIndex("").length, 0)
check("null yields no accounts", S.parseIndex(null).length, 0)
check("missing accounts key yields none", S.parseIndex('{"version":1}').length, 0)
check("non-object rows are skipped",
  S.parseIndex('{"accounts":[1,"two",null]}').length, 0)
check("rows without a usable id are skipped",
  S.parseIndex('{"accounts":[{"label":"x"}]}').length, 0)
check("path-traversal ids are skipped",
  S.parseIndex('{"accounts":[{"id":"../../etc/passwd","label":"x"}]}').length, 0)
check("ids with slashes are skipped",
  S.parseIndex('{"accounts":[{"id":"a/b","label":"x"}]}').length, 0)
check("overlong ids are skipped",
  S.parseIndex(`{"accounts":[{"id":"${"a".repeat(65)}","label":"x"}]}`).length, 0)
check("duplicate ids collapse to the first",
  S.parseIndex('{"accounts":[{"id":"a","label":"first"},{"id":"a","label":"second"}]}')[0].label,
  "first")
check("out-of-range digits fall back to 6",
  S.parseIndex('{"accounts":[{"id":"a","label":"x","digits":99}]}')[0].digits, 6)
check("out-of-range period falls back to 30",
  S.parseIndex('{"accounts":[{"id":"a","label":"x","period":-5}]}')[0].period, 30)
check("unknown algorithm falls back to SHA1",
  S.parseIndex('{"accounts":[{"id":"a","label":"x","algorithm":"md5"}]}')[0].algorithm, "SHA1")
check("a label-less row falls back to its id",
  S.parseIndex('{"accounts":[{"id":"a"}]}')[0].label, "a")
{
  // An index written by a buggy build might carry a secret. Reading it must
  // not carry that secret forward into the running plugin.
  const loaded = S.parseIndex(`{"accounts":[{"id":"a","label":"x","secret":"${SEED}"}]}`)
  check("a stray secret in the index is dropped", loaded[0].secret, "undefined")
  check("re-serializing does not reintroduce it",
    S.serializeIndex(loaded).indexOf(SEED) < 0, "true")
}

// --- ids -------------------------------------------------------------------

console.log("\nIds")
{
  const ids = new Set()
  for (let i = 0; i < 2000; i++) ids.add(S.newId([]))
  check("2000 ids are unique", ids.size, 2000)
  check("id shape is index-safe", /^[A-Za-z0-9._-]{1,64}$/.test(S.newId([])), "true")

  const taken = S.newId([])
  check("avoids ids already in use", S.newId([taken]) === taken, "false")
}

// --- display helpers -------------------------------------------------------

console.log("\nDisplay helpers")
check("groups 6 digits", S.groupCode("482913"), "482 913")
check("groups 7 digits", S.groupCode("4829134"), "4829 134")
check("groups 8 digits", S.groupCode("48291340"), "4829 1340")
check("leaves an empty code alone", S.groupCode(""), "")

// --- otpauth-migration:// (Google Authenticator export) --------------------

console.log("\notpauth-migration:// parsing")

// Minimal protobuf writer for building fixtures: enough to emit the exact
// shape Google Authenticator produces, without a dependency.
function protoVarint(value) {
  const out = []
  do { out.push((value & 0x7f) | (value > 0x7f ? 0x80 : 0)); value >>>= 7 }
  while (value > 0)
  return Buffer.from(out)
}
function protoBytes(field, bytes) {
  return Buffer.concat([
    protoVarint(field * 8 + 2), protoVarint(bytes.length), bytes
  ])
}
function protoInt(field, value) {
  return Buffer.concat([protoVarint(field * 8), protoVarint(value)])
}
function otpParameters({ secret, name, issuer, algorithm = 1, digits = 1, type = 2, packed }) {
  const encode = (field, value) => packed === field
    ? protoBytes(field, Buffer.from([value]))
    : protoInt(field, value)
  return Buffer.concat([
    protoBytes(1, secret),
    protoBytes(2, Buffer.from(name, "utf8")),
    ...(issuer ? [protoBytes(3, Buffer.from(issuer, "utf8"))] : []),
    encode(4, algorithm),
    encode(5, digits),
    encode(6, type)
  ])
}
function migrationUri(params) {
  // Field 1 repeats per account; field 2 is a version number.
  const payload = Buffer.concat([
    ...params.map((p) => protoBytes(1, otpParameters(p))),
    protoInt(2, 1)
  ])
  return "otpauth-migration://offline?data=" + encodeURIComponent(payload.toString("base64"))
}

{
  // Two accounts in one export, with non-default parameters on the second.
  const uri = migrationUri([
    { secret: Buffer.from("12345678901234567890"), name: "GitHub:sasiru", issuer: "GitHub" },
    { secret: Buffer.from("12345678901234567890123456789012"), name: "Twitter",
      issuer: "", algorithm: 2, digits: 2 }
  ])
  const parsed = S.parseOtpauthBatch(uri)
  check("migration imports both accounts", parsed.accounts.length, 2)
  check("migration errors none", parsed.errors.length, 0)
  const first = parsed.accounts[0]
  check("migration label splits at colon", first.label, "sasiru")
  check("migration issuer", first.issuer, "GitHub")
  check("migration secret becomes base32", first.secret,
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
  check("migration default algorithm SHA1", first.algorithm, "SHA1")
  check("migration default digits 6", first.digits, 6)
  const second = parsed.accounts[1]
  check("migration bare name keeps whole string", second.label, "Twitter")
  check("migration issuer field empty stays empty", second.issuer, "")
  check("migration SHA256 honoured", second.algorithm, "SHA256")
  check("migration eight digits honoured", second.digits, 8)
}

// The name field's own colon wins only when there is no issuer submessage;
// when both exist the dedicated issuer field is authoritative.
{
  const parsed = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("12345678901234567890"), name: "Old:name", issuer: "New" }
  ]))
  check("migration issuer field beats name prefix", parsed.accounts[0].issuer, "New")
}

{
  // No issuer submessage: a plausible prefix still becomes the issuer.
  const parsed = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("12345678901234567890"), name: "GitHub:sasiru" }
  ]))
  check("name-only prefix becomes issuer", parsed.accounts[0].issuer, "GitHub")
  check("name-only prefix leaves account", parsed.accounts[0].label, "sasiru")
}

{
  // Plaintext names are not percent-encoded, so a colon in a URL must not
  // be treated as the issuer separator.
  const parsed = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("12345678901234567890"), name: '<img src="http://x">' }
  ]))
  check("html-like name stays one label", parsed.accounts[0].label, '<img src="http://x">')
  check("html-like name has no issuer", parsed.accounts[0].issuer, "")
}

{
  // A HOTP entry must be reported, not imported — and must not sink the rest.
  const parsed = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("1234567890"), name: "CounterOne", type: 1 },
    { secret: Buffer.from("12345678901234567890"), name: "TimeBased" }
  ]))
  check("hotp sibling still imports", parsed.accounts.length, 1)
  check("hotp account is named TimeBased", parsed.accounts[0].label, "TimeBased")
  check("hotp entry is reported", parsed.errors.length, 1)
}

{
  // Length-delimited encoding of a known enum must not drop the field and
  // import protobuf defaults.
  const packedHotp = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("12345678901234567890"), name: "PackedHotp", type: 1, packed: 6 }
  ]))
  check("length-delimited hotp is not imported", packedHotp.accounts.length, 0)
  check("length-delimited hotp is reported", packedHotp.errors.length, 1)

  const packedDigits = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("12345678901234567890"), name: "PackedDigits", digits: 3, packed: 5 }
  ]))
  check("length-delimited unknown digits are not imported", packedDigits.accounts.length, 0)
  check("length-delimited unknown digits are reported", packedDigits.errors.length, 1)

  const packedAlgo = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("12345678901234567890"), name: "PackedAlgo", algorithm: 9, packed: 4 }
  ]))
  check("length-delimited unknown algorithm is not imported", packedAlgo.accounts.length, 0)
  check("length-delimited unknown algorithm is reported", packedAlgo.errors.length, 1)
}

{
  // Google's real payloads: type=2 is TOTP, type=1 is HOTP.
  const totp = S.parseOtpauthBatch(
    "otpauth-migration://offline?data=CjUKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEg5FeGFtcGxlOnRvdHBAeBoHRXhhbXBsZSABKAEwAhAB")
  check("google totp payload imports", totp.accounts.length, 1)
  check("google totp payload has no errors", totp.errors.length, 0)
  check("google totp payload label", totp.accounts[0].label, "totp@x")

  const hotp = S.parseOtpauthBatch(
    "otpauth-migration://offline?data=CjUKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEg5FeGFtcGxlOmhvdHBAeBoHRXhhbXBsZSABKAEwARAB")
  check("google hotp payload is not imported", hotp.accounts.length, 0)
  check("google hotp payload is reported", hotp.errors.length, 1)
}

{
  const unspecified = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("12345678901234567890"), name: "Unspecified", type: 0 }
  ]))
  check("unspecified type imports as totp", unspecified.accounts.length, 1)
  check("unspecified type has no errors", unspecified.errors.length, 0)
}

{
  const unknownType = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("12345678901234567890"), name: "FutureType", type: 3 }
  ]))
  check("unknown type is not imported", unknownType.accounts.length, 0)
  check("unknown type is reported", unknownType.errors.length, 1)
}

{
  const unknownAlgo = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("12345678901234567890"), name: "WeirdHash", algorithm: 9 }
  ]))
  check("unknown algorithm is not imported", unknownAlgo.accounts.length, 0)
  check("unknown algorithm is reported", unknownAlgo.errors.length, 1)
}

{
  const unspecifiedDigits = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("12345678901234567890"), name: "UnspecifiedDigits", digits: 0 }
  ]))
  check("unspecified digits import as 6", unspecifiedDigits.accounts.length, 1)
  check("unspecified digits are 6", unspecifiedDigits.accounts[0].digits, 6)
  check("unspecified digits has no errors", unspecifiedDigits.errors.length, 0)
}

{
  const unknownDigits = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("12345678901234567890"), name: "WeirdDigits", digits: 3 }
  ]))
  check("unknown digits are not imported", unknownDigits.accounts.length, 0)
  check("unknown digits are reported", unknownDigits.errors.length, 1)
}

{
  // A forbidden wire type inside one OtpParameters must not abort the batch.
  const good = otpParameters({
    secret: Buffer.from("12345678901234567890"), name: "Good"
  })
  const bad = Buffer.concat([protoVarint(1 * 8 + 5), Buffer.alloc(4)])
  const payload = Buffer.concat([
    protoBytes(1, good),
    protoBytes(1, bad),
    protoInt(2, 1)
  ])
  const parsed = S.parseOtpauthBatch(
    "otpauth-migration://offline?data=" + encodeURIComponent(payload.toString("base64")))
  check("malformed entry does not sink sibling", parsed.accounts.length, 1)
  check("malformed entry sibling label", parsed.accounts[0].label, "Good")
  check("malformed entry is reported", parsed.errors.length, 1)
}

{
  // A damaged tag after a valid account must keep what already parsed.
  const good = otpParameters({
    secret: Buffer.from("12345678901234567890"), name: "Kept"
  })
  const payload = Buffer.concat([
    protoBytes(1, good),
    protoVarint(2 * 8 + 5),
    Buffer.alloc(4)
  ])
  const parsed = S.parseOtpauthBatch(
    "otpauth-migration://offline?data=" + encodeURIComponent(payload.toString("base64")))
  check("top-level damage keeps prior accounts", parsed.accounts.length, 1)
  check("top-level damage sibling label", parsed.accounts[0].label, "Kept")
  check("top-level damage is reported", parsed.errors.length, 1)
}

{
  const parsed = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("1234567890"), name: "A".repeat(300) + "\n", type: 1 }
  ]))
  check("overlong error name is reported", parsed.errors.length, 1)
  const err = parsed.errors[0]
  check("error name has no newline", err.indexOf("\n") < 0, "true")
  check("error name is cleaned then capped", err.slice(0, 128), "A".repeat(128))
  check("error uses cleaned prefix",
    err.startsWith("A".repeat(128) + ": "), "true")
}

rejects("rejects a non-migration link as such",
  () => S.parseMigration(`otpauth://totp/X?secret=${SEED}`),
  "Not a Google Authenticator export")
rejects("rejects an export without data", () => S.parseMigration("otpauth-migration://offline"),
  "The export link carries no payload")
rejects("rejects undecodable payload",
  () => S.parseMigration("otpauth-migration://offline?data=!!!!"),
  "The export payload could not be decoded")

{
  // Truncated protobuf must throw rather than loop or read past the end.
  let threw = false
  try {
    S.parseMigration(`otpauth-migration://offline?data=${encodeURIComponent(
      Buffer.from([0x0a, 0x20, 0x01]).toString("base64"))}`)
  } catch (e) { threw = true }
  check("truncated payload throws", threw, true)
}

{
  // UTF-8 names survive the trip through raw bytes.
  const parsed = S.parseOtpauthBatch(migrationUri([
    { secret: Buffer.from("12345678901234567890"), name: "Iss:café ✓" }
  ]))
  check("utf-8 name decodes", parsed.accounts[0].label, "café ✓")
}

// --- mixed batch -------------------------------------------------------------

console.log("\nMixed batches")
{
  const plain = `otpauth://totp/Plain?secret=${SEED}`
  const migration = migrationUri([
    { secret: Buffer.from("1234567890"), name: "FromExport" }
  ])
  const parsed = S.parseOtpauthBatch(`${plain}\n${migration}\nnot-a-link\n`)
  check("batch mixes plain and export codes", parsed.accounts.length, 2)
  check("non-link lines are ignored quietly", parsed.errors.length, 0)

  const broken = S.parseOtpauthBatch("otpauth://totp/x?secret=nope!!\n")
  check("a bad line is counted", broken.accounts.length, 0)
  check("a bad line is reported", broken.errors.length, 1)
  check("empty input yields nothing", S.parseOtpauthBatch("").accounts.length, 0)
}

// --- base32 / base64 helpers --------------------------------------------------

console.log("\nByte helpers")
check("base64 round-trips through bytes",
  Buffer.from(S.base64ToBytes(Buffer.from("hello world").toString("base64")))
    .toString(), "hello world")
check("base64url variant is accepted",
  Buffer.from(S.base64ToBytes("-_8")).toString("latin1"), "\xfb\xff")
check("base32 of a single high byte", S.bytesToBase32([0x7f]), "P4")
check("base32 of the RFC seed", S.bytesToBase32(
  Array.from(Buffer.from("12345678901234567890"))),
  "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
check("utf-8 decode of ascii", S.utf8Decode(Array.from(Buffer.from("abc"))), "abc")

const row = { label: "alice@acme.com", issuer: "ACME" }
check("matches on label", S.matches(row, "alice"), "true")
check("matches on issuer", S.matches(row, "acme"), "true")
check("match is case-insensitive", S.matches(row, "ACME"), "true")
check("empty query matches everything", S.matches(row, "  "), "true")
check("non-match is rejected", S.matches(row, "github"), "false")

// --- export round-trip ------------------------------------------------------

console.log("\nExport")
{
  const account = S.normalizeAccount({ label: "alice@acme.com", issuer: "ACME Co", secret: SEED })
  const link = S.toOtpauth(S.toRecord("x", account), account.secret)
  check("link is an otpauth totp url", link.indexOf("otpauth://totp/") === 0, "true")
  check("issuer and label are encoded",
    link.indexOf("ACME%20Co:alice%40acme.com") > 0, "true")

  // The whole point: what comes out must parse back to what went in.
  const back = S.parseOtpauth(link)
  check("round-trip label", back.label, account.label)
  check("round-trip issuer", back.issuer, account.issuer)
  check("round-trip secret", back.secret, account.secret)
  check("round-trip digits", back.digits, account.digits)
  check("round-trip period", back.period, account.period)
  check("round-trip algorithm", back.algorithm, account.algorithm)
}

{
  // Non-default parameters have to survive too, or a restore silently
  // downgrades an 8-digit SHA-512 account to a 6-digit SHA-1 one and every
  // code it produces is wrong.
  const odd = S.normalizeAccount({
    label: "eight", issuer: "Odd", secret: SEED,
    digits: 8, period: 60, algorithm: "SHA512"
  })
  const back = S.parseOtpauth(S.toOtpauth(S.toRecord("y", odd), odd.secret))
  check("round-trip 8 digits", back.digits, 8)
  check("round-trip 60s period", back.period, 60)
  check("round-trip SHA512", back.algorithm, "SHA512")
}

{
  // A name containing the separator must not split differently on the way back.
  const tricky = S.normalizeAccount({ label: "a:b", issuer: "Iss:uer", secret: SEED })
  const back = S.parseOtpauth(S.toOtpauth(S.toRecord("z", tricky), tricky.secret))
  check("colon in the account name survives", back.label, "a:b")
  check("colon in the issuer survives", back.issuer, "Iss:uer")
}

{
  const records = [
    S.toRecord("a", S.normalizeAccount({ label: "one", issuer: "One", secret: SEED })),
    S.toRecord("b", S.normalizeAccount({ label: "two", issuer: "Two", secret: "JBSWY3DPEHPK3PXP" }))
  ]
  const secrets = { a: SEED, b: "JBSWY3DPEHPK3PXP" }
  const out = S.buildExport(records, (id) => secrets[id])
  check("exported both accounts", out.exported, 2)
  check("nothing was missing", out.missing, 0)
  check("export carries both secrets",
    out.text.indexOf(SEED) > 0 && out.text.indexOf("JBSWY3DPEHPK3PXP") > 0, "true")

  const restored = S.parseExport(out.text)
  check("restore found both", restored.accounts.length, 2)
  check("restore had no errors", restored.errors.length, 0)
  check("restore keeps the first label", restored.accounts[0].label, "one")
  check("restore keeps the second secret", restored.accounts[1].secret, "JBSWY3DPEHPK3PXP")

  // An account whose secret could not be read must be counted, not dropped
  // silently — the user has to know the export is incomplete.
  const partial = S.buildExport(records, (id) => (id === "a" ? SEED : ""))
  check("unreadable secret is counted", partial.missing, 1)
  check("unreadable secret is not exported", partial.exported, 1)
}

console.log("\nRestore: comments and damage")
check("comments are skipped",
  S.parseExport("# a comment\n\n" + S.toOtpauth(
    S.toRecord("q", S.normalizeAccount({ label: "n", secret: SEED })), SEED)).accounts.length, 1)
check("a damaged line is reported",
  S.parseExport("otpauth://totp/x?secret=!!!").errors.length, 1)
check("a damaged line does not abort the rest",
  S.parseExport("garbage\n" + S.toOtpauth(
    S.toRecord("q", S.normalizeAccount({ label: "n", secret: SEED })), SEED)).accounts.length, 1)
check("an empty export restores nothing", S.parseExport("").accounts.length, 0)

console.log(failures === 0
  ? "\nAll checks passed.\n"
  : `\n${failures} check(s) FAILED.\n`)
process.exit(failures === 0 ? 0 : 1)
