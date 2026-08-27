.pragma library
.import "Totp.js" as Totp

// Parsing, validation, and on-disk shape for 2FA accounts.
//
// Everything that reaches this file is untrusted: otpauth:// URIs decoded from
// a QR code someone put on a web page, text pasted from a clipboard, and the
// index file itself (which a previous version, or a text editor, may have left
// malformed). Nothing here trusts its input, and nothing here ever handles the
// shared secret's storage — that belongs to the keyring, via Vault.qml.

var MAX_TEXT = 128
var VALID_DIGITS = [6, 7, 8]
var MIN_PERIOD = 1
var MAX_PERIOD = 300

// Control characters have no place in a display label. They are stripped
// rather than rejected: a stray one should not block an otherwise valid
// enrolment, and they carry no meaning worth preserving. Everything else is
// kept verbatim — including anything that looks like markup, which the UI
// renders literally by using Text.PlainText everywhere.
function cleanText(value) {
  return String(value === undefined || value === null ? "" : value)
    .replace(/[\x00-\x1f\x7f]/g, "")
    .trim()
    .substring(0, MAX_TEXT)
}

function isBlank(value) {
  return cleanText(value).length === 0
}

// --------------------------------------------------------------- otpauth://

// Splits "scheme://type/label?query" without relying on a URL parser, which
// QML's JS environment does not provide. Returns {type, label, params}.
function splitUri(uri) {
  var text = String(uri || "").trim()
  var match = text.match(/^otpauth:\/\/([^\/?#]+)\/?([^?#]*)(?:\?([^#]*))?/i)
  if (!match) throw new Error("Not an otpauth:// link")

  var params = {}
  var query = match[3] || ""
  if (query.length > 0) {
    var pairs = query.split("&")
    for (var i = 0; i < pairs.length; i++) {
      if (pairs[i].length === 0) continue
      var eq = pairs[i].indexOf("=")
      var rawKey = eq < 0 ? pairs[i] : pairs[i].substring(0, eq)
      var rawValue = eq < 0 ? "" : pairs[i].substring(eq + 1)
      // A malformed percent-escape throws out of decodeURIComponent; treat the
      // segment as literal rather than failing the whole enrolment.
      var key, value
      try { key = decodeURIComponent(rawKey) } catch (e) { key = rawKey }
      try { value = decodeURIComponent(rawValue) } catch (e2) { value = rawValue }
      params[key.toLowerCase()] = value
    }
  }

  // The label is returned still encoded. Splitting it into issuer and account
  // has to happen before decoding: the separator is a literal colon in the
  // path, while a colon *inside* either half arrives as %3A. Decode first and
  // the two become indistinguishable, so "<img src=\"http://x\">" would split
  // at the colon in "http:" instead of being one name.
  return { type: match[1].toLowerCase(), label: match[2] || "", params: params }
}

function decodeOrRaw(text) {
  try { return decodeURIComponent(text) } catch (e) { return text }
}

// The label is "issuer:account" or just "account", per the Key Uri Format.
// The issuer= parameter wins over the label prefix when they disagree, which
// is what every other authenticator does.
//
// A literal colon is the separator. Some producers encode it as %3A instead,
// so that is accepted too — but only when there is no literal colon anywhere
// in the label. The two spellings are genuinely ambiguous: an issuer that
// itself contains a colon also arrives as %3A, and treating that as the
// separator splits "Iss:uer:account" in the wrong place. Preferring the
// literal form resolves it, because a name's own colon is always encoded
// while the separator this plugin writes never is.
function splitLabel(rawLabel) {
  var text = String(rawLabel || "")
  var separator = text.indexOf(":") >= 0 ? /^([^:]*):\s*(?:%20)*(.*)$/
                                         : /^(.*?)%3a\s*(?:%20)*(.*)$/i
  var match = text.match(separator)
  if (!match) return { issuer: "", account: decodeOrRaw(text) }
  return {
    issuer: decodeOrRaw(match[1]),
    account: decodeOrRaw(match[2]).replace(/^\s+/, "")
  }
}

// Parses an otpauth:// URI into an account record. Throws with a message meant
// to be shown to the user.
function parseOtpauth(uri) {
  var parts = splitUri(uri)

  if (parts.type === "hotp") {
    throw new Error("Counter-based (HOTP) codes are not supported")
  }
  if (parts.type !== "totp") {
    throw new Error("Unsupported otpauth type: " + cleanText(parts.type))
  }

  var named = splitLabel(parts.label)
  var issuer = cleanText(parts.params.issuer || named.issuer)
  var account = cleanText(named.account)

  return normalizeAccount({
    label: account.length > 0 ? account : issuer,
    issuer: issuer,
    secret: parts.params.secret || "",
    digits: parts.params.digits,
    period: parts.params.period,
    algorithm: parts.params.algorithm
  })
}

// ------------------------------------------------------- otpauth-migration://

// Google Authenticator's otpauth-migration format is a protobuf-based
// migration format. It is not the same as the standardized otpauth:// URI
// format; we decode it here to import supported TOTP credentials.
//
// A batch export produces a QR holding a single
// otpauth-migration://offline?data=<base64> link. The data parameter is a
// protobuf message with one OtpParameters submessage per account:
//
//   OtpParameters {
//     1: secret   (bytes)      raw secret, not base32
//     2: name     (string)     "issuer:account" or just "account"
//     3: issuer   (string)
//     4: algorithm (varint)    0 unspecified · 1 SHA1 · 2 SHA256 · 3 SHA512 · 4 MD5
//     5: digits   (varint)     0 unspecified · 1 six · 2 eight
//     6: type     (varint)     0 unspecified · 1 HOTP · 2 TOTP
//   }
//
// Decoding it here is what makes an image import able to enroll a whole
// authenticator in one pass.

var B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

function base64ToBytes(text) {
  // Standard base64 and the URL-safe variant both arrive; normalise to one.
  var clean = String(text || "")
    .replace(/-/g, "+").replace(/_/g, "/")
    .replace(/[^A-Za-z0-9+\/]/g, "")
  var out = []
  var acc = 0, bits = 0
  for (var i = 0; i < clean.length; i++) {
    acc = (acc << 6) | B64_ALPHABET.indexOf(clean.charAt(i))
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out.push((acc >> bits) & 0xff)
    }
  }
  return out
}

var B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

function bytesToBase32(bytes) {
  var out = ""
  var acc = 0, bits = 0
  for (var i = 0; i < bytes.length; i++) {
    acc = (acc << 8) | bytes[i]
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += B32_ALPHABET.charAt((acc >> bits) & 31)
    }
  }
  if (bits > 0) out += B32_ALPHABET.charAt((acc << (5 - bits)) & 31)
  return out
}

// Account names arrive as raw UTF-8 bytes inside the protobuf, and this JS
// environment offers no TextDecoder, so they are decoded by hand.
function utf8Decode(bytes) {
  var out = ""
  var i = 0
  while (i < bytes.length) {
    var b = bytes[i++]
    var cp
    if (b < 0x80) {
      cp = b
    } else if ((b & 0xe0) === 0xc0 && i < bytes.length) {
      cp = ((b & 0x1f) << 6) | (bytes[i++] & 0x3f)
    } else if ((b & 0xf0) === 0xe0 && i + 1 < bytes.length) {
      cp = ((b & 0x0f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f)
    } else if ((b & 0xf8) === 0xf0 && i + 2 < bytes.length) {
      cp = ((b & 0x07) << 18) | ((bytes[i++] & 0x3f) << 12)
        | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f)
    } else {
      cp = 0xfffd  // replacement character: never throw on hostile bytes
    }
    if (cp > 0xffff) {
      cp -= 0x10000
      out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff))
    } else {
      out += String.fromCharCode(cp)
    }
  }
  return out
}

// Walks protobuf fields, handing each to `visit` as (fieldNumber, wireType,
// value): a Number for varints, a byte array for length-delimited fields.
// Only these two wire types appear in this format; anything else means the
// bytes are not a migration payload at all.
function readProtoFields(bytes, visit) {
  var pos = 0

  function varint() {
    var value = 0, shift = 0, b
    do {
      if (pos >= bytes.length) throw new Error("The QR payload is truncated")
      // Values can exceed 32 bits (counters are uint64), so no bitwise ops.
      value += (bytes[pos] & 0x7f) * Math.pow(2, shift)
      shift += 7
      if (shift > 70) throw new Error("The QR payload is malformed")
    } while (bytes[pos++] & 0x80)
    return value
  }

  while (pos < bytes.length) {
    var tag = varint()
    var field = Math.floor(tag / 8)
    var wire = tag % 8
    if (wire === 0) {
      visit(field, wire, varint())
    } else if (wire === 2) {
      var len = varint()
      if (pos + len > bytes.length) throw new Error("The QR payload is truncated")
      visit(field, wire, bytes.slice(pos, pos + len))
      pos += len
    } else {
      throw new Error("The QR payload is malformed")
    }
  }
}

var MIGRATION_ALGORITHMS = { 0: "", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5" }

function normalizeDigits(value) {
  switch (value) {
  case 0: // unspecified: Google Authenticator's default
  case 1: // six digits
    return 6
  case 2:
    return 8
  default:
    throw new Error("Unsupported digit count")
  }
}

// Migration names are protobuf UTF-8, not percent-encoded otpauth paths.
// Only split when the left-hand side looks like an issuer (no whitespace, no '<').
function splitMigrationName(name) {
  var text = String(name || "")
  var colon = text.indexOf(":")
  if (colon <= 0) return { issuer: "", account: text }
  var prefix = text.substring(0, colon)
  if (/[\s<]/.test(prefix)) return { issuer: "", account: text }
  return { issuer: prefix, account: text.substring(colon + 1) }
}

// Parses an otpauth-migration:// link into { accounts, errors }: every account
// that could be normalized, plus a reason per one that had to be skipped. One
// bad entry — a HOTP account, say — must not sink the other nine.
function parseMigration(uri) {
  var text = String(uri || "").trim()
  var match = text.match(/^otpauth-migration:\/\/offline(?:\?(.*))?$/i)
  if (!match) throw new Error("Not a Google Authenticator export")

  var data = null
  var pairs = (match[1] || "").split("&")
  for (var i = 0; i < pairs.length; i++) {
    var eq = pairs[i].indexOf("=")
    if (eq < 0) continue
    try {
      if (pairs[i].substring(0, eq).toLowerCase() === "data") {
        data = decodeURIComponent(pairs[i].substring(eq + 1))
        break
      }
    } catch (e) { /* keep looking */ }
  }
  if (!data) throw new Error("The export link carries no payload")

  var payload = base64ToBytes(data)
  if (payload.length === 0) throw new Error("The export payload could not be decoded")

  var accounts = []
  var errors = []

  try {
    readProtoFields(payload, function(field, wire, value) {
      // Field 1 repeats once per account. Field 2 is a version number; ignore it.
      if (field !== 1 || wire !== 2) return

      var secretBytes = [], name = "", issuer = "", algorithm = 0,
          digitsEnum = 0, typeEnum = -1
      try {
        readProtoFields(value, function(f, w, v) {
          if (w === 0 && f === 4) algorithm = v
          else if (w === 0 && f === 5) digitsEnum = v
          else if (w === 0 && f === 6) typeEnum = v
          else if (w === 2 && f === 1) secretBytes = v
          else if (w === 2 && f === 2) name = utf8Decode(v)
          else if (w === 2 && f === 3) issuer = utf8Decode(v)
          // Unknown field numbers are ignored (forward-compatible). A known
          // field with the wrong wire type is not: packed-repeated encoding
          // would otherwise drop type/digits/algorithm and import defaults.
          else if (f >= 1 && f <= 6) throw new Error("The QR payload is malformed")
        })

        if (typeEnum === 1) {
          throw new Error("Counter-based (HOTP) codes are not supported")
        }
        // Missing (-1) and unspecified (0) are treated as TOTP, matching Google's
        // protobuf default. Anything else is not a time-based code we can honour.
        if (typeEnum !== 2 && typeEnum !== 0 && typeEnum !== -1) {
          throw new Error("Unsupported otpauth type")
        }
        if (!Object.prototype.hasOwnProperty.call(MIGRATION_ALGORITHMS, algorithm)) {
          throw new Error("Unsupported algorithm")
        }
        var named = splitMigrationName(name)
        accounts.push(normalizeAccount({
          label: named.account.trim(),
          issuer: issuer.length > 0 ? issuer : named.issuer,
          secret: bytesToBase32(secretBytes),
          digits: normalizeDigits(digitsEnum),
          period: 30,
          algorithm: MIGRATION_ALGORITHMS[algorithm]
        }))
      } catch (e) {
        var safeName = cleanText(name)
        errors.push(safeName.length > 0 ? safeName + ": " + e.message : e.message)
      }
    })
  } catch (e) {
    // A damaged tag after some entries must not discard the ones already
    // collected. Completely unreadable payloads still throw.
    if (accounts.length === 0) throw e
    errors.push(e.message)
  }

  return { accounts: accounts, errors: errors }
}

// Reads every otpauth link in a blob of decoded-QR output — one code per line.
// A plain otpauth:// line yields one account; an Authenticator export line can
// carry many. Returns what parsed plus why the rest did not, so the caller can
// import the good half and report the remainder.
function parseOtpauthBatch(text) {
  var lines = String(text || "").split("\n")
  var accounts = []
  var errors = []
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (line.length === 0) continue
    if (!/^otpauth/i.test(line)) continue
    try {
      if (/^otpauth-migration:\/\//i.test(line)) {
        var migration = parseMigration(line)
        for (var j = 0; j < migration.accounts.length; j++) accounts.push(migration.accounts[j])
        for (j = 0; j < migration.errors.length; j++) errors.push(migration.errors[j])
      } else {
        accounts.push(parseOtpauth(line))
      }
    } catch (e) {
      errors.push(e.message)
    }
  }
  return { accounts: accounts, errors: errors }
}

// ------------------------------------------------------------- normalisation

// Applies defaults, coerces types, and rejects anything out of range. The
// caller gets back a record safe to store, or an exception explaining why not.
//
// `secret` is validated but is NOT part of the stored record — Vault.qml hands
// it to the keyring and drops it. Keeping it out of the index file is the
// whole point of the split.
function normalizeAccount(input) {
  var raw = input || {}

  var label = cleanText(raw.label)
  var issuer = cleanText(raw.issuer)
  if (label.length === 0) label = issuer
  if (label.length === 0) throw new Error("A name is required")

  var digits = raw.digits === undefined || raw.digits === null || raw.digits === ""
    ? 6 : parseInt(raw.digits, 10)
  if (VALID_DIGITS.indexOf(digits) < 0) {
    throw new Error("Digits must be 6, 7, or 8")
  }

  var period = raw.period === undefined || raw.period === null || raw.period === ""
    ? 30 : parseInt(raw.period, 10)
  if (!isFinite(period) || period < MIN_PERIOD || period > MAX_PERIOD) {
    throw new Error("Period must be between " + MIN_PERIOD + " and " + MAX_PERIOD + " seconds")
  }

  var algorithm = Totp.normalizeAlgorithm(raw.algorithm)
  if (!algorithm) {
    throw new Error("Unsupported algorithm: " + cleanText(raw.algorithm))
  }

  var secret = String(raw.secret || "").replace(/[\s-]/g, "")
  if (secret.length === 0) throw new Error("A secret is required")

  // Decode the secret and actually generate a code. A secret that only fails
  // at sign-in time — when the account is already locked behind it — is the
  // worst bug this plugin could ship, so it fails here instead.
  try {
    Totp.totp(secret, { digits: digits, period: period, algorithm: algorithm, t: 0 })
  } catch (e) {
    throw new Error("That secret is not valid base32")
  }

  return {
    label: label,
    issuer: issuer,
    digits: digits,
    period: period,
    algorithm: algorithm,
    secret: secret
  }
}

// ------------------------------------------------------------- index records

// Ids only need to be unique and stable — they key the keyring lookup and
// never authenticate anything, so a timestamp plus randomness is enough. The
// caller passes the ids already in use so a collision cannot silently
// overwrite another account's secret.
function newId(existingIds) {
  var taken = {}
  var list = existingIds || []
  for (var i = 0; i < list.length; i++) taken[list[i]] = true

  for (var attempt = 0; attempt < 1000; attempt++) {
    var id = Date.now().toString(36) + "-" +
      Math.floor(Math.random() * 0x100000000).toString(36) +
      Math.floor(Math.random() * 0x100000000).toString(36)
    if (!taken[id]) return id
  }
  throw new Error("Could not allocate an account id")
}

// Strips an account down to what may be written to disk. The secret is absent
// by construction: this function names every field it copies, so a secret
// cannot reach the index file by being added to the record upstream.
function toRecord(id, account) {
  return {
    id: id,
    label: account.label,
    issuer: account.issuer,
    digits: account.digits,
    period: account.period,
    algorithm: account.algorithm
  }
}

// Reads the index file. Anything unparseable or structurally wrong yields an
// empty list rather than an exception — a corrupt index must not stop the
// panel from opening, and the accounts it describes are recoverable from the
// keyring entries that outlive it.
function parseIndex(text) {
  var parsed
  try {
    parsed = JSON.parse(String(text || ""))
  } catch (e) {
    return []
  }
  if (!parsed || !parsed.accounts || parsed.accounts.length === undefined) return []

  var out = []
  var seen = {}
  for (var i = 0; i < parsed.accounts.length; i++) {
    var row = parsed.accounts[i]
    if (!row || typeof row !== "object") continue

    var id = cleanText(row.id)
    // Ids address keyring items, so keep them to a conservative shape and
    // never let a duplicate shadow an earlier entry.
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(id) || seen[id]) continue
    seen[id] = true

    var digits = parseInt(row.digits, 10)
    var period = parseInt(row.period, 10)
    var algorithm = Totp.normalizeAlgorithm(row.algorithm)

    out.push({
      id: id,
      label: cleanText(row.label) || id,
      issuer: cleanText(row.issuer),
      digits: VALID_DIGITS.indexOf(digits) >= 0 ? digits : 6,
      period: isFinite(period) && period >= MIN_PERIOD && period <= MAX_PERIOD ? period : 30,
      algorithm: algorithm || "SHA1"
    })
  }
  return out
}

function serializeIndex(records) {
  var rows = []
  for (var i = 0; i < records.length; i++) {
    rows.push(toRecord(records[i].id, records[i]))
  }
  return JSON.stringify({ version: 1, accounts: rows }, null, 2) + "\n"
}

// ------------------------------------------------------------------- export

// Renders an account back into the otpauth:// form every authenticator
// understands, so an export is a migration path rather than a snapshot only
// this plugin can read.
//
// Both halves of the label are percent-encoded, which is what keeps the
// issuer/account separator unambiguous: a colon inside either name becomes
// %3A and cannot be mistaken for the separator when the link is read back.
function toOtpauth(record, secret) {
  var label = encodeURIComponent(record.label)
  if (record.issuer.length > 0) {
    label = encodeURIComponent(record.issuer) + ":" + label
  }

  var params = ["secret=" + encodeURIComponent(secret)]
  if (record.issuer.length > 0) {
    params.push("issuer=" + encodeURIComponent(record.issuer))
  }
  params.push("algorithm=" + record.algorithm)
  params.push("digits=" + record.digits)
  params.push("period=" + record.period)

  return "otpauth://totp/" + label + "?" + params.join("&")
}

// The export is a plain list of otpauth:// links with a short header. Comment
// lines are ignored on the way back in, so the header can explain itself
// without breaking a restore.
function buildExport(records, secretFor) {
  var lines = [
    "# Omarchy 2FA export",
    "# One otpauth:// link per account. Any authenticator can read these.",
    "# Anyone holding this file can generate your codes — keep it encrypted.",
    ""
  ]
  var missing = 0
  for (var i = 0; i < records.length; i++) {
    var secret = secretFor(records[i].id)
    if (!secret || secret.length === 0) { missing++; continue }
    lines.push(toOtpauth(records[i], secret))
  }
  return { text: lines.join("\n") + "\n", exported: lines.length - 4, missing: missing }
}

// Reads an export back. Blank lines and comments are skipped; every other line
// must parse, and a line that does not is reported rather than silently
// dropped — a restore that quietly loses an account is worse than one that
// fails loudly.
function parseExport(text) {
  var lines = String(text || "").split("\n")
  var accounts = []
  var errors = []
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (line.length === 0 || line.charAt(0) === "#") continue
    try {
      accounts.push(parseOtpauth(line))
    } catch (e) {
      errors.push("line " + (i + 1) + ": " + e.message)
    }
  }
  return { accounts: accounts, errors: errors }
}

// ------------------------------------------------------------------ display

// Case-insensitive substring match over the name and issuer, for the filter
// field. Kept here so the panel does no string logic of its own.
function matches(record, query) {
  var q = String(query || "").trim().toLowerCase()
  if (q.length === 0) return true
  return (record.label + " " + record.issuer).toLowerCase().indexOf(q) >= 0
}

// Codes are read aloud and typed in groups; every authenticator splits them.
function groupCode(code) {
  var text = String(code || "")
  if (text.length === 6) return text.substring(0, 3) + " " + text.substring(3)
  if (text.length === 8) return text.substring(0, 4) + " " + text.substring(4)
  if (text.length === 7) return text.substring(0, 4) + " " + text.substring(4)
  return text
}
