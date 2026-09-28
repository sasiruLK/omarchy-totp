.pragma library

// Parsing for the `ykman` output the YubiKey source consumes. Pure string
// handling, so it lives here and is tested with node (test/yubikey.js) rather
// than in the QML that spawns the process — the same split Store.js uses.
//
// The YubiKey's OATH applet is write-only: a secret can be written to it and
// never read back. So this file only ever sees account *names* and the codes
// `ykman` prints for them, never a shared secret.

// The id namespaces YubiKey accounts away from vault records, which are bare
// hex ids, so the two sets can never collide in one list model.
function accountId(name) {
  return "yk:" + name
}

// "issuer:name" -> {issuer, label}. The issuer is optional; `ykman` uses the
// colon form, and a name with no colon is all label.
function splitName(name) {
  var text = String(name || "")
  var at = text.indexOf(":")
  if (at < 0) return { issuer: "", label: text }
  return { issuer: text.substring(0, at).trim(), label: text.substring(at + 1).trim() }
}

// `ykman oath accounts list -o` prints one account per line, the name followed
// by ", TOTP" or ", HOTP". The name may contain spaces, colons and commas; only
// the trailing type is structural. Stripping it is safer than trusting a column
// layout, and a name that literally ends in "TOTP" is not a real case.
function parseAccountList(text) {
  var out = []
  var lines = String(text || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].replace(/\s+$/, "")
    if (line.replace(/^\s+/, "").length === 0) continue

    var type = ""
    // `-o` writes ", TOTP"; accept plain whitespace too so the parser is not
    // tied to one ykman version's exact separator.
    var match = line.match(/^(.*?)(?:,\s*|\s+)(TOTP|HOTP)$/i)
    var name = line
    if (match) {
      name = match[1].replace(/\s+$/, "")
      type = match[2].toUpperCase()
    }
    if (name.length === 0) continue

    var parts = splitName(name)
    out.push({
      id: accountId(name),
      name: name,
      issuer: parts.issuer,
      label: parts.label,
      type: type,
      // The list command does not carry the period; the OATH default is 30
      // seconds and almost every issuer uses it.
      period: 30
    })
  }
  return out
}

// HOTP codes advance a counter on the key, so reading one changes it. Only
// time-based accounts are safe to poll; the rest are listed but not generated.
function isTimeBased(record) {
  return !record || record.type !== "HOTP"
}

// `ykman oath accounts code` prints the name and the code on one line. The code
// is the trailing run of digits; everything before it is the name.
function parseCodes(text) {
  var codes = {}
  var lines = String(text || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var match = lines[i].replace(/\s+$/, "").match(/^(.*?)\s+(\d{6,8})$/)
    if (!match) continue
    var name = match[1].replace(/\s+$/, "")
    if (name.length === 0) continue
    // `ykman oath accounts code <query>` prints a header line naming the
    // account before the code; only the bare "name code" form is a result.
    codes[accountId(name)] = match[2]
  }
  return codes
}

// `ykman oath accounts code -s <name>` prints only the code.
function parseSingleCode(text) {
  var match = String(text || "").match(/(\d{6,8})/)
  return match ? match[1] : ""
}
