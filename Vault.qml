import QtQuick
import Quickshell
import Quickshell.Io
import "Store.js" as Store

// Owns where a 2FA account lives, split in two so that neither half is enough
// on its own:
//
//   the index   ~/.local/share/omarchy-totp/accounts.json — names, digits,
//               period, algorithm. Never a secret. Mode 0600.
//   the secret  the Secret Service (gnome-keyring), one item per account,
//               addressed by the account's id.
//
// A copied index file is therefore useless, and the secrets sit behind the
// same lock as the rest of the login keyring.
//
// Two rules hold everywhere below:
//   * A secret never appears in a command line. `secret-tool store` takes it
//     on stdin; /proc/<pid>/cmdline is world-readable and would leak it.
//   * Secrets live in memory only while the panel is open. forgetSecrets()
//     drops them on close.
Item {
  id: root

  readonly property string home: Quickshell.env("HOME")
  readonly property string dataDir: home + "/.local/share/omarchy-totp"
  readonly property string indexPath: dataDir + "/accounts.json"

  // Attribute pair identifying this plugin's keyring items. `secret-tool clear
  // service omarchy-totp` matches on the service alone, which is what makes a
  // complete uninstall a single command.
  readonly property string keyringService: "omarchy-totp"

  // Index records, secret-free. Rendered by the panel.
  property var records: []
  // id -> base32 secret, populated on open and dropped on close.
  property var secrets: ({})

  property bool secretsLoaded: false
  property bool busy: false
  // Set when the keyring itself is unreachable or refuses a write, so the UI
  // can say so instead of showing a silently empty list.
  property string error: ""

  signal accountAdded(string id)
  signal actionFailed(string message)
  // Emitted once the index has been read, successfully or not, so the panel
  // knows when it is meaningful to start resolving secrets.
  signal indexLoaded()
  signal exportFinished(bool ok, string message)
  signal restoreFinished(bool ok, string message)

  function ids() {
    var out = []
    for (var i = 0; i < records.length; i++) out.push(records[i].id)
    return out
  }

  function recordFor(id) {
    for (var i = 0; i < records.length; i++) {
      if (records[i].id === id) return records[i]
    }
    return null
  }

  function secretFor(id) {
    return secrets.hasOwnProperty(id) ? secrets[id] : ""
  }

  // ------------------------------------------------------------- the index

  readonly property bool _mutating: _adding || _addQueue.length > 0
                                 || indexWriter.running

  function reload() {
    indexFile.reload()
  }

  function writeIndex() {
    indexWriter.payload = Store.serializeIndex(records)
    // Re-open stdin before every run. onStarted closes it to signal EOF, and
    // that closed state persists on a reused Process — a second run would then
    // have no pipe to write to and would block forever on a stdin that never
    // ends. See the note on `store` below; this cost us a hung secret-tool.
    indexWriter.stdinEnabled = true
    indexWriter.running = true
  }

  FileView {
    id: indexFile
    path: root.indexPath
    // Deliberately NOT watching for changes. Every write here is one this
    // object just made, and a reload racing the next write would overwrite
    // newer in-memory records with the previous version of the file — adding
    // three accounts quickly ended up keeping one. The panel reloads on open,
    // which is the only moment an outside edit could matter.
    watchChanges: false
    printErrors: false
    // A read that lands while a write is in flight must not be believed: the
    // file it read is the version from before the change. The QR path hits
    // this exactly — finishing a scan reopens the panel, which reloads the
    // index, while the scanned account is still being written.
    onLoaded: {
      if (!root._mutating) root.records = Store.parseIndex(text())
      root.indexLoaded()
    }
    // A missing index is the normal first-run state, not a failure.
    onLoadFailed: {
      if (!root._mutating) root.records = []
      root.indexLoaded()
    }
  }

  // Writes the index with the restrictive mode applied *before* any bytes land,
  // then renames it into place. Creating the file and chmod-ing it afterwards
  // would leave a window — under a normal umask of 022 — where another local
  // user could read it. Same reasoning as the umask on the directory.
  //
  // The script is a constant and the only variable reaches it as an argument,
  // never as interpolated shell text. The payload goes over stdin, so even a
  // pathological account name cannot become shell syntax.
  Process {
    id: indexWriter
    property string payload: ""

    command: ["sh", "-c",
      "umask 077 && mkdir -p \"$1\" && cat > \"$1/accounts.json.new\" && " +
      "mv -f \"$1/accounts.json.new\" \"$1/accounts.json\"",
      "omarchy-totp-write-index", root.dataDir]
    stdinEnabled: true

    onStarted: {
      write(payload)
      payload = ""
      // secret-tool and cat alike read to EOF. Closing stdin is what ends the
      // write; leaving it open hangs the process forever.
      stdinEnabled = false
    }
    onExited: function(code) {
      if (code !== 0) root.actionFailed("Could not save the account list")
    }
  }

  // ------------------------------------------------------------- the keyring

  // Sequential lookup queue. One Process is reused rather than spawning one
  // per account, so a long list cannot fork a burst of subprocesses.
  property var _pendingIds: []

  function loadSecrets() {
    if (busy) return
    root.error = ""
    secretsLoaded = false
    secrets = ({})
    var queue = []
    for (var i = 0; i < records.length; i++) queue.push(records[i].id)
    _pendingIds = queue
    busy = true
    _nextSecret()
  }

  function _nextSecret() {
    if (_pendingIds.length === 0) {
      busy = false
      secretsLoaded = true
      if (_pendingExport) {
        var waiting = _pendingExport
        _pendingExport = null
        _runExport(waiting.path, waiting.passphrase)
      }
      return
    }
    var next = _pendingIds.shift()
    lookup.accountId = next
    lookup.command = ["secret-tool", "lookup",
      "service", root.keyringService, "account", next]
    lookup.running = true
  }

  // Drops every decrypted secret. Called when the panel closes so they are not
  // held for the rest of the session.
  function forgetSecrets() {
    secrets = ({})
    secretsLoaded = false
    _pendingIds = []
  }

  Process {
    id: lookup
    property string accountId: ""
    property string found: ""

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: lookup.found = text
    }
    stderr: StdioCollector { waitForEnd: true }

    onExited: function(code) {
      if (code === 0 && found.length > 0) {
        var merged = {}
        for (var key in root.secrets) merged[key] = root.secrets[key]
        merged[accountId] = found
        root.secrets = merged
      } else if (code !== 0 && code !== 1) {
        // Exit 1 is "no such item" — an account whose secret was removed from
        // the keyring behind our back. Anything else means the Secret Service
        // is unreachable, which the panel must say out loud.
        root.error = "Keyring unavailable. Is gnome-keyring running and unlocked?"
      }
      found = ""
      root._nextSecret()
    }
  }

  // ------------------------------------------------------------- mutations

  // `account` is a record from Store.normalizeAccount: already validated, and
  // still carrying its secret. The secret goes to the keyring and is dropped
  // here; only the metadata reaches the index.
  //
  // Adds are queued rather than started immediately. There is one `store`
  // Process, so two adds arriving close together — a restore, or an impatient
  // double click — would otherwise reconfigure it mid-flight and lose one of
  // the secrets.
  property var _addQueue: []
  property bool _adding: false
  property bool _restoring: false
  readonly property bool restoring: _restoring

  // Same name, same issuer and same secret means this account is already
  // stored. Two rows generating identical codes is pure confusion, and
  // deleting "the duplicate" risks deleting the one that was meant to stay.
  function alreadyStored(account) {
    return _identityOf(account) !== "" && _storedIdentities()[_identityOf(account)] === true
  }

  function _identityOf(account) {
    var secret = account.secret !== undefined ? account.secret : ""
    if (secret.length === 0) return ""
    return account.label + "\u0000" + account.issuer + "\u0000" + secret
  }

  function _storedIdentities() {
    var seen = {}
    for (var i = 0; i < records.length; i++) {
      var secret = secretFor(records[i].id)
      if (secret.length === 0) continue
      seen[records[i].label + "\u0000" + records[i].issuer + "\u0000" + secret] = true
    }
    return seen
  }

  function add(account) {
    var queue = _addQueue.slice(0)
    queue.push(account)
    _addQueue = queue
    _drainAdds()
  }

  // `verb` names the operation in the completion message — "Restored" for an
  // export file, "Imported" when the batch came from QR codes in an image.
  function addMany(accounts, verb) {
    // One named batch at a time: _batchVerb is read when the queue drains, so
    // a second call here would relabel the in-flight completion message.
    if (_restoring) {
      actionFailed("Wait for the current import to finish")
      return
    }
    _batchVerb = typeof verb === "string" && verb.length > 0 ? verb : "Restored"

    if (accounts.length === 0) {
      restoreFinished(false, "That export contained no accounts")
      return
    }

    // Restoring the same file twice should be harmless, so anything already
    // present is skipped rather than added a second time. The set grows as the
    // batch is scanned, which also collapses duplicates inside one file.
    var seen = _storedIdentities()
    var queue = _addQueue.slice(0)
    var added = 0
    var skipped = 0
    for (var i = 0; i < accounts.length; i++) {
      var identity = _identityOf(accounts[i])
      if (identity === "" || seen[identity] === true) { skipped++; continue }
      seen[identity] = true
      queue.push(accounts[i])
      added++
    }

    _restoreSkipped = skipped
    if (added === 0) {
      restoreFinished(false, "Every account found is already here")
      return
    }

    _restoring = true
    _addQueue = queue
    _drainAdds()
  }

  property int _restoreSkipped: 0
  property string _batchVerb: "Restored"

  function _drainAdds() {
    if (_adding) return
    if (_addQueue.length === 0) {
      if (_restoring) {
        _restoring = false
        restoreFinished(true, _restoreSkipped > 0
          ? _batchVerb + ", skipping " + _restoreSkipped + " already here"
          : _batchVerb)
      }
      return
    }

    var queue = _addQueue.slice(0)
    var account = queue.shift()
    _addQueue = queue

    var id = Store.newId(ids())
    _adding = true
    store.accountId = id
    store.account = account
    store.secret = account.secret
    store.command = ["secret-tool", "store",
      "--label", labelForKeyring(account),
      "service", root.keyringService, "account", id]
    store.stdinEnabled = true
    store.running = true
  }

  function labelForKeyring(account) {
    var name = account.issuer.length > 0 && account.issuer !== account.label
      ? account.issuer + " (" + account.label + ")"
      : account.label
    return "TOTP: " + name
  }

  Process {
    id: store
    property string accountId: ""
    property var account: null
    property string secret: ""

    stdinEnabled: true
    stderr: StdioCollector { waitForEnd: true }

    onStarted: {
      // No trailing newline. secret-tool reads to EOF and strips at most one,
      // so appending one only works if exactly one survives the pipe — and a
      // stray extra would be stored as part of the secret, producing codes
      // that are wrong in a way nothing here could detect. Writing the bare
      // value and closing the pipe is unambiguous.
      write(secret)
      // Clear the copy held on this object the moment it is handed over, so a
      // failed or slow keyring call does not leave it sitting in a property.
      secret = ""
      // secret-tool reads to EOF, so this close is what completes the store.
      // Without it the process waits forever with the secret in flight — and
      // because the closed state sticks to a reused Process, every launch has
      // to re-enable stdin first. add() does that.
      stdinEnabled = false
    }

    onExited: function(code) {
      root._adding = false
      if (code !== 0) {
        account = null
        root._addQueue = []
        root._restoring = false
        root.actionFailed("Could not save to the keyring. Is it unlocked?")
        return
      }

      var next = root.records.slice(0)
      next.push(Store.toRecord(accountId, account))
      root.records = next

      var merged = {}
      for (var key in root.secrets) merged[key] = root.secrets[key]
      merged[accountId] = account.secret
      root.secrets = merged

      account = null
      root.writeIndex()
      root.accountAdded(accountId)
      Qt.callLater(root._drainAdds)
    }
  }

  function remove(id) {
    clear.accountId = id
    clear.command = ["secret-tool", "clear",
      "service", root.keyringService, "account", id]
    clear.running = true
  }

  Process {
    id: clear
    property string accountId: ""
    stderr: StdioCollector { waitForEnd: true }

    onExited: function(code) {
      // The index entry is dropped even if the keyring item was already gone,
      // so a half-removed account cannot become permanently unremovable.
      var next = []
      for (var i = 0; i < root.records.length; i++) {
        if (root.records[i].id !== accountId) next.push(root.records[i])
      }
      root.records = next

      var merged = {}
      for (var key in root.secrets) {
        if (key !== accountId) merged[key] = root.secrets[key]
      }
      root.secrets = merged

      root.writeIndex()
      if (code !== 0 && code !== 1) {
        root.actionFailed("Removed locally, but the keyring entry may remain")
      }
    }
  }

  // ------------------------------------------------------- export / restore

  // Exports every account as otpauth:// links, symmetrically encrypted with
  // GnuPG. Encryption is not optional: an export holds every shared secret in
  // full, and one left readable on disk undoes the point of keeping them in
  // the keyring. The links inside are the standard format, so the file is a
  // migration path to any other authenticator, not a private snapshot.
  //
  // GnuPG is part of every Arch base system (the package manager itself
  // depends on it), so this adds no dependency of its own.
  //
  // The passphrase reaches gpg through a FIFO in a private temporary
  // directory. It cannot go on the command line (world-readable in /proc) and
  // should not go in a file (it would touch disk), but gpg needs it on a
  // different channel from the plaintext, which is already using stdin. A FIFO
  // is that channel, and it never stores a byte.
  //
  // The caller sends the passphrase as the first line of stdin; everything
  // after it is the plaintext.
  readonly property string _passphraseFifo:
    "umask 077\n" +
    "dir=$(mktemp -d) || exit 1\n" +
    "trap 'rm -rf \"$dir\"' EXIT INT TERM\n" +
    "mkfifo \"$dir/pass\" || exit 1\n" +
    "IFS= read -r phrase || exit 1\n" +
    // printf is a bash builtin, so the passphrase never becomes a process
    // argument. The subshell writes it into the FIFO and exits.
    "printf %s \"$phrase\" > \"$dir/pass\" &\n" +
    "unset phrase\n"

  function expandPath(path) {
    var text = String(path || "").trim()
    if (text === "~") return home
    if (text.indexOf("~/") === 0) return home + text.substring(1)
    return text
  }

  // Set while an export is waiting for the keyring lookups to finish.
  property var _pendingExport: null

  function exportTo(path, passphrase) {
    var target = expandPath(path)
    if (target.length === 0) {
      exportFinished(false, "Choose where to save the export")
      return
    }
    if (passphrase.length === 0) {
      exportFinished(false, "A passphrase is required")
      return
    }

    // Asking to export a second after opening the panel used to fail outright,
    // because the secrets were still being fetched from the keyring one at a
    // time. Wait for them instead: telling someone to "try again" for a
    // condition that clears itself is just a bug with a message attached.
    if (!secretsLoaded) {
      _pendingExport = { path: path, passphrase: passphrase }
      loadSecrets()
      return
    }

    _runExport(path, passphrase)
  }

  function _runExport(path, passphrase) {
    var target = expandPath(path)
    var built = Store.buildExport(records, secretFor)
    if (built.exported === 0) {
      exportFinished(false, "No account secrets could be read")
      return
    }

    exporter.exported = built.exported
    exporter.missing = built.missing
    exporter.target = path
    exporter.payload = passphrase + "\n" + built.text
    exporter.command = ["bash", "-c",
      root._passphraseFifo +
      "gpg --batch --yes --quiet --symmetric --cipher-algo AES256 " +
      "--pinentry-mode loopback --passphrase-file \"$dir/pass\" " +
      "--armor --output \"$1\"",
      "omarchy-totp-export", target]
    exporter.stdinEnabled = true
    exporter.running = true
  }

  Process {
    id: exporter
    property string payload: ""
    property int exported: 0
    property int missing: 0
    property string target: ""

    stderr: StdioCollector { waitForEnd: true }

    onStarted: {
      write(payload)
      // Dropped immediately: this string holds every secret the plugin knows.
      payload = ""
      stdinEnabled = false
    }
    onExited: function(code) {
      if (code !== 0) {
        root.exportFinished(false, "Export failed. Is gpg working?")
        return
      }
      var message = "Saved " + exported + (exported === 1 ? " account to " : " accounts to ") + target
      if (missing > 0) {
        // Never let a partial export look complete.
        message += " (" + missing + " could not be read)"
      }
      root.exportFinished(true, message)
    }
  }

  function restoreFrom(path, passphrase) {
    var source = expandPath(path)
    if (source.length === 0) {
      restoreFinished(false, "Choose a file to restore from")
      return
    }
    if (passphrase.length === 0) {
      restoreFinished(false, "A passphrase is required")
      return
    }

    restorer.payload = passphrase + "\n"
    restorer.command = ["bash", "-c",
      root._passphraseFifo +
      "gpg --batch --quiet --decrypt --pinentry-mode loopback " +
      "--passphrase-file \"$dir/pass\" -- \"$1\"",
      "omarchy-totp-restore", source]
    restorer.stdinEnabled = true
    restorer.running = true
  }

  Process {
    id: restorer
    property string payload: ""
    property string plaintext: ""

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: restorer.plaintext = text
    }
    stderr: StdioCollector { waitForEnd: true }

    onStarted: {
      write(payload)
      payload = ""
      stdinEnabled = false
    }
    onExited: function(code) {
      var decrypted = plaintext
      plaintext = ""
      if (code !== 0) {
        root.restoreFinished(false, "Could not decrypt — wrong passphrase or file?")
        return
      }

      var parsed = Store.parseExport(decrypted)
      if (parsed.errors.length > 0 && parsed.accounts.length === 0) {
        root.restoreFinished(false, "Nothing in that file could be read")
        return
      }
      if (parsed.errors.length > 0) {
        // Report the shortfall rather than quietly restoring a subset.
        root.actionFailed(parsed.errors.length + " line(s) could not be read")
      }
      root.addMany(parsed.accounts)
    }
  }

  // Removes every trace this plugin has written: all keyring items carrying
  // the service attribute, and the data directory. `omarchy plugin remove`
  // executes nothing from the plugin, so without this the only way to clean up
  // is by hand — and state left behind after an uninstall is exactly what the
  // README's uninstall section has to be able to promise away.
  function purgeAll() {
    purge.running = true
  }

  Process {
    id: purge
    // The directory is passed as an argument and re-checked in the script
    // rather than interpolated: rm -rf deserves a belt as well as braces.
    command: ["sh", "-c",
      "secret-tool clear service \"$1\"; " +
      "case \"$2\" in */.local/share/omarchy-totp) rm -rf -- \"$2\" ;; esac",
      "omarchy-totp-purge", root.keyringService, root.dataDir]

    onExited: function(code) {
      root.records = []
      root.forgetSecrets()
      root.error = ""
    }
  }
}
