import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Totp.js" as Totp
import "Store.js" as Store

// Bar widget and popup for the 2FA plugin. The bar-widget entry point is this
// Panel itself, matching omarchy.audio and omarchy.network: the button lives in
// the widget slot and the popup hangs off it.
//
// Security note that shapes this whole file: account names and issuers come
// from scanned QR codes and pasted otpauth:// links, so they are attacker
// controlled. Every Text that renders one sets `textFormat: Text.PlainText`.
// Without it Qt sniffs the string, decides `<img src="http://…">` is rich
// text, and the shell fetches that URL — turning an offline plugin into a
// beacon. There is no exception to this rule anywhere in this plugin.
Panel {
  id: root
  moduleName: "io.github.sasirulk.totp"
  ipcTarget: "io.github.sasirulk.totp"

  // "list" | "add" | "manual" | "export" | "restore" | "image"
  property string view: "list"
  property string query: ""
  property string notice: ""
  property string formError: ""
  property string pendingDeleteId: ""
  property bool purgeArmed: false

  // Keyboard cursor. `cursorActive` stays false until the first key press, so
  // opening the popup does not paint a selection the mouse user did not ask for.
  property bool cursorActive: false
  property int listIndex: 0
  property int addIndex: 0

  // Unix seconds, refreshed once a second while the popup is open. One timer
  // drives every row's code and countdown; a timer per row would be dozens of
  // wakeups a second for the same instant in time.
  property int now: 0

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property var visibleRecords: {
    var out = []
    for (var i = 0; i < vault.records.length; i++) {
      if (Store.matches(vault.records[i], root.query)) out.push(vault.records[i])
    }
    return out
  }

  // Off until the "yubikey" setting is turned on. When it is off, YubiKey.qml
  // spawns no process at all — see the note there.
  readonly property bool yubikeyEnabled: setting("yubikey", false) === true

  readonly property var visibleYubiKey: {
    var out = []
    for (var i = 0; i < yubikey.accounts.length; i++) {
      if (Store.matches(yubikey.accounts[i], root.query)) out.push(yubikey.accounts[i])
    }
    return out
  }

  readonly property string yubikeyStatusText: {
    if (!root.yubikeyEnabled) return "Off"
    if (yubikey.status === "missing") return "Needs setup"
    if (yubikey.status === "service") return "Service off"
    if (yubikey.status === "no-key") return "No key"
    if (yubikey.status === "locked") return "Locked"
    if (yubikey.status === "loading") return "Reading…"
    if (yubikey.status === "error") return "Error"
    if (yubikey.accounts.length === 0) return "No accounts"
    return yubikey.accounts.length === 1 ? "1 account"
                                         : yubikey.accounts.length + " accounts"
  }

  // The fix for whatever is blocking a first run, in the words the user needs,
  // with the action that does it. Empty when there is nothing to fix — a
  // YubiKey feature must not send anyone to a README to get started.
  readonly property string yubikeyHint: {
    if (!root.yubikeyEnabled) return ""
    if (yubikey.status === "missing") return "yubikey-manager is needed to read the key."
    if (yubikey.status === "service") return "The smart-card service (pcscd) isn't running."
    if (yubikey.status === "no-key") return "Insert your YubiKey, then check again."
    if (yubikey.status === "locked") return "Unlock the key's OATH app once on this machine."
    if (yubikey.status === "error") return yubikey.error
    return ""
  }

  readonly property string yubikeyAction: {
    if (!root.yubikeyEnabled) return ""
    if (yubikey.status === "missing") return "Install"
    if (yubikey.status === "service") return "Start"
    if (yubikey.status === "locked") return "Unlock"
    if (yubikey.status === "no-key") return "Check again"
    if (yubikey.status === "error") return "Check again"
    return ""
  }

  // Where a fix opens a terminal, the popup has to close first: while it is up
  // it holds the keyboard, so the terminal would come up behind it unfocused.
  // Same hand-off typeCode() does before it types.
  property string deferredYubiAction: ""

  function runYubiKeyAction() {
    if (yubikey.status === "missing" || yubikey.status === "locked") {
      deferredYubiAction = yubikey.status
      root.close()
      yubiActionDelay.restart()
      return
    }
    if (yubikey.status === "service") {
      // Starting the socket opens no window of its own, so keep the popup and
      // let the re-read fill it in.
      yubikey.startService()
      return
    }
    yubikey.refresh()
  }

  function performDeferredYubiAction() {
    var action = deferredYubiAction
    deferredYubiAction = ""
    if (action === "missing") yubikey.install()
    else if (action === "locked") yubikey.unlockKey()
  }

  readonly property var addActions: [
    { key: "scan", label: "Scan a QR code on screen" },
    { key: "image", label: "Import QR codes from an image" },
    { key: "paste", label: "Paste an otpauth:// link" },
    { key: "manual", label: "Enter a secret by hand" },
    { key: "restore", label: "Restore from an encrypted export" }
  ]

  function defaultExportPath() {
    var today = new Date()
    var stamp = today.getFullYear() + "-"
      + ("0" + (today.getMonth() + 1)).slice(-2) + "-"
      + ("0" + today.getDate()).slice(-2)
    return "~/2fa-export-" + stamp + ".asc"
  }

  // --------------------------------------------------------------- codes

  function codeFor(record) {
    var secret = vault.secretFor(record.id)
    if (secret.length === 0) return ""
    try {
      return Totp.totp(secret, {
        digits: record.digits,
        period: record.period,
        algorithm: record.algorithm,
        t: root.now
      })
    } catch (e) {
      // A secret that no longer decodes cannot produce a code; the row shows
      // it as locked rather than a plausible-looking wrong number.
      return ""
    }
  }

  function flash(message) {
    root.notice = message
    noticeTimer.restart()
  }

  // Writes this panel's inline settings back to shell.json. The shell owns the
  // file, so the write goes through it; the local copy is updated at once so
  // the UI reacts without waiting for a reload.
  function persist(values) {
    var entry = { id: root.moduleName }
    var current = root.settings || ({})
    for (var existing in current) if (existing !== "id") entry[existing] = current[existing]
    for (var key in values) entry[key] = values[key]

    root.settings = entry
    if (root.bar && root.bar.shell && typeof root.bar.shell.updateEntryInline === "function")
      root.bar.shell.updateEntryInline(root.moduleName, entry)
  }

  // The opt-in for the YubiKey source. Nothing reads the key until this is on.
  function toggleYubiKey() {
    persist({ yubikey: !root.yubikeyEnabled })
  }

  function copyCode(code) {
    if (code.length === 0) return
    copier.payload = code
    // stdin has to be re-opened for each run: onStarted closes it to send EOF,
    // and that closed state persists on a reused Process.
    copier.stdinEnabled = true
    copier.running = true
    flash("Copied")
  }

  // Types the code into whatever had focus before the popup opened. The popup
  // holds keyboard focus while it is up, so it has to close first and let the
  // compositor hand focus back before wtype runs.
  function typeCode(code) {
    if (code.length === 0) return
    typer.payload = code
    root.close()
    typeDelay.restart()
  }

  // ---------------------------------------------------------- navigation

  function selectedRecord() {
    if (visibleRecords.length === 0) return null
    var i = Math.max(0, Math.min(listIndex, visibleRecords.length - 1))
    return visibleRecords[i]
  }

  function moveCursor(dy) {
    cursorActive = true
    if (dy === 0) return
    if (view === "add") {
      addIndex = Math.max(0, Math.min(addActions.length - 1, addIndex + dy))
      return
    }
    if (view === "list" && visibleRecords.length > 0) {
      listIndex = Math.max(0, Math.min(visibleRecords.length - 1, listIndex + dy))
    }
  }

  function activateCursor() {
    if (view === "add") {
      runAddAction(addActions[addIndex].key)
      return
    }
    if (view === "list") {
      var record = selectedRecord()
      if (record) copyCode(codeFor(record))
    }
  }

  function runAddAction(key) {
    root.formError = ""
    if (key === "scan") scanQr()
    else if (key === "manual") beginManual()
    else if (key === "restore") beginRestore()
    else if (key === "image") beginImageImport()
    else if (key === "paste") {
      linkField.text = ""
      linkVisible = true
      Qt.callLater(function() { linkField.forceActiveFocus() })
    }
  }

  property bool linkVisible: false
  // True from the moment a scan starts until it resolves, so the panel can say
  // that something is happening rather than just closing.
  property bool scanning: false

  function beginAdd() {
    root.formError = ""
    root.linkVisible = false
    root.addIndex = 0
    root.view = "add"
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function beginManual() {
    nameField.text = ""
    issuerField.text = ""
    secretField.text = ""
    root.formError = ""
    root.view = "manual"
    Qt.callLater(function() { nameField.forceActiveFocus() })
  }

  function beginExport() {
    exportPathField.text = root.defaultExportPath()
    exportPassField.text = ""
    exportConfirmField.text = ""
    root.formError = ""
    root.view = "export"
    Qt.callLater(function() { exportPassField.forceActiveFocus() })
  }

  function beginRestore() {
    restorePathField.text = root.defaultExportPath()
    restorePassField.text = ""
    root.formError = ""
    root.view = "restore"
    Qt.callLater(function() { restorePathField.forceActiveFocus() })
  }

  function runExport() {
    if (exportPassField.text !== exportConfirmField.text) {
      // A mistyped passphrase produces a file nobody can ever open, and the
      // mistake only surfaces on the day it is needed.
      root.formError = "The two passphrases do not match"
      return
    }
    root.formError = ""
    vault.exportTo(exportPathField.text, exportPassField.text)
  }

  function runRestore() {
    root.formError = ""
    vault.restoreFrom(restorePathField.text, restorePassField.text)
  }

  function backToList() {
    // The secret field is cleared explicitly rather than left for the next
    // open: an abandoned form should not keep a typed secret alive in a
    // property for the rest of the session.
    secretField.text = ""
    linkField.text = ""
    exportPassField.text = ""
    exportConfirmField.text = ""
    restorePassField.text = ""
    root.view = "list"
    root.formError = ""
    root.linkVisible = false
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function deleteSelected() {
    var record = selectedRecord()
    if (!record) return
    // Two presses to destroy: the first arms the row, the second removes it.
    // Losing a second factor to a stray keypress is not recoverable.
    if (root.pendingDeleteId === record.id) {
      vault.remove(record.id)
      root.pendingDeleteId = ""
      root.listIndex = Math.max(0, root.listIndex - 1)
      root.flash("Removed")
    } else {
      root.pendingDeleteId = record.id
      root.flash("Press x again to remove")
    }
  }

  // ------------------------------------------------------------ submission

  // Shared by the manual form and the paste field, so a link and a hand-typed
  // secret cannot diverge in what they accept.
  function submitAccount(candidate) {
    var account
    try {
      account = Store.normalizeAccount(candidate)
    } catch (e) {
      root.formError = e.message
      return false
    }
    if (vault.alreadyStored(account)) {
      root.formError = "That account is already here"
      return false
    }
    vault.add(account)
    return true
  }

  function submitLink(text) {
    var account
    try {
      account = Store.parseOtpauth(text)
    } catch (e) {
      root.formError = e.message
      return false
    }
    if (vault.alreadyStored(account)) {
      root.formError = "That account is already here"
      return false
    }
    vault.add(account)
    return true
  }

  // Scanning happens in up to three steps, cheapest first.
  //
  // 1. Photograph the screen with the popup still open. The popup is a small
  //    card in one corner and the code is usually nowhere near it, so this
  //    normally succeeds — and because nothing closes, there is no moment
  //    where the panel has vanished and you are left wondering whether
  //    anything is happening.
  // 2. If that finds nothing, the popup might be covering the code. Close it,
  //    let it finish animating away, and look again.
  // 3. Only if that also fails ask for a region, which is the answer to
  //    several codes on screen at once or one too small to resolve.
  function scanQr() {
    root.formError = ""
    root.scanning = true
    quickScanner.running = true
  }

  function scanWithPanelHidden() {
    root.close()
    scanDelay.restart()
  }

  // Reads QR codes out of an image file rather than the screen. The usual
  // case is a screenshot of a setup page saved earlier, or an image someone
  // sent over chat. Every otpauth:// code in the image is imported as one
  // batch, so a contact sheet of codes enrolls in a single pass.
  // Every scanning route funnels decoded QR text through here, so a screen
  // scan and an image import accept exactly the same things: plain otpauth://
  // codes, and Google Authenticator's otpauth-migration:// format, a
  // protobuf-based export that is not the standardized otpauth:// URI. We
  // decode it to import supported TOTP credentials, including a whole
  // authenticator in one pass. What parses is batched into the vault; what
  // does not is reported without sinking the rest.
  function importFoundLinks(text) {
    var parsed = Store.parseOtpauthBatch(text)
    if (parsed.accounts.length === 0) {
      if (root.view !== "image") root.view = "add"
      root.formError = parsed.errors.length > 0
        ? "A QR code was found, but it did not hold a readable two-factor "
          + "setup code."
        : "No two-factor QR code found."
      return false
    }
    if (parsed.errors.length > 0) {
      root.flash(parsed.errors.length + " QR code(s) could not be read")
    }
    vault.addMany(parsed.accounts, "Imported")
    return true
  }

  function beginImageImport() {
    imagePathField.text = ""
    root.formError = ""
    root.view = "image"
    Qt.callLater(function() { imagePathField.forceActiveFocus() })
  }

  function runImageImport() {
    if (root.scanning) return
    var path = vault.expandPath(imagePathField.text)
    if (path.length === 0) {
      root.formError = "Choose an image to scan"
      return
    }
    root.formError = ""
    root.scanning = true
    // zbarimg's numeric codes differ by version (1 vs 2 vs 4), so this
    // script owns the contract: 2 means the path could not be read as an
    // image. Everything else with empty stdout is "no otpauth QR".
    imageScanner.command = ["bash", "-c",
      "if [ ! -f \"$1\" ] || [ ! -r \"$1\" ]; then exit 2; fi\n" +
      "found=$(zbarimg --raw -q -Sdisable -Sqrcode.enable -- \"$1\" 2>&1) || true\n" +
      "if [ \"${found#ERROR:}\" != \"$found\" ]; then exit 2; fi\n" +
      "printf %s \"$found\" | grep -i '^otpauth' || true",
      "omarchy-totp-image-scan", path]
    imageScanner.running = true
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: {
    if (opened) {
      root.now = Math.floor(Date.now() / 1000)
      root.view = "list"
      root.query = ""
      root.notice = ""
      root.formError = ""
      root.pendingDeleteId = ""
      root.purgeArmed = false
      root.cursorActive = false
      root.listIndex = 0
      root.linkVisible = false
      root.scanning = scanner.running || quickScanner.running || imageScanner.running
      searchField.text = ""
      vault.reload()
      if (root.yubikeyEnabled) yubikey.refresh()
      Qt.callLater(function() { keyCatcher.forceActiveFocus() })
    } else {
      // Decrypted secrets do not outlive the popup.
      vault.forgetSecrets()
      // Nor do the codes read off the key.
      yubikey.forget()
      secretField.text = ""
      linkField.text = ""
      exportPassField.text = ""
      exportConfirmField.text = ""
      restorePassField.text = ""
    }
  }

  Vault {
    id: vault
    onIndexLoaded: if (root.opened) loadSecrets()
    onActionFailed: function(message) { root.flash(message) }
    onAccountAdded: {
      // A restore adds many accounts at once; let it finish before saying so.
      // An image import batches the same way, but stays on the image view, so
      // the guard has to cover the vault's batch state directly.
      if (root.view === "restore" || vault.restoring) return
      root.backToList()
      root.flash("Added")
    }
    onExportFinished: function(ok, message) {
      if (ok) {
        root.backToList()
        root.flash(message)
      } else {
        root.formError = message
      }
    }
    onRestoreFinished: function(ok, message) {
      if (ok) {
        root.backToList()
        root.flash(message)
      } else {
        root.formError = message
      }
    }
  }

  // A second, read-only source of codes. Inert unless the setting is on: it
  // spawns no process and stores nothing of its own.
  YubiKey {
    id: yubikey
    enabled: root.yubikeyEnabled
  }

  Timer {
    // Only runs while the popup is visible. A background tick would derive
    // codes nobody is looking at and keep secrets warm for no reason.
    running: root.opened
    interval: 1000
    repeat: true
    triggeredOnStart: true
    onTriggered: root.now = Math.floor(Date.now() / 1000)
  }

  Timer {
    id: noticeTimer
    interval: 1800
    onTriggered: root.notice = ""
  }

  Timer {
    id: scanDelay
    interval: 350
    onTriggered: scanner.running = true
  }

  Timer {
    id: typeDelay
    interval: 220
    onTriggered: {
      typer.stdinEnabled = true
      typer.running = true
    }
  }

  // Runs a terminal-opening fix once the popup has closed and the compositor
  // has handed the keyboard to whatever comes up.
  Timer {
    id: yubiActionDelay
    interval: 220
    onTriggered: root.performDeferredYubiAction()
  }

  // Both of these take the code on stdin rather than as an argument. A TOTP
  // code is short-lived, but /proc/<pid>/cmdline is readable by every process
  // running as this user and there is no reason to publish it there.
  Process {
    id: copier
    property string payload: ""
    command: ["wl-copy"]
    stdinEnabled: true
    onStarted: {
      write(payload)
      payload = ""
      stdinEnabled = false  // wl-copy reads to EOF
    }
  }

  Process {
    id: typer
    property string payload: ""
    command: ["wtype", "-"]  // "-" reads the text to type from stdin
    stdinEnabled: true
    onStarted: {
      write(payload)
      payload = ""
      stdinEnabled = false
    }
  }

  // Finds a QR code on screen and reads the otpauth:// link out of it. No
  // camera is involved: this photographs the screen, which is where the code
  // actually is when a website is walking you through setup.
  //
  // The whole screen is scanned first. Asking someone to drag a box around a
  // code the machine can already see is work for nothing, and the selector
  // appearing over a browser is exactly when it is most fiddly. The region
  // selector is the fallback for when the full screen yields nothing — several
  // codes on screen at once, or one too small to resolve.
  //
  // Codes that are not otpauth:// links are skipped rather than taken and
  // rejected later, so an unrelated QR sharing the screen cannot swallow the
  // attempt.
  //
  // The script is a constant with no interpolation, and the decoded link is
  // read from stdout and parsed as data — it never re-enters a shell.
  // Step 1. Same decode as the full scanner, but no region selector and no
  // closing of the popup, so it can be tried before disturbing anything.
  Process {
    id: quickScanner
    property string result: ""

    command: ["bash", "-c",
      "grim - | zbarimg --raw -q -Sdisable -Sqrcode.enable - 2>/dev/null " +
      "| grep -m1 -i '^otpauth'"]

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: quickScanner.result = text
    }
    stderr: StdioCollector { waitForEnd: true }

    onExited: function(code) {
      var link = result.trim()
      result = ""
      if (link.length === 0) {
        // Nothing visible from here; the popup may be in the way.
        root.scanWithPanelHidden()
        return
      }
      root.scanning = false
      if (!root.importFoundLinks(link)) root.flash(root.formError)
    }
  }

  Process {
    id: scanner
    property string result: ""

    command: ["bash", "-c",
      "scan() { " +
      "  if [ -n \"$1\" ]; then grim -g \"$1\" -; else grim -; fi " +
      "  | zbarimg --raw -q -Sdisable -Sqrcode.enable - 2>/dev/null " +
      "  | grep -m1 -i '^otpauth'; " +
      "}; " +
      "found=$(scan) || true; " +
      "if [ -z \"$found\" ]; then " +
      "  geometry=$(slurp -b 00000080 -w 2) || exit 3; " +
      "  found=$(scan \"$geometry\") || true; " +
      "fi; " +
      "[ -n \"$found\" ] || exit 4; " +
      "printf %s \"$found\""]

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: scanner.result = text
    }
    stderr: StdioCollector { waitForEnd: true }

    onExited: function(code) {
      var link = result.trim()
      result = ""
      root.scanning = false
      root.open()
      if (link.length === 0) {
        root.view = "add"
        // 3 is a cancelled selection, which needs no complaint; anything else
        // means we looked and found nothing usable.
        if (code !== 3) {
          root.formError = "No two-factor QR code found. Make sure the code "
            + "is on screen, then try again."
        }
        return
      }
      root.importFoundLinks(link)
    }
  }

  // Same decoder options as the screen scanners, minus grim: the pixels
  // already exist in a file. No -m1 on the grep — an image may hold several
  // codes, and every otpauth one of them is wanted.
  //
  // The path reaches zbarimg as an argument, never interpolated into the
  // script text, so a filename cannot become shell syntax. command is set by
  // runImageImport immediately before launch.
  Process {
    id: imageScanner
    property string result: ""

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: imageScanner.result = text
    }
    stderr: StdioCollector { waitForEnd: true }

    onExited: function(code) {
      var text = result
      result = ""
      root.scanning = false
      if (String(text || "").trim().length === 0) {
        // 2 is the script's unreadable-path status, not zbarimg's — missing,
        // directory and undecodable files must not look like "no QR".
        root.formError = code === 2
          ? "Could not read that image. Check the path and try again."
          : "No two-factor QR code found."
        return
      }
      root.importFoundLinks(text)
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: "\udb82\udfc4"  // Nerd Font shield-key (U+F0BC4)
    tooltipText: "Two-factor codes"
    onPressed: function(buttonCode) { root.toggle() }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(360))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(560))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent

      // While any field has focus the catcher stands down completely, so "j"
      // types a j instead of moving the cursor.
      blocked: searchField.activeFocus || linkField.activeFocus
            || nameField.activeFocus || issuerField.activeFocus
            || secretField.activeFocus || exportPathField.activeFocus
            || exportPassField.activeFocus || exportConfirmField.activeFocus
            || restorePathField.activeFocus || restorePassField.activeFocus
            || imagePathField.activeFocus

      onMoveRequested: function(dx, dy) {
        if (!root.cursorActive) { root.cursorActive = true; return }
        root.moveCursor(dy)
      }
      onActivateRequested: root.activateCursor()
      onDeleteRequested: if (root.view === "list") root.deleteSelected()
      onCloseRequested: {
        if (root.view !== "list") root.backToList()
        else root.close()
      }
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(text) {
        if (root.view === "list") {
          if (text === "a") root.beginAdd()
          else if (text === "t") {
            var record = root.selectedRecord()
            if (record) root.typeCode(root.codeFor(record))
          } else if (text === "/") {
            root.cursorActive = true
            searchField.forceActiveFocus()
          }
        }
      }

      Flickable {
        id: panelFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: panelFlick.width
          spacing: Style.space(10)

          PanelHero {
            width: parent.width
            title: "Two-factor"
            meta: {
              if (root.scanning) return "Looking for a QR code..."
              if (root.notice.length > 0) return root.notice
              if (root.view === "manual") return "New account"
              if (root.view === "add") return "Add an account"
              if (root.view === "export") return "Export"
              if (root.view === "restore") return "Restore"
              if (root.view === "image") return "Import from an image"
              if (vault.error.length > 0) return "Keyring unavailable"
              if (!vault.secretsLoaded && vault.records.length > 0) return "Unlocking…"
              // With no vault accounts but a key present, the count below would
              // read "0 accounts" beside a full YubiKey list.
              if (vault.records.length === 0 && root.visibleYubiKey.length > 0) {
                return root.visibleYubiKey.length === 1 ? "1 key account"
                                                        : root.visibleYubiKey.length + " key accounts"
              }
              return vault.records.length === 1 ? "1 account"
                                                : vault.records.length + " accounts"
            }
            foreground: root.foreground
            fontFamily: root.fontFamily
          }

          Text {
            visible: vault.error.length > 0 && root.view === "list"
            width: parent.width
            text: vault.error
            textFormat: Text.PlainText
            wrapMode: Text.WordWrap
            color: root.urgent
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
          }

          // ---------------------------------------------------------- list

          Column {
            visible: root.view === "list"
            width: parent.width
            spacing: Style.space(10)

            Row {
              width: parent.width
              spacing: Style.space(8)

              TextField {
                id: searchField
                width: parent.width - addButton.width - Style.space(8)
                visible: vault.records.length + yubikey.accounts.length > 1
                placeholderText: "Search"
                foreground: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                onTextChanged: {
                  root.query = text
                  root.listIndex = 0
                }
                // The catcher stands down while this field has focus, so the
                // keys that cannot collide with typing are forwarded by hand:
                // arrows move the cursor, Enter copies, and Ctrl+Enter types,
                // without leaving the field or losing the filter.
                Keys.onUpPressed: root.moveCursor(-1)
                Keys.onDownPressed: root.moveCursor(1)
                Keys.onReturnPressed: function(event) { searchField.submit(event) }
                Keys.onEnterPressed: function(event) { searchField.submit(event) }
                function submit(event) {
                  if (event.modifiers & Qt.ControlModifier) {
                    var record = root.selectedRecord()
                    if (record) root.typeCode(root.codeFor(record))
                  } else {
                    root.activateCursor()
                  }
                }
                Keys.onEscapePressed: {
                  text = ""
                  keyCatcher.forceActiveFocus()
                }
              }

              Button {
                id: addButton
                text: "Add"
                bordered: true
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.beginAdd()
              }
            }

            Text {
              visible: vault.records.length === 0 && !yubikey.showing
              width: parent.width
              text: "No accounts yet. Add one by scanning the QR code on a "
                  + "site's two-factor setup page."
              textFormat: Text.PlainText
              wrapMode: Text.WordWrap
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            Text {
              visible: vault.records.length > 0 && root.visibleRecords.length === 0
              width: parent.width
              text: "Nothing matches that search."
              textFormat: Text.PlainText
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            Repeater {
              model: root.visibleRecords

              Item {
                id: accountRow
                required property var modelData
                required property int index
                width: column.width
                implicitHeight: rowBody.implicitHeight + Style.space(10)

                readonly property string code: root.codeFor(modelData)
                readonly property int remaining: Totp.secondsRemaining(modelData.period, root.now)
                readonly property bool expiring: remaining <= 5
                readonly property bool locked: code.length === 0
                readonly property bool armed: root.pendingDeleteId === modelData.id
                readonly property bool hasCursor: root.cursorActive
                                               && root.view === "list"
                                               && root.listIndex === index

                MouseArea {
                  id: rowMouse
                  anchors.fill: parent
                  hoverEnabled: true
                  acceptedButtons: Qt.LeftButton | Qt.RightButton
                  cursorShape: accountRow.locked ? Qt.ArrowCursor : Qt.PointingHandCursor
                  onEntered: {
                    root.cursorActive = false
                    root.listIndex = accountRow.index
                  }
                  onClicked: function(mouse) {
                    if (accountRow.locked) return
                    if (mouse.button === Qt.RightButton) root.typeCode(accountRow.code)
                    else root.copyCode(accountRow.code)
                  }
                }

                Rectangle {
                  anchors.fill: parent
                  radius: Style.cornerRadius
                  color: rowMouse.containsMouse || accountRow.hasCursor
                    ? Util.alpha(root.foreground, 0.07) : "transparent"
                }

                Column {
                  id: rowBody
                  width: parent.width
                  anchors.verticalCenter: parent.verticalCenter
                  spacing: Style.space(1)

                  Row {
                    width: parent.width
                    spacing: Style.space(6)

                    Text {
                      width: parent.width - deleteButton.width - Style.space(6)
                      // Untrusted: this came out of a QR code.
                      text: accountRow.modelData.issuer.length > 0
                            && accountRow.modelData.issuer !== accountRow.modelData.label
                        ? accountRow.modelData.issuer + " · " + accountRow.modelData.label
                        : accountRow.modelData.label
                      textFormat: Text.PlainText
                      elide: Text.ElideRight
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.bodySmall
                    }

                    // Always present rather than revealed on hover: a control
                    // that only exists once you happen to be over it is hard to
                    // find. It sits dim until the row is under the pointer or
                    // the keyboard cursor, and turns into a labelled red
                    // confirmation once armed.
                    Button {
                      id: deleteButton
                      // \uf1f8 is the Nerd Font trash can.
                      text: accountRow.armed ? "\uf1f8  Remove?" : "\uf1f8"
                      tooltipText: accountRow.armed
                        ? "Click again to remove this account"
                        : "Remove this account"
                      bordered: accountRow.armed
                      foreground: accountRow.armed
                        ? root.urgent
                        : (rowMouse.containsMouse || accountRow.hasCursor
                            ? root.foreground : root.dim)
                      accent: root.urgent
                      opacity: accountRow.armed || rowMouse.containsMouse
                            || accountRow.hasCursor ? 1 : 0.35
                      fontFamily: root.fontFamily
                      fontSize: Style.font.bodySmall
                      horizontalPadding: Style.space(6)
                      verticalPadding: Style.space(2)
                      onClicked: {
                        root.listIndex = accountRow.index
                        root.deleteSelected()
                      }
                    }
                  }

                  Row {
                    width: parent.width
                    spacing: Style.space(8)

                    Text {
                      text: accountRow.locked ? "· · · · · ·"
                                              : Store.groupCode(accountRow.code)
                      textFormat: Text.PlainText
                      color: accountRow.locked ? root.dim : root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.displayLarge
                    }

                    Text {
                      anchors.verticalCenter: parent.verticalCenter
                      visible: !accountRow.locked
                      text: accountRow.remaining + "s"
                      textFormat: Text.PlainText
                      color: accountRow.expiring ? root.urgent : root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.bodySmall
                    }
                  }
                }
              }
            }

            Text {
              visible: vault.records.length > 0
              width: parent.width
              text: "Click a code to copy it, right-click to type it into the "
                  + "window underneath. Keys: a add · t type · x remove · / search"
              textFormat: Text.PlainText
              wrapMode: Text.WordWrap
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }

            Row {
              visible: vault.records.length > 0
              width: parent.width
              spacing: Style.space(8)

              Button {
                width: (parent.width - Style.space(8)) / 2
                text: "Export"
                tooltipText: "Save every account to an encrypted file"
                bordered: true
                foreground: root.dim
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.beginExport()
              }

              // Uninstalling the plugin deletes its directory and nothing else
              // — `omarchy plugin remove` runs no code from the plugin. This is
              // the in-app way to leave nothing behind, and it is what the
              // README's uninstall section points at.
              Button {
                width: (parent.width - Style.space(8)) / 2
                text: root.purgeArmed ? "Erase all?" : "Remove all"
                tooltipText: root.purgeArmed
                  ? "Click again to erase every account and its keyring entry"
                  : "Erase every account and its keyring entry"
                bordered: true
                foreground: root.purgeArmed ? root.urgent : root.dim
                accent: root.urgent
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: {
                  if (root.purgeArmed) {
                    vault.purgeAll()
                    root.purgeArmed = false
                    root.flash("Everything removed")
                  } else {
                    root.purgeArmed = true
                    purgeTimer.restart()
                  }
                }
              }
            }

            // ------------------------------------------- yubikey source
            // A second, read-only source. Nothing here is added to the vault,
            // exported, or removed — the accounts live on the key and are only
            // read from it. Rendered only when the setting is on.

            Column {
              width: parent.width
              spacing: Style.space(8)

              PanelSeparator { foreground: root.foreground }

              Item {
                width: parent.width
                implicitHeight: Math.max(headerRow.implicitHeight, toggleButton.implicitHeight)

                Row {
                  id: headerRow
                  anchors.left: parent.left
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - toggleButton.width - Style.space(8)
                  spacing: Style.space(6)

                  // \uf0bc is a Nerd Font shield; the key is a distinct source,
                  // so it gets a heading instead of blending into the list.
                  Text {
                    text: "\uf0bc YubiKey"
                    textFormat: Text.PlainText
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.bodySmall
                  }

                  Text {
                    width: parent.width - Style.space(70)
                    text: root.yubikeyEnabled ? root.yubikeyStatusText : "Off"
                    textFormat: Text.PlainText
                    elide: Text.ElideRight
                    color: yubikey.status === "error" ? root.urgent : root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }

                // The opt-in. Turning it on is the only thing that ever starts
                // a ykman call; off is the default and the quiet state.
                Button {
                  id: toggleButton
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  text: root.yubikeyEnabled ? "Turn off" : "Turn on"
                  tooltipText: root.yubikeyEnabled
                    ? "Stop reading codes from the key"
                    : "Read codes from OATH accounts on an inserted YubiKey"
                  foreground: root.dim
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.toggleYubiKey()
                }
              }

              // Guided setup: when the first run is blocked, say what is
              // missing and offer the one action that clears it.
              Row {
                visible: root.yubikeyHint.length > 0
                width: parent.width
                spacing: Style.space(8)

                Text {
                  width: parent.width - fixButton.width - Style.space(8)
                  text: root.yubikeyHint
                  textFormat: Text.PlainText
                  wrapMode: Text.WordWrap
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                Button {
                  id: fixButton
                  text: root.yubikeyAction
                  bordered: true
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.runYubiKeyAction()
                }
              }

              Repeater {
                model: root.visibleYubiKey

                Item {
                  id: ykRow
                  required property var modelData
                  required property int index
                  width: column.width
                  implicitHeight: ykBody.implicitHeight + Style.space(10)

                  readonly property string code: yubikey.codeFor(modelData)
                  readonly property bool timeBased: modelData.type !== "HOTP"
                  readonly property int remaining: Totp.secondsRemaining(modelData.period, root.now)
                  readonly property bool expiring: remaining <= 5

                  MouseArea {
                    id: ykMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    acceptedButtons: Qt.LeftButton | Qt.RightButton
                    onClicked: function(mouse) {
                      if (!ykRow.timeBased) return
                      if (ykRow.code.length === 0) {
                        // Nothing read yet — ask the key. This is where a
                        // credential that needs a touch prompts for one.
                        yubikey.fetchCode(ykRow.modelData.name)
                        root.flash("Touch the key")
                        return
                      }
                      if (mouse.button === Qt.RightButton) root.typeCode(ykRow.code)
                      else root.copyCode(ykRow.code)
                    }
                  }

                  Rectangle {
                    anchors.fill: parent
                    radius: Style.cornerRadius
                    color: ykMouse.containsMouse ? Util.alpha(root.foreground, 0.07)
                                                 : "transparent"
                  }

                  Column {
                    id: ykBody
                    width: parent.width
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(1)

                    Text {
                      width: parent.width
                      // Untrusted: the name came off the key.
                      text: ykRow.modelData.issuer.length > 0
                            && ykRow.modelData.issuer !== ykRow.modelData.label
                          ? ykRow.modelData.issuer + " · " + ykRow.modelData.label
                          : ykRow.modelData.label
                      textFormat: Text.PlainText
                      elide: Text.ElideRight
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.bodySmall
                    }

                    Row {
                      width: parent.width
                      spacing: Style.space(8)

                      Text {
                        text: !ykRow.timeBased
                          ? "Counter-based, not generated"
                          : ykRow.code.length > 0
                            ? Store.groupCode(ykRow.code)
                            : "Touch the key to read"
                        textFormat: Text.PlainText
                        color: ykRow.timeBased && ykRow.code.length > 0
                          ? root.foreground : root.dim
                        font.family: root.fontFamily
                        font.pixelSize: ykRow.timeBased && ykRow.code.length > 0
                          ? Style.font.displayLarge : Style.font.bodySmall
                      }

                      Text {
                        anchors.verticalCenter: parent.verticalCenter
                        visible: ykRow.timeBased && ykRow.code.length > 0
                        text: ykRow.remaining + "s"
                        textFormat: Text.PlainText
                        color: ykRow.expiring ? root.urgent : root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                      }
                    }
                  }
                }
              }

              Text {
                visible: root.visibleYubiKey.length > 0
                width: parent.width
                text: "Read straight from the key. Nothing here is stored or "
                    + "exported, and the countdown assumes the usual 30 seconds."
                textFormat: Text.PlainText
                wrapMode: Text.WordWrap
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
            }
          }

          Timer {
            id: purgeTimer
            interval: 4000
            onTriggered: root.purgeArmed = false
          }

          // ----------------------------------------------------- add menu

          Column {
            visible: root.view === "add"
            width: parent.width
            spacing: Style.space(8)

            Repeater {
              model: root.addActions

              Button {
                required property var modelData
                required property int index
                width: column.width
                text: modelData.label
                bordered: true
                leftAlign: true
                hasCursor: root.cursorActive && root.addIndex === index
                foreground: root.foreground
                fontFamily: root.fontFamily
                onHovered: function(on) { if (on) { root.cursorActive = false } }
                onClicked: {
                  root.addIndex = index
                  root.runAddAction(modelData.key)
                }
              }
            }

            TextField {
              id: linkField
              visible: root.linkVisible
              width: parent.width
              placeholderText: "otpauth://totp/..."
              foreground: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              onAccepted: root.submitLink(text)
              Keys.onEscapePressed: {
                text = ""
                root.linkVisible = false
                keyCatcher.forceActiveFocus()
              }
            }

            Text {
              visible: root.formError.length > 0
              width: parent.width
              text: root.formError
              textFormat: Text.PlainText
              wrapMode: Text.WordWrap
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            Button {
              width: parent.width
              text: "Back"
              leftAlign: true
              foreground: root.dim
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.backToList()
            }
          }

          // -------------------------------------------------- manual form

          Column {
            visible: root.view === "manual"
            width: parent.width
            spacing: Style.space(8)

            TextField {
              id: nameField
              width: parent.width
              placeholderText: "Account name"
              foreground: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              onAccepted: issuerField.forceActiveFocus()
              Keys.onEscapePressed: root.backToList()
            }

            TextField {
              id: issuerField
              width: parent.width
              placeholderText: "Issuer (optional)"
              foreground: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              onAccepted: secretField.forceActiveFocus()
              Keys.onEscapePressed: root.backToList()
            }

            TextField {
              id: secretField
              width: parent.width
              placeholderText: "Secret key"
              // Masked like any other credential field. It is shoulder-surfable
              // otherwise, and it is the one string here whose disclosure
              // actually matters.
              password: true
              foreground: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              onAccepted: saveButton.clicked()
              Keys.onEscapePressed: root.backToList()
            }

            Text {
              visible: root.formError.length > 0
              width: parent.width
              text: root.formError
              textFormat: Text.PlainText
              wrapMode: Text.WordWrap
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                id: saveButton
                text: "Save"
                bordered: true
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.submitAccount({
                  label: nameField.text,
                  issuer: issuerField.text,
                  secret: secretField.text
                })
              }

              Button {
                text: "Cancel"
                foreground: root.dim
                fontFamily: root.fontFamily
                onClicked: root.backToList()
              }
            }

            Text {
              width: parent.width
              text: "Defaults to 6 digits, 30 seconds, SHA-1 — what almost "
                  + "every site uses. Scan the QR code instead if yours differs."
              textFormat: Text.PlainText
              wrapMode: Text.WordWrap
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }

          // ------------------------------------------------------- export

          Column {
            visible: root.view === "export"
            width: parent.width
            spacing: Style.space(8)

            Text {
              width: parent.width
              text: "Saves every account as standard otpauth:// links that any "
                  + "authenticator can read, encrypted with GnuPG."
              textFormat: Text.PlainText
              wrapMode: Text.WordWrap
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            TextField {
              id: exportPathField
              width: parent.width
              placeholderText: "~/2fa-export.asc"
              foreground: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              onAccepted: exportPassField.forceActiveFocus()
              Keys.onEscapePressed: root.backToList()
            }

            // The field accepts "~/…", so show the path it actually resolves
            // to. Writing a file somewhere the person cannot then find is a
            // failure even when the write succeeds.
            Text {
              width: parent.width
              text: "Saves to " + vault.expandPath(exportPathField.text)
              textFormat: Text.PlainText
              wrapMode: Text.WrapAnywhere
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }

            TextField {
              id: exportPassField
              width: parent.width
              placeholderText: "Passphrase"
              password: true
              foreground: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              onAccepted: exportConfirmField.forceActiveFocus()
              Keys.onEscapePressed: root.backToList()
            }

            TextField {
              id: exportConfirmField
              width: parent.width
              placeholderText: "Passphrase again"
              password: true
              foreground: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              onAccepted: root.runExport()
              Keys.onEscapePressed: root.backToList()
            }

            Text {
              visible: root.formError.length > 0
              width: parent.width
              text: root.formError
              textFormat: Text.PlainText
              wrapMode: Text.WordWrap
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: "Export"
                bordered: true
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.runExport()
              }

              Button {
                text: "Cancel"
                foreground: root.dim
                fontFamily: root.fontFamily
                onClicked: root.backToList()
              }
            }

            Text {
              width: parent.width
              text: "Keep the file safe. Anyone who has it and the passphrase "
                  + "can generate your codes. Lose the passphrase and the file "
                  + "cannot be opened by anyone, including you."
              textFormat: Text.PlainText
              wrapMode: Text.WordWrap
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }

          // ------------------------------------------------------ restore

          Column {
            visible: root.view === "restore"
            width: parent.width
            spacing: Style.space(8)

            Text {
              width: parent.width
              text: "Adds the accounts from an encrypted export. Existing "
                  + "accounts are kept, so restoring twice duplicates them."
              textFormat: Text.PlainText
              wrapMode: Text.WordWrap
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            TextField {
              id: restorePathField
              width: parent.width
              placeholderText: "~/2fa-export.asc"
              foreground: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              onAccepted: restorePassField.forceActiveFocus()
              Keys.onEscapePressed: root.backToList()
            }

            TextField {
              id: restorePassField
              width: parent.width
              placeholderText: "Passphrase"
              password: true
              foreground: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              onAccepted: root.runRestore()
              Keys.onEscapePressed: root.backToList()
            }

            Text {
              visible: root.formError.length > 0
              width: parent.width
              text: root.formError
              textFormat: Text.PlainText
              wrapMode: Text.WordWrap
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: "Restore"
                bordered: true
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.runRestore()
              }

              Button {
                text: "Cancel"
                foreground: root.dim
                fontFamily: root.fontFamily
                onClicked: root.backToList()
              }
            }
          }

          // -------------------------------------------------------- image

          Column {
            visible: root.view === "image"
            width: parent.width
            spacing: Style.space(8)

            Text {
              width: parent.width
              text: "Reads every two-factor QR code in an image file — a "
                  + "screenshot of a setup page, or a Google Authenticator "
                  + "migration QR. Accounts already stored are skipped."
              textFormat: Text.PlainText
              wrapMode: Text.WordWrap
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            TextField {
              id: imagePathField
              width: parent.width
              placeholderText: "~/screenshot.png"
              foreground: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              onAccepted: root.runImageImport()
              Keys.onEscapePressed: root.backToList()
            }

            Text {
              width: parent.width
              text: "Reads from " + vault.expandPath(imagePathField.text)
              textFormat: Text.PlainText
              wrapMode: Text.WrapAnywhere
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }

            Text {
              visible: root.formError.length > 0
              width: parent.width
              text: root.formError
              textFormat: Text.PlainText
              wrapMode: Text.WordWrap
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: "Import"
                bordered: true
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.runImageImport()
              }

              Button {
                text: "Cancel"
                foreground: root.dim
                fontFamily: root.fontFamily
                onClicked: root.backToList()
              }
            }
          }
        }
      }
    }
  }
}
