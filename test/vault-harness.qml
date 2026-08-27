import QtQuick
import Quickshell

// Headless exercise of Vault.qml, run with:
//
//   test/run.sh
//
// It is staged next to Vault.qml before running, because Quickshell only
// resolves QML from inside the config folder it was pointed at.
//
// Vault talks to the real keyring and the real index file, and its Process
// objects are reused across calls — behaviour no pure-JS test can reach. This
// harness drives the sequence that matters most: several adds in a row, each
// starting only once the previous one reported success.
//
// It regression-tests a bug that shipped in an early draft. Each of these
// Processes closes its stdin in onStarted to send EOF, and Quickshell keeps
// that closed state on the object; the *second* add therefore launched
// `secret-tool store` with no stdin pipe at all, and it sat there forever
// waiting for a secret that could never arrive. Every launch now re-enables
// stdin first. If that regresses, this harness hangs and the watchdog fails it.
//
// It writes to the real account store, so run it only on a machine whose 2FA
// accounts are expendable — it purges before and after.
ShellRoot {
  id: harness

  property int step: 0
  property int failures: 0
  property bool seeding: true
  property bool expectWaitMessage: false
  property bool sawWaitMessage: false

  // Left on disk for run.sh to assert against (mode, armour, no plaintext
  // secrets), then removed there.
  readonly property string exportPath:
    Quickshell.env("HOME") + "/.cache/omarchy-2fa-harness-export.asc"
  readonly property string exportPassphrase: "correct horse battery staple"
  readonly property var plan: [
    { label: "harness-one", issuer: "One", secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      digits: 6, period: 30, algorithm: "SHA1" },
    { label: "harness-two", issuer: "Two", secret: "JBSWY3DPEHPK3PXP",
      digits: 6, period: 30, algorithm: "SHA1" },
    { label: "harness-three", issuer: "Three", secret: "MZXW6YTBOI======",
      digits: 8, period: 60, algorithm: "SHA256" }
  ]
  readonly property var importedAccount: ({
    label: "harness-imported", issuer: "Import",
    secret: "NBSWY3DPEB3W64TMMQ======",
    digits: 6, period: 30, algorithm: "SHA1"
  })
  readonly property var overlapAccount: ({
    label: "harness-overlap", issuer: "Overlap",
    secret: "KRUGS4ZANFZSA3TPOQ======",
    digits: 6, period: 30, algorithm: "SHA1"
  })

  // Values are stringified so a difference in whitespace is visible rather
  // than invisible — a trailing newline off a subprocess looks identical to a
  // clean value otherwise.
  function check(name, actual, expected) {
    var ok = String(actual) === String(expected)
    if (!ok) harness.failures++
    console.log((ok ? "  ok   " : "FAIL   ") + name +
      (ok ? "" : "  (expected " + JSON.stringify(String(expected))
                + ", got " + JSON.stringify(String(actual)) + ")"))
  }

  function addNext() {
    if (step >= plan.length) {
      harness.seeding = false
      Qt.callLater(harness.verify)
      return
    }
    console.log("       adding " + plan[step].label)
    vault.add(plan[step])
  }

  function verify() {
    console.log("\nAfter " + plan.length + " consecutive adds:")
    check("every account was stored", vault.records.length, plan.length)
    for (var i = 0; i < plan.length && i < vault.records.length; i++) {
      check("record " + i + " label", vault.records[i].label, plan[i].label)
      check("record " + i + " digits", vault.records[i].digits, plan[i].digits)
      check("record " + i + " period", vault.records[i].period, plan[i].period)
      check("record " + i + " algorithm", vault.records[i].algorithm, plan[i].algorithm)
    }
    // The secrets were cached as each add completed; drop and re-resolve them
    // from the keyring so the lookup queue is exercised too.
    vault.forgetSecrets()
    vault.loadSecrets()
    secretsTimer.start()
  }

  function verifySecrets() {
    console.log("\nSecrets resolved from the keyring:")
    check("keyring returned every secret", Object.keys(vault.secrets).length, plan.length)
    for (var i = 0; i < plan.length && i < vault.records.length; i++) {
      check("secret " + i + " round-trips",
        vault.secretFor(vault.records[i].id), plan[i].secret)
    }

    console.log("\nExporting:")
    vault.exportTo(harness.exportPath, harness.exportPassphrase)
  }

  function afterExport(ok, message) {
    check("export reported success", ok, true)
    console.log("       " + message)
    console.log("\nPurging before restore, so a restore cannot pass on stale state:")
    vault.purgeAll()
    restoreTimer.start()
  }

  function doRestore() {
    check("store is empty before restore", vault.records.length, 0)
    console.log("\nRestoring from the encrypted export:")
    vault.restoreFrom(harness.exportPath, harness.exportPassphrase)
  }

  function afterRestore(ok, message) {
    check("restore reported success", ok, true)
    if (!ok) { console.log("       " + message); harness.finishUp(); return }
    check("every account came back", vault.records.length, plan.length)
    // Names survive; so must the parameters, or restored codes are wrong.
    for (var i = 0; i < plan.length && i < vault.records.length; i++) {
      check("restored " + i + " label", vault.records[i].label, plan[i].label)
      check("restored " + i + " issuer", vault.records[i].issuer, plan[i].issuer)
      check("restored " + i + " digits", vault.records[i].digits, plan[i].digits)
      check("restored " + i + " period", vault.records[i].period, plan[i].period)
      check("restored " + i + " algorithm", vault.records[i].algorithm, plan[i].algorithm)
    }
    vault.forgetSecrets()
    vault.loadSecrets()
    restoredSecretsTimer.start()
  }

  function afterRestoredSecrets() {
    for (var i = 0; i < plan.length && i < vault.records.length; i++) {
      check("restored " + i + " secret",
        vault.secretFor(vault.records[i].id), plan[i].secret)
    }

    console.log("\nRestoring the same file again must not duplicate anything:")
    vault.restoreFrom(harness.exportPath, harness.exportPassphrase)
  }

  function afterDuplicateRestore(ok, message) {
    check("second restore reported nothing to do", ok, false)
    check("second restore added nothing", vault.records.length, plan.length)
    console.log("       " + message)

    console.log("\nRestoring with the wrong passphrase must fail:")
    vault.restoreFrom(harness.exportPath, "not the passphrase")
  }

  function afterBadPassphrase(ok, message) {
    check("wrong passphrase was rejected", ok, false)
    check("account count unchanged by the failure", vault.records.length, plan.length)

    console.log("\nImporting via addMany:")
    vault.addMany([harness.importedAccount], "Imported")
    harness.expectWaitMessage = true
    vault.addMany([harness.overlapAccount], "Restored")
  }

  function afterImport(ok, message) {
    check("import reported success", ok, true)
    check("import used Imported verb", message, "Imported")
    check("imported account is present", vault.records.length, plan.length + 1)
    check("overlapping addMany was refused", harness.sawWaitMessage, true)
    var foundImported = false
    var foundOverlap = false
    for (var i = 0; i < vault.records.length; i++) {
      if (vault.records[i].label === harness.importedAccount.label) foundImported = true
      if (vault.records[i].label === harness.overlapAccount.label) foundOverlap = true
    }
    check("imported label is in the index", foundImported, true)
    check("overlapping account was not queued", foundOverlap, false)

    console.log("\nRemoving one account:")
    var target = vault.records[1].id
    vault.remove(target)
    removeTimer.target = target
    removeTimer.start()
  }

  function finishUp() {
    vault.purgeAll()
    purgeTimer.start()
  }

  function verifyRemoval() {
    check("account was dropped from the index", vault.records.length, plan.length)
    var stillThere = false
    for (var i = 0; i < vault.records.length; i++) {
      if (vault.records[i].id === removeTimer.target) stillThere = true
    }
    check("the right account went", stillThere, false)

    console.log("\nPurging:")
    harness.finishUp()
  }

  function finish() {
    check("purge emptied the index", vault.records.length, 0)
    console.log(harness.failures === 0
      ? "\nAll checks passed.\n"
      : "\n" + harness.failures + " check(s) FAILED.\n")
    harness.done(harness.failures === 0 ? 0 : 1)
  }

  Vault {
    id: vault

    // Only drives the initial seeding sequence. A restore also emits this
    // signal per account, and without the guard the harness would treat each
    // restored account as a cue to seed another one and never converge.
    onAccountAdded: {
      if (!harness.seeding) return
      harness.step++
      Qt.callLater(harness.addNext)
    }
    onActionFailed: function(message) {
      if (harness.expectWaitMessage
          && message === "Wait for the current import to finish") {
        harness.expectWaitMessage = false
        harness.sawWaitMessage = true
        return
      }
      console.log("FAIL   vault reported: " + message)
      harness.failures++
    }

    // Restore runs three times: a real one, the same file again (which must
    // add nothing), and one with the wrong passphrase. addMany then reuses
    // the same signal for the image-import path.
    property int restoreCalls: 0

    onExportFinished: function(ok, message) { harness.afterExport(ok, message) }
    onRestoreFinished: function(ok, message) {
      vault.restoreCalls++
      if (vault.restoreCalls === 1) harness.afterRestore(ok, message)
      else if (vault.restoreCalls === 2) harness.afterDuplicateRestore(ok, message)
      else if (vault.restoreCalls === 3) harness.afterBadPassphrase(ok, message)
      else harness.afterImport(ok, message)
    }
  }

  Component.onCompleted: harness.begin()

  // Start from a clean store so a previous run cannot make this one pass.
  function begin() {
    console.log("\nPurging any previous state...")
    vault.purgeAll()
    startTimer.start()
  }

  // Quickshell does not wire Qt.exit(), so the verdict is printed for the
  // caller to read and the process simply quits.
  function done(code) {
    console.log("HARNESS RESULT: " + (code === 0 ? "PASS" : "FAIL"))
    Qt.quit()
  }

  Timer { id: startTimer; interval: 1200; onTriggered: harness.addNext() }
  Timer { id: secretsTimer; interval: 1500; onTriggered: harness.verifySecrets() }
  Timer {
    id: removeTimer
    property string target: ""
    interval: 1200
    onTriggered: harness.verifyRemoval()
  }
  Timer { id: purgeTimer; interval: 1500; onTriggered: harness.finish() }
  Timer { id: restoreTimer; interval: 1500; onTriggered: harness.doRestore() }
  Timer { id: restoredSecretsTimer; interval: 1500; onTriggered: harness.afterRestoredSecrets() }

  // A hang here is the failure mode this harness exists to catch, so it must
  // not be allowed to hang the caller.
  Timer {
    running: true
    interval: 60000
    onTriggered: {
      console.log("FAIL   timed out — an operation never completed")
      harness.done(1)
    }
  }
}
