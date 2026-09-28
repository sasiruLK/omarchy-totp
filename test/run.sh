#!/bin/bash
# Runs every test for this plugin.
#
#   test/run.sh
#
# The two Node suites cover the pure logic: RFC 6238 vectors for the code
# generator, and parsing / validation / index handling for the store. The
# Quickshell harness covers what those cannot reach — real subprocesses, the
# real keyring, and Process objects being reused across calls.
#
# The harness writes to the real account store, so it is skipped unless
# TOTP_HARNESS=1 is set.

set -o pipefail
cd "$(dirname "$0")/.." || exit 1

status=0

echo "== Totp.js =="
node test/vectors.js | tail -2 || status=1

echo "== Store.js =="
node test/store.js | tail -2 || status=1

echo "== YubiKey.js =="
node test/yubikey.js | tail -2 || status=1

if [[ ${TOTP_HARNESS:-0} != 1 ]]; then
  echo "== Vault.qml == skipped (set TOTP_HARNESS=1 to run; it purges your accounts)"
  exit $status
fi

echo "== Vault.qml =="
staging=$(mktemp -d) || exit 1
trap 'rm -rf "$staging"' EXIT
cp Vault.qml Store.js Totp.js test/vault-harness.qml "$staging/" || exit 1

output=$(timeout 60 quickshell -p "$staging/vault-harness.qml" 2>&1 |
  sed 's/\x1b\[[0-9;]*m//g' |
  grep -E "ok   |FAIL |HARNESS RESULT|adding |^After|^Secrets|^Removing|^Purging" |
  sed 's/^ *DEBUG qml: //')

echo "$output"
grep -q "HARNESS RESULT: PASS" <<<"$output" || status=1

# On-disk assertions about the export the harness left behind. These belong
# here rather than in QML: what matters is what landed on the filesystem.
export_file="$HOME/.cache/omarchy-2fa-harness-export.asc"
echo "== export file =="
if [[ ! -f $export_file ]]; then
  echo "FAIL   no export file was written"
  status=1
else
  mode=$(stat -c '%a' "$export_file")
  [[ $mode == 600 ]] && echo "  ok   export is owner-only ($mode)" \
                     || { echo "FAIL   export mode is $mode, expected 600"; status=1; }

  head -1 "$export_file" | grep -q "BEGIN PGP MESSAGE" \
    && echo "  ok   export is PGP-encrypted" \
    || { echo "FAIL   export is not a PGP message"; status=1; }

  # The one assertion that matters most: no shared secret is readable in it.
  if grep -qE "GEZDGNBVGY3TQOJQ|JBSWY3DPEHPK3PXP|MZXW6YTBOI|otpauth://" "$export_file"; then
    echo "FAIL   plaintext secrets are readable in the export"
    status=1
  else
    echo "  ok   no plaintext secret or otpauth link in the file"
  fi
  rm -f "$export_file"
fi

exit $status
