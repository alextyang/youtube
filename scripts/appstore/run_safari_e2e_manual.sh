#!/bin/bash
set -euo pipefail

if [[ ${1:-} == --help || $# -eq 0 ]]; then
  cat <<'USAGE'
usage: scripts/appstore/run_safari_e2e_manual.sh \
  --expected-version VERSION --expected-build BUILD \
  [--feature STORAGE_KEY] \
  [--expected-extension-asset-sha256 SHA256] \
  [--allow-permission] [--allow-account] [--allow-destructive] \
  [--account-fixture REMOTE_JSON_PATH]

Run this as the active macOS desktop user. It starts only Safari Technology
Preview's driver, binds the Aqua observer to the owned test window, runs the
complete signed TestFlight catalog through codex-user-2, and cleans its children.
Pass one --feature to run only that feature; omit it to run the full catalog.
All three allow flags plus an exact account fixture are required for a release PASS.
USAGE
  exit $(( $# == 0 ? 64 : 0 ))
fi

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
REMOTE_HOST=${IMPROVEDTUBE_E2E_REMOTE_HOST:-codex-user-2}
PORT=${IMPROVEDTUBE_E2E_PORT:-49861}
DRIVER="/Applications/Safari Technology Preview.app/Contents/MacOS/safaridriver"
CURRENT_UID=$(/usr/bin/id -u)
CONSOLE_UID=$(/usr/bin/stat -f %u /dev/console)

if [[ $CURRENT_UID != "$CONSOLE_UID" ]]; then
  echo "run this command as the active Aqua user" >&2
  exit 1
fi
if [[ ! -x $DRIVER ]]; then
  echo "Safari Technology Preview safaridriver is unavailable" >&2
  exit 1
fi
if /usr/bin/nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
  echo "refusing to reuse occupied WebDriver port $PORT" >&2
  exit 1
fi

RUN_ID=$(/usr/bin/python3 -c 'import secrets; print(secrets.token_urlsafe(18))')
PREFIX="/tmp/improvedtube-e2e-${CURRENT_UID}-${RUN_ID}"
SOCKET_PATH="${PREFIX}.sock"
CAPABILITY_PATH="${PREFIX}.cap"
READY_PATH="${PREFIX}.ready"
OBSERVER_LOG="${PREFIX}.observer.log"
DRIVER_LOG="${PREFIX}.driver.log"
OBSERVER_PID=
DRIVER_PID=
REMOTE_CAPABILITY_PATH=
FEATURE_COUNT=0

for argument in "$@"; do
  [[ $argument == --feature || $argument == --feature=* ]] && ((FEATURE_COUNT+=1))
done
if (( FEATURE_COUNT > 1 )); then
  echo "manual runs accept at most one --feature" >&2
  exit 64
fi

cleanup() {
  status=$?
  trap - EXIT INT TERM
  for child_pid in "$DRIVER_PID" "$OBSERVER_PID"; do
    if [[ -n $child_pid ]] && /bin/kill -0 "$child_pid" 2>/dev/null; then
      /bin/kill -TERM "$child_pid" 2>/dev/null || true
      wait "$child_pid" 2>/dev/null || true
    fi
  done
  if [[ $REMOTE_CAPABILITY_PATH == /tmp/improvedtube-e2e-cap.* ]]; then
    remote_capability_quoted=$(printf '%q' "$REMOTE_CAPABILITY_PATH")
    /usr/bin/ssh "$REMOTE_HOST" "/bin/rm -f -- $remote_capability_quoted" >/dev/null 2>&1 || true
  fi
  /bin/rm -f -- "$SOCKET_PATH" "$CAPABILITY_PATH" "$READY_PATH"
  if [[ $status -eq 0 ]]; then
    /bin/rm -f -- "$OBSERVER_LOG" "$DRIVER_LOG"
  else
    echo "manual Safari E2E failed; logs: $OBSERVER_LOG $DRIVER_LOG" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

PEER_UID=$(/usr/bin/ssh "$REMOTE_HOST" /usr/bin/id -u)
PEER_GID=$(/usr/bin/ssh "$REMOTE_HOST" /usr/bin/id -g)
/usr/bin/python3 "$REPO_ROOT/scripts/appstore/launch_aqua_observer.py" \
  --socket "$SOCKET_PATH" --run-id "$RUN_ID" \
  --peer-uid "$PEER_UID" --peer-gid "$PEER_GID" \
  --capability-file "$CAPABILITY_PATH" --ready-file "$READY_PATH" \
  >"$OBSERVER_LOG" 2>&1 &
OBSERVER_PID=$!

for _ in {1..120}; do
  [[ -S $SOCKET_PATH && -s $CAPABILITY_PATH ]] && break
  /bin/kill -0 "$OBSERVER_PID" 2>/dev/null || { /bin/cat "$OBSERVER_LOG" >&2; exit 1; }
  /bin/sleep .25
done
[[ -S $SOCKET_PATH && -s $CAPABILITY_PATH ]] || { echo "Aqua observer did not become ready" >&2; exit 1; }

"$DRIVER" --port "$PORT" >"$DRIVER_LOG" 2>&1 &
DRIVER_PID=$!
for _ in {1..60}; do
  /usr/bin/nc -z 127.0.0.1 "$PORT" 2>/dev/null && break
  /bin/kill -0 "$DRIVER_PID" 2>/dev/null || { /bin/cat "$DRIVER_LOG" >&2; exit 1; }
  /bin/sleep .25
done
/usr/bin/nc -z 127.0.0.1 "$PORT" 2>/dev/null || { echo "Safari Technology Preview WebDriver did not become ready" >&2; exit 1; }

REMOTE_CAPABILITY_PATH=$(/usr/bin/ssh "$REMOTE_HOST" /usr/bin/mktemp /tmp/improvedtube-e2e-cap.XXXXXX)
if [[ $REMOTE_CAPABILITY_PATH != /tmp/improvedtube-e2e-cap.* ]]; then
  echo "remote capability path was outside the expected temporary prefix" >&2
  exit 1
fi
/bin/cat "$CAPABILITY_PATH" | /usr/bin/ssh "$REMOTE_HOST" "/bin/chmod 600 '$REMOTE_CAPABILITY_PATH' && /bin/cat > '$REMOTE_CAPABILITY_PATH'"

HARNESS=(python3 scripts/appstore/safari_e2e.py
  --full-live --contracts-dir .appstore/testing/full-live-contracts
  --source installed --sut signed --driver-mode external
  --host 127.0.0.1 --port "$PORT"
  --observer-socket "$SOCKET_PATH" --observer-run-id "$RUN_ID"
  --observer-capability-file "$REMOTE_CAPABILITY_PATH" --observer-server-uid "$CURRENT_UID"
  --window-x -1408 --window-y -900 --window-width 1360 --window-height 2480
  "$@")
printf -v REMOTE_COMMAND '%q ' "${HARNESS[@]}"
printf -v REMOTE_REPO '%q' "$REPO_ROOT"
/usr/bin/ssh "$REMOTE_HOST" "cd $REMOTE_REPO && PATH=/opt/homebrew/bin:/usr/bin:/bin $REMOTE_COMMAND"
