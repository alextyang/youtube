#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="ImprovedTube"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="$ROOT_DIR/.appstore/policy.json"
BUILD_ROOT="${TMPDIR:-/tmp}/appstore-local-run"
DERIVED_DATA="${BUILD_ROOT}-derived-data"
PROJECT="$BUILD_ROOT/project/ImprovedTube/ImprovedTube.xcodeproj"
APP_BUNDLE="$DERIVED_DATA/Build/Products/Release/ImprovedTube.app"
APP_BINARY="$APP_BUNDLE/Contents/MacOS/ImprovedTube"
MINIMUM_MACOS_VERSION="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["minimum_macos_version"])' "$POLICY")"

pkill -x "$APP_NAME" >/dev/null 2>&1 || true

"$ROOT_DIR/scripts/appstore/build_project.sh" "$BUILD_ROOT"
xcodebuild \
  -quiet \
  -project "$PROJECT" \
  -scheme ImprovedTube \
  -configuration Release \
  -destination 'platform=macOS' \
  -derivedDataPath "$DERIVED_DATA" \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  MACOSX_DEPLOYMENT_TARGET="$MINIMUM_MACOS_VERSION" \
  clean build

test -d "$APP_BUNDLE"
test -x "$APP_BINARY"

open_app() {
  /usr/bin/open -n "$APP_BUNDLE"
}

case "$MODE" in
  run)
    open_app
    ;;
  --debug|debug)
    lldb -- "$APP_BINARY"
    ;;
  --logs|logs)
    open_app
    /usr/bin/log stream --info --style compact --predicate 'process == "ImprovedTube"'
    ;;
  --telemetry|telemetry)
    open_app
    /usr/bin/log stream --info --style compact --predicate 'subsystem == "com.tiendoxuan.improvedtube"'
    ;;
  --verify|verify)
    open_app
    sleep 2
    pgrep -x "$APP_NAME" >/dev/null
    pkill -x "$APP_NAME"
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac
