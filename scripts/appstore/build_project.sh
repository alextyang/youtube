#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 64
fi

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUTPUT_DIRECTORY=$1
if [[ $(basename "$OUTPUT_DIRECTORY") != appstore-* ]]; then
  echo "output directory basename must start with appstore-" >&2
  exit 64
fi
POLICY="$REPO_ROOT/.appstore/policy.json"
APP_NAME=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["app_name"])' "$POLICY")
BUNDLE_ID=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bundle_identifier"])' "$POLICY")

rm -rf -- "$OUTPUT_DIRECTORY"
mkdir -p "$OUTPUT_DIRECTORY"
WORK_DIRECTORY=$(mktemp -d "${TMPDIR:-/tmp}/improvedtube-appstore.XXXXXX")
trap 'rm -rf "$WORK_DIRECTORY"' EXIT

mkdir "$WORK_DIRECTORY/source"
git -C "$REPO_ROOT" archive HEAD | tar -x -C "$WORK_DIRECTORY/source"
(
  cd "$WORK_DIRECTORY/source"
  python3 build/build.py -safari
)

SAFARI_ZIP=$(find "$WORK_DIRECTORY" -maxdepth 1 -name 'safari-*.zip' -type f -print -quit)
if [[ -z "$SAFARI_ZIP" ]]; then
  echo "Safari packaging did not create a zip" >&2
  exit 1
fi

mkdir "$OUTPUT_DIRECTORY/extension"
unzip -q "$SAFARI_ZIP" -d "$OUTPUT_DIRECTORY/extension"
"$REPO_ROOT/scripts/appstore/verify.py" --extension-root "$OUTPUT_DIRECTORY/extension"

xcrun safari-web-extension-converter "$OUTPUT_DIRECTORY/extension" \
  --macos-only \
  --no-open \
  --force \
  --swift \
  --no-prompt \
  --copy-resources \
  --project-location "$OUTPUT_DIRECTORY/project" \
  --app-name "$APP_NAME" \
  --bundle-identifier "$BUNDLE_ID"

"$REPO_ROOT/scripts/appstore/configure_project.py" "$OUTPUT_DIRECTORY/project"
"$REPO_ROOT/scripts/appstore/verify.py" \
  --extension-root "$OUTPUT_DIRECTORY/extension" \
  --project-root "$OUTPUT_DIRECTORY/project"

cp "$SAFARI_ZIP" "$OUTPUT_DIRECTORY/"
echo "Generated App Store project at $OUTPUT_DIRECTORY/project/$APP_NAME"
