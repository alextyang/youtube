#!/bin/bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUTPUT_DIRECTORY=${1:-"${RUNNER_TEMP:-/tmp}/appstore-ci"}
DERIVED_DATA="${OUTPUT_DIRECTORY}-derived-data"
MINIMUM_MACOS_VERSION=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["minimum_macos_version"])' "$REPO_ROOT/.appstore/policy.json")
BUNDLE_ID=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bundle_identifier"])' "$REPO_ROOT/.appstore/policy.json")
EXTENSION_BUNDLE_ID=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["extension_bundle_identifier"])' "$REPO_ROOT/.appstore/policy.json")

cd "$REPO_ROOT"
./scripts/appstore/verify.py
npm ci
npm test -- --runInBand
npm run lint
npm audit --omit=dev --audit-level=high
./scripts/appstore/build_project.sh "$OUTPUT_DIRECTORY"

PROJECT="$OUTPUT_DIRECTORY/project/ImprovedTube/ImprovedTube.xcodeproj"
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
  MARKETING_VERSION=999.0.0 \
  CURRENT_PROJECT_VERSION=9999 \
  clean build

BUILT_APP="$DERIVED_DATA/Build/Products/Release/ImprovedTube.app"
BUILT_EXTENSION="$BUILT_APP/Contents/PlugIns/ImprovedTube Extension.appex"
[[ -d "$BUILT_APP" ]]
[[ -d "$BUILT_EXTENSION" ]]
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$BUILT_APP/Contents/Info.plist") == "$BUNDLE_ID" ]]
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$BUILT_EXTENSION/Contents/Info.plist") == "$EXTENSION_BUNDLE_ID" ]]
[[ $(/usr/libexec/PlistBuddy -c 'Print :ITSAppUsesNonExemptEncryption' "$BUILT_APP/Contents/Info.plist") == false ]]
[[ $(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$BUILT_APP/Contents/Info.plist") == "$MINIMUM_MACOS_VERSION" ]]
./scripts/appstore/verify.py --extension-root "$BUILT_EXTENSION/Contents/Resources"
