#!/bin/bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 PROJECT_ARTIFACT MARKETING_VERSION BUILD_NUMBER" >&2
  exit 64
fi

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PROJECT_ARTIFACT=$1
MARKETING_VERSION=$2
BUILD_NUMBER=$3
POLICY="$REPO_ROOT/.appstore/policy.json"
TEAM_ID=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["apple_team_id"])' "$POLICY")
BUNDLE_ID=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bundle_identifier"])' "$POLICY")
MINIMUM_MACOS_VERSION=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["minimum_macos_version"])' "$POLICY")

: "${ASC_KEY_ID:?ASC_KEY_ID is required}"
: "${ASC_ISSUER_ID:?ASC_ISSUER_ID is required}"
: "${ASC_PRIVATE_KEY_BASE64:?ASC_PRIVATE_KEY_BASE64 is required}"

"$REPO_ROOT/scripts/appstore/verify.py" \
  --project-root "$PROJECT_ARTIFACT/project" \
  --marketing-version "$MARKETING_VERSION" \
  --build-number "$BUILD_NUMBER"

AUTH_KEY_PATH="${RUNNER_TEMP:-/tmp}/AuthKey_${ASC_KEY_ID}.p8"
ARCHIVE_PATH="${RUNNER_TEMP:-/tmp}/ImprovedTube-${MARKETING_VERSION}-${BUILD_NUMBER}.xcarchive"
EXPORT_PATH="${RUNNER_TEMP:-/tmp}/ImprovedTube-export"
EXPORT_OPTIONS="${RUNNER_TEMP:-/tmp}/AppStoreExportOptions.plist"
PROJECT="$PROJECT_ARTIFACT/project/ImprovedTube/ImprovedTube.xcodeproj"

cleanup() {
  rm -f "$AUTH_KEY_PATH"
}
trap cleanup EXIT

printf '%s' "$ASC_PRIVATE_KEY_BASE64" | base64 --decode > "$AUTH_KEY_PATH"
chmod 600 "$AUTH_KEY_PATH"

xcodebuild \
  -project "$PROJECT" \
  -scheme ImprovedTube \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  -archivePath "$ARCHIVE_PATH" \
  -allowProvisioningUpdates \
  -authenticationKeyPath "$AUTH_KEY_PATH" \
  -authenticationKeyID "$ASC_KEY_ID" \
  -authenticationKeyIssuerID "$ASC_ISSUER_ID" \
  DEVELOPMENT_TEAM="$TEAM_ID" \
  CODE_SIGN_STYLE=Automatic \
  MACOSX_DEPLOYMENT_TARGET="$MINIMUM_MACOS_VERSION" \
  MARKETING_VERSION="$MARKETING_VERSION" \
  CURRENT_PROJECT_VERSION="$BUILD_NUMBER" \
  archive

APP_PATH=$(find "$ARCHIVE_PATH/Products/Applications" -maxdepth 1 -name '*.app' -type d -print -quit)
if [[ -z "$APP_PATH" ]]; then
  echo "archive did not contain a macOS app" >&2
  exit 1
fi

APP_BUNDLE_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP_PATH/Contents/Info.plist")
APP_VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP_PATH/Contents/Info.plist")
APP_BUILD=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP_PATH/Contents/Info.plist")
APP_ENCRYPTION=$(/usr/libexec/PlistBuddy -c 'Print :ITSAppUsesNonExemptEncryption' "$APP_PATH/Contents/Info.plist")
[[ "$APP_BUNDLE_ID" == "$BUNDLE_ID" ]]
[[ "$APP_VERSION" == "$MARKETING_VERSION" ]]
[[ "$APP_BUILD" == "$BUILD_NUMBER" ]]
[[ "$APP_ENCRYPTION" == "false" ]]

codesign --verify --deep --strict --verbose=4 "$APP_PATH"

EXTENSION_PATH=$(find "$APP_PATH/Contents/PlugIns" -maxdepth 1 -name '*.appex' -type d -print -quit)
if [[ -z "$EXTENSION_PATH" ]]; then
  echo "archive did not contain a Safari extension" >&2
  exit 1
fi
EXPECTED_EXTENSION_ID=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["extension_bundle_identifier"])' "$POLICY")
EXTENSION_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$EXTENSION_PATH/Contents/Info.plist")
[[ "$EXTENSION_ID" == "$EXPECTED_EXTENSION_ID" ]]

plutil -create xml1 "$EXPORT_OPTIONS"
plutil -insert method -string app-store-connect "$EXPORT_OPTIONS"
plutil -insert destination -string upload "$EXPORT_OPTIONS"
plutil -insert signingStyle -string automatic "$EXPORT_OPTIONS"
plutil -insert teamID -string "$TEAM_ID" "$EXPORT_OPTIONS"
plutil -insert distributionBundleIdentifier -string "$BUNDLE_ID" "$EXPORT_OPTIONS"
plutil -insert manageAppVersionAndBuildNumber -bool false "$EXPORT_OPTIONS"
plutil -insert uploadSymbols -bool true "$EXPORT_OPTIONS"

xcodebuild \
  -exportArchive \
  -archivePath "$ARCHIVE_PATH" \
  -exportPath "$EXPORT_PATH" \
  -exportOptionsPlist "$EXPORT_OPTIONS" \
  -allowProvisioningUpdates \
  -authenticationKeyPath "$AUTH_KEY_PATH" \
  -authenticationKeyID "$ASC_KEY_ID" \
  -authenticationKeyIssuerID "$ASC_ISSUER_ID"

cleanup
trap - EXIT
echo "ARCHIVE_PATH=$ARCHIVE_PATH" >> "${GITHUB_OUTPUT:-/dev/null}"
