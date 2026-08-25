#!/bin/bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUTPUT_DIRECTORY=${1:-"${RUNNER_TEMP:-/tmp}/improvedtube-appstore-ci"}
MINIMUM_MACOS_VERSION=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["minimum_macos_version"])' "$REPO_ROOT/.appstore/policy.json")

cd "$REPO_ROOT"
./scripts/appstore/verify.py
npm ci
npm test -- --runInBand
npm run lint
npm audit --omit=dev --audit-level=high
./scripts/appstore/build_project.sh "$OUTPUT_DIRECTORY"

PROJECT="$OUTPUT_DIRECTORY/project/ImprovedTube/ImprovedTube.xcodeproj"
xcodebuild \
  -project "$PROJECT" \
  -scheme ImprovedTube \
  -configuration Release \
  -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  MACOSX_DEPLOYMENT_TARGET="$MINIMUM_MACOS_VERSION" \
  MARKETING_VERSION=999.0.0 \
  CURRENT_PROJECT_VERSION=9999 \
  build
