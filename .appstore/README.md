# ImprovedTube App Store release lane

This branch is the publisher-owned release lane for the macOS Safari Web
Extension. It follows upstream `code-charity/youtube` and deliberately carries
one downstream source change: unused AES-GCM encrypt/decrypt helpers are removed
from `menu/satus.js`.

## Safety boundary

- Upstream changes arrive through a pull request created by
  `appstore-sync.yml`; sync never uploads a build.
- `appstore-ci.yml` tests the extension, audits production dependencies,
  validates the permission baseline, verifies the encryption removal, converts
  the Safari extension, and compiles an unsigned Release build.
- `appstore-release.yml` can upload only from the `appstore` branch. Its signing
  and upload job uses the `app-store-production` GitHub environment so an
  environment reviewer can approve access to App Store Connect credentials.
- The workflow uploads a processed build to App Store Connect. It does not
  select that build for a version or submit it to App Review.

## One-time GitHub setup

Create an `app-store-production` environment with a required reviewer and
prevent self-review when the repository plan supports it. Add these environment
secrets:

- `ASC_KEY_ID`: App Store Connect API key ID.
- `ASC_ISSUER_ID`: App Store Connect issuer ID.
- `ASC_PRIVATE_KEY_BASE64`: base64 of the downloaded `AuthKey_*.p8` file.

The App Store Connect user/key needs permission to upload builds and access to
cloud-managed certificates. Keep these credentials in the environment, never as
repository files or ordinary workflow inputs.

The checked-in identifiers are intentionally non-secret and match the currently
installed publisher build:

- App bundle ID: `com.tiendoxuan.improvedtube`
- Extension bundle ID: `com.tiendoxuan.improvedtube.Extension`
- Apple team: `76JE9YNX29`
- Minimum macOS: 12.0

## Routine update flow

1. Review and merge the automated `chore(appstore): sync upstream ...` PR.
2. Let App Store CI pass on the exact merged commit.
3. Run **App Store release** from the `appstore` branch with a new
   `marketing_version` and `build_number`.
4. First leave `upload_to_app_store` disabled to exercise the unsigned build.
5. Run it again with upload enabled, inspect the approval summary, and approve
   the `app-store-production` environment job.
6. After Apple processes the upload, test it through TestFlight (or your normal
   pre-release route), then select and submit it in App Store Connect.

Apple requires `CFBundleShortVersionString` to contain three dot-separated
integers. The workflow also requires the marketing version and integer build to
be greater than the last known published values in `policy.json`. Update those
baselines after a release if App Store Connect has a newer value than the file.

## Export compliance note

The generated host app declares `ITSAppUsesNonExemptEncryption=false`. The gate
proves that the custom AES-GCM helpers remain absent; cryptographic digest calls
and browser/OS HTTPS remain possible. Export classification is a publisher/legal
determination, so revisit this declaration if upstream adds any encryption,
VPN, secure messaging, cryptographic library, or similar functionality.
