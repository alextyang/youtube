#!/usr/bin/env python3
"""Fail closed on App Store-specific source and generated-project policy."""

from __future__ import annotations

import argparse
import json
import plistlib
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / ".appstore" / "policy.json"
FORBIDDEN_CRYPTO = {
    "AES-GCM": re.compile(r"AES-GCM", re.IGNORECASE),
    "custom cryptographic algorithm": re.compile(
        r"\b(?:AES-(?:CBC|CTR|GCM|KW)|RSA-(?:OAEP|PSS)|ECDH|ECDSA|Ed25519|X25519|ChaCha|Poly1305)\b",
        re.IGNORECASE,
    ),
    "SubtleCrypto key or encryption operation": re.compile(
        r"crypto\s*\.\s*subtle\s*\.\s*(?:decrypt|deriveBits|deriveKey|encrypt|generateKey|importKey|sign|unwrapKey|verify|wrapKey)\s*\("
    ),
    "bundled cryptography library": re.compile(
        r"\b(?:CryptoJS|libsodium|openpgp|tweetnacl)\b", re.IGNORECASE
    ),
    "satus.encrypt": re.compile(r"satus\s*\.\s*encrypt\b"),
    "satus.decrypt": re.compile(r"satus\s*\.\s*decrypt\b"),
}


class VerificationError(RuntimeError):
    pass


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid JSON at {path}: {error}") from error


def assert_exact_list(manifest: dict, key: str, expected: list[str]) -> None:
    actual = manifest.get(key, [])
    if sorted(actual) != sorted(expected):
        raise VerificationError(
            f"manifest {key} changed; expected {sorted(expected)!r}, got {sorted(actual)!r}"
        )


def verify_manifest(path: Path, policy: dict, safari: bool) -> None:
    manifest = load_json(path)
    expected_permissions = (
        policy["safari_permissions"] if safari else policy["source_permissions"]
    )
    assert_exact_list(manifest, "permissions", expected_permissions)
    assert_exact_list(manifest, "host_permissions", policy["host_permissions"])
    assert_exact_list(
        manifest, "optional_host_permissions", policy["optional_host_permissions"]
    )
    assert_exact_list(manifest, "optional_permissions", policy["optional_permissions"])

    matches = set()
    for content_script in manifest.get("content_scripts", []):
        matches.update(content_script.get("matches", []))
    if matches != set(policy["host_permissions"]):
        raise VerificationError(
            f"content-script match scope changed; expected {policy['host_permissions']!r}, "
            f"got {sorted(matches)!r}"
        )

    resources_matches = set()
    for resource in manifest.get("web_accessible_resources", []):
        resources_matches.update(resource.get("matches", []))
    if resources_matches != set(policy["host_permissions"]):
        raise VerificationError(
            "web-accessible resource scope changed; "
            f"expected {policy['host_permissions']!r}, got {sorted(resources_matches)!r}"
        )


def verify_locales(root: Path) -> None:
    locale_root = root / "_locales"
    if not locale_root.is_dir():
        raise VerificationError(f"missing locale directory: {locale_root}")
    malformed = []
    for locale in sorted(locale_root.iterdir()):
        if not locale.is_dir():
            malformed.append(str(locale.relative_to(root)))
            continue
        messages = locale / "messages.json"
        if not messages.is_file():
            malformed.append(str(messages.relative_to(root)))
            continue
        load_json(messages)
    if malformed:
        raise VerificationError(
            "every Safari locale must be a directory containing messages.json: "
            + ", ".join(malformed)
        )


def verify_no_custom_encryption(root: Path) -> None:
    hits = []
    for path in sorted(root.rglob("*")):
        if {".git", "node_modules"}.intersection(path.parts):
            continue
        if not path.is_file() or path.suffix.lower() not in {".js", ".mjs", ".cjs"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for label, pattern in FORBIDDEN_CRYPTO.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                hits.append(f"{path.relative_to(root)}:{line}: {label}")
    if hits:
        raise VerificationError(
            "custom encryption was reintroduced; reassess export compliance:\n  "
            + "\n  ".join(hits)
        )


def verify_no_symlinks(root: Path) -> None:
    symlinks = [str(path.relative_to(root)) for path in root.rglob("*") if path.is_symlink()]
    if symlinks:
        raise VerificationError(
            "release inputs must not contain symbolic links: " + ", ".join(symlinks)
        )


def verify_generated_project(project_root: Path, policy: dict) -> None:
    project_files = list(project_root.rglob("project.pbxproj"))
    if len(project_files) != 1:
        raise VerificationError(
            f"expected one generated project.pbxproj, found {len(project_files)}"
        )
    project_text = project_files[0].read_text(encoding="utf-8")
    if "PBXShellScriptBuildPhase" in project_text:
        raise VerificationError("generated Xcode project unexpectedly has a shell build phase")

    bundle_ids = set(
        re.findall(r"PRODUCT_BUNDLE_IDENTIFIER = ([^;]+);", project_text)
    )
    expected_ids = {
        policy["bundle_identifier"],
        policy["extension_bundle_identifier"],
    }
    if bundle_ids != expected_ids:
        raise VerificationError(
            f"generated bundle IDs changed; expected {sorted(expected_ids)!r}, "
            f"got {sorted(bundle_ids)!r}"
        )

    app_plists = [
        path
        for path in project_root.rglob("Info.plist")
        if "Extension" not in str(path.parent)
    ]
    if len(app_plists) != 1:
        raise VerificationError(f"expected one host Info.plist, found {len(app_plists)}")
    with app_plists[0].open("rb") as file:
        app_info = plistlib.load(file)
    if app_info.get("ITSAppUsesNonExemptEncryption") is not False:
        raise VerificationError(
            "host Info.plist must set ITSAppUsesNonExemptEncryption to false"
        )


def parse_version(value: str) -> tuple[int, int, int]:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise VerificationError(
            "marketing version must contain exactly three dot-separated integers"
        )
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def verify_release_version(marketing_version: str, build_number: str, policy: dict) -> None:
    candidate = parse_version(marketing_version)
    baseline = parse_version(policy["last_known_marketing_version"])
    if candidate <= baseline:
        raise VerificationError(
            f"marketing version {marketing_version} must be greater than last known "
            f"App Store version {policy['last_known_marketing_version']}"
        )
    if not re.fullmatch(r"[1-9][0-9]{0,3}", build_number):
        raise VerificationError("build number must be an integer from 1 through 9999")
    if int(build_number) <= int(policy["last_known_build_number"]):
        raise VerificationError(
            f"build {build_number} must be greater than last known App Store build "
            f"{policy['last_known_build_number']}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--extension-root", type=Path)
    parser.add_argument("--project-root", type=Path)
    parser.add_argument("--marketing-version")
    parser.add_argument("--build-number")
    arguments = parser.parse_args()
    policy = load_json(POLICY_PATH)

    try:
        verify_manifest(ROOT / "manifest.json", policy, safari=False)
        verify_locales(ROOT)
        verify_no_custom_encryption(ROOT)
        if arguments.extension_root:
            verify_no_symlinks(arguments.extension_root)
            verify_manifest(arguments.extension_root / "manifest.json", policy, safari=True)
            verify_locales(arguments.extension_root)
            verify_no_custom_encryption(arguments.extension_root)
        if arguments.project_root:
            verify_no_symlinks(arguments.project_root)
            verify_generated_project(arguments.project_root, policy)
        if bool(arguments.marketing_version) != bool(arguments.build_number):
            raise VerificationError(
                "marketing version and build number must be supplied together"
            )
        if arguments.marketing_version and arguments.build_number:
            verify_release_version(
                arguments.marketing_version, arguments.build_number, policy
            )
    except VerificationError as error:
        print(f"App Store verification failed: {error}", file=sys.stderr)
        return 1

    print("App Store policy verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
