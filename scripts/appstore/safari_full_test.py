#!/usr/bin/env python3
"""Fail-closed Safari/App Store release test for ImprovedTube.

The runner proves every deterministic source and signed-artifact assertion, then
requires a machine-readable evidence ledger for Safari/YouTube behavior that
cannot be established by static analysis or unit tests.
"""

from __future__ import annotations

import argparse
import base64
from html.parser import HTMLParser
import json
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from typing import Callable, Iterable
from urllib import parse, request


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / ".appstore" / "testing" / "4.1322.0-safari-test.json"
PRODUCT_PATHS = [
    "_locales",
    "background.js",
    "build",
    "js&css",
    "manifest.json",
    "menu",
    "package-lock.json",
    "package.json",
    "tests",
]
MANUAL_PREFIXES = {
    "A11Y",
    "ART",
    "CAT",
    "ENV",
    "FIX",
    "GLB",
    "LOC",
    "REG",
    "SFR",
    "STB",
}
AUTOMATIC_TEST_INDEX_IDS = {f"ART-{number:02d}" for number in range(1, 14)}


@dataclass
class Result:
    identifier: str
    status: str
    assertion: str
    detail: str
    duration_seconds: float


class CheckFailure(RuntimeError):
    pass


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CheckFailure(f"invalid JSON at {path}: {error}") from error


def resolve_from_root(value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else (ROOT / path).resolve()


def command(
    arguments: list[str],
    *,
    cwd: Path = ROOT,
    acceptable_codes: set[int] | None = None,
) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    allowed = acceptable_codes or {0}
    if completed.returncode not in allowed:
        output = "\n".join(
            line for line in (completed.stdout + "\n" + completed.stderr).splitlines()[-40:]
            if line.strip()
        )
        raise CheckFailure(
            f"command failed ({completed.returncode}): {' '.join(arguments)}\n{output}"
        )
    return completed


def run_check(
    results: list[Result],
    identifier: str,
    assertion: str,
    check: Callable[[], str],
) -> None:
    started = time.monotonic()
    try:
        detail = check()
    except Exception as error:  # a release gate must convert every error to FAIL
        results.append(
            Result(identifier, "FAIL", assertion, str(error), time.monotonic() - started)
        )
    else:
        results.append(
            Result(identifier, "PASS", assertion, detail, time.monotonic() - started)
        )


def product_source_check(config: dict) -> str:
    source = config["source_commit"]
    command(["git", "cat-file", "-e", f"{source}^{{commit}}"])
    changed = command(
        ["git", "diff", "--name-only", f"{source}..HEAD", "--", *PRODUCT_PATHS]
    ).stdout.splitlines()
    if changed:
        raise CheckFailure(
            "product source differs from uploaded commit: " + ", ".join(changed)
        )
    return f"product paths match uploaded commit {source}"


def safari_converter_warnings(output: str) -> set[str]:
    warnings: set[str] = set()
    collecting = False
    for line in output.splitlines():
        if line.startswith("Warning: The following keys in your manifest.json are not supported"):
            collecting = True
            continue
        if collecting and line.startswith("\t"):
            warnings.add(line.strip())
            continue
        if collecting:
            collecting = False
    return warnings


def source_pipeline_check(config: dict) -> str:
    output = Path(tempfile.mkdtemp(prefix="appstore-safari-full-test."))
    derived_data = Path(str(output) + "-derived-data")
    try:
        completed = command(["./scripts/appstore/ci.sh", str(output)])
        converter_warnings = safari_converter_warnings(
            completed.stdout + "\n" + completed.stderr
        )
        expected_warnings = set(config["expected"]["safari_converter_warnings"])
        if converter_warnings != expected_warnings:
            raise CheckFailure(
                "Safari converter warning set changed: "
                f"got {sorted(converter_warnings)!r}, expected {sorted(expected_warnings)!r}"
            )
    finally:
        for generated in (output, derived_data):
            if generated.exists() and generated.parent == Path(tempfile.gettempdir()):
                shutil.rmtree(generated)
    return (
        "policy, npm ci, 113 Jest assertions, lint, audit, Safari conversion, "
        "known-warning baseline, and Release compile passed"
    )


def inventory_check(config: dict, kind: str) -> str:
    source = config["source_commit"]
    release = config["release"]
    if kind == "features":
        target = config["feature_index"]
        script = "scripts/appstore/generate_feature_index.mjs"
        expected = config["expected"]["feature_count"]
        marker = f"Total interactive controls: **{expected}**"
    else:
        target = config["automated_assertion_index"]
        script = "scripts/appstore/generate_automated_assertion_index.mjs"
        expected = config["expected"]["automated_assertion_count"]
        suites = config["expected"]["automated_suite_count"]
        marker = f"Jest assertions indexed: **{expected}** across **{suites}** suites"
    command(
        [
            "node",
            script,
            "--release",
            release,
            "--source",
            source,
            "--check",
            target,
        ]
    )
    text = resolve_from_root(target).read_text(encoding="utf-8")
    if marker not in text:
        raise CheckFailure(f"expected inventory marker not found: {marker}")
    return f"{kind} inventory is reproducible and contains {expected} entries"


def locate_artifact(config: dict, override: str | None) -> tuple[Path, Path, Path, Path]:
    artifact = resolve_from_root(override or config["artifact_path"])
    if not artifact.is_dir():
        raise CheckFailure(f"artifact directory is missing: {artifact}")
    applications = list((artifact / "Products" / "Applications").glob("*.app"))
    if len(applications) != 1:
        raise CheckFailure(f"expected one host app, found {len(applications)}")
    app = applications[0]
    extensions = list((app / "Contents" / "PlugIns").glob("*.appex"))
    if len(extensions) != 1:
        raise CheckFailure(f"expected one Safari extension, found {len(extensions)}")
    extension = extensions[0]
    resources = extension / "Contents" / "Resources"
    if not resources.is_dir():
        raise CheckFailure(f"extension resources are missing: {resources}")
    return artifact, app, extension, resources


def github_artifact_check(config: dict) -> str:
    github = config["github"]
    completed = command(
        [
            "gh",
            "api",
            f"repos/{github['repository']}/actions/artifacts/{github['artifact_id']}",
        ]
    )
    artifact = json.loads(completed.stdout)
    if artifact.get("expired"):
        raise CheckFailure("preserved GitHub artifact is expired")
    if artifact.get("digest") != github["artifact_digest"]:
        raise CheckFailure(
            f"artifact digest changed: {artifact.get('digest')!r}"
        )
    if artifact.get("workflow_run", {}).get("id") != github["release_run_id"]:
        raise CheckFailure("artifact belongs to a different release workflow run")
    return f"GitHub artifact {github['artifact_id']} digest and release run match"


def plist(path: Path) -> dict:
    try:
        with path.open("rb") as file:
            return plistlib.load(file)
    except (OSError, plistlib.InvalidFileException) as error:
        raise CheckFailure(f"invalid plist at {path}: {error}") from error


def artifact_metadata_check(config: dict, app: Path, extension: Path) -> str:
    expected = config["expected"]
    host_info = plist(app / "Contents" / "Info.plist")
    extension_info = plist(extension / "Contents" / "Info.plist")
    required = {
        "host bundle": (host_info.get("CFBundleIdentifier"), expected["app_bundle_id"]),
        "extension bundle": (
            extension_info.get("CFBundleIdentifier"),
            expected["extension_bundle_id"],
        ),
        "host version": (host_info.get("CFBundleShortVersionString"), config["release"]),
        "extension version": (
            extension_info.get("CFBundleShortVersionString"),
            config["release"],
        ),
        "host build": (host_info.get("CFBundleVersion"), config["build"]),
        "extension build": (extension_info.get("CFBundleVersion"), config["build"]),
        "minimum macOS": (host_info.get("LSMinimumSystemVersion"), expected["minimum_macos"]),
        "category": (host_info.get("LSApplicationCategoryType"), expected["category"]),
        "encryption": (host_info.get("ITSAppUsesNonExemptEncryption"), False),
    }
    mismatches = [
        f"{name}: got {actual!r}, expected {wanted!r}"
        for name, (actual, wanted) in required.items()
        if str(actual) != str(wanted)
    ]
    if mismatches:
        raise CheckFailure("; ".join(mismatches))
    return "bundle IDs, version/build, macOS floor, category, and encryption plist match"


def executable(bundle: Path) -> Path:
    info = plist(bundle / "Contents" / "Info.plist")
    name = info.get("CFBundleExecutable")
    candidate = bundle / "Contents" / "MacOS" / str(name)
    if not candidate.is_file():
        raise CheckFailure(f"bundle executable is missing: {candidate}")
    return candidate


def architecture_check(config: dict, app: Path, extension: Path) -> str:
    expected = set(config["expected"]["architectures"])
    actual_by_bundle = {}
    for bundle in (app, extension):
        actual = set(command(["lipo", "-archs", str(executable(bundle))]).stdout.split())
        actual_by_bundle[bundle.name] = actual
        if actual != expected:
            raise CheckFailure(
                f"{bundle.name} architectures {sorted(actual)!r}, expected {sorted(expected)!r}"
            )
    return ", ".join(f"{name}: {sorted(values)}" for name, values in actual_by_bundle.items())


def signature_check(app: Path, extension: Path) -> str:
    command(["codesign", "--verify", "--deep", "--strict", "--verbose=4", str(app)])
    command(["codesign", "--verify", "--strict", "--verbose=4", str(extension)])
    return "deep strict host signature and nested extension signature pass"


def runtime_and_nested_code_check(config: dict, app: Path, extension: Path) -> str:
    expected = config["expected"]
    for bundle, identifier in (
        (app, expected["app_bundle_id"]),
        (extension, expected["extension_bundle_id"]),
    ):
        details = command(
            ["codesign", "-dv", "--verbose=4", str(bundle)], acceptable_codes={0}
        ).stderr
        required_fragments = [
            f"Identifier={identifier}",
            f"TeamIdentifier={expected['team_id']}",
            "flags=0x10000(runtime)",
        ]
        missing = [fragment for fragment in required_fragments if fragment not in details]
        if missing:
            raise CheckFailure(f"{bundle.name} signature detail missing {missing!r}")
    forbidden_directories = ["Frameworks", "Helpers", "Library", "XPCServices"]
    unexpected = [
        str(path.relative_to(app))
        for directory in forbidden_directories
        for path in (app / "Contents" / directory).rglob("*")
        if path.is_file()
    ]
    if unexpected:
        raise CheckFailure("unexpected nested code/resources: " + ", ".join(unexpected))
    return "hardened runtime, identifiers, team, and no unexpected nested code pass"


def signed_entitlements(bundle: Path) -> dict:
    completed = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", str(bundle)],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise CheckFailure(
            f"could not read entitlements for {bundle}: {completed.stderr.decode(errors='replace')}"
        )
    try:
        return plistlib.loads(completed.stdout)
    except plistlib.InvalidFileException as error:
        raise CheckFailure(f"invalid signed entitlements for {bundle}") from error


def entitlement_check(config: dict, app: Path, extension: Path) -> str:
    expected = config["expected"]
    actual_host = signed_entitlements(app)
    actual_extension = signed_entitlements(extension)
    if actual_host != expected["host_entitlements"]:
        raise CheckFailure(
            f"host entitlements changed: {actual_host!r}"
        )
    if actual_extension != expected["extension_entitlements"]:
        raise CheckFailure(
            f"extension entitlements changed: {actual_extension!r}"
        )
    return "host and extension entitlements exactly match the reviewed baseline"


def manifest_reference_paths(manifest: dict) -> Iterable[str]:
    for icon in manifest.get("icons", {}).values():
        yield icon
    background = manifest.get("background", {})
    if background.get("service_worker"):
        yield background["service_worker"]
    yield from background.get("scripts", [])
    action = manifest.get("action", {})
    if action.get("default_popup"):
        yield action["default_popup"]
    if manifest.get("options_page"):
        yield manifest["options_page"]
    if manifest.get("options_ui", {}).get("page"):
        yield manifest["options_ui"]["page"]
    if manifest.get("side_panel", {}).get("default_path"):
        yield manifest["side_panel"]["default_path"]
    for content_script in manifest.get("content_scripts", []):
        yield from content_script.get("css", [])
        yield from content_script.get("js", [])
    for group in manifest.get("web_accessible_resources", []):
        yield from group.get("resources", [])


class LocalReferenceParser(HTMLParser):
    def __init__(self, html_path: Path, root: Path, missing: list[str]):
        super().__init__()
        self.html_path = html_path
        self.root = root
        self.missing = missing

    def handle_starttag(self, _tag: str, attributes: list[tuple[str, str | None]]) -> None:
        for name, value in attributes:
            if name not in {"href", "src"} or not value:
                continue
            before = len(self.missing)
            check_local_reference(self.html_path.parent, value, self.root, self.missing)
            if len(self.missing) > before:
                self.missing[-1] = (
                    f"{self.html_path.relative_to(self.root)}: {self.missing[-1]}"
                )


def check_local_reference(base: Path, value: str, root: Path, missing: list[str]) -> None:
    cleaned = value.split("?", 1)[0].split("#", 1)[0].strip().strip('"\'')
    if not cleaned or cleaned.startswith(("data:", "http:", "https:", "//", "/", "#")):
        return
    target = (base / cleaned).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError:
        missing.append(f"reference escapes package: {value}")
        return
    if any(character in cleaned for character in "*?["):
        if not list(base.glob(cleaned)):
            missing.append(f"unmatched resource pattern: {value}")
    elif not target.exists():
        missing.append(f"missing: {value}")


def resource_closure(root: Path) -> list[str]:
    missing: list[str] = []
    manifest_path = root / "manifest.json"
    manifest = load_json(manifest_path)
    for value in manifest_reference_paths(manifest):
        check_local_reference(root, value, root, missing)
    for html in root.rglob("*.html"):
        parser = LocalReferenceParser(html, root, missing)
        parser.feed(html.read_text(encoding="utf-8", errors="replace"))
    css_pattern = re.compile(r"url\(\s*([^\)]+?)\s*\)", re.IGNORECASE)
    for css in root.rglob("*.css"):
        for match in css_pattern.finditer(css.read_text(encoding="utf-8", errors="replace")):
            before = len(missing)
            check_local_reference(css.parent, match.group(1), root, missing)
            if len(missing) > before:
                missing[-1] = f"{css.relative_to(root)}: {missing[-1]}"
    return sorted(set(missing))


def artifact_resource_check(resources: Path) -> str:
    missing = resource_closure(resources)
    if missing:
        raise CheckFailure("unresolved packaged resources:\n  " + "\n  ".join(missing))
    return "manifest, HTML, and CSS local resource references all resolve"


def manifest_policy_check(resources: Path) -> str:
    command(["./scripts/appstore/verify.py", "--extension-root", str(resources)])
    return "Safari manifest permissions, host scope, layout, locales, symlinks, and crypto pass policy"


def release_layout_check(resources: Path) -> str:
    expected = {"_locales", "background.js", "js&css", "manifest.json", "menu"}
    actual = {path.name for path in resources.iterdir()}
    if actual != expected:
        raise CheckFailure(f"release root changed: got {sorted(actual)!r}")
    symlinks = [str(path.relative_to(resources)) for path in resources.rglob("*") if path.is_symlink()]
    if symlinks:
        raise CheckFailure("symlinks in release: " + ", ".join(symlinks))
    return "top-level release layout is exact and contains no symlinks"


def locale_check(config: dict, resources: Path) -> str:
    locale_root = resources / "_locales"
    locales = sorted(path for path in locale_root.iterdir() if path.is_dir())
    expected_count = config["expected"]["locale_count"]
    if len(locales) != expected_count:
        raise CheckFailure(f"locale count {len(locales)}, expected {expected_count}")
    for locale in locales:
        load_json(locale / "messages.json")
    return f"all {expected_count} shipped locale files parse"


def crypto_check(resources: Path) -> str:
    command(["./scripts/appstore/verify.py", "--extension-root", str(resources)])
    return "custom encryption remains absent and export declaration was checked in host metadata"


def dependency_and_tooling_check(resources: Path) -> str:
    command(["npm", "audit", "--omit=dev", "--audit-level=high"])
    forbidden = [".appstore", ".github", "scripts", "node_modules", "package.json"]
    present = [name for name in forbidden if (resources / name).exists()]
    if present:
        raise CheckFailure("publisher/build tooling shipped: " + ", ".join(present))
    return "production audit passes and publisher/build tooling is absent"


def jwt_for_app_store_connect(issuer: str, key_id: str, key_path: Path) -> str:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    except ImportError as error:
        raise CheckFailure("Python cryptography package is required for App Store status") from error

    def base64_url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    now = int(time.time())
    header = base64_url(json.dumps({"alg": "ES256", "kid": key_id, "typ": "JWT"}, separators=(",", ":")).encode())
    payload = base64_url(json.dumps({"iss": issuer, "iat": now, "exp": now + 1200, "aud": "appstoreconnect-v1"}, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    try:
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except OSError as error:
        raise CheckFailure(f"App Store Connect key is unavailable: {key_path}") from error
    der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(der_signature)
    signature = base64_url(r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big"))
    return f"{header}.{payload}.{signature}"


def app_store_request(token: str, path: str, parameters: dict[str, str]) -> dict:
    url = "https://api.appstoreconnect.apple.com" + path + "?" + parse.urlencode(parameters)
    api_request = request.Request(url, headers={"Authorization": "Bearer " + token})
    try:
        with request.urlopen(api_request, timeout=30) as response:
            return json.load(response)
    except Exception as error:
        raise CheckFailure(f"App Store Connect request failed: {error}") from error


def app_store_status_check(config: dict) -> str:
    app_store = config["app_store_connect"]
    key_path = resolve_from_root(app_store["key_path"])
    token = jwt_for_app_store_connect(
        app_store["issuer_id"], app_store["key_id"], key_path
    )
    apps = app_store_request(
        token,
        "/v1/apps",
        {"filter[bundleId]": app_store["bundle_id"], "limit": "5"},
    ).get("data", [])
    if len(apps) != 1:
        raise CheckFailure(f"expected one App Store app, found {len(apps)}")
    builds = app_store_request(
        token,
        "/v1/builds",
        {
            "filter[app]": apps[0]["id"],
            "filter[version]": config["build"],
            "include": "preReleaseVersion",
            "limit": "5",
        },
    )
    data = builds.get("data", [])
    if len(data) != 1:
        raise CheckFailure(f"expected one App Store build {config['build']}, found {len(data)}")
    item = data[0]
    attributes = item.get("attributes", {})
    included = {entry["id"]: entry for entry in builds.get("included", [])}
    relation = item.get("relationships", {}).get("preReleaseVersion", {}).get("data")
    marketing = included.get(relation.get("id"), {}).get("attributes", {}).get("version") if relation else None
    required = {
        "build": (attributes.get("version"), config["build"]),
        "marketing version": (marketing, config["release"]),
        "processing state": (attributes.get("processingState"), "VALID"),
        "expired": (attributes.get("expired"), False),
        "non-exempt encryption": (attributes.get("usesNonExemptEncryption"), False),
    }
    mismatches = [
        f"{name}: got {actual!r}, expected {expected!r}"
        for name, (actual, expected) in required.items()
        if actual != expected
    ]
    if mismatches:
        raise CheckFailure("; ".join(mismatches))
    return f"App Store build {config['release']} ({config['build']}) is VALID and unexpired"


def indexed_ids(path: Path, prefixes: set[str]) -> set[str]:
    ids = set()
    pattern = re.compile(r"^\| ([A-Z0-9]+-[A-Z0-9]+) \|")
    for line in path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match and match.group(1).split("-", 1)[0] in prefixes:
            ids.add(match.group(1))
    return ids


def required_manual_ids(config: dict) -> tuple[set[str], set[str]]:
    test_ids = indexed_ids(resolve_from_root(config["test_index"]), MANUAL_PREFIXES)
    test_ids -= AUTOMATIC_TEST_INDEX_IDS
    feature_ids = indexed_ids(
        resolve_from_root(config["feature_index"]),
        {
            "ACT", "ANL", "APP", "BLK", "CHN", "DRK", "GEN", "KEY",
            "MIX", "MNU", "NGT", "PLY", "PLS", "SET", "SRC", "THM",
        },
    )
    expected_features = config["expected"]["feature_count"]
    if len(feature_ids) != expected_features:
        raise CheckFailure(
            f"manual ledger requires {len(feature_ids)} feature IDs, expected {expected_features}"
        )
    return test_ids, feature_ids


def initialize_manual_results(config: dict, target: Path) -> str:
    test_ids, feature_ids = required_manual_ids(config)
    if target.exists():
        raise CheckFailure(f"refusing to overwrite existing manual results: {target}")
    template = {
        "target": {
            "release": config["release"],
            "build": config["build"],
            "source_commit": config["source_commit"],
        },
        "session": {
            "tester": "",
            "date": "",
            "macos": "",
            "safari": "",
            "architecture": "",
            "account_state": "",
        },
        "results": {
            identifier: {"status": "NOT_RUN", "evidence": [], "notes": ""}
            for identifier in sorted(test_ids | feature_ids)
        },
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")
    return f"wrote {target} with {len(test_ids)} manual assertions and {len(feature_ids)} features"


def manual_results_check(config: dict, override: str | None) -> str:
    test_ids, feature_ids = required_manual_ids(config)
    target = resolve_from_root(override or config["manual_results_path"])
    ledger = load_json(target)
    target_metadata = ledger.get("target", {})
    expected_metadata = {
        "release": config["release"],
        "build": config["build"],
        "source_commit": config["source_commit"],
    }
    if target_metadata != expected_metadata:
        raise CheckFailure(
            f"manual ledger target mismatch: got {target_metadata!r}, expected {expected_metadata!r}"
        )
    results = ledger.get("results", {})
    required = test_ids | feature_ids
    missing = sorted(required - set(results))
    invalid = []
    for identifier in sorted(required & set(results)):
        entry = results[identifier]
        status = entry.get("status")
        evidence = entry.get("evidence")
        notes = str(entry.get("notes", "")).strip()
        if status == "PASS" and not evidence:
            invalid.append(f"{identifier}: PASS requires evidence")
        elif status == "N/A" and not notes:
            invalid.append(f"{identifier}: N/A requires justification")
        elif status not in {"PASS", "N/A"}:
            invalid.append(f"{identifier}: status is {status!r}")
    if missing or invalid:
        details = []
        if missing:
            details.append(f"missing {len(missing)} IDs: {', '.join(missing[:20])}")
        if invalid:
            details.append(f"incomplete {len(invalid)} IDs: {', '.join(invalid[:20])}")
        raise CheckFailure("; ".join(details))
    return f"manual evidence passes for {len(test_ids)} assertions and {len(feature_ids)} features"


def print_results(results: list[Result]) -> None:
    width = max(len(result.identifier) for result in results)
    print("\nSafari full-test results")
    print("=" * 80)
    for result in results:
        print(
            f"{result.identifier:<{width}}  {result.status:<4}  "
            f"{result.duration_seconds:6.2f}s  {result.assertion}"
        )
        if result.detail:
            for line in result.detail.splitlines():
                print(f"{'':<{width}}             {line}")
    passed = sum(result.status == "PASS" for result in results)
    failed = sum(result.status == "FAIL" for result in results)
    print("-" * 80)
    print(f"PASS {passed}  FAIL {failed}")


def write_report(path: Path, config: dict, results: list[Result]) -> None:
    payload = {
        "target": {
            "release": config["release"],
            "build": config["build"],
            "source_commit": config["source_commit"],
        },
        "generated_at_epoch": int(time.time()),
        "results": [asdict(result) for result in results],
        "passed": all(result.status == "PASS" for result in results),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--artifact")
    parser.add_argument("--manual-results")
    parser.add_argument("--init-manual", type=Path)
    parser.add_argument("--automated-only", action="store_true")
    parser.add_argument("--quick", action="store_true", help="skip the full clean Safari rebuild")
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    config = load_json(arguments.config.resolve())

    if arguments.init_manual:
        try:
            print(initialize_manual_results(config, arguments.init_manual.resolve()))
        except CheckFailure as error:
            print(f"Could not initialize manual ledger: {error}", file=sys.stderr)
            return 1
        return 0

    results: list[Result] = []
    artifact, app, extension, resources = locate_artifact(config, arguments.artifact)

    run_check(results, "SRC-01", "Product source matches uploaded commit", lambda: product_source_check(config))
    run_check(results, "SRC-02", "App Store source policy passes", lambda: command(["./scripts/appstore/verify.py"]).stdout.strip())
    if not arguments.quick:
        run_check(
            results,
            "SRC-03",
            "Clean Safari build/test/audit pipeline passes",
            lambda: source_pipeline_check(config),
        )
    run_check(results, "IDX-01", "All interactive controls are indexed", lambda: inventory_check(config, "features"))
    run_check(results, "IDX-02", "All Jest assertions are indexed", lambda: inventory_check(config, "assertions"))
    run_check(results, "ART-01", "Preserved artifact digest and provenance match", lambda: github_artifact_check(config))
    run_check(results, "ART-02", "Bundle metadata matches publisher policy", lambda: artifact_metadata_check(config, app, extension))
    run_check(results, "ART-03", "Host and extension are universal binaries", lambda: architecture_check(config, app, extension))
    run_check(results, "ART-04", "Nested code signatures pass strict validation", lambda: signature_check(app, extension))
    run_check(results, "ART-05", "Hardened runtime and nested-code boundary pass", lambda: runtime_and_nested_code_check(config, app, extension))
    run_check(results, "ART-06", "Signed entitlements match reviewed baseline", lambda: entitlement_check(config, app, extension))
    run_check(results, "ART-07", "Safari manifest and permission policy pass", lambda: manifest_policy_check(resources))
    run_check(results, "ART-08", "Every packaged local resource reference resolves", lambda: artifact_resource_check(resources))
    run_check(results, "RES-01", "HTML/manifest/CSS resource closure passes", lambda: artifact_resource_check(resources))
    run_check(results, "ART-09", "Release layout and symlink boundary pass", lambda: release_layout_check(resources))
    run_check(results, "ART-10", "All shipped locales parse", lambda: locale_check(config, resources))
    run_check(results, "ART-11", "Custom encryption remains absent", lambda: crypto_check(resources))
    run_check(results, "ART-12", "Dependency and shipped-tooling boundary pass", lambda: dependency_and_tooling_check(resources))
    run_check(results, "ART-13", "Live App Store Connect build state is valid", lambda: app_store_status_check(config))

    if not arguments.automated_only:
        run_check(
            results,
            "MAN-01",
            "Every Safari/manual assertion and feature has evidence",
            lambda: manual_results_check(config, arguments.manual_results),
        )

    print_results(results)
    if arguments.report:
        write_report(arguments.report.resolve(), config, results)
        print(f"Report: {arguments.report.resolve()}")
    return 0 if all(result.status == "PASS" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
