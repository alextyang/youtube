"""Small, browser-independent foundation for the full-live harness.

Contract files are intentionally disjoint: one file owns one ``menuSource``
and its ``contracts`` object is keyed by storage key.  The exact envelope is
the value returned by :func:`contract_file_schema`.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional


CONTRACT_SCHEMA = "improvedtube.full-live-contract-file.v1"
CONTRACT_SCHEMA_VERSION = 1
ORACLE_RELATIONS = frozenset(
    {"changed_to", "equals", "not_present", "contains", "count_delta", "url_matches", "within_tolerance"}
)
RISK_LEVELS = frozenset({"safe", "account", "destructive", "permission"})
TRUSTED_GESTURE_KEYS = frozenset({"full_screen_quality", "fullscreen_return_button", "player_autofullscreen", "player_autoPip", "player_autoPip_outside"})
APPLICABILITIES = frozenset({"applicable", "not_applicable"})
MISSING = object()
JSC_PATH = Path("/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc")
CONTRACT_FIELDS = frozenset(
    {
        "featureId",
        "storageKey",
        "fixtureId",
        "route",
        "surface",
        "applicability",
        "reason",
        "setup",
        "postActivation",
        "activation",
        "beforeOracle",
        "afterOracle",
        "cleanup",
        "afterRestoration",
        "oracle",
        "prerequisites",
        "dependencyKeys",
        "dependencyValues",
        "preActivationValue",
        "accountBindingMode",
        "sideEffectKeys",
        "sideEffectState",
        "restoreScope",
        "viewportWidth",
        "sourceRefs",
        "settle",
        "risk",
        "contractVersion",
        "contractSource",
        "allowSharedStorage",
    }
)


def contract_file_schema() -> dict[str, Any]:
    """Return the exact JSON schema used by disjoint menu-source files."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": CONTRACT_SCHEMA,
        "type": "object",
        "additionalProperties": False,
        "required": ["schemaVersion", "menuSource", "contracts"],
        "properties": {
            "schemaVersion": {"const": CONTRACT_SCHEMA_VERSION},
            "menuSource": {"type": "string", "pattern": r"^menu/[^/].*\.js$"},
            "contracts": {
                "type": "object",
                "minProperties": 1,
                "propertyNames": {"pattern": r"^[A-Za-z_$][\w$-]*$"},
                "additionalProperties": {
                    "type": "object",
                    "required": ["applicability"],
                    "additionalProperties": False,
                    "properties": {
                        "featureId": {"type": "string", "minLength": 1},
                        "storageKey": {"type": "string", "minLength": 1},
                        "fixtureId": {"type": "string", "minLength": 1},
                        "route": {"type": "string", "minLength": 1},
                        "surface": {"type": "string", "minLength": 1},
                        "applicability": {"enum": sorted(APPLICABILITIES)},
                        "reason": {"type": "string"},
                        "setup": {
                            "type": "object", "additionalProperties": False, "required": ["script"],
                            "properties": {"script": {"type": "string", "minLength": 1}, "args": {"type": "array"}},
                        },
                        "postActivation": {
                            "type": "object", "additionalProperties": False, "required": ["script"],
                            "properties": {"script": {"type": "string", "minLength": 1}, "args": {"type": "array"}},
                        },
                        "activation": {
                            "oneOf": [
                                {
                                    "type": "object", "additionalProperties": False,
                                    "required": ["kind", "key", "value"],
                                    "properties": {
                                        "kind": {"const": "storage"}, "key": {"type": "string", "minLength": 1},
                                        "value": {}, "script": {"type": "string", "minLength": 1}, "args": {"type": "array"},
                                    },
                                },
                                {
                                    "type": "object", "additionalProperties": False,
                                    "required": ["kind", "key", "value", "actions"],
                                    "properties": {
                                        "kind": {"const": "storage-key"}, "key": {"type": "string", "minLength": 1},
                                        "value": {}, "script": {"type": "string", "minLength": 1}, "args": {"type": "array"},
                                        "actions": {
                                            "type": "array", "minItems": 2,
                                            "items": {
                                                "type": "object", "additionalProperties": False,
                                                "required": ["type", "value"],
                                                "properties": {"type": {"enum": ["keyDown", "keyUp"]}, "value": {"type": "string", "minLength": 1, "maxLength": 1}},
                                            },
                                        },
                                    },
                                },
                                {
                                    "type": "object", "additionalProperties": False,
                                    "required": ["kind", "key", "value", "navigationUrl", "promptAction"],
                                    "properties": {
                                        "kind": {"const": "storage-prompt"}, "key": {"type": "string", "minLength": 1},
                                        "value": {}, "script": {"type": "string", "minLength": 1}, "args": {"type": "array"},
                                        "navigationUrl": {"type": "string", "pattern": "^https://www\\.youtube\\.com/"},
                                        "promptAction": {"enum": ["accept", "dismiss"]},
                                    },
                                },
                                {
                                    "type": "object", "additionalProperties": False,
                                    "required": ["kind", "key", "value", "postFixtureId"],
                                    "properties": {
                                        "kind": {"const": "storage-redirect"}, "key": {"type": "string", "minLength": 1},
                                        "value": {}, "script": {"type": "string", "minLength": 1}, "args": {"type": "array"},
                                        "postFixtureId": {"type": "string", "minLength": 1},
                                    },
                                },
                                {
                                    "type": "object", "additionalProperties": False,
                                    "required": ["kind", "key", "value", "secondFixtureId"],
                                    "properties": {
                                        "kind": {"const": "storage-multi-window"}, "key": {"type": "string", "minLength": 1},
                                        "value": {}, "script": {"type": "string", "minLength": 1}, "args": {"type": "array"},
                                        "secondFixtureId": {"type": "string", "minLength": 1},
                                    },
                                },
                                {
                                    "type": "object", "additionalProperties": False,
                                    "required": ["kind", "key", "value", "phases"],
                                    "properties": {
                                        "kind": {"const": "storage-key-phased"}, "key": {"type": "string", "minLength": 1},
                                        "value": {}, "script": {"type": "string", "minLength": 1}, "args": {"type": "array"},
                                        "phases": {
                                            "type": "array", "minItems": 2, "maxItems": 2,
                                            "items": {
                                                "type": "object", "additionalProperties": False,
                                                "required": ["prepare", "actions", "observe"],
                                                "properties": {
                                                    "prepare": {"type": "object", "additionalProperties": False, "required": ["script"], "properties": {"script": {"type": "string", "minLength": 1}, "args": {"type": "array"}}},
                                                    "actions": {"type": "array", "minItems": 2, "items": {"type": "object", "additionalProperties": False, "required": ["type", "value"], "properties": {"type": {"enum": ["keyDown", "keyUp"]}, "value": {"type": "string", "minLength": 1, "maxLength": 1}}}},
                                                    "observe": {"type": "object", "additionalProperties": False, "required": ["script"], "properties": {"script": {"type": "string", "minLength": 1}, "args": {"type": "array"}}},
                                                },
                                            },
                                        },
                                    },
                                },
                            ]
                        },
                        "beforeOracle": {
                            "type": "object", "additionalProperties": False, "required": ["script"],
                            "properties": {"script": {"type": "string", "minLength": 1}, "args": {"type": "array"}},
                        },
                        "afterOracle": {
                            "type": "object", "additionalProperties": False, "required": ["script"],
                            "properties": {"script": {"type": "string", "minLength": 1}, "args": {"type": "array"}},
                        },
                        "cleanup": {
                            "type": "object", "additionalProperties": False, "required": ["script"],
                            "properties": {"script": {"type": "string", "minLength": 1}, "args": {"type": "array"}},
                        },
                        "afterRestoration": {
                            "type": "object", "additionalProperties": False, "required": ["script"],
                            "properties": {"script": {"type": "string", "minLength": 1}, "args": {"type": "array"}},
                        },
                        "oracle": {
                            "type": "object", "additionalProperties": False, "required": ["kind", "relation", "target"],
                            "properties": {
                                "kind": {"enum": sorted(kind.value for kind in OracleKind)},
                                "relation": {"enum": sorted(ORACLE_RELATIONS)},
                                "target": {"type": "string", "pattern": r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$"},
                                "expected": {}, "tolerance": {"type": "number", "minimum": 0},
                            },
                        },
                        "prerequisites": {"type": "array", "items": {"type": "string"}},
                        "dependencyKeys": {"type": "array", "items": {"type": "string"}},
                        "dependencyValues": {"type": "object"},
                        "preActivationValue": {},
                        "accountBindingMode": {"const": "fixture-card"},
                        "sideEffectKeys": {"type": "array", "items": {"type": "string"}},
                        "sideEffectState": {
                            "type": "object", "additionalProperties": False,
                            "properties": {
                                "localStorageKeys": {"type": "array", "items": {"type": "string", "minLength": 1}},
                                "sessionStorageKeys": {"type": "array", "items": {"type": "string", "minLength": 1}},
                                "cookieNames": {"type": "array", "items": {"type": "string", "minLength": 1}},
                            },
                        },
                        "restoreScope": {"type": "array", "items": {"type": "string"}},
                        "viewportWidth": {"type": "integer", "minimum": 320, "maximum": 8192},
                        "sourceRefs": {
                            "type": "array", "minItems": 1,
                            "items": {
                                "type": "object", "additionalProperties": False,
                                "required": ["path", "startLine", "endLine"],
                                "properties": {
                                    "path": {"type": "string", "minLength": 1},
                                    "startLine": {"type": "integer", "minimum": 1},
                                    "endLine": {"type": "integer", "minimum": 1},
                                },
                            },
                        },
                        "settle": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "timeoutMs": {"type": "number", "exclusiveMinimum": 0},
                                "pollMs": {"type": "number", "exclusiveMinimum": 0},
                            },
                        },
                        "risk": {"enum": sorted(RISK_LEVELS)},
                        "contractVersion": {"type": "integer", "minimum": 1},
                        "contractSource": {"enum": ["generated", "curated"]},
                        "allowSharedStorage": {"type": "boolean"},
                    },
                },
            },
        },
    }


@dataclass(frozen=True)
class Fixture:
    fixture_id: str
    route: str
    exact_url: str
    readiness_js: str
    content_fingerprint: str = ""
    required_selectors: tuple[str, ...] = ()
    optional_capabilities: tuple[str, ...] = ()
    cleanup_policy: str = "refresh"
    surface: str = "youtube-page"
    auth: str = "anonymous"
    version: str = "1"

    @property
    def id(self) -> str:
        return self.fixture_id

    @property
    def route_name(self) -> str:
        return self.route


def _youtube_fixture(
    fixture_id: str,
    route: str,
    url: str,
    required: tuple[str, ...],
    optional: tuple[str, ...] = (),
    auth: str = "anonymous",
) -> Fixture:
    return Fixture(
        fixture_id,
        route,
        url,
        "return {url: location.href, readyState: document.readyState, host: location.host};",
        required_selectors=required,
        optional_capabilities=optional,
        auth=auth,
    )


_FIXTURE_ROWS = (
    _youtube_fixture("watch.base", "watch", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", ("ytd-watch-flexy", "#player video"), ("captions", "comments", "chapters")),
    _youtube_fixture("watch.account", "watch", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", ("ytd-watch-flexy", "#player video"), ("captions", "comments", "chapters"), auth="dedicated_test_account"),
    _youtube_fixture("watch.captions", "watch", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", ("#player video", ".ytp-subtitles-button"), ("transcript",)),
    _youtube_fixture("watch.player", "watch", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", ("#player video",)),
    _youtube_fixture("watch.paid-promotion", "watch", "https://www.youtube.com/watch?v=f3t1d1zzu54", ("#player video", ".ytp-paid-content-overlay")),
    _youtube_fixture("watch.redirected-short", "watch", "https://www.youtube.com/watch?v=aqz-KE-bpKQ", ("#player video",)),
    _youtube_fixture("watch.education", "watch", "https://www.youtube.com/watch?v=aircAruvnKk", ("#player video",), ("captions",)),
    _youtube_fixture("watch.chapters", "watch", "https://www.youtube.com/watch?v=aircAruvnKk", ("#player video",), ("chapters", "captions")),
    _youtube_fixture("watch.lyrics", "watch", "https://www.youtube.com/watch?v=RbmS3tQJ7Os", ("#player video",), ("captions",)),
    _youtube_fixture("channel.public", "channel", "https://www.youtube.com/@YouTube", ("ytd-browse",)),
    _youtube_fixture("channel.videos", "channel", "https://www.youtube.com/@YouTube/videos", ("ytd-browse",)),
    _youtube_fixture("playlist.public", "playlist", "https://www.youtube.com/playlist?list=PLk0bA6F9VgRV1iQ-vMtRjzZAjiml5PjVm", ("ytd-browse", "ytd-playlist-video-renderer"), ("playlist-rows",)),
    _youtube_fixture("playlist.watch", "playlist", "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLk0bA6F9VgRV1iQ-vMtRjzZAjiml5PjVm", ("#player video", "ytd-playlist-panel-renderer"), ("playlist-rows",)),
    _youtube_fixture("search.improvedtube", "search", "https://www.youtube.com/results?search_query=ImprovedTube", ("ytd-search", "#voice-search-button"), ("shorts-shelf",)),
    _youtube_fixture("shorts.public", "shorts", "https://www.youtube.com/shorts/aqz-KE-bpKQ", ("video", "ytd-reel-video-renderer")),
    _youtube_fixture("comments.public", "watch", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", ("ytd-comments", "ytd-comment-thread-renderer")),
    _youtube_fixture("live.public", "watch", "https://www.youtube.com/watch?v=jfKfPfyJRdk", ("video", "ytd-live-chat-frame#chat"), auth="anonymous_read_only"),
    _youtube_fixture("embed.public", "watch", "https://www.youtube.com/embed/dQw4w9WgXcQ?controls=1&rel=0", ("video",)),
    _youtube_fixture("home.public", "watch", "https://www.youtube.com/", ("ytd-app",)),
    _youtube_fixture("subscriptions.account", "watch", "https://www.youtube.com/feed/subscriptions?it_e2e=1", ("ytd-app",), auth="dedicated_test_account"),
    _youtube_fixture("history.account", "watch", "https://www.youtube.com/feed/history?it_e2e=1", ("ytd-app",), auth="dedicated_test_account"),
    _youtube_fixture("trending.public", "watch", "https://www.youtube.com/feed/trending", ("ytd-app",)),
    _youtube_fixture("music.public", "watch", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", ("#player video",)),
    _youtube_fixture("watch_later.account", "playlist", "https://www.youtube.com/playlist?list=WL", ("ytd-playlist-panel-renderer",), auth="dedicated_test_account"),
    _youtube_fixture("liked.account", "playlist", "https://www.youtube.com/playlist?list=LL", ("ytd-playlist-panel-renderer",), auth="dedicated_test_account"),
    _youtube_fixture("library.account", "watch", "https://www.youtube.com/feed/library", ("ytd-app",), auth="dedicated_test_account"),
    _youtube_fixture("mobile.responsive", "mobile", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", ("ytd-watch-flexy", "#player video")),
    Fixture("extension.options", "extension", "safari-web-extension://<extension-id>/menu/index.html", "return {readyState: document.readyState};", surface="extension-page", auth="installed-extension"),
)
FIXTURES = {item.fixture_id: item for item in _FIXTURE_ROWS}
_FIXTURE_ALIASES = {
    "watch_public": "watch.base",
    "watch_account": "watch.account",
    "search_public": "search.improvedtube",
    "shorts_public": "shorts.public",
    "channel_public": "channel.public",
    "playlist_public": "playlist.public",
    "comments_public": "comments.public",
    "live_public": "live.public",
    "embed_public": "embed.public",
    "home_public": "home.public",
    "subscriptions_account": "subscriptions.account",
    "history_account": "history.account",
    "trending_public": "trending.public",
    "music_public": "music.public",
    "captions_chapters": "watch.captions",
    "watch_later_account": "watch_later.account",
    "liked_account": "liked.account",
    "library_account": "library.account",
    "mobile_responsive": "mobile.responsive",
}
for _alias, _canonical in _FIXTURE_ALIASES.items():
    FIXTURES[_alias] = FIXTURES[_canonical]
_ROUTE_DEFAULTS = {
    "watch": "watch.base",
    "channel": "channel.public",
    "playlist": "playlist.public",
    "search": "search.improvedtube",
    "shorts": "shorts.public",
    "mobile": "mobile.responsive",
    "extension": "extension.options",
}
ROUTE_FIXTURES = {**FIXTURES, **{route: FIXTURES[fixture_id] for route, fixture_id in _ROUTE_DEFAULTS.items()}}


def fixture_for(route: str, key: str = "") -> Optional[Fixture]:
    if key == "player_playback_speed":
        return FIXTURES["watch.player"]
    if key == "shortcut_activate_captions":
        return FIXTURES["watch.captions"]
    preferred = {
        "watch": "watch.base",
        "channel": "channel.public",
        "playlist": "playlist.public",
        "search": "search.improvedtube",
        "shorts": "shorts.public",
        "mobile": "mobile.responsive",
        "extension": "extension.options",
    }
    fixture_id = preferred.get(route)
    return FIXTURES.get(fixture_id) if fixture_id else None


def validate_fixture(fixture: Fixture | str, observed: Mapping[str, Any]) -> dict[str, Any]:
    """Return fail-closed exact URL/host/readiness evidence for a fixture."""
    item = FIXTURES[fixture] if isinstance(fixture, str) else fixture
    evidence = dict(observed) if isinstance(observed, Mapping) else {}
    errors: list[str] = []
    if item.surface == "youtube-page":
        if evidence.get("url") != item.exact_url:
            errors.append("observed URL is not the exact fixture URL")
        if evidence.get("host") != "www.youtube.com":
            errors.append("fixture host is not www.youtube.com")
        if evidence.get("protocol") != "https:":
            errors.append("fixture protocol is not HTTPS")
    else:
        extension_url = str(evidence.get("url", ""))
        if not extension_url.startswith("safari-web-extension://"):
            errors.append("extension fixture was not observed in extension context")
    ready = evidence.get("readyState", evidence.get("ready"))
    if ready != "complete":
        errors.append("fixture document is not complete")
    raw_selectors = evidence.get("selectors", MISSING)
    selectors = set(raw_selectors) if isinstance(raw_selectors, (list, tuple, set)) else set()
    if item.required_selectors and raw_selectors is MISSING:
        errors.append("required selector proof is unavailable")
    elif item.required_selectors and not selectors:
        errors.append("required selector proof is empty")
    missing = [selector for selector in item.required_selectors if selector not in selectors]
    if missing and raw_selectors is not MISSING:
        errors.extend("required selector missing: " + selector for selector in missing)
    return {"ok": not errors, "fixtureId": item.fixture_id, "requestedUrl": item.exact_url, "observed": evidence, "errors": errors}


class OracleKind(str, Enum):
    VISIBILITY = "visibility"
    PRESENCE = "presence"
    ATTRIBUTE_STYLE = "attribute_style"
    SELECTED_STATE = "selected_state"
    NUMERIC_MEDIA = "numeric_media"
    NAVIGATION = "navigation"
    KEYBOARD_INTERACTION = "keyboard_interaction"
    COLLECTION_FILTER = "collection_filter"
    SIDE_EFFECT = "side_effect"
    TEXT_COLOR = "text_color"
    PERMISSION_ARTIFACT = "permission_artifact"
    ACCOUNT_REMOTE = "account_remote"


@dataclass(frozen=True)
class OracleSpec:
    kind: OracleKind | str
    relation: str
    target: Optional[str] = None
    expected: Any = MISSING
    tolerance: Optional[float] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", OracleKind(self.kind))


@dataclass(frozen=True)
class OracleResult:
    matched: bool
    kind: str
    relation: str
    reason: str
    before: Any = None
    after: Any = None

    def __bool__(self) -> bool:
        return self.matched


def _value_at(value: Any, target: Optional[str]) -> Any:
    if target in (None, ""):
        if isinstance(value, Mapping) and "semantic" in value:
            return value["semantic"]
        return value
    current = value
    for part in target.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return MISSING
    return current


def _storage_echo(value: Any, kind: OracleKind) -> bool:
    if not isinstance(value, Mapping) or not value:
        return False
    keys = set(value)
    generic = {
        "present",
        "value",
        "storage",
        "storageState",
        "mirrorOwn",
        "storageLoaded",
        "queueDepth",
        "sent",
        "operation",
        "requested",
    }
    if not keys.issubset(generic):
        return False
    # ``present`` and ``value`` are also common semantic observation fields.
    # Permit them only for the oracle kinds whose named semantic value uses
    # those fields; a visibility oracle over ``value`` remains a storage echo.
    semantic_fields = {
        OracleKind.PRESENCE: {"present"},
        OracleKind.NUMERIC_MEDIA: {"present", "value"},
        OracleKind.SELECTED_STATE: {"present", "value"},
        OracleKind.ATTRIBUTE_STYLE: {"value"},
        OracleKind.TEXT_COLOR: {"value"},
    }.get(kind, set())
    return not keys.issubset(semantic_fields)


def dispatch_oracle(spec: OracleSpec | Mapping[str, Any] | str, before: Any, after: Any, **overrides: Any) -> OracleResult:
    """Evaluate one named semantic oracle; storage echo is never an effect."""
    if isinstance(spec, OracleSpec):
        item = spec
    elif isinstance(spec, Mapping):
        item = OracleSpec(
            spec.get("kind", "presence"),
            spec.get("relation", "changed_to"),
            spec.get("target"),
            spec["expected"] if "expected" in spec else MISSING,
            spec.get("tolerance"),
        )
    else:
        item = OracleSpec(spec, overrides.get("relation", "changed_to"), overrides.get("target"), overrides.get("expected", MISSING), overrides.get("tolerance"))
    before_value = _value_at(before, item.target)
    after_value = _value_at(after, item.target)
    if _storage_echo(before, item.kind) or _storage_echo(after, item.kind):
        return OracleResult(False, item.kind.value, item.relation, "semantic effect is not proven by generic storage echo", before_value, after_value)
    if item.relation not in ORACLE_RELATIONS:
        return OracleResult(False, item.kind.value, item.relation, "unknown oracle relation", before_value, after_value)
    expected = item.expected
    if item.relation == "changed_to":
        matched = before_value != after_value and (expected is MISSING or after_value == expected)
    elif item.relation == "equals":
        matched = expected is not MISSING and after_value == expected
    elif item.relation == "not_present":
        matched = after_value is MISSING or after_value is None or after_value is False or (isinstance(after_value, Mapping) and after_value.get("present") is False)
    elif item.relation == "contains":
        try:
            matched = expected is not MISSING and expected in after_value
        except TypeError:
            matched = False
    elif item.relation == "count_delta":
        def count(value: Any) -> Any:
            return value.get("count") if isinstance(value, Mapping) else value
        try:
            matched = expected is not MISSING and float(count(after_value)) - float(count(before_value)) == float(expected)
        except (TypeError, ValueError):
            matched = False
    elif item.relation == "url_matches":
        matched = isinstance(after_value, str) and expected is not MISSING and re.search(str(expected), after_value) is not None
    else:
        try:
            tolerance = 0.01 if item.tolerance is None else float(item.tolerance)
            matched = expected is not MISSING and abs(float(after_value) - float(expected)) <= tolerance
        except (TypeError, ValueError):
            matched = False
    return OracleResult(bool(matched), item.kind.value, item.relation, "oracle matched" if matched else "semantic expectation did not match", before_value, after_value)


def oracle_matches(spec: OracleSpec | Mapping[str, Any] | str, before: Any, after: Any, **overrides: Any) -> bool:
    return bool(dispatch_oracle(spec, before, after, **overrides))


@dataclass(frozen=True)
class StorageSnapshot:
    key: str
    present: bool
    value: Any = None
    value_type: str = "absent"
    digest: str = ""
    byte_length: int = 0

    @classmethod
    def capture(cls, key: str, present: bool, value: Any = None) -> "StorageSnapshot":
        value_type = "absent" if not present else ("null" if value is None else type(value).__name__)
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() if present else b""
        return cls(key, bool(present), value if present else None, value_type, hashlib.sha256(encoded).hexdigest() if present else "", len(encoded))

    @property
    def type(self) -> str:
        return self.value_type

    def redacted(self) -> dict[str, Any]:
        return {"present": self.present, "type": self.value_type, "digest": self.digest, "byteLength": self.byte_length}


class StorageAdapter:
    """Future direct extension-context storage seam; page mirrors do not implement it."""

    authority = "extension-context"

    def snapshot(self, keys: Optional[Iterable[str]] = None) -> Mapping[str, StorageSnapshot]:
        raise NotImplementedError("bind StorageAdapter to chrome.storage.local in extension context")

    def set(self, key: str, value: Any) -> StorageSnapshot:
        raise NotImplementedError

    def remove(self, key: str) -> StorageSnapshot:
        raise NotImplementedError

    def restore(self, snapshot: Mapping[str, StorageSnapshot]) -> Mapping[str, StorageSnapshot]:
        result: dict[str, StorageSnapshot] = {}
        for key, state in snapshot.items():
            result[key] = self.set(key, state.value) if state.present else self.remove(key)
        return result


DirectStorageAdapter = StorageAdapter


def _balanced_end(text: str, start: int) -> int:
    opener = text[start]
    closer = "]" if opener == "[" else "}"
    depth = 0
    quote = ""
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index + 1
    return len(text)


def _top_fields(body: str) -> dict[str, str]:
    start = body.find("{")
    if start < 0:
        return {}
    fields: dict[str, str] = {}
    index = start + 1
    while index < len(body):
        while index < len(body) and (body[index].isspace() or body[index] == ","):
            index += 1
        if body.startswith("//", index):
            end = body.find("\n", index)
            index = len(body) if end < 0 else end + 1
            continue
        if body.startswith("/*", index):
            end = body.find("*/", index + 2)
            index = len(body) if end < 0 else end + 2
            continue
        if index >= len(body) or body[index] == "}":
            break
        if body[index] in "'\"":
            quote = body[index]
            end = index + 1
            while end < len(body):
                if body[end] == "\\":
                    end += 2
                    continue
                if body[end] == quote:
                    break
                end += 1
            name = body[index + 1 : end]
            index = end + 1
        else:
            match = re.match(r"[A-Za-z_$][\w$-]*", body[index:])
            if not match:
                index += 1
                continue
            name = match.group(0)
            index += len(name)
        while index < len(body) and body[index].isspace():
            index += 1
        if index >= len(body) or body[index] != ":":
            continue
        index += 1
        while index < len(body) and body[index].isspace():
            index += 1
        value_start = index
        if index < len(body) and body[index] in "'\"`":
            quote = body[index]
            index += 1
            while index < len(body):
                if body[index] == "\\":
                    index += 2
                    continue
                if body[index] == quote:
                    index += 1
                    break
                index += 1
        elif index < len(body) and body[index] in "[{":
            index = _balanced_end(body, index)
        else:
            while index < len(body) and body[index] not in ",\n}":
                index += 1
        fields[name] = body[value_start:index].strip()
    return fields


def _atom(raw: Any) -> Any:
    if not isinstance(raw, str):
        return raw
    value = raw.strip().rstrip(",")
    if value in {"true", "false"}:
        return value == "true"
    if value == "null":
        return None
    if re.fullmatch(r"-?(?:\d+(?:\.\d*)?|\.\d+)", value):
        return float(value) if "." in value else int(value)
    if value[:1] in {"'", '"'} and value[-1:] == value[:1]:
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return value[1:-1]
    return value


def extract_menu_metadata(body: str, key: str, component: str, source: str = "", menu_id: Optional[str] = None) -> dict[str, Any]:
    """Normalize the small literal subset used by menu skeleton controls."""
    fields = _top_fields(body)
    storage_key = _atom(fields.get("storage", fields.get("storageKey", key)))
    menu_id = _atom(fields.get("id", menu_id or key))
    text = _atom(fields.get("text", fields.get("label", "")))
    tags_raw = _atom(fields.get("tags", ""))
    tags = tuple(part.strip() for part in str(tags_raw).split(",") if part.strip()) if tags_raw else ()
    options_raw = fields.get("options", fields.get("values", ""))
    options: list[Any] = []
    option_labels: list[str] = []
    for match in re.finditer(r"\bvalue\s*:\s*('(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\"|-?(?:\d+(?:\.\d*)?|\.\d+)|true|false|null)", options_raw):
        options.append(_atom(match.group(1)))
    for match in re.finditer(r"\btext\s*:\s*('(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\")", options_raw):
        option_labels.append(str(_atom(match.group(1))))
    default_present = "default" in fields or "value" in fields
    default = _atom(fields.get("default", fields.get("value"))) if default_present else None
    metadata: dict[str, Any] = {
        "storageKey": str(storage_key) if storage_key else key,
        "menuId": str(menu_id) if menu_id else key,
        "property": str(menu_id) if menu_id else key,
        "labels": [str(text)] if text else [],
        "tags": list(tags),
        "default": default,
        "defaultPresent": default_present,
        "options": options,
        "optionLabels": option_labels,
        "min": _atom(fields.get("min")) if "min" in fields else None,
        "max": _atom(fields.get("max")) if "max" in fields else None,
        "step": _atom(fields.get("step")) if "step" in fields else None,
        "component": component,
        "source": source,
        "rawDigest": hashlib.sha256(body.encode()).hexdigest(),
        "sourceHints": [
            "ImprovedTube." + _camelize(key),
            "extension.features." + _camelize(key),
            "it-" + key.replace("_", "-"),
        ],
        "sourceHintsStatus": "candidate",
    }
    digest_input = json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    metadata["metadataDigest"] = hashlib.sha256(digest_input).hexdigest()
    return metadata


def _camelize(value: str) -> str:
    parts = value.split("_")
    return parts[0] + "".join(part[:1].upper() + part[1:] for part in parts[1:])


@dataclass(frozen=True)
class OracleContract:
    key: str
    kind: OracleKind
    relation: str
    target: Optional[str]
    expected: Any
    tolerance: Optional[float]


@dataclass(frozen=True)
class ContractSpec:
    key: str
    menu_source: str = ""
    feature_id: str = ""
    storage_key: str = ""
    fixture_id: str = ""
    route: str = ""
    surface: str = "youtube-page"
    applicability: str = "applicable"
    setup: Any = None
    post_activation: Any = None
    activation: Any = None
    before_oracle: Any = None
    after_oracle: Any = None
    cleanup: Any = None
    after_restoration: Any = None
    oracle: Optional[OracleSpec] = None
    prerequisites: tuple[str, ...] = ()
    dependency_keys: tuple[str, ...] = ()
    dependency_values: Any = None
    pre_activation_value: Any = MISSING
    account_binding_mode: Optional[str] = None
    side_effect_keys: tuple[str, ...] = ()
    side_effect_state: Any = None
    restore_scope: tuple[str, ...] = ()
    viewport_width: Optional[int] = None
    source_refs: tuple[Any, ...] = ()
    settle: Any = None
    risk: str = "safe"
    gate_reason: Optional[str] = None
    contract_version: int = 1
    contract_source: str = "curated"
    allow_shared_storage: bool = False

    @property
    def is_not_applicable(self) -> bool:
        return self.applicability == "not_applicable"

    @property
    def activation_value(self) -> Any:
        if isinstance(self.activation, Mapping) and "value" in self.activation:
            return self.activation["value"]
        return self.activation

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        if self.pre_activation_value is MISSING:
            value.pop("pre_activation_value", None)
        if self.oracle is not None:
            value["oracle"] = asdict(self.oracle)
            value["oracle"]["kind"] = self.oracle.kind.value
            if self.oracle.expected is MISSING:
                value["oracle"].pop("expected", None)
        return value


def _oracle_from(raw: Any) -> Optional[OracleSpec]:
    if raw is None:
        return None
    if isinstance(raw, OracleSpec):
        return raw
    if isinstance(raw, str):
        return OracleSpec(raw, "changed_to")
    if not isinstance(raw, Mapping):
        return None
    return OracleSpec(raw.get("kind", "presence"), raw.get("relation", "changed_to"), raw.get("target"), raw["expected"] if "expected" in raw else MISSING, raw.get("tolerance"))


def _tuple_values(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value) if isinstance(value, (list, tuple, set)) else (str(value),)


def normalize_contract(key: str, raw: Any, menu_source: str = "", contract_source: str = "curated") -> ContractSpec:
    if isinstance(raw, ContractSpec):
        return raw
    if not isinstance(raw, Mapping):
        raise ValueError("contract " + key + " must be an object")
    applicability = str(raw.get("applicability", "applicable")).lower().replace("-", "_")
    if applicability in {"na", "n/a", "not_applicable", "notapplicable"}:
        applicability = "not_applicable"
    oracle = _oracle_from(raw.get("oracle"))
    return ContractSpec(
        key=key,
        menu_source=str(raw.get("menuSource", menu_source)),
        feature_id=str(raw.get("featureId", "")),
        storage_key=str(raw.get("storageKey", key)),
        fixture_id=str(raw.get("fixtureId", raw.get("fixture", ""))),
        route=str(raw.get("route", "")),
        surface=str(raw.get("surface", "youtube-page")),
        applicability=applicability,
        setup=raw.get("setup", raw.get("setupJs")),
        post_activation=raw.get("postActivation"),
        activation=raw.get("activation", raw.get("activationJs")),
        before_oracle=raw.get("beforeOracle", raw.get("beforeObserve")),
        after_oracle=raw.get("afterOracle", raw.get("afterObserve")),
        cleanup=raw.get("cleanup"),
        after_restoration=raw.get("afterRestoration"),
        oracle=oracle,
        prerequisites=_tuple_values(raw.get("prerequisites")),
        dependency_keys=_tuple_values(raw.get("dependencyKeys", raw.get("dependencies"))),
        dependency_values=raw.get("dependencyValues", {}),
        pre_activation_value=raw["preActivationValue"] if "preActivationValue" in raw else MISSING,
        account_binding_mode=raw.get("accountBindingMode"),
        side_effect_keys=_tuple_values(raw.get("sideEffectKeys", raw.get("sideEffects"))),
        side_effect_state=raw.get("sideEffectState", {}),
        restore_scope=_tuple_values(raw.get("restoreScope", raw.get("restore"))),
        viewport_width=raw.get("viewportWidth"),
        source_refs=tuple(raw.get("sourceRefs", ())),
        settle=raw.get("settle", raw.get("poll")),
        risk=str(raw.get("risk", "safe")),
        gate_reason=raw.get("reason", raw.get("gateReason")),
        contract_version=int(raw.get("contractVersion", 1)),
        contract_source=str(raw.get("contractSource", contract_source)),
        allow_shared_storage=bool(raw.get("allowSharedStorage", False)),
    )


def _strict_load(path: Path) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member: " + key)
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON constant " + value)))


def atomic_json_dump(path: str | Path, value: Any) -> None:
    """Write one strict JSON artifact atomically, then parse the final bytes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False, allow_nan=False, default=str)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _strict_load(path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def validate_javascript_bodies(bodies: Mapping[str, str]) -> None:
    """Parse every lifecycle body inside the same async wrapper used live."""
    if not bodies:
        return
    if not JSC_PATH.is_file():
        raise ValueError("JavaScriptCore parser is unavailable: " + str(JSC_PATH))
    payload = json.dumps([{"name": name, "script": script} for name, script in bodies.items()], ensure_ascii=False)
    program = (
        "const entries=" + payload + ";const errors=[];"
        "for(const entry of entries){try{new Function('return (async function(){\\n'+entry.script+'\\n})');}"
        "catch(error){errors.push({name:entry.name,error:String(error)});}}"
        "print('IT_JSC_RESULT='+JSON.stringify(errors));"
    )
    try:
        completed = subprocess.run([str(JSC_PATH)], input=program, text=True, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("JavaScriptCore parse validation failed to run") from exc
    marker = next((line[len("IT_JSC_RESULT="):] for line in completed.stdout.splitlines() if line.startswith("IT_JSC_RESULT=")), None)
    if completed.returncode or marker is None:
        raise ValueError("JavaScriptCore parse validation failed: " + (completed.stderr.strip() or completed.stdout.strip()))
    errors = json.loads(marker)
    if errors:
        raise ValueError("invalid executable JavaScript: " + "; ".join(item["name"] + ": " + item["error"] for item in errors))


def load_contract_file(path: str | Path) -> dict[str, ContractSpec]:
    path = Path(path)
    raw = _strict_load(path)
    if not isinstance(raw, Mapping) or raw.get("schemaVersion") != CONTRACT_SCHEMA_VERSION:
        raise ValueError(str(path) + ": schemaVersion must be 1")
    if set(raw) != {"schemaVersion", "menuSource", "contracts"}:
        raise ValueError(str(path) + ": envelope must contain only schemaVersion, menuSource, and contracts")
    source = raw.get("menuSource")
    if not isinstance(source, str) or not re.fullmatch(r"menu/[^/].*\.js", source):
        raise ValueError(str(path) + ": menuSource must be a relative menu/*.js path")
    contracts = raw.get("contracts")
    if not isinstance(contracts, Mapping) or not contracts:
        raise ValueError(str(path) + ": contracts must be a non-empty object")
    result: dict[str, ContractSpec] = {}
    javascript_bodies: dict[str, str] = {}
    for key, value in contracts.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_$][\w$-]*", key):
            raise ValueError(str(path) + ": invalid contract key")
        if not isinstance(value, Mapping):
            raise ValueError(str(path) + ": contract " + key + " must be an object")
        unknown = set(value) - CONTRACT_FIELDS
        if unknown:
            raise ValueError(str(path) + ": contract " + key + " has unknown field(s): " + ", ".join(sorted(unknown)))
        if value.get("applicability") not in APPLICABILITIES:
            raise ValueError(str(path) + ": contract " + key + " applicability must be applicable or not_applicable")
        for field_name in ("featureId", "storageKey", "fixtureId", "route", "surface", "reason", "contractSource"):
            if field_name in value and not isinstance(value[field_name], str):
                raise ValueError(str(path) + ": contract " + key + " " + field_name + " must be a string")
        for field_name in ("prerequisites", "dependencyKeys", "sideEffectKeys", "restoreScope"):
            if field_name in value and (
                not isinstance(value[field_name], list)
                or any(not isinstance(item, str) for item in value[field_name])
            ):
                raise ValueError(str(path) + ": contract " + key + " " + field_name + " must be an array of strings")
        if value.get("applicability") == "applicable":
            for field_name in ("setup", "beforeOracle", "afterOracle"):
                step = value.get(field_name)
                if (not isinstance(step, Mapping) or set(step) - {"script", "args"}
                        or not isinstance(step.get("script"), str) or not step["script"].strip()
                        or "return" not in step["script"]
                        or ("args" in step and not isinstance(step["args"], list))):
                    raise ValueError(str(path) + ": contract " + key + " " + field_name + " must be exact executable {script,args?}")
            for field_name in ("postActivation", "cleanup", "afterRestoration"):
                if field_name not in value:
                    continue
                step = value[field_name]
                if (not isinstance(step, Mapping) or set(step) - {"script", "args"}
                        or not isinstance(step.get("script"), str) or not step["script"].strip()
                        or ("args" in step and not isinstance(step["args"], list))):
                    raise ValueError(str(path) + ": contract " + key + " " + field_name + " must be exact executable {script,args?}")
            activation = value.get("activation")
            if not isinstance(activation, Mapping) or activation.get("kind") not in {"storage", "storage-key", "storage-key-phased", "storage-prompt", "storage-redirect", "storage-multi-window"}:
                raise ValueError(str(path) + ": contract " + key + " activation kind is unsupported")
            allowed_activation = {"kind", "key", "value", "script", "args", "actions", "phases", "navigationUrl", "promptAction", "postFixtureId", "secondFixtureId"}
            if set(activation) - allowed_activation or not {"kind", "key", "value"}.issubset(activation):
                raise ValueError(str(path) + ": contract " + key + " activation shape is not exact")
            if activation["key"] != value.get("storageKey", key):
                raise ValueError(str(path) + ": contract " + key + " activation key must equal storageKey")
            if "script" in activation and (not isinstance(activation["script"], str) or not activation["script"].strip()):
                raise ValueError(str(path) + ": contract " + key + " activation script must be non-empty")
            if "args" in activation and not isinstance(activation["args"], list):
                raise ValueError(str(path) + ": contract " + key + " activation args must be an array")
            actions = activation.get("actions")
            if activation["kind"] == "storage-key":
                if not isinstance(actions, list) or len(actions) < 2:
                    raise ValueError(str(path) + ": contract " + key + " storage-key activation requires actions")
                if any(not isinstance(action, Mapping) or set(action) != {"type", "value"}
                       or action["type"] not in {"keyDown", "keyUp"}
                       or not isinstance(action["value"], str) or len(action["value"]) != 1 for action in actions):
                    raise ValueError(str(path) + ": contract " + key + " key actions must be exact W3C single-code-point actions")
            elif actions is not None:
                raise ValueError(str(path) + ": contract " + key + " storage activation cannot contain actions")
            phases = activation.get("phases")
            if activation["kind"] == "storage-key-phased":
                if key != "player_autoPip_outside" or activation.get("value") is not True or not isinstance(phases, list) or len(phases) != 2:
                    raise ValueError(str(path) + ": contract " + key + " phased activation is restricted to player_autoPip_outside with exactly two phases")
                for index, phase in enumerate(phases):
                    if not isinstance(phase, Mapping) or set(phase) != {"prepare", "actions", "observe"}:
                        raise ValueError(str(path) + ": contract " + key + " phased activation phase shape is not exact")
                    for step_name in ("prepare", "observe"):
                        step = phase.get(step_name)
                        if (not isinstance(step, Mapping) or set(step) - {"script", "args"}
                                or not isinstance(step.get("script"), str) or not step["script"].strip()
                                or ("args" in step and not isinstance(step["args"], list))):
                            raise ValueError(str(path) + ": contract " + key + " phased " + step_name + " must be exact executable {script,args?}")
                        javascript_bodies[key + ".activation.phase" + str(index) + "." + step_name] = step["script"]
                    phase_actions = phase.get("actions")
                    if (not isinstance(phase_actions, list) or len(phase_actions) < 2
                            or any(not isinstance(action, Mapping) or set(action) != {"type", "value"}
                                   or action["type"] not in {"keyDown", "keyUp"}
                                   or not isinstance(action["value"], str) or len(action["value"]) != 1 for action in phase_actions)):
                        raise ValueError(str(path) + ": contract " + key + " phased actions must be exact W3C single-code-point actions")
                    downs = [action["value"] for action in phase_actions if action["type"] == "keyDown"]
                    ups = [action["value"] for action in phase_actions if action["type"] == "keyUp"]
                    if sorted(downs) != sorted(ups):
                        raise ValueError(str(path) + ": contract " + key + " phased key actions must be balanced")
            elif phases is not None:
                raise ValueError(str(path) + ": contract " + key + " phases require storage-key-phased")
            if activation["kind"] == "storage-prompt":
                if set(activation) - {"kind", "key", "value", "script", "args", "navigationUrl", "promptAction"}:
                    raise ValueError(str(path) + ": contract " + key + " storage-prompt shape is not exact")
                if (not isinstance(activation.get("navigationUrl"), str)
                        or not activation["navigationUrl"].startswith("https://www.youtube.com/")
                        or activation.get("promptAction") not in {"accept", "dismiss"}):
                    raise ValueError(str(path) + ": contract " + key + " storage-prompt requires exact YouTube navigationUrl and promptAction")
            elif "navigationUrl" in activation or "promptAction" in activation:
                raise ValueError(str(path) + ": contract " + key + " prompt fields require storage-prompt")
            if activation["kind"] == "storage-redirect":
                if set(activation) - {"kind", "key", "value", "script", "args", "postFixtureId"}:
                    raise ValueError(str(path) + ": contract " + key + " storage-redirect shape is not exact")
                source_fixture = FIXTURES.get(value.get("fixtureId"));post_fixture = FIXTURES.get(activation.get("postFixtureId"))
                if source_fixture is None or source_fixture.surface != "youtube-page" or post_fixture is None or post_fixture.surface != "youtube-page":
                    raise ValueError(str(path) + ": contract " + key + " storage-redirect requires registered YouTube source and post fixtures")
                expected_redirect={"redirect_shorts_to_watch":("shorts.public","watch.redirected-short"),"youtube_home_page":("home.public","trending.public")}.get(key)
                if expected_redirect!=(value.get("fixtureId"),activation.get("postFixtureId")):
                    raise ValueError(str(path) + ": contract " + key + " storage-redirect is restricted to the two exact reviewed redirect fixtures")
            elif "postFixtureId" in activation:
                raise ValueError(str(path) + ": contract " + key + " postFixtureId requires storage-redirect")
            if activation["kind"] == "storage-multi-window":
                source_fixture=FIXTURES.get(value.get("fixtureId"));second_fixture=FIXTURES.get(activation.get("secondFixtureId"))
                if (key!="only_one_player_instance_playing" or activation.get("value") is not True or value.get("fixtureId")!="watch.player"
                        or activation.get("secondFixtureId")!="watch.player" or source_fixture is None or source_fixture.surface!="youtube-page"
                        or second_fixture is None or second_fixture.surface!="youtube-page"):
                    raise ValueError(str(path) + ": contract " + key + " storage-multi-window is restricted to the exact two-player contract and a YouTube fixture")
            elif "secondFixtureId" in activation:
                raise ValueError(str(path) + ": contract " + key + " secondFixtureId requires storage-multi-window")
            if value.get("risk") not in RISK_LEVELS:
                raise ValueError(str(path) + ": contract " + key + " exact risk is required")
            if key in TRUSTED_GESTURE_KEYS and activation["kind"] not in {"storage-key", "storage-key-phased"}:
                raise ValueError(str(path) + ": contract " + key + " fullscreen/PiP requires trusted W3C activation")
            dependency_keys = value.get("dependencyKeys", [])
            dependency_values = value.get("dependencyValues", {})
            if not isinstance(dependency_values, Mapping) or set(dependency_values) != set(dependency_keys):
                raise ValueError(str(path) + ": contract " + key + " dependencyValues keys must exactly equal dependencyKeys")
            if len(dependency_keys) != len(set(dependency_keys)):
                raise ValueError(str(path) + ": contract " + key + " dependencyKeys must be unique")
            if value.get("storageKey", key) in dependency_keys:
                raise ValueError(str(path) + ": contract " + key + " dependencyKeys cannot contain storageKey")
            if "preActivationValue" in value and value["preActivationValue"] == activation.get("value"):
                raise ValueError(str(path) + ": contract " + key + " preActivationValue must neutralize rather than equal activation value")
            binding_mode=value.get("accountBindingMode")
            if binding_mode is not None and (binding_mode!="fixture-card" or key not in {"hide_watch_later","watch_later_buttons"}
                                             or value.get("fixtureId")!="library.account" or value.get("risk") not in {"account","destructive"}):
                raise ValueError(str(path) + ": contract " + key + " accountBindingMode fixture-card is restricted to the exact library card contracts")
            if "viewportWidth" in value and (type(value["viewportWidth"]) is not int or not 320 <= value["viewportWidth"] <= 8192):
                raise ValueError(str(path) + ": contract " + key + " viewportWidth must be an integer from 320 through 8192")
            side_effect_state = value.get("sideEffectState", {})
            if not isinstance(side_effect_state, Mapping) or set(side_effect_state) - {"localStorageKeys", "sessionStorageKeys", "cookieNames"}:
                raise ValueError(str(path) + ": contract " + key + " sideEffectState shape is not exact")
            for state_field, items in side_effect_state.items():
                if (not isinstance(items, list) or len(items) != len(set(items))
                        or any(not isinstance(item, str) or not item for item in items)):
                    raise ValueError(str(path) + ": contract " + key + " " + state_field + " must be unique non-empty strings")
            source_refs = value.get("sourceRefs")
            if not isinstance(source_refs, list) or not source_refs:
                raise ValueError(str(path) + ": contract " + key + " sourceRefs must be a non-empty array")
            root = Path(__file__).resolve().parents[2]
            for ref in source_refs:
                if not isinstance(ref, Mapping) or set(ref) != {"path", "startLine", "endLine"}:
                    raise ValueError(str(path) + ": contract " + key + " sourceRef shape is not exact")
                rel = ref.get("path")
                start, end = ref.get("startLine"), ref.get("endLine")
                if (not isinstance(rel, str) or not rel or Path(rel).is_absolute() or ".." in Path(rel).parts
                        or type(start) is not int or type(end) is not int or start < 1 or end < start):
                    raise ValueError(str(path) + ": contract " + key + " sourceRef path/range is invalid")
                source_path = root / rel
                if not source_path.is_file():
                    raise ValueError(str(path) + ": contract " + key + " sourceRef does not exist: " + rel)
                with source_path.open(encoding="utf-8", errors="replace") as handle:
                    line_count = sum(1 for _ in handle)
                if end > line_count:
                    raise ValueError(str(path) + ": contract " + key + " sourceRef exceeds file length: " + rel)
            before_script=(value.get("beforeOracle") or {}).get("script","")
            if re.search(r"(?:window\.)?__it[A-Za-z0-9_$]*",before_script) and "afterRestoration" not in value:
                raise ValueError(str(path) + ": contract " + key + " sentinel-backed beforeOracle requires explicit afterRestoration")
            for field_name in ("setup", "postActivation", "beforeOracle", "afterOracle", "cleanup", "afterRestoration"):
                step = value.get(field_name)
                if isinstance(step, Mapping) and isinstance(step.get("script"), str):
                    javascript_bodies[key + "." + field_name] = step["script"]
            if isinstance(activation.get("script"), str):
                javascript_bodies[key + ".activation"] = activation["script"]
        if "oracle" in value:
            oracle = value["oracle"]
            if isinstance(oracle, Mapping):
                if set(oracle) - {"kind", "relation", "target", "expected", "tolerance"}:
                    raise ValueError(str(path) + ": contract " + key + " oracle has unknown field(s)")
                if not {"kind", "relation", "target"}.issubset(oracle):
                    raise ValueError(str(path) + ": contract " + key + " oracle requires kind, relation, and target")
                try:
                    OracleKind(oracle["kind"])
                except ValueError as exc:
                    raise ValueError(str(path) + ": contract " + key + " oracle kind is invalid") from exc
                if oracle["relation"] not in ORACLE_RELATIONS:
                    raise ValueError(str(path) + ": contract " + key + " oracle relation is invalid")
                if "target" in oracle and not isinstance(oracle["target"], str):
                    raise ValueError(str(path) + ": contract " + key + " oracle target must be a string")
                if not re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", oracle["target"]):
                    raise ValueError(str(path) + ": contract " + key + " oracle target must be an observation field path")
                if oracle["relation"] != "not_present" and "expected" not in oracle:
                    raise ValueError(str(path) + ": contract " + key + " oracle relation requires expected")
                if oracle["relation"] == "within_tolerance" and (
                    type(oracle.get("expected")) not in {int, float}
                    or type(oracle.get("tolerance")) not in {int, float}
                ):
                    raise ValueError(str(path) + ": contract " + key + " within_tolerance requires numeric expected and tolerance")
                if "tolerance" in oracle and (type(oracle["tolerance"]) not in {int, float} or oracle["tolerance"] < 0):
                    raise ValueError(str(path) + ": contract " + key + " oracle tolerance must be non-negative")
            else:
                raise ValueError(str(path) + ": contract " + key + " oracle must be an exact object")
        if "settle" in value and not isinstance(value["settle"], Mapping):
            raise ValueError(str(path) + ": contract " + key + " settle must be an object")
        if "settle" in value:
            unknown_settle = set(value["settle"]) - {"timeoutMs", "pollMs"}
            if unknown_settle:
                raise ValueError(str(path) + ": contract " + key + " settle has unknown field(s)")
        if "risk" in value and value["risk"] not in RISK_LEVELS:
            raise ValueError(str(path) + ": contract " + key + " risk is invalid")
        if "contractSource" in value and value["contractSource"] not in {"generated", "curated"}:
            raise ValueError(str(path) + ": contract " + key + " contractSource is invalid")
        if "contractVersion" in value and (
            type(value["contractVersion"]) is not int or value["contractVersion"] < 1
        ):
            raise ValueError(str(path) + ": contract " + key + " contractVersion must be a positive integer")
        if "allowSharedStorage" in value and type(value["allowSharedStorage"]) is not bool:
            raise ValueError(str(path) + ": contract " + key + " allowSharedStorage must be boolean")
        if value.get("applicability") == "not_applicable":
            expected_na = {"storageKey", "applicability", "reason"}
            if set(value) != expected_na or not value.get("reason"):
                raise ValueError(str(path) + ": contract " + key + " not_applicable shape must be exactly storageKey, applicability, reason")
        result[key] = normalize_contract(key, value, source, "curated")
    validate_javascript_bodies(javascript_bodies)
    return result


def load_contract_files(paths: Iterable[str | Path]) -> dict[str, ContractSpec]:
    files: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        else:
            files.append(path)
    result: dict[str, ContractSpec] = {}
    sources: set[str] = set()
    for path in sorted(files):
        file_contracts = load_contract_file(path)
        source = next(iter(file_contracts.values())).menu_source
        if source in sources:
            raise ValueError("contract files must be disjoint by menuSource: " + source)
        sources.add(source)
        for key, contract in file_contracts.items():
            if key in result:
                raise ValueError("duplicate contract key across files: " + key)
            result[key] = contract
    return result


load_contracts = load_contract_files


def contract_from_feature_contract(contract: Any, feature: Any = None) -> ContractSpec:
    """Normalize the legacy five seed contracts without adding feature rules."""
    key = str(contract.key)
    route = str(contract.route)
    kind_map = {
        "css_visibility": (OracleKind.VISIBILITY, "changed_to", "visible", False),
        "dom_presence": (OracleKind.PRESENCE, "changed_to", "present", True),
        "slider_value": (OracleKind.NUMERIC_MEDIA, "within_tolerance", "value", contract.activation_value),
        "shortcut_toggle": (OracleKind.KEYBOARD_INTERACTION, "changed_to", "pressed", "true"),
        "watched_side_effect": (OracleKind.SIDE_EFFECT, "contains", "watchedPresent", True),
    }
    kind, relation, target, expected = kind_map.get(contract.observation_kind, (None, "changed_to", None, MISSING))
    oracle = OracleSpec(kind, relation, target, expected, 0.01) if kind else None
    dependencies = ("player_forced_playback_speed",) if key == "player_playback_speed" else ()
    side_effects = ("watched",) if key == "track_watched_videos" else ()
    fixture = "watch.base" if route == "watch" else "search.improvedtube"
    if key == "player_playback_speed":
        fixture = "watch.player"
    elif key == "shortcut_activate_captions":
        fixture = "watch.captions"
    storage_key = getattr(feature, "storage_key", None) or key
    source = getattr(feature, "source", "")
    return ContractSpec(
        key=key,
        menu_source=source,
        feature_id=getattr(feature, "feature_id", ""),
        storage_key=storage_key,
        fixture_id=fixture,
        route=route,
        setup={"script": contract.setup_js},
        activation={"kind": "storage", "key": storage_key, "value": contract.activation_value},
        before_oracle={"script": contract.before_observe_js},
        after_oracle={"script": contract.after_observe_js},
        cleanup={"script": "return {ok:true};"},
        oracle=oracle,
        prerequisites=tuple(contract.prerequisites),
        dependency_keys=dependencies,
        dependency_values={"player_forced_playback_speed": True} if dependencies else {},
        side_effect_keys=side_effects,
        restore_scope=(storage_key,) + dependencies + side_effects,
        settle={"timeoutMs": 5000, "pollMs": 250},
        risk="safe",
        contract_source="curated",
    )


@dataclass(frozen=True)
class FeaturePlan:
    feature_id: str
    key: str
    storage_key: str
    component: str
    source: str
    route: str
    contract: Optional[ContractSpec]
    status: str
    reason: Optional[str] = None
    metadata: Any = None

    @property
    def applicability(self) -> str:
        if self.status == "not_applicable":
            return "NOT_APPLICABLE"
        if self.status == "contracted":
            return "applicable"
        return "uncontracted"

    @property
    def complete(self) -> bool:
        return self.status in {"contracted", "not_applicable"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "featureId": self.feature_id,
            "key": self.key,
            "storageKey": self.storage_key,
            "component": self.component,
            "source": self.source,
            "route": self.route,
            "status": self.status,
            "applicability": self.applicability,
            "reason": self.reason,
            "metadata": self.metadata,
            "contract": self.contract.to_dict() if self.contract else None,
        }


def build_feature_plan(features: Iterable[Any], contracts: Mapping[str, Any]) -> list[FeaturePlan]:
    result: list[FeaturePlan] = []
    for feature in features:
        raw = contracts.get(feature.key)
        if raw is None:
            result.append(
                FeaturePlan(
                    feature.feature_id,
                    feature.key,
                    getattr(feature, "storage_key", None) or feature.key,
                    feature.component,
                    feature.source,
                    feature.route,
                    None,
                    "uncontracted",
                    "no curated contract or reviewed applicability",
                    getattr(feature, "metadata", None),
                )
            )
            continue
        contract = raw if isinstance(raw, ContractSpec) else contract_from_feature_contract(raw, feature) if hasattr(raw, "observation_kind") else normalize_contract(feature.key, raw, getattr(feature, "source", ""))
        status = "not_applicable" if contract.is_not_applicable else "contracted"
        result.append(
            FeaturePlan(
                feature.feature_id,
                feature.key,
                getattr(feature, "storage_key", None) or feature.key,
                feature.component,
                feature.source,
                feature.route,
                contract,
                status,
                contract.gate_reason,
                getattr(feature, "metadata", None),
            )
        )
    return sorted(result, key=lambda item: (item.route, item.key))


def _activation_valid(feature: Any, contract: ContractSpec) -> Optional[str]:
    activation = contract.activation
    if (not isinstance(activation, Mapping) or activation.get("kind") not in {"storage", "storage-key", "storage-key-phased", "storage-prompt", "storage-redirect", "storage-multi-window"}
            or not {"kind", "key", "value"}.issubset(activation)
            or set(activation) - {"kind", "key", "value", "script", "args", "actions", "phases", "navigationUrl", "promptAction", "postFixtureId", "secondFixtureId"}):
        return "activation must have the exact supported storage shape"
    if activation["key"] != contract.storage_key:
        return "activation key must equal storageKey"
    if "script" in activation and (not isinstance(activation["script"], str) or not activation["script"].strip()):
        return "activation script must be non-empty"
    if "args" in activation and not isinstance(activation["args"], list):
        return "activation args must be an array"
    actions = activation.get("actions")
    if activation["kind"] == "storage-key":
        if not isinstance(actions, list) or len(actions) < 2:
            return "storage-key activation requires actions"
        if any(not isinstance(action, Mapping) or set(action) != {"type", "value"}
               or action["type"] not in {"keyDown", "keyUp"}
               or not isinstance(action["value"], str) or len(action["value"]) != 1 for action in actions):
            return "key actions must be exact W3C single-code-point actions"
    elif actions is not None:
        return "storage activation cannot contain actions"
    phases=activation.get("phases")
    if activation["kind"]=="storage-key-phased":
        if contract.key!="player_autoPip_outside" or activation.get("value") is not True or not isinstance(phases,list) or len(phases)!=2:
            return "phased activation is restricted to player_autoPip_outside with exactly two phases"
        for phase in phases:
            if not isinstance(phase,Mapping) or set(phase)!={"prepare","actions","observe"}:return "phased activation phase shape is not exact"
            for step_name in ("prepare","observe"):
                step=phase.get(step_name)
                if (not isinstance(step,Mapping) or set(step)-{"script","args"} or not isinstance(step.get("script"),str)
                        or not step["script"].strip() or ("args" in step and not isinstance(step["args"],list))):return "phased lifecycle shape is not exact"
            phase_actions=phase.get("actions")
            if (not isinstance(phase_actions,list) or len(phase_actions)<2
                    or any(not isinstance(action,Mapping) or set(action)!={"type","value"} or action["type"] not in {"keyDown","keyUp"}
                           or not isinstance(action["value"],str) or len(action["value"])!=1 for action in phase_actions)):
                return "phased actions must be exact W3C single-code-point actions"
            if sorted(action["value"] for action in phase_actions if action["type"]=="keyDown")!=sorted(action["value"] for action in phase_actions if action["type"]=="keyUp"):
                return "phased key actions must be balanced"
    elif phases is not None:
        return "phases require storage-key-phased"
    if activation["kind"] == "storage-prompt":
        if (not isinstance(activation.get("navigationUrl"), str)
                or not activation["navigationUrl"].startswith("https://www.youtube.com/")
                or activation.get("promptAction") not in {"accept", "dismiss"}):
            return "storage-prompt requires an exact YouTube navigationUrl and promptAction"
    elif "navigationUrl" in activation or "promptAction" in activation:
        return "prompt fields require storage-prompt"
    if activation["kind"] == "storage-redirect":
        source_fixture=FIXTURES.get(contract.fixture_id);post_fixture=FIXTURES.get(activation.get("postFixtureId"))
        if source_fixture is None or source_fixture.surface!="youtube-page" or post_fixture is None or post_fixture.surface!="youtube-page":return "storage-redirect requires registered YouTube source and post fixtures"
        expected_redirect={"redirect_shorts_to_watch":("shorts.public","watch.redirected-short"),"youtube_home_page":("home.public","trending.public")}.get(contract.key)
        if expected_redirect!=(contract.fixture_id,activation.get("postFixtureId")):return "storage-redirect is restricted to the two exact reviewed redirect fixtures"
    elif "postFixtureId" in activation:
        return "postFixtureId requires storage-redirect"
    if activation["kind"]=="storage-multi-window":
        source_fixture=FIXTURES.get(contract.fixture_id);second_fixture=FIXTURES.get(activation.get("secondFixtureId"))
        if (contract.key!="only_one_player_instance_playing" or activation.get("value") is not True or contract.fixture_id!="watch.player"
                or activation.get("secondFixtureId")!="watch.player" or source_fixture is None or source_fixture.surface!="youtube-page"
                or second_fixture is None or second_fixture.surface!="youtube-page"):return "storage-multi-window is restricted to the exact two-player contract and fixtures"
    elif "secondFixtureId" in activation:
        return "secondFixtureId requires storage-multi-window"
    value = contract.activation_value
    component = getattr(feature, "component", "")
    options = tuple(getattr(feature, "options", ()) or ())
    if component == "switch" and not isinstance(value, bool) and not (contract.key=="undo_the_new_sidebar" and value=="true"):
        return "switch activation must be boolean"
    if component in {"select", "radio"} and options and value not in options:
        return "activation is not one of the discovered options"
    if component == "slider":
        try:
            number = float(value)
            low, high = getattr(feature, "min", None), getattr(feature, "max", None)
            if low is not None and number < float(low) or high is not None and number > float(high):
                return "slider activation is outside the discovered range"
            step = getattr(feature, "step", None)
            if step not in (None, 0):
                origin = float(low) if low is not None else 0.0
                if abs((number - origin) / float(step) - round((number - origin) / float(step))) > 1e-6:
                    return "slider activation does not match the discovered step"
        except (TypeError, ValueError):
            return "slider activation must be numeric"
    if component == "color-picker":
        if isinstance(value, str):
            if not value.strip():
                return "color activation must be a non-empty color string or channel array"
        elif isinstance(value, (list, tuple)):
            if len(value) not in {3, 4} or any(type(channel) not in {int, float} or not 0 <= float(channel) <= 255 for channel in value):
                return "color activation must have three or four numeric channels in the 0-255 range"
        else:
            return "color activation must be a color string or channel array"
    if component == "text-field" and not isinstance(value, str):
        return "text-field activation must be a string"
    if component == "shortcut" and not isinstance(value, Mapping):
        return "shortcut activation must be a key map"
    return None


def validate_plan(features: Iterable[Any], contracts: Optional[Mapping[str, Any]] = None, mode: str = "focused") -> list[str]:
    features = list(features)
    contracts = {} if contracts is None else contracts
    plans = build_feature_plan(features, contracts)
    errors: list[str] = []
    keys = [item.key for item in features]
    if len(keys) != len(set(keys)):
        errors.append("discovery contains duplicate feature keys")
    ids = [item.feature_id for item in features]
    if len(ids) != len(set(ids)):
        errors.append("discovery contains duplicate feature IDs")
    storage_keys: dict[str, FeaturePlan] = {}
    for plan in plans:
        previous = storage_keys.get(plan.storage_key)
        if previous and not (plan.contract and plan.contract.allow_shared_storage) and not (previous.contract and previous.contract.allow_shared_storage):
            errors.append(plan.key + ": duplicate storage key " + plan.storage_key)
        storage_keys[plan.storage_key] = plan
        contract = plan.contract
        if contract is None:
            if mode == "full-live":
                errors.append(plan.key + ": uncontracted actual feature; add a complete contract or reviewed NOT_APPLICABLE")
            continue
        feature = next(feature for feature in features if feature.key == plan.key)
        if contract.menu_source and contract.menu_source != plan.source:
            errors.append(plan.key + ": contract menuSource does not match discovered source")
        if contract.feature_id and contract.feature_id != plan.feature_id:
            errors.append(plan.key + ": contract featureId does not match discovery")
        if contract.storage_key and contract.storage_key != plan.storage_key:
            errors.append(plan.key + ": contract storageKey does not match discovery")
        if contract.applicability not in APPLICABILITIES:
            errors.append(plan.key + ": invalid applicability")
        if contract.is_not_applicable:
            if not contract.gate_reason or not str(contract.gate_reason).strip():
                errors.append(plan.key + ": NOT_APPLICABLE requires a reviewed reason")
            continue
        for name, value in (("setup", contract.setup), ("beforeOracle", contract.before_oracle), ("afterOracle", contract.after_oracle)):
            if (not isinstance(value, Mapping) or set(value) - {"script", "args"}
                    or not isinstance(value.get("script"), str) or not value["script"].strip()
                    or "return" not in value["script"]
                    or ("args" in value and not isinstance(value["args"], list))):
                errors.append(plan.key + ": " + name + " must be exact executable {script,args?}")
        if contract.cleanup is not None and (
            not isinstance(contract.cleanup, Mapping) or set(contract.cleanup) - {"script", "args"}
            or not isinstance(contract.cleanup.get("script"), str) or not contract.cleanup["script"].strip()
            or ("args" in contract.cleanup and not isinstance(contract.cleanup["args"], list))
        ):
            errors.append(plan.key + ": cleanup must be exact executable {script,args?}")
        for name, value in (("postActivation", contract.post_activation), ("afterRestoration", contract.after_restoration)):
            if value is not None and (not isinstance(value, Mapping) or set(value) - {"script", "args"}
                    or not isinstance(value.get("script"), str) or not value["script"].strip()
                    or ("args" in value and not isinstance(value["args"], list))):
                errors.append(plan.key + ": " + name + " must be exact executable {script,args?}")
        before_script=contract.before_oracle.get("script","") if isinstance(contract.before_oracle,Mapping) else ""
        if re.search(r"(?:window\.)?__it[A-Za-z0-9_$]*",before_script) and contract.after_restoration is None:
            errors.append(plan.key + ": sentinel-backed beforeOracle requires explicit afterRestoration")
        if contract.risk != "safe" and contract.cleanup is None:
            errors.append(plan.key + ": non-safe risk requires executable cleanup")
        if not contract.fixture_id or contract.fixture_id not in FIXTURES:
            errors.append(plan.key + ": unknown fixture")
        elif contract.route != FIXTURES[contract.fixture_id].route:
            errors.append(plan.key + ": fixture route mismatch")
        if contract.route not in {item.route for item in _FIXTURE_ROWS}:
            errors.append(plan.key + ": unknown route")
        for name, value in (("setup", contract.setup), ("activation", contract.activation), ("beforeOracle", contract.before_oracle), ("afterOracle", contract.after_oracle), ("settle", contract.settle), ("restoreScope", contract.restore_scope)):
            if value is None or value == "" or value == ():
                errors.append(plan.key + ": " + name + " is required")
        if contract.oracle is None:
            errors.append(plan.key + ": oracle is required")
        else:
            if contract.oracle.relation not in ORACLE_RELATIONS:
                errors.append(plan.key + ": invalid oracle relation")
            if contract.oracle.kind not in set(OracleKind):
                errors.append(plan.key + ": invalid oracle kind")
            if not contract.oracle.target or not re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", contract.oracle.target):
                errors.append(plan.key + ": oracle target must be an observation field path")
            if contract.oracle.relation != "not_present" and contract.oracle.expected is MISSING:
                errors.append(plan.key + ": oracle relation requires expected")
            if contract.oracle.relation == "within_tolerance" and (
                type(contract.oracle.expected) not in {int, float} or type(contract.oracle.tolerance) not in {int, float}
            ):
                errors.append(plan.key + ": within_tolerance requires numeric expected and tolerance")
        if contract.storage_key not in contract.restore_scope:
            errors.append(plan.key + ": primary storage key is outside restoreScope")
        for dependency in contract.dependency_keys + contract.side_effect_keys:
            if dependency not in contract.restore_scope:
                errors.append(plan.key + ": declared dependency is outside restoreScope: " + dependency)
        if not isinstance(contract.dependency_values, Mapping) or set(contract.dependency_values) != set(contract.dependency_keys):
            errors.append(plan.key + ": dependencyValues keys must exactly equal dependencyKeys")
        if contract.pre_activation_value is not MISSING and contract.pre_activation_value==contract.activation_value:
            errors.append(plan.key + ": preActivationValue must neutralize rather than equal activation value")
        if contract.account_binding_mode is not None and (contract.account_binding_mode!="fixture-card"
                or plan.key not in {"hide_watch_later","watch_later_buttons"} or contract.fixture_id!="library.account"
                or contract.risk not in {"account","destructive"}):
            errors.append(plan.key + ": accountBindingMode fixture-card is restricted to the exact library card contracts")
        if contract.risk not in RISK_LEVELS:
            errors.append(plan.key + ": explicit risk is required")
        if plan.key in TRUSTED_GESTURE_KEYS and isinstance(contract.activation, Mapping) and contract.activation.get("kind") not in {"storage-key", "storage-key-phased"}:
            errors.append(plan.key + ": fullscreen/PiP requires trusted W3C activation")
        if isinstance(contract.settle, Mapping):
            for name in ("timeoutMs", "pollMs"):
                try:
                    if float(contract.settle[name]) <= 0:
                        errors.append(plan.key + ": settle." + name + " must be positive")
                except (KeyError, TypeError, ValueError):
                    errors.append(plan.key + ": settle." + name + " is required")
        activation_error = _activation_valid(feature, contract)
        if activation_error:
            errors.append(plan.key + ": " + activation_error)
    for key in contracts:
        if key not in set(keys):
            errors.append("contract key not discovered: " + key)
    return errors


@dataclass(frozen=True)
class FullLivePreflight:
    ok: bool
    errors: tuple[str, ...]
    plans: tuple[FeaturePlan, ...]
    plan_digest: str
    counts: Mapping[str, int]


def preflight_full_live(features: Iterable[Any], contracts: Optional[Mapping[str, Any]] = None) -> FullLivePreflight:
    features = list(features)
    contracts = {} if contracts is None else contracts
    plans = tuple(build_feature_plan(features, contracts))
    errors = tuple(validate_plan(features, contracts, "full-live"))
    digest = hashlib.sha256(json.dumps([plan.to_dict() for plan in plans], sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    counts = {
        "discovered": len(plans),
        "contracted": sum(plan.status == "contracted" for plan in plans),
        "notApplicable": sum(plan.status == "not_applicable" for plan in plans),
        "uncontracted": sum(plan.status == "uncontracted" for plan in plans),
    }
    return FullLivePreflight(not errors, errors, plans, digest, counts)


__all__ = [
    "APPLICABILITIES", "CONTRACT_FIELDS", "CONTRACT_SCHEMA", "CONTRACT_SCHEMA_VERSION", "ContractSpec", "DirectStorageAdapter", "FIXTURES", "FeaturePlan", "Fixture", "FullLivePreflight", "OracleContract", "OracleKind", "OracleResult", "OracleSpec", "ROUTE_FIXTURES", "RISK_LEVELS", "StorageAdapter", "StorageSnapshot", "atomic_json_dump", "build_feature_plan", "contract_file_schema", "contract_from_feature_contract", "dispatch_oracle", "extract_menu_metadata", "fixture_for", "load_contract_file", "load_contract_files", "load_contracts", "normalize_contract", "oracle_matches", "preflight_full_live", "validate_fixture", "validate_plan"
]
