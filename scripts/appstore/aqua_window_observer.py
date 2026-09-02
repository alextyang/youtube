#!/usr/bin/env python3
"""One-run read-only CoreGraphics observer for the active Aqua user.

The observer has a bounded protocol: baseline, title-probe, place, claim,
observe, final. Placement is a single late-binding, nonce-scoped action. It
maps one exact target through Accessibility. It reads position/size mutability
independently, moves through AX, and may use only the fixed
Safari-Technology-Preview Apple Event fallback for a typed AXSize-not-settable
result; that fallback changes size only at the existing position. It never
activates, moves, clicks, closes, kills, or queries arbitrary processes/windows.
The socket and capability are per-run and expire at final.
"""
from __future__ import annotations
import argparse, copy, ctypes, datetime as dt, hashlib, hmac, json, math, os, plistlib, re, stat
import secrets, socket, struct, subprocess, sys, tempfile, time
from pathlib import Path
from typing import Any, Callable

STP_APP = Path("/Applications/Safari Technology Preview.app")
STP_EXECUTABLE = str(STP_APP / "Contents/MacOS/Safari Technology Preview")
STP_BUNDLE_ID = "com.apple.SafariTechnologyPreview"
STP_DESIGNATED_REQUIREMENT = 'identifier "com.apple.SafariTechnologyPreview" and anchor apple'
STP_REQUIRED_AUTHORITIES = ("Apple Code Signing Certification Authority","Apple Root CA")
AX_TRUSTED_EXPORTING_IMAGE = "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/HIServices.framework/Versions/A/HIServices"
AX_TRUSTED_RESOLVER_METHOD = "_AXUIElementGetWindow@HIServices"
AX_TRUSTED_PROVENANCE_METHOD = "dladdr-exact-sealed-system-image"
KG271U_BOUNDS = {"x": -1440, "y": -940, "right": 0, "bottom": 1620}
OPERATIONS = {"baseline", "title-probe", "place", "claim", "observe", "final"}
EMPTY_CG_BINDING_MODE = "webdriver-pid-single-window-empty-cg-title"
MAX_FRAME = 65536
CONNECTION_IDLE_TIMEOUT_SECONDS = 240
CAP_ENV = "IMPROVEDTUBE_AQUA_OBSERVER_CAPABILITY"
BOUND_KEYS = frozenset(("x", "y", "width", "height"))
IMMUTABLE_HELPER_FLAGS = getattr(stat,"UF_IMMUTABLE",2) | getattr(stat,"UF_NOUNLINK",16)

# The fallback is intentionally a fixed Apple Event script.  The application
# identity is a literal in the script, never a caller-controlled argument;
# all run-specific values arrive as typed argv values and are compared before
# any mutation.  The tab-delimited protocol contains only fixed tokens and
# canonical integers, so no title is echoed by the script or parsed as code.
DIRECT_STP_PROTOCOL = "IMPROVEDTUBE_STP_DIRECT_V1"
DIRECT_STP_APPLESCRIPT = r'''property protocolMarker : "IMPROVEDTUBE_STP_DIRECT_V1"
property fieldSeparator : ASCII character 9

on parseInteger(rawValue, labelText)
    if class of rawValue is not text or rawValue is "" then error labelText & " is malformed"
    try
        set parsedValue to rawValue as integer
    on error
        error labelText & " is malformed"
    end try
    if (parsedValue as text) is not rawValue then error labelText & " is not canonical"
    return parsedValue
end parseInteger

on exactIntegerList(rawList, labelText)
    if class of rawList is not list or count of rawList is not 4 then error labelText & " is malformed"
    repeat with rawItem in rawList
        if class of (contents of rawItem) is not integer then error labelText & " is not integral"
    end repeat
    return rawList
end exactIntegerList

on boundsMatch(rawBounds, expectedX, expectedY, expectedWidth, expectedHeight, labelText)
    set checkedBounds to my exactIntegerList(rawBounds, labelText)
    set actualLeft to item 1 of checkedBounds
    set actualTop to item 2 of checkedBounds
    set actualRight to item 3 of checkedBounds
    set actualBottom to item 4 of checkedBounds
    if actualRight - actualLeft is not expectedWidth then return false
    if actualBottom - actualTop is not expectedHeight then return false
    if actualLeft is not expectedX or actualTop is not expectedY then return false
    return true
end boundsMatch

on protocolError(reasonText, countValue)
    return protocolMarker & fieldSeparator & "ERROR" & fieldSeparator & reasonText & fieldSeparator & (countValue as text)
end protocolError

on run argv
    if count of argv is not 11 and count of argv is not 12 then error "direct STP helper requires exactly ten typed values and one title"
    set targetPID to my parseInteger(item 1 of argv, "pid")
    set targetWindowID to my parseInteger(item 2 of argv, "windowId")
    if targetPID < 1 or targetWindowID < 1 then error "process and window IDs must be positive"
    set expectedTitle to item 3 of argv
    if class of expectedTitle is not text or expectedTitle is "" then error "native title is malformed"
    set beforeX to my parseInteger(item 4 of argv, "before x")
    set beforeY to my parseInteger(item 5 of argv, "before y")
    set beforeWidth to my parseInteger(item 6 of argv, "before width")
    set beforeHeight to my parseInteger(item 7 of argv, "before height")
    set requestedX to my parseInteger(item 8 of argv, "requested x")
    set requestedY to my parseInteger(item 9 of argv, "requested y")
    set requestedWidth to my parseInteger(item 10 of argv, "requested width")
    set requestedHeight to my parseInteger(item 11 of argv, "requested height")
    if beforeWidth < 1 or beforeHeight < 1 or requestedWidth < 1 or requestedHeight < 1 then error "window dimensions must be positive"
    set operationMode to "full"
    if count of argv is 12 then set operationMode to item 12 of argv
    if operationMode is not "full" and operationMode is not "resize-only" then error "direct STP helper operation is malformed"

    tell application id "com.apple.SafariTechnologyPreview"
        set matchingWindows to {}
        set applicationWindows to every window
        repeat with candidateWindow in applicationWindows
            set rawCandidateName to name of candidateWindow
            if class of rawCandidateName is not text then error "candidate title is malformed"
            set candidateName to rawCandidateName
            set candidateBounds to bounds of candidateWindow
            if my boundsMatch(candidateBounds, beforeX, beforeY, beforeWidth, beforeHeight, "candidate bounds") then
                considering case, diacriticals
                    if candidateName is expectedTitle then set end of matchingWindows to contents of candidateWindow
                end considering
            end if
        end repeat
        if count of matchingWindows is not 1 then return my protocolError("candidate-count", count of matchingWindows)
        set targetWindow to item 1 of matchingWindows

        set appIDStatus to "UNAVAILABLE"
        set appIDValue to 0
        try
            set rawAppID to id of targetWindow
            if class of rawAppID is not integer then return my protocolError("app-window-id-malformed", 1)
            if rawAppID < 1 then return my protocolError("app-window-id-malformed", 1)
            set appIDStatus to "EXACT"
            set appIDValue to rawAppID
        on error
            set appIDStatus to "UNAVAILABLE"
            set appIDValue to 0
        end try
        if appIDStatus is "EXACT" and appIDValue is not targetWindowID then return my protocolError("app-window-id-mismatch", 1)

        if operationMode is "resize-only" then
            set targetBounds to {beforeX, beforeY, beforeX + requestedWidth, beforeY + requestedHeight}
        else
            set targetBounds to {requestedX, requestedY, requestedX + requestedWidth, requestedY + requestedHeight}
        end if
        try
            set bounds of targetWindow to targetBounds
        on error
            return my protocolError("bounds-write", 1)
        end try
        set afterBounds to bounds of targetWindow
        if operationMode is "resize-only" then
            if not my boundsMatch(afterBounds, beforeX, beforeY, requestedWidth, requestedHeight, "after bounds") then return my protocolError("bounds-readback", 1)
        else
            if not my boundsMatch(afterBounds, requestedX, requestedY, requestedWidth, requestedHeight, "after bounds") then return my protocolError("bounds-readback", 1)
        end if

        return protocolMarker & fieldSeparator & "OK" & fieldSeparator & appIDStatus & fieldSeparator & (appIDValue as text) & fieldSeparator & "1" & fieldSeparator & (beforeX as text) & fieldSeparator & (beforeY as text) & fieldSeparator & (beforeWidth as text) & fieldSeparator & (beforeHeight as text) & fieldSeparator & (requestedX as text) & fieldSeparator & (requestedY as text) & fieldSeparator & (requestedWidth as text) & fieldSeparator & (requestedHeight as text)
    end tell
end run
'''

class ObserverError(Exception):
    pass

class ProcessExitedError(ObserverError):
    """The claimed PID was unambiguously absent during an identity lookup."""
    pass

class AXNotSettableError(ObserverError):
    """The trusted AX helper mapped one target but reported a settable query of false.

    This is deliberately distinct from permission, lookup, malformed-result, and
    AX API failures.  Only this typed result is eligible for the narrow direct
    Safari Technology Preview scripting fallback.
    """
    def __init__(self, message: str, mapping: dict[str, Any]):
        super().__init__(message)
        self.mapping = copy.deepcopy(mapping)

class AXResizeNotSettableError(ObserverError):
    """The split AX helper mapped one target whose size cannot be written.

    This is narrower than the historical ``AXNotSettableError``: the helper
    must have independently read both AX settable flags, prove that position
    *is* settable, and prove that the current size differs from the requested
    size.  Only that typed result can authorize the STP-only resize fallback;
    the final move is always performed by AX.
    """
    def __init__(self, message: str, mapping: dict[str, Any]):
        super().__init__(message)
        self.mapping = copy.deepcopy(mapping)

class AXPositionIgnoredError(ObserverError):
    """AX accepted a position write, but exact readback was clamped/ignored."""
    def __init__(self, message: str, mapping: dict[str, Any]):
        super().__init__(message)
        self.mapping = copy.deepcopy(mapping)

def strict_bounds(value: Any, label: str = "bounds") -> dict[str, int]:
    if type(value) is not dict or set(value) != BOUND_KEYS:
        raise ObserverError(f"{label} must have exactly x, y, width, and height fields")
    for key in ("x", "y", "width", "height"):
        if type(value[key]) is not int:
            raise ObserverError(f"{label}.{key} must be a finite integer")
    if value["width"] <= 0 or value["height"] <= 0:
        raise ObserverError(f"{label} width and height must be positive")
    return {key: value[key] for key in ("x", "y", "width", "height")}

def strict_window_bounds(value: Any, label: str = "observed target bounds") -> dict[str, int]:
    if type(value) is not dict:
        raise ObserverError(f"{label} must be a window object")
    return strict_bounds({key: value.get(key) for key in ("x", "y", "width", "height")}, label)

def strict_title_nonce(value: Any) -> str:
    if type(value) is not str or not value or any(char.isspace() for char in value) or any(ord(char)<0x20 for char in value):
        raise ObserverError("title nonce must be a non-empty string without whitespace")
    return value

def strict_native_title(value: Any, label: str = "native title") -> str:
    """Native titles may contain localized text and spaces, but never controls."""
    if type(value) is not str or not value or "\x00" in value or any(ord(char) < 0x20 or ord(char)==0x7f for char in value):
        raise ObserverError(f"{label} must be a non-empty title without controls")
    return value

def derive_native_title_prefix(native_title: Any, nonce: Any) -> str:
    """Derive the platform decoration only from one exact terminal nonce."""
    title = strict_native_title(native_title)
    marker = strict_title_nonce(nonce)
    occurrences=sum(1 for index in range(0,len(title)-len(marker)+1)
                    if title.startswith(marker,index))
    if not title.endswith(marker) or occurrences != 1:
        raise ObserverError("native title does not contain one terminal title nonce")
    prefix = title[:-len(marker)]
    if not prefix or prefix + marker != title:
        raise ObserverError("native title decoration is ambiguous")
    return prefix

def strict_helper_json_loads(value: Any) -> Any:
    """Decode the native helper's one-line JSON without collapsing duplicates."""
    if type(value) is not str or not value or not value.endswith("\n") or value.count("\n") != 1:
        raise ObserverError("native AX helper output is malformed")
    def object_without_duplicates(pairs: list[tuple[str,Any]]) -> dict[str,Any]:
        result: dict[str,Any] = {}
        for key,item in pairs:
            if key in result:
                raise ObserverError("native AX helper output has duplicate members")
            result[key]=item
        return result
    def reject_constant(value: str) -> Any:
        raise ObserverError("native AX helper output has a non-finite value")
    try:
        return json.loads(value[:-1],object_pairs_hook=object_without_duplicates,parse_constant=reject_constant)
    except ObserverError:
        raise
    except (UnicodeDecodeError,json.JSONDecodeError,TypeError,ValueError) as exc:
        raise ObserverError("native AX helper output is malformed") from exc

SAFE_EMPTY_TITLE_AX_HELPER_ERRORS=frozenset({
    "exactly eight helper arguments, an optional operation, and an optional binding mode are required",
    "title nonce is malformed","helper binding mode is malformed","helper operation is malformed",
    "native title is malformed for binding mode","native title is malformed",
    "empty-title helper operation is forbidden","requested bounds are outside KG271U",
    "Accessibility trust is unavailable","target process identity is not exact STP",
    "CoreGraphics bounds are malformed","CoreGraphics target window mapping is not unique",
    "AX windows attribute is missing or malformed","AX window title is missing or malformed",
    "empty-CG-title AXWindowNumber is missing","empty-CG-title AX title is malformed",
    "empty-CG-title AX title contradicts WebDriver document title",
    "empty-CG-title AX geometry contradicts CoreGraphics","AXWindowNumber is duplicated",
    "AX window ID/title mapping is not unique","AXWindowNumber support is inconsistent",
    "AXWindowNumber is not positive","AXWindowNumber is not an integer","AXWindowNumber is out of range",
    "AX geometry has the wrong type","AX geometry has the wrong shape",
    "AX geometry could not be decoded","AX size is not positive",
    "empty-title inspection bounds are not exact","integer argument is empty",
    "integer argument is malformed","integer argument is not canonical","integer argument is not positive",
})
AX_ERROR_RAW_VALUES=frozenset({0,-25200,-25201,-25202,-25203,-25204,-25205,-25206,-25207,
                               -25208,-25209,-25210,-25211,-25212,-25213,-25214})

def safe_empty_title_ax_helper_error(value:Any)->bool:
    """Allow only fixed diagnostics emitted by the pinned read-only AX path."""
    if type(value) is not str or not value or len(value)>512 \
            or any(ord(char)<0x20 or ord(char)>0x7e for char in value):
        return False
    if value in SAFE_EMPTY_TITLE_AX_HELPER_ERRORS:
        return True
    status=re.fullmatch(r"AX (?:attribute unavailable: (?:AXWindows|AXTitle|AXPosition|AXSize)|window number unavailable: (?:AXWindowNumber|_AXWindowNumber)) status=(-?[0-9]+)",value)
    if status:
        raw=status.group(1);parsed=int(raw)
        return str(parsed)==raw and parsed in AX_ERROR_RAW_VALUES
    return bool(re.fullmatch(r"AX (?:position [xy]|size (?:width|height)) is (?:not a finite integer|out of range)",value))

def visible_alpha(window: Any) -> bool:
    if type(window) is not dict:
        raise ObserverError("malformed CoreGraphics window record")
    alpha=window.get("alpha",1)
    if type(alpha) is int:
        return alpha > 0
    if type(alpha) is float and math.isfinite(alpha):
        return alpha > 0
    raise ObserverError("window alpha must be a finite number")

def now() -> tuple[int, str]:
    return time.monotonic_ns(), dt.datetime.now(dt.timezone.utc).isoformat()

def bounds_inside(bounds: Any) -> bool:
    try:
        checked=strict_bounds(bounds) if type(bounds) is dict and set(bounds)==BOUND_KEYS else strict_window_bounds(bounds)
        x,y,w,h=(checked[k] for k in ("x","y","width","height"))
        return x >= KG271U_BOUNDS["x"] and y >= KG271U_BOUNDS["y"] and x+w <= KG271U_BOUNDS["right"] and y+h <= KG271U_BOUNDS["bottom"]
    except (ObserverError,KeyError,TypeError,ValueError):
        return False

def _strict_helper_digest(value: Any) -> str:
    if (type(value) is not str or len(value) != hashlib.sha256().digest_size * 2
            or any(char not in "0123456789abcdef" for char in value)):
        raise ObserverError("native AX helper digest is malformed")
    return value

def _helper_stat(fd: Any, require_protected: bool=True) -> os.stat_result:
    if type(fd) is not int or fd < 0:
        raise ObserverError("native AX helper fd is malformed")
    try:
        info=os.fstat(fd)
    except OSError as exc:
        raise ObserverError("native AX helper fd is unavailable") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or not info.st_mode & 0o111 or info.st_mode & 0o077
            or info.st_nlink != 1):
        raise ObserverError("native AX helper fd is not a private single-link executable")
    if require_protected and info.st_flags & IMMUTABLE_HELPER_FLAGS != IMMUTABLE_HELPER_FLAGS:
        raise ObserverError("native AX helper fd is not kernel-protected")
    return info

def _hash_helper_fd(fd: int) -> str:
    digest=hashlib.sha256()
    try:
        offset=os.lseek(fd,0,os.SEEK_CUR)
        os.lseek(fd,0,os.SEEK_SET)
        while True:
            chunk=os.read(fd,1024*1024)
            if not chunk: break
            digest.update(chunk)
        os.lseek(fd,offset,os.SEEK_SET)
    except OSError as exc:
        raise ObserverError("native AX helper fd cannot be hashed") from exc
    return digest.hexdigest()

def _validate_helper_fd(fd: Any, expected_digest: Any, expected_device: Any,
                        expected_inode: Any) -> os.stat_result:
    digest=_strict_helper_digest(expected_digest)
    if (type(expected_device) is not int or expected_device < 0
            or type(expected_inode) is not int or expected_inode < 1):
        raise ObserverError("native AX helper file identity is malformed")
    info=_helper_stat(fd)
    if info.st_dev != expected_device or info.st_ino != expected_inode:
        raise ObserverError("native AX helper fd identity changed or was substituted")
    if not hmac.compare_digest(_hash_helper_fd(fd),digest):
        raise ObserverError("native AX helper fd digest changed or is not pinned")
    return info

def _read_validated_helper_fd(fd: Any, expected_digest: Any, expected_device: Any,
                              expected_inode: Any) -> tuple[os.stat_result, bytes]:
    """Read and authenticate the exact helper bytes that will be loaded.

    The digest is calculated over this one read, and the loader below receives
    these bytes directly. No pathname is consulted after the descriptor is
    inherited, so a same-UID pathname swap cannot change executed code.
    """
    digest = _strict_helper_digest(expected_digest)
    before = _validate_helper_fd(fd, digest, expected_device, expected_inode)
    if before.st_size < 1 or before.st_size > 64 * 1024 * 1024:
        raise ObserverError("native AX helper size is malformed")
    try:
        offset = os.lseek(fd, 0, os.SEEK_CUR)
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise ObserverError("native AX helper fd ended unexpectedly")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except ObserverError:
        raise
    except OSError as exc:
        raise ObserverError("native AX helper fd cannot be read") from exc
    finally:
        try:
            os.lseek(fd, offset, os.SEEK_SET)
        except (OSError, UnboundLocalError):
            pass
    after = _validate_helper_fd(fd, digest, expected_device, expected_inode)
    if after.st_size != before.st_size or len(raw) != before.st_size:
        raise ObserverError("native AX helper changed while being read")
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), digest):
        raise ObserverError("native AX helper bytes are not pinned")
    return after, raw

def _call_helper_bundle(raw: bytes, argv: list[str]) -> int:
    """Call the exported helper entrypoint from an authenticated Mach-O bundle.

    macOS has no libc fexecve and rejects executing an O_RDONLY /dev/fd/N
    through fdescfs. The supported equivalent here is dyld's memory
    object-file API: bytes read from the already validated descriptor
    are loaded as an MH_BUNDLE and its fixed C ABI entrypoint is called.
    """
    if sys.platform != "darwin":
        raise ObserverError("macOS in-memory helper execution is required")
    if type(raw) is not bytes or not raw:
        raise ObserverError("native AX helper bytes are malformed")
    try:
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        create = libc.NSCreateObjectFileImageFromMemory
        create.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p)]
        create.restype = ctypes.c_int
        link = libc.NSLinkModule
        link.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
        link.restype = ctypes.c_void_p
        lookup = libc.NSLookupSymbolInModule
        lookup.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lookup.restype = ctypes.c_void_p
        address = libc.NSAddressOfSymbol
        address.argtypes = [ctypes.c_void_p]
        address.restype = ctypes.c_void_p
    except (AttributeError, OSError) as exc:
        raise ObserverError("macOS in-memory helper loader is unavailable") from exc
    buffer = ctypes.create_string_buffer(raw)
    image = ctypes.c_void_p()
    try:
        status = create(buffer, len(raw), ctypes.byref(image))
    except (OSError, TypeError) as exc:
        raise ObserverError("native AX helper image creation failed") from exc
    if type(status) is not int or status != 1 or not image.value:
        raise ObserverError("native AX helper is not a valid Mach-O bundle")
    try:
        module = link(image, b"improvedtube-aqua-ax-memory",
                      0x1 | 0x2 | 0x4)  # bind-now, private, return-on-error
    except (OSError, TypeError) as exc:
        raise ObserverError("native AX helper bundle linking failed") from exc
    if not module:
        raise ObserverError("native AX helper bundle linking failed")
    try:
        symbol = lookup(module, b"_improvedtube_ax_helper_main")
        if not symbol:
            raise ObserverError("native AX helper entrypoint is unavailable")
        entrypoint = address(symbol)
        if not entrypoint:
            raise ObserverError("native AX helper entrypoint is unavailable")
        encoded = [argument.encode("utf-8") for argument in argv]
        c_argv_type = ctypes.c_char_p * (len(encoded) + 1)
        c_argv = c_argv_type(*(encoded + [None]))
        function = ctypes.CFUNCTYPE(
            ctypes.c_int32, ctypes.c_int32,
            ctypes.POINTER(ctypes.c_char_p))(entrypoint)
        result = function(len(encoded), c_argv)
    except ObserverError:
        raise
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        raise ObserverError("native AX helper entrypoint invocation failed") from exc
    if type(result) is not int:
        raise ObserverError("native AX helper returned a malformed status")
    return result

def _run_helper_fd(fd: Any, expected_digest: Any, expected_device: Any,
                   expected_inode: Any, argv: list[str]) -> Any:
    """Execute one helper from descriptor bytes in an isolated fork.

    The child never calls execve or reopens a helper pathname. Temporary
    anonymous files capture the helper's protocol streams without allowing
    diagnostics to mix with the JSON response.
    """
    _validate_helper_fd(fd, expected_digest, expected_device, expected_inode)
    stdout_file = tempfile.TemporaryFile(mode="w+b")
    stderr_file = tempfile.TemporaryFile(mode="w+b")
    try:
        try:
            child = os.fork()
        except (AttributeError, OSError) as exc:
            raise ObserverError("isolated helper execution is unavailable") from exc
        if child == 0:
            try:
                os.dup2(stdout_file.fileno(), 1)
                os.dup2(stderr_file.fileno(), 2)
                _info, raw = _read_validated_helper_fd(
                    fd, expected_digest, expected_device, expected_inode)
                status = _call_helper_bundle(raw, argv)
                if status < 0 or status > 255:
                    os._exit(125)
                os._exit(status)
            except BaseException:
                try:
                    os.write(2, b"native AX helper fd execution failed\n")
                except BaseException:
                    pass
                os._exit(125)
        while True:
            try:
                _pid, wait_status = os.waitpid(child, 0)
                break
            except InterruptedError:
                continue
        returncode = os.waitstatus_to_exitcode(wait_status)
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read()
        stderr = stderr_file.read()
        if len(stdout) > MAX_FRAME or len(stderr) > MAX_FRAME:
            raise ObserverError("native AX helper output is too large")
        try:
            stdout_text = stdout.decode("utf-8")
            stderr_text = stderr.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ObserverError("native AX helper output is not UTF-8") from exc
        return type("HelperResult", (), {
            "returncode": returncode, "stdout": stdout_text, "stderr": stderr_text})()
    finally:
        stdout_file.close()
        stderr_file.close()

def _open_helper_path(value: Any) -> tuple[int,str,int,int]:
    """Open a diagnostic helper once; production receives an inherited fd."""
    if type(value) is not str and not isinstance(value,Path):
        raise ObserverError("native AX helper path is required")
    path=Path(value)
    nofollow=getattr(os,"O_NOFOLLOW",0)
    if not nofollow:
        raise ObserverError("native AX helper requires O_NOFOLLOW")
    flags=os.O_RDONLY | nofollow | getattr(os,"O_CLOEXEC",0)
    try:
        fd=os.open(path,flags)
    except OSError as exc:
        raise ObserverError("native AX helper path cannot be opened safely") from exc
    try:
        info=_helper_stat(fd,require_protected=False);digest=_hash_helper_fd(fd)
        try:os.chflags(path,IMMUTABLE_HELPER_FLAGS)
        except OSError as exc:raise ObserverError("native AX helper cannot be kernel-protected") from exc
        info=_helper_stat(fd)
        os.set_inheritable(fd,False)
        return fd,digest,int(info.st_dev),int(info.st_ino)
    except Exception:
        try:os.close(fd)
        except OSError:pass
        raise

def _clear_helper_flags_if_same_path(path: Path, expected_device: Any, expected_inode: Any) -> None:
    try:
        info=os.lstat(path)
        if info.st_dev == expected_device and info.st_ino == expected_inode:
            os.chflags(path,0)
    except OSError:
        pass

def _parse_ax_not_settable_mapping(payload: dict[str,Any], pid: int, window_id: int,
                                    nonce: str, native_title: str,
                                    expected_before_bounds: dict[str,int]) -> dict[str,Any]:
    """Validate the AX mapping attached to a typed settable=false result."""
    expected={"ok","method","errorCode","error","attribute","status","helperUid",
              "pid","windowId","axWindowNumber","titleNonce","nativeTitle","mappingMethod",
              "cgBefore","candidateCount","matchedCount","candidates","before"}
    if set(payload) != expected:
        raise ObserverError("native AX not-settable mapping response is malformed")
    if (payload.get("ok") is not False or payload.get("method") != "application-services-ax"
            or type(payload.get("helperUid")) is not int or payload.get("helperUid") != os.getuid()
            or type(payload.get("attribute")) is not str or payload.get("attribute") not in {"AXPosition","AXSize"}
            or type(payload.get("status")) is not int or payload.get("status") != 0
            or type(payload.get("error")) is not str
            or payload.get("error") != f"AX attribute is not settable: {payload.get('attribute')} status=0"
            or payload.get("errorCode") != "not-settable"
            or type(payload.get("pid")) is not int or payload.get("pid") != pid
            or type(payload.get("windowId")) is not int or payload.get("windowId") != window_id
            or type(payload.get("titleNonce")) is not str or payload.get("titleNonce") != nonce
            or type(payload.get("nativeTitle")) is not str or payload.get("nativeTitle") != native_title):
        raise ObserverError("native AX not-settable identity evidence is not exact")
    mapping_method=payload.get("mappingMethod")
    if mapping_method not in {"ax-window-number","title-geometry"}:
        raise ObserverError("native AX not-settable mapping method is not exact")
    ax_number=payload.get("axWindowNumber")
    if ax_number is not None and (type(ax_number) is not int or ax_number < 1):
        raise ObserverError("native AX not-settable AXWindowNumber is malformed")
    if mapping_method == "ax-window-number" and ax_number != window_id:
        raise ObserverError("native AX not-settable AXWindowNumber is not exact")
    if mapping_method == "title-geometry" and ax_number is not None:
        raise ObserverError("native AX not-settable title-geometry mapping has an AX number")
    before=strict_bounds(payload.get("before"),"native AX not-settable before bounds")
    cg_before=strict_bounds(payload.get("cgBefore"),"native AX not-settable CoreGraphics before bounds")
    expected_before=strict_bounds(expected_before_bounds,"expected CoreGraphics before bounds")
    if before != cg_before or before != expected_before:
        raise ObserverError("native AX not-settable before bounds do not match target")
    candidate_count=payload.get("candidateCount");matched_count=payload.get("matchedCount")
    candidates=payload.get("candidates")
    if (type(candidate_count) is not int or candidate_count < 1
            or type(matched_count) is not int or matched_count != 1
            or type(candidates) is not list or len(candidates) != candidate_count):
        raise ObserverError("native AX not-settable candidate evidence is malformed")
    seen:set[int]=set();matches=[];normalized=[]
    for candidate in candidates:
        if type(candidate) is not dict or set(candidate) != {"pid","windowId","axWindowNumber","title","bounds"}:
            raise ObserverError("native AX not-settable candidate evidence is malformed")
        number=candidate.get("axWindowNumber")
        if number is not None:
            if type(number) is not int or number < 1 or number in seen:
                raise ObserverError("native AX not-settable AXWindowNumber is malformed or duplicated")
            seen.add(number)
        if (type(candidate.get("pid")) is not int or candidate.get("pid") != pid
                or type(candidate.get("windowId")) is not int or candidate.get("windowId") != window_id
                or type(candidate.get("title")) is not str or candidate.get("title") != native_title):
            raise ObserverError("native AX not-settable candidate identity is not exact")
        candidate_bounds=strict_bounds(candidate.get("bounds"),"native AX not-settable candidate bounds")
        item=copy.deepcopy(candidate);item["bounds"]=candidate_bounds;normalized.append(item)
        if candidate_bounds == before and (mapping_method == "title-geometry" or number == window_id):
            matches.append(item)
    if mapping_method == "ax-window-number" and any(item.get("axWindowNumber") is None for item in normalized):
        raise ObserverError("native AX not-settable AXWindowNumber support is inconsistent")
    if mapping_method == "title-geometry" and any(item.get("axWindowNumber") is not None for item in normalized):
        raise ObserverError("native AX not-settable AXWindowNumber support is inconsistent")
    if len(matches) != 1:
        raise ObserverError("native AX not-settable target mapping is not unique")
    return {"verified":True,"pid":pid,"windowId":window_id,"axWindowNumber":ax_number,
            "title":native_title,"mappingMethod":mapping_method,"before":before,
            "cgBefore":cg_before,"candidateCount":candidate_count,"matchedCount":matched_count,
            "candidates":normalized,"titleNonce":nonce,"nativeTitle":native_title,
            "helperUid":payload["helperUid"],"method":payload["method"]}

def _strict_position(value: Any, label: str) -> dict[str,int]:
    if type(value) is not dict or set(value) != {"x", "y"}:
        raise ObserverError(f"{label} must have exactly x and y fields")
    if type(value["x"]) is not int or type(value["y"]) is not int:
        raise ObserverError(f"{label} must contain finite integers")
    return {"x":value["x"], "y":value["y"]}

def _strict_size(value: Any, label: str) -> dict[str,int]:
    if type(value) is not dict or set(value) != {"width", "height"}:
        raise ObserverError(f"{label} must have exactly width and height fields")
    if type(value["width"]) is not int or type(value["height"]) is not int:
        raise ObserverError(f"{label} must contain finite integers")
    if value["width"] <= 0 or value["height"] <= 0:
        raise ObserverError(f"{label} must be positive")
    return {"width":value["width"], "height":value["height"]}

def _strict_cgevent_point(value: Any, label: str) -> dict[str,int]:
    """Decode a CGEvent point as two finite integer JSON primitives."""
    return _strict_position(value, label)

_CGEVENT_BUTTON_NAMES = frozenset(str(index) for index in range(32))

def _strict_quiescent_button_state(value: Any, label: str) -> dict[str,bool]:
    """Require a complete, typed, all-up standard mouse-button snapshot."""
    if type(value) is not dict or set(value) != _CGEVENT_BUTTON_NAMES:
        raise ObserverError(f"{label} is incomplete or has unknown buttons")
    if any(type(value[name]) is not bool for name in _CGEVENT_BUTTON_NAMES):
        raise ObserverError(f"{label} contains a malformed button state")
    if any(value[name] is not False for name in _CGEVENT_BUTTON_NAMES):
        raise ObserverError(f"{label} is not quiescent")
    return {name:False for name in sorted(_CGEVENT_BUTTON_NAMES)}

def _cgevent_point_inside(point: dict[str,int], bounds: dict[str,int]) -> bool:
    return (bounds["x"] <= point["x"] < bounds["x"] + bounds["width"]
            and bounds["y"] <= point["y"] < bounds["y"] + bounds["height"])

def _cgevent_candidate_points(before: dict[str,int]) -> list[dict[str,int]]:
    """Return the bounded, deterministic title-bar hit-test candidates.

    The production source of truth is the native AX hit test.  Keeping the
    candidate construction here lets the response parser prove that the
    helper did not invent an arbitrary caller-controlled point.
    """
    before = strict_bounds(before,"CGEvent candidate bounds")
    if before["width"] < 260 or before["height"] < 40:
        raise ObserverError("CGEvent target is too small for a safe title-bar point")
    offsets = (220, before["width"] // 2, before["width"] - 220)
    points: list[dict[str,int]] = []
    for offset in offsets:
        point = {"x":before["x"] + offset, "y":before["y"] + 18}
        if point not in points:
            points.append(point)
    return points

_NONINTERACTIVE_AX_PAIRS = frozenset((
    ("AXWindow", "AXStandardWindow"),
    ("AXGroup", "AXTitleBar"),
))
_INTERACTIVE_AX_ACTIONS = frozenset((
    "AXPress", "AXShowMenu", "AXConfirm", "AXCancel", "AXPick",
    "AXIncrement", "AXDecrement", "AXRaise", "AXOpen", "AXClose",
))
_AX_RECEIVERS = ("system-wide", "application")
_AX_SOURCE_METHODS = frozenset(("system-wide", "application", "descendant-frame", "injected"))
_AX_ANCESTRY_METHODS = frozenset((
    "kAXWindowAttribute", "kAXTopLevelUIElement", "top-level-AXWindow",
    "top-level-parent-chain", "top-level-target-descendant",
    "system-wide-native-window-id", "self-AXWindow", "parent-chain", "injected"))
_AX_UNAVAILABLE_STATUSES = frozenset((-25205, -25212))
_NATIVE_WINDOW_BINDING_KEYS = frozenset((
    "version", "candidateIndex", "receiver", "hitPid", "hitRole", "hitSubrole",
    "hitActions", "hitEnabled", "hitMatchedTarget",
    "nativeWindowIDMethod", "nativeWindowIDStatus", "nativeWindowID",
    "targetNativeWindowIDStatus", "targetNativeWindowID",
    "topLevelNativeWindowIDStatus", "topLevelNativeWindowID", "hitWindowStatus",
    "nativeWindowIDProvenanceMethod", "nativeWindowIDProvenanceImage",
    "nativeWindowIDProvenanceExpectedImage", "nativeWindowIDProvenanceVerified",
    "nativeWindowIDProvenanceBasePresent", "nativeWindowIDProvenanceHandlePresent",
    "topLevelStatus", "topLevelType",
    "topLevelPid", "topLevelRole", "topLevelSubrole", "topLevelActions",
    "topLevelEnabled", "topLevelMatchedTarget", "topLevelWindowStatus",
    "topLevelParentStatus", "targetChildrenStatus", "targetType", "targetPid",
    "targetRole", "targetSubrole", "targetMatched"))

def _parse_ax_receiver_outcomes(value: Any, candidate_count: int,
                                source_method: str, chosen_index: int) -> list[dict[str,Any]]:
    """Validate the native receiver/API outcome chain before accepting AX proof."""
    if type(value) is not list or not value:
        raise ObserverError("CGEvent AX receiver outcomes are malformed")
    if (type(source_method) is not str or source_method not in _AX_SOURCE_METHODS
            or type(chosen_index) is not int
            or isinstance(chosen_index,bool) or not 0 <= chosen_index < candidate_count):
        raise ObserverError("CGEvent AX receiver binding is malformed")
    normalized=[];seen=set();last_index=-1;last_receiver_index=-1;hit_count=0
    for item in value:
        if type(item) is not dict or set(item) != {"candidateIndex","receiver","result","status"}:
            raise ObserverError("CGEvent AX receiver outcome is malformed")
        index=item.get("candidateIndex");receiver=item.get("receiver")
        result=item.get("result");status=item.get("status")
        if type(index) is not int or isinstance(index,bool) or not 0 <= index < candidate_count:
            raise ObserverError("CGEvent AX receiver outcome candidate is malformed")
        if type(receiver) is not str or receiver not in (*_AX_RECEIVERS,"injected"):
            raise ObserverError("CGEvent AX receiver name is malformed")
        if type(result) is not str or result not in {"hit","unavailable"}:
            raise ObserverError("CGEvent AX receiver outcome result is malformed")
        if type(status) is not int or isinstance(status,bool):
            raise ObserverError("CGEvent AX receiver outcome status is malformed")
        if result == "hit":
            if status != 0: raise ObserverError("CGEvent AX hit outcome status is not success")
            hit_count += 1
        elif status >= 0:
            raise ObserverError("CGEvent AX unavailable outcome status is not a failure")
        key=(index,receiver)
        if key in seen: raise ObserverError("CGEvent AX receiver outcome is duplicated")
        seen.add(key)
        if index < last_index: raise ObserverError("CGEvent AX receiver outcomes are out of order")
        receiver_index=0 if receiver == "system-wide" else 1 if receiver == "application" else 0
        if index == last_index and receiver_index < last_receiver_index:
            raise ObserverError("CGEvent AX receiver outcome receiver order is malformed")
        last_index=index;last_receiver_index=receiver_index
        normalized.append({"candidateIndex":index,"receiver":receiver,
                           "result":result,"status":status})
    grouped={i:[] for i in range(candidate_count)}
    for item in normalized: grouped[item["candidateIndex"]].append(item)
    chosen_group=grouped[chosen_index]
    if source_method == "descendant-frame":
        # Descendant acceptance is computed inside the authenticated helper,
        # but the wire transcript intentionally carries only direct receiver
        # failures, not a per-candidate descendant selection log.  The native
        # fallback therefore examines the first deterministic point only;
        # reject a later declared point rather than allowing an earlier or
        # later descendant hit to be concealed by the incomplete transcript.
        if chosen_index != 0:
            raise ObserverError("CGEvent descendant fallback chosen candidate is not first")
        if any(len(grouped[i]) != len(_AX_RECEIVERS) for i in grouped):
            raise ObserverError("CGEvent descendant fallback lacks complete receiver failures")
        for i in grouped:
            if [item["receiver"] for item in grouped[i]] != list(_AX_RECEIVERS):
                raise ObserverError("CGEvent descendant fallback receiver order is malformed")
            if any(item["result"] != "unavailable" for item in grouped[i]):
                raise ObserverError("CGEvent descendant fallback followed a successful hit")
        if hit_count: raise ObserverError("CGEvent descendant fallback has a successful hit")
        if ([item["receiver"] for item in chosen_group] != list(_AX_RECEIVERS)
                or any(item["result"] != "unavailable" for item in chosen_group)):
            raise ObserverError("CGEvent descendant fallback chosen point is not fully unavailable")
    elif source_method == "injected":
        if len(normalized) != candidate_count or any(
                len(grouped[i]) != 1 or grouped[i][0]["receiver"] != "injected"
                or grouped[i][0]["result"] != "hit" or grouped[i][0]["status"] != 0
                for i in grouped):
            raise ObserverError("CGEvent injected receiver outcomes are not exact")
        # The injectable backend models one deterministic native traversal;
        # its first successful candidate is the only canonical choice.  Keep
        # the seam subject to the same selection rule so a test-only callback
        # cannot authorize an index that production would never select.
        if chosen_index != 0:
            raise ObserverError("CGEvent injected chosen candidate is not first")
        if (len(chosen_group) != 1 or chosen_group[0]["receiver"] != "injected"
                or chosen_group[0]["result"] != "hit" or chosen_group[0]["status"] != 0):
            raise ObserverError("CGEvent injected receiver does not match chosen point")
    else:
        if hit_count == 0:
            raise ObserverError("CGEvent AX receiver outcomes contain no successful hit")
        if any(len(grouped[i]) > len(_AX_RECEIVERS) for i in grouped):
            raise ObserverError("CGEvent AX receiver outcomes are too numerous")
        for i in grouped:
            group=grouped[i]
            names=[item["receiver"] for item in group]
            if names == ["system-wide"]:
                if group[0]["result"] != "hit":
                    raise ObserverError("CGEvent AX receiver outcome is incomplete")
            elif names == ["system-wide","application"]:
                if group[0]["result"] != "unavailable":
                    raise ObserverError("CGEvent AX application retry was not gated by API failure")
            else:
                raise ObserverError("CGEvent AX receiver outcome sequence is malformed")
        # The native helper walks candidate points in order and must select
        # the first point with any successful receiver.  A later candidate is
        # therefore valid only when every earlier point has a complete,
        # all-receivers-unavailable transcript.  Do not infer this from the
        # chosen hit alone: an earlier hit would make the evidence a
        # non-canonical selection (and could hide an overlay/decoy).
        for prior_index in range(chosen_index):
            prior_group=grouped[prior_index]
            if ([item["receiver"] for item in prior_group]
                    != list(_AX_RECEIVERS)
                    or any(item["result"] != "unavailable"
                           or item["status"] >= 0 for item in prior_group)):
                raise ObserverError(
                    "CGEvent AX chosen candidate has an earlier receiver hit")
        chosen_names=[item["receiver"] for item in chosen_group]
        if source_method == "system-wide":
            if (chosen_names != ["system-wide"] or chosen_group[0]["result"] != "hit"
                    or chosen_group[0]["status"] != 0):
                raise ObserverError("CGEvent system-wide receiver does not match chosen point")
        elif source_method == "application":
            if (chosen_names != ["system-wide","application"]
                    or chosen_group[0]["result"] != "unavailable"
                    or chosen_group[0]["status"] >= 0
                    or chosen_group[1]["result"] != "hit"
                    or chosen_group[1]["status"] != 0):
                raise ObserverError("CGEvent application receiver does not match chosen point")
    return normalized

def _parse_native_window_receiver_outcomes(value: Any) -> list[dict[str,Any]]:
    """The native window-ID route stops after its one system-wide hit."""
    if type(value) is not list or len(value) != 1:
        raise ObserverError("CGEvent native window-ID receiver transcript is malformed")
    item=value[0]
    if type(item) is not dict or set(item) != {"candidateIndex","receiver","result","status"}:
        raise ObserverError("CGEvent native window-ID receiver outcome is malformed")
    if (type(item.get("candidateIndex")) is not int or isinstance(item["candidateIndex"],bool)
            or item["candidateIndex"] != 0 or item.get("receiver") != "system-wide"
            or item.get("result") != "hit" or type(item.get("status")) is not int
            or isinstance(item["status"],bool) or item["status"] != 0):
        raise ObserverError("CGEvent native window-ID receiver outcome is not exact")
    return [{"candidateIndex":0,"receiver":"system-wide","result":"hit","status":0}]

def _parse_native_window_binding(value: Any, *, hit: dict[str,Any], pid: int,
                                 window_id: int, candidate_index: int,
                                 source_method: str,
                                 ancestor_method: str) -> dict[str,Any]:
    """Validate exact native AX-to-CoreGraphics window-ID binding evidence."""
    if type(value) is not dict or set(value) != _NATIVE_WINDOW_BINDING_KEYS:
        raise ObserverError("CGEvent native window-ID binding transcript is malformed")
    if (value.get("version") != "system-wide-native-window-id-v1"
            or type(value.get("candidateIndex")) is not int
            or isinstance(value.get("candidateIndex"),bool)
            or value.get("candidateIndex") != 0
            or candidate_index != 0
            or value.get("receiver") != "system-wide"
            or source_method != "system-wide"
            or ancestor_method != "system-wide-native-window-id"):
        raise ObserverError("CGEvent native window-ID binding is not production candidate zero")
    if (type(value.get("hitPid")) is not int or value["hitPid"] != pid
            or value.get("hitRole") != hit.get("role")
            or value.get("hitSubrole") != hit.get("subrole")
            or value.get("hitActions") != hit.get("actions")
            or value.get("hitEnabled") is not hit.get("enabled")):
        raise ObserverError("CGEvent native window-ID hit evidence is not bound")
    if type(value.get("hitRole")) is not str or type(value.get("hitSubrole")) is not str:
        raise ObserverError("CGEvent native window-ID hit role evidence is malformed")
    if type(value.get("hitActions")) is not list or value["hitActions"] != []:
        raise ObserverError("CGEvent native window-ID hit actions are not inert")
    if value.get("hitEnabled") is not True:
        raise ObserverError("CGEvent native window-ID hit is not enabled")
    hit_pair=(value.get("hitRole"),value.get("hitSubrole"))
    if hit_pair == ("AXWindow","AXStandardWindow"):
        if value.get("hitMatchedTarget") is not True:
            raise ObserverError("CGEvent native window-ID hit window is not the exact target")
    elif hit_pair == ("AXGroup","AXTitleBar"):
        if value.get("hitMatchedTarget") is not False:
            raise ObserverError("CGEvent native window-ID non-window hit identity is malformed")
    else:
        raise ObserverError("CGEvent native window-ID hit role is unsafe")
    if (value.get("nativeWindowIDMethod") != AX_TRUSTED_RESOLVER_METHOD
            or type(value.get("nativeWindowIDStatus")) is not int
            or isinstance(value.get("nativeWindowIDStatus"),bool)
            or value.get("nativeWindowIDStatus") != 0
            or type(value.get("nativeWindowID")) is not int
            or isinstance(value.get("nativeWindowID"),bool)
            or value.get("nativeWindowID") != window_id
            or type(value.get("targetNativeWindowIDStatus")) is not int
            or isinstance(value.get("targetNativeWindowIDStatus"),bool)
            or value.get("targetNativeWindowIDStatus") != 0
            or type(value.get("targetNativeWindowID")) is not int
            or isinstance(value.get("targetNativeWindowID"),bool)
            or value.get("targetNativeWindowID") != window_id
            or type(value.get("topLevelNativeWindowIDStatus")) is not int
            or isinstance(value.get("topLevelNativeWindowIDStatus"),bool)
            or value.get("topLevelNativeWindowIDStatus") != 0
            or type(value.get("topLevelNativeWindowID")) is not int
            or isinstance(value.get("topLevelNativeWindowID"),bool)
            or value.get("topLevelNativeWindowID") != window_id):
        raise ObserverError("CGEvent native window-ID relation is unavailable, malformed, or mismatched")
    if (value.get("nativeWindowIDProvenanceMethod") != AX_TRUSTED_PROVENANCE_METHOD
            or type(value.get("nativeWindowIDProvenanceImage")) is not str
            or value.get("nativeWindowIDProvenanceImage") != AX_TRUSTED_EXPORTING_IMAGE
            or type(value.get("nativeWindowIDProvenanceExpectedImage")) is not str
            or value.get("nativeWindowIDProvenanceExpectedImage") != AX_TRUSTED_EXPORTING_IMAGE
            or value.get("nativeWindowIDProvenanceVerified") is not True
            or value.get("nativeWindowIDProvenanceBasePresent") is not True
            or value.get("nativeWindowIDProvenanceHandlePresent") is not True):
        raise ObserverError("CGEvent native window-ID resolver provenance is not exact")
    for key in ("hitWindowStatus", "topLevelWindowStatus", "topLevelParentStatus",
                "targetChildrenStatus"):
        status=value.get(key)
        if type(status) is not int or isinstance(status,bool) or status not in _AX_UNAVAILABLE_STATUSES:
            raise ObserverError("CGEvent native window-ID binding has an unsafe AX unavailable status")
    if (type(value.get("topLevelStatus")) is not int
            or isinstance(value.get("topLevelStatus"),bool)
            or value.get("topLevelStatus") != 0
            or value.get("topLevelType") != "AXUIElement"
            or type(value.get("topLevelPid")) is not int
            or value["topLevelPid"] != pid
            or value.get("topLevelMatchedTarget") is not False):
        raise ObserverError("CGEvent native window-ID top-level evidence is not exact")
    top_level_pair=(value.get("topLevelRole"),value.get("topLevelSubrole"))
    if top_level_pair != ("AXGroup","AXTitleBar"):
        raise ObserverError("CGEvent native window-ID top-level role is not an inert non-window pair")
    if (type(value.get("topLevelActions")) is not list
            or value.get("topLevelActions") != []
            or value.get("topLevelEnabled") is not True):
        raise ObserverError("CGEvent native window-ID top-level object is interactive")
    if (value.get("targetType") != "AXUIElement"
            or type(value.get("targetPid")) is not int or value["targetPid"] != pid
            or value.get("targetRole") != "AXWindow"
            or value.get("targetSubrole") != "AXStandardWindow"
            or value.get("targetMatched") is not True):
        raise ObserverError("CGEvent native window-ID target evidence is not exact")
    return copy.deepcopy(value)

def _same_native_window_binding_evidence(lhs: dict[str,Any], rhs: dict[str,Any]) -> bool:
    """Compare pre/post native hit evidence by its exact SPI window binding.

    AX hover can change the inert descendant object while the pointer remains
    over one window.  The trusted native window-ID relation is the explicit
    canonical identity for that route; roles/actions/enabled are still
    revalidated independently by `_parse_ax_hit_evidence`.
    """
    native_method="system-wide-native-window-id"
    lhs_method=lhs.get("ancestorMethod");rhs_method=rhs.get("ancestorMethod")
    if native_method not in {lhs_method,rhs_method}:
        return lhs == rhs
    if lhs_method != native_method or rhs_method != native_method:
        return False
    lhs_binding=lhs.get("nativeWindowBinding");rhs_binding=rhs.get("nativeWindowBinding")
    if type(lhs_binding) is not dict or type(rhs_binding) is not dict:
        return False
    safe_pairs={("AXGroup","AXTitleBar"),("AXWindow","AXStandardWindow")}
    for binding in (lhs_binding,rhs_binding):
        if ((binding.get("hitRole"),binding.get("hitSubrole")) not in safe_pairs
                or (binding.get("topLevelRole"),binding.get("topLevelSubrole"))
                   != ("AXGroup","AXTitleBar")
                or binding.get("hitActions") != []
                or binding.get("topLevelActions") != []
                or binding.get("hitEnabled") is not True
                or binding.get("topLevelEnabled") is not True):
            return False
    stable_binding_keys=(
        "version","candidateIndex","receiver","hitPid",
        "nativeWindowIDMethod","nativeWindowIDStatus","nativeWindowID",
        "targetNativeWindowIDStatus","targetNativeWindowID",
        "topLevelNativeWindowIDStatus","topLevelNativeWindowID","hitWindowStatus",
        "nativeWindowIDProvenanceMethod","nativeWindowIDProvenanceImage",
        "nativeWindowIDProvenanceExpectedImage","nativeWindowIDProvenanceVerified",
        "nativeWindowIDProvenanceBasePresent","nativeWindowIDProvenanceHandlePresent",
        "topLevelStatus","topLevelType","topLevelPid","topLevelMatchedTarget",
        "topLevelWindowStatus","topLevelParentStatus","targetChildrenStatus",
        "targetType","targetPid","targetRole","targetSubrole","targetMatched")
    stable_outer_keys=("candidatePoints","candidateIndex","chosenPoint","pid",
        "ancestorPid","ancestorRole","ancestorSubrole","ancestorMethod",
        "targetWindowMatched","targetAxWindowNumber","mappingMethod","sourceMethod",
        "receiverOutcomes")
    return ({key:lhs_binding.get(key) for key in stable_binding_keys}
            == {key:rhs_binding.get(key) for key in stable_binding_keys}
            and {key:lhs.get(key) for key in stable_outer_keys}
            == {key:rhs.get(key) for key in stable_outer_keys})

def _parse_cgevent_topmost_snapshot(value: Any, *, pid: int, window_id: int,
                                    native_title: str, source: dict[str,int],
                                    before: dict[str,int], label: str) -> dict[str,Any]:
    """Validate one complete front-to-back CG target/topmost snapshot."""
    expected_keys={"targetPid","targetWindowId","targetTitle","sourcePoint",
                   "targetBounds","targetIndex","eligibleCount","overlayAbove",
                   "eligibleRecords"}
    if type(value) is not dict or set(value) != expected_keys:
        raise ObserverError(f"CGEvent {label} topmost proof is malformed")
    if (type(value.get("targetPid")) is not int or value["targetPid"] != pid
            or type(value.get("targetWindowId")) is not int
            or value["targetWindowId"] != window_id
            or type(value.get("targetTitle")) is not str
            or value["targetTitle"] != native_title
            or _strict_cgevent_point(value.get("sourcePoint"),
                                     f"CGEvent {label} proof source point") != source
            or strict_bounds(value.get("targetBounds"),
                             f"CGEvent {label} proof target bounds") != before
            or type(value.get("targetIndex")) is not int
            or value["targetIndex"] != 0
            or type(value.get("eligibleCount")) is not int
            or value["eligibleCount"] < 1
            or type(value.get("overlayAbove")) is not int
            or value["overlayAbove"] != 0):
        raise ObserverError(f"CGEvent {label} topmost target proof is not exact")
    records=value.get("eligibleRecords")
    if type(records) is not list or len(records) != value["eligibleCount"]:
        raise ObserverError(f"CGEvent {label} topmost eligible-record evidence is malformed")
    record_keys={"index","cgIndex","layer","alpha","owner","pid","windowId","title","bounds"}
    normalized=[];target_record_count=0;previous_cg_index=-1
    for expected_index, record in enumerate(records):
        if type(record) is not dict or set(record) != record_keys:
            raise ObserverError(f"CGEvent {label} topmost eligible record is malformed")
        if type(record.get("index")) is not int or record["index"] != expected_index:
            raise ObserverError(f"CGEvent {label} topmost eligible-record order is malformed")
        if (type(record.get("cgIndex")) is not int
                or record["cgIndex"] < 0
                or record["cgIndex"] <= previous_cg_index):
            raise ObserverError(f"CGEvent {label} topmost CoreGraphics order is malformed")
        previous_cg_index=record["cgIndex"]
        if type(record.get("layer")) is not int:
            raise ObserverError(f"CGEvent {label} topmost layer is malformed")
        if (type(record.get("alpha")) not in {int,float}
                or isinstance(record["alpha"],bool)
                or not math.isfinite(float(record["alpha"]))
                or record["alpha"] <= 0):
            raise ObserverError(f"CGEvent {label} topmost alpha is malformed")
        rec_bounds=strict_bounds(record.get("bounds"),f"CGEvent {label} record bounds")
        if not _cgevent_point_inside(source,rec_bounds):
            raise ObserverError(f"CGEvent {label} record does not cover the exact source point")
        for key, expected_type in (("owner",str),("title",str)):
            if record.get(key) is not None and type(record.get(key)) is not expected_type:
                raise ObserverError(f"CGEvent {label} record identity is malformed")
        for key in ("pid","windowId"):
            if record.get(key) is not None and type(record.get(key)) is not int:
                raise ObserverError(f"CGEvent {label} record identity is malformed")
        if (record.get("owner") == "Safari Technology Preview"
                and record.get("pid") == pid
                and record.get("windowId") == window_id
                and record.get("title") == native_title
                and rec_bounds == before):
            target_record_count += 1
        normalized.append({"index":record["index"],"cgIndex":record["cgIndex"],
                           "layer":record["layer"],"alpha":record["alpha"],
                           "owner":record.get("owner"),"pid":record.get("pid"),
                           "windowId":record.get("windowId"),"title":record.get("title"),
                           "bounds":rec_bounds})
    if (target_record_count != 1
            or normalized[0]["owner"] != "Safari Technology Preview"
            or normalized[0]["pid"] != pid
            or normalized[0]["windowId"] != window_id
            or normalized[0]["title"] != native_title
            or normalized[0]["bounds"] != before):
        raise ObserverError(f"CGEvent {label} topmost eligible record is not the exact first target")
    return {**copy.deepcopy(value),"eligibleRecords":normalized}

def _parse_ax_hit_evidence(value: Any, before: dict[str,int], pid: int,
                           window_id: int|None = None,
                           *, source: dict[str,int]|None = None,
                           allow_injected: bool = False) -> dict[str,Any]:
    """Validate native AX title-bar hit-test evidence before any event post."""
    if type(allow_injected) is not bool:
        raise ObserverError("CGEvent AX parsing context is malformed")
    expected = {"candidatePoints","candidateIndex","chosenPoint","role","subrole",
                "actions","enabled","pid","ancestorPid","ancestorRole",
                "ancestorSubrole","ancestorMethod","targetWindowMatched","targetAxWindowNumber",
                "mappingMethod","sourceMethod","receiverOutcomes"}
    actual_keys=set(value) if type(value) is dict else None
    if type(value) is not dict or (actual_keys != expected and actual_keys != expected | {"nativeWindowBinding"}):
        raise ObserverError("CGEvent AX hit-test evidence is malformed")
    candidates = value.get("candidatePoints")
    expected_candidates = _cgevent_candidate_points(before)
    if type(candidates) is not list or len(candidates) != len(expected_candidates):
        raise ObserverError("CGEvent AX candidate point set is malformed")
    normalized_candidates = [_strict_cgevent_point(item,"CGEvent AX candidate point")
                             for item in candidates]
    if normalized_candidates != expected_candidates:
        raise ObserverError("CGEvent AX candidate points are not deterministic")
    candidate_index=value.get("candidateIndex")
    if type(candidate_index) is not int or isinstance(candidate_index,bool) or not 0 <= candidate_index < len(candidates):
        raise ObserverError("CGEvent AX candidate index is malformed")
    chosen = _strict_cgevent_point(value.get("chosenPoint"),"CGEvent AX chosen point")
    if chosen != normalized_candidates[candidate_index]:
        raise ObserverError("CGEvent AX chosen point is not a candidate")
    if source is not None and chosen != source:
        raise ObserverError("CGEvent AX chosen point does not match source")
    source_pair=(value.get("role"),value.get("subrole"))
    if source_pair not in _NONINTERACTIVE_AX_PAIRS:
        raise ObserverError("CGEvent AX source role/subrole pair is not allowlisted title-bar chrome")
    actions = value.get("actions")
    if type(actions) is not list or any(type(action) is not str for action in actions):
        raise ObserverError("CGEvent AX source actions are malformed")
    # No action is needed for inert title-bar chrome.  Rejecting even an
    # unfamiliar action avoids treating a future/unknown Accessibility action
    # as safe by accident; known interactive actions are retained for clear
    # diagnostics in the native implementation.
    if actions or any(action in _INTERACTIVE_AX_ACTIONS for action in actions):
        raise ObserverError("CGEvent AX source exposes an interactive or unknown action")
    if value.get("enabled") is not True:
        raise ObserverError("CGEvent AX source is not enabled")
    if type(value.get("pid")) is not int or value["pid"] != pid:
        raise ObserverError("CGEvent AX source PID is not exact")
    if type(value.get("ancestorPid")) is not int or value["ancestorPid"] != pid:
        raise ObserverError("CGEvent AX source ancestor PID is not exact")
    ancestor_role=value.get("ancestorRole")
    ancestor_subrole=value.get("ancestorSubrole")
    if ancestor_role != "AXWindow" or ancestor_subrole != "AXStandardWindow":
        raise ObserverError("CGEvent AX source window ancestry is not exact")
    ancestor_method=value.get("ancestorMethod")
    if type(ancestor_method) is not str or ancestor_method not in _AX_ANCESTRY_METHODS:
        raise ObserverError("CGEvent AX source ancestry method is malformed")
    mapping_method=value.get("mappingMethod")
    source_method=value.get("sourceMethod")
    if type(source_method) is not str or source_method not in _AX_SOURCE_METHODS:
        raise ObserverError("CGEvent AX source method is malformed")
    # Native production evidence and the explicit unit-test seam are
    # disjoint proof domains.  In particular, opting into the seam must not
    # make a native-looking transcript acceptable, because that would turn a
    # parser test hook into a release attribution path.
    if allow_injected:
        if source_method != "injected" or ancestor_method != "injected":
            raise ObserverError(
                "CGEvent AX injected proof is not an explicit test context: "
                "injected mode is exclusive")
    elif source_method == "injected" or ancestor_method == "injected":
        raise ObserverError("CGEvent injected proof is not an explicit test context")
    if source_method == "descendant-frame" and ancestor_method == "self-AXWindow":
        raise ObserverError("CGEvent descendant source cannot be its target window")
    if ancestor_method == "self-AXWindow" and source_pair != ("AXWindow","AXStandardWindow"):
        raise ObserverError("CGEvent self-window ancestry does not match source role")
    if ancestor_method == "parent-chain" and source_pair != ("AXGroup","AXTitleBar"):
        raise ObserverError("CGEvent parent-chain ancestry does not match source role")
    if source_method == "injected" and mapping_method != "ax-window-number":
        raise ObserverError("CGEvent injected proof requires exact window-number mapping")
    if value.get("targetWindowMatched") is not True:
        raise ObserverError("CGEvent AX source is not bound to the target AX window")
    native_window_binding=None
    if ancestor_method == "system-wide-native-window-id":
        if "nativeWindowBinding" not in value:
            raise ObserverError("CGEvent native window-ID binding transcript is missing")
        native_window_binding=_parse_native_window_binding(
            value["nativeWindowBinding"], hit=value, pid=pid,
            window_id=window_id if window_id is not None else -1,
            candidate_index=candidate_index, source_method=source_method,
            ancestor_method=ancestor_method)
    elif "nativeWindowBinding" in value:
        raise ObserverError("CGEvent native window-ID binding is only valid for its canonical ancestry method")
    target_number=value.get("targetAxWindowNumber")
    if mapping_method == "ax-window-number":
        if window_id is None or type(target_number) is not int or target_number != window_id:
            raise ObserverError("CGEvent AX target window number is not exact")
    elif mapping_method == "title-geometry":
        if target_number is not None:
            raise ObserverError("CGEvent title-geometry mapping carries an AX number")
    else:
        raise ObserverError("CGEvent AX mapping method is malformed")
    if ancestor_method == "system-wide-native-window-id":
        receiver_outcomes=_parse_native_window_receiver_outcomes(value.get("receiverOutcomes"))
    else:
        receiver_outcomes=_parse_ax_receiver_outcomes(value.get("receiverOutcomes"),
                                                      len(expected_candidates),source_method,
                                                      candidate_index)
    return {"candidatePoints":copy.deepcopy(normalized_candidates),
            "candidateIndex":candidate_index,"chosenPoint":chosen,
            "role":value["role"],"subrole":value["subrole"],
            "actions":list(actions),"enabled":True,"pid":pid,
            "ancestorPid":pid,"ancestorRole":ancestor_role,
            "ancestorSubrole":ancestor_subrole,"ancestorMethod":ancestor_method,
            "targetWindowMatched":True,
            "targetAxWindowNumber":target_number,"mappingMethod":mapping_method,
            "sourceMethod":source_method,"receiverOutcomes":receiver_outcomes,
            **({"nativeWindowBinding":native_window_binding}
               if ancestor_method == "system-wide-native-window-id" else {})}

def _parse_cgevent_evidence(payload: dict[str,Any], pid: int, window_id: int,
                            native_title: str, requested: dict[str,int],
                            before: dict[str,int], after: dict[str,int],
                            intermediate: dict[str,int], *, allow_injected: bool = False) -> dict[str,Any]:
    """Validate the one-shot title-bar drag evidence returned by Swift."""
    source=_strict_cgevent_point(payload.get("sourcePoint"),"CGEvent source point")
    destination=_strict_cgevent_point(payload.get("destinationPoint"),"CGEvent destination point")
    delta=_strict_cgevent_point(payload.get("delta"),"CGEvent drag delta")
    ax_hit=_parse_ax_hit_evidence(payload.get("axHitTest"),before,pid,window_id,
                                  source=source,allow_injected=allow_injected)
    expected_delta={"x":requested["x"]-before["x"],"y":requested["y"]-before["y"]}
    if delta != expected_delta:
        raise ObserverError("CGEvent drag delta is not the exact requested top-left delta")
    if destination != {"x":source["x"]+delta["x"],"y":source["y"]+delta["y"]}:
        raise ObserverError("CGEvent destination does not match source plus exact delta")
    _cgevent_candidate_points(before)
    if destination != {"x":source["x"]+delta["x"],"y":source["y"]+delta["y"]}:
        raise ObserverError("CGEvent destination is not the exact requested title-bar delta")
    if payload.get("safePoint") is not True:
        raise ObserverError("CGEvent safe-point proof is not exact")
    top=payload.get("topmostProof")
    if type(top) is not dict or set(top) != {"targetPid","targetWindowId","targetTitle",
            "sourcePoint","targetBounds","targetIndex","eligibleCount","overlayAbove",
            "eligibleRecords"}:
        raise ObserverError("CGEvent topmost proof is malformed")
    if (type(top.get("targetPid")) is not int or top["targetPid"] != pid
            or type(top.get("targetWindowId")) is not int or top["targetWindowId"] != window_id
            or type(top.get("targetTitle")) is not str or top["targetTitle"] != native_title
            or _strict_cgevent_point(top.get("sourcePoint"),"CGEvent proof source point") != source
            or strict_bounds(top.get("targetBounds"),"CGEvent proof target bounds") != before
            or type(top.get("targetIndex")) is not int or top["targetIndex"] != 0
            or type(top.get("eligibleCount")) is not int or top["eligibleCount"] < 1
            or type(top.get("overlayAbove")) is not int or top["overlayAbove"] != 0):
        raise ObserverError("CGEvent topmost target proof is not exact")
    records=top.get("eligibleRecords")
    if type(records) is not list or len(records) != top["eligibleCount"]:
        raise ObserverError("CGEvent topmost eligible-record evidence is malformed")
    record_keys={"index","cgIndex","layer","alpha","owner","pid","windowId","title","bounds"}
    normalized_records=[]
    target_record_count=0
    previous_cg_index=-1
    for expected_index, record in enumerate(records):
        if type(record) is not dict or set(record) != record_keys:
            raise ObserverError("CGEvent topmost eligible record is malformed")
        if type(record.get("index")) is not int or record["index"] != expected_index:
            raise ObserverError("CGEvent topmost eligible-record order is malformed")
        if type(record.get("cgIndex")) is not int or record["cgIndex"] < 0:
            raise ObserverError("CGEvent topmost CoreGraphics index is malformed")
        if record["cgIndex"] <= previous_cg_index:
            raise ObserverError("CGEvent topmost CoreGraphics order is malformed")
        previous_cg_index=record["cgIndex"]
        if type(record.get("layer")) is not int:
            raise ObserverError("CGEvent topmost layer is malformed")
        if type(record.get("alpha")) not in {int,float} or isinstance(record["alpha"],bool) or not math.isfinite(float(record["alpha"])) or record["alpha"] <= 0:
            raise ObserverError("CGEvent topmost alpha is malformed")
        rec_bounds=strict_bounds(record.get("bounds"),"CGEvent topmost record bounds")
        if not _cgevent_point_inside(source, rec_bounds):
            raise ObserverError("CGEvent topmost record does not cover the exact source point")
        for key, expected_type in (("owner",str),("title",str)):
            if record.get(key) is not None and type(record.get(key)) is not expected_type:
                raise ObserverError("CGEvent topmost record identity is malformed")
        for key in ("pid","windowId"):
            if record.get(key) is not None and type(record.get(key)) is not int:
                raise ObserverError("CGEvent topmost record identity is malformed")
        if (record.get("owner") == "Safari Technology Preview" and record.get("pid") == pid
                and record.get("windowId") == window_id and record.get("title") == native_title
                and rec_bounds == before):
            target_record_count += 1
        normalized_records.append({"index":record["index"],"cgIndex":record["cgIndex"],"layer":record["layer"],
                                   "alpha":record["alpha"],"owner":record.get("owner"),
                                   "pid":record.get("pid"),"windowId":record.get("windowId"),
                                   "title":record.get("title"),"bounds":rec_bounds})
    if target_record_count != 1 or normalized_records[0]["owner"] != "Safari Technology Preview" \
            or normalized_records[0]["pid"] != pid or normalized_records[0]["windowId"] != window_id \
            or normalized_records[0]["title"] != native_title or normalized_records[0]["bounds"] != before:
        raise ObserverError("CGEvent topmost eligible record is not the exact first target")
    button_before_warp=_strict_quiescent_button_state(
        payload.get("buttonStateBeforeWarp"),"CGEvent button state before warp")
    pre_bounds=strict_bounds(payload.get("preMouseDownBounds"),
                              "CGEvent pre-mouse-down bounds")
    if pre_bounds != before:
        raise ObserverError("CGEvent pre-mouse-down target bounds are not exact")
    pre_top=_parse_cgevent_topmost_snapshot(
        payload.get("preMouseDownTopmostProof"),pid=pid,window_id=window_id,
        native_title=native_title,source=source,before=before,label="pre-mouse-down")
    pre_ax=_parse_ax_hit_evidence(payload.get("preMouseDownAXHitTest"),before,pid,window_id,
                                  source=source,allow_injected=allow_injected)
    if not _same_native_window_binding_evidence(ax_hit, pre_ax):
        raise ObserverError("CGEvent AX source reattestation is not bound to the same native window")
    button_before_down=_strict_quiescent_button_state(
        payload.get("buttonStateBeforeMouseDown"),"CGEvent button state before mouse-down")
    if payload.get("inputReattested") is not True:
        raise ObserverError("CGEvent input reattestation is not exact")
    cursor_before=_strict_cgevent_point(payload.get("cursorBefore"),"CGEvent cursor before")
    cursor_after=_strict_cgevent_point(payload.get("cursorAfter"),"CGEvent cursor after")
    if payload.get("cursorRestored") is not True or cursor_after != cursor_before:
        raise ObserverError("CGEvent cursor restoration proof is not exact")
    if (type(payload.get("cleanupUpAttempted")) is not bool
            or type(payload.get("cleanupUpSucceeded")) is not bool
            or type(payload.get("leftMouseUpConfirmed")) is not bool
            or payload.get("leftMouseUpConfirmed") is not True):
        raise ObserverError("CGEvent mouse-up cleanup evidence is malformed")
    cleanup_point=payload.get("cleanupUpPoint")
    if payload["cleanupUpAttempted"]:
        cleanup_point=_strict_cgevent_point(cleanup_point,"CGEvent cleanup up point")
        if not payload["cleanupUpSucceeded"]:
            raise ObserverError("CGEvent compensating mouse-up did not succeed")
    elif cleanup_point is not None or payload["cleanupUpSucceeded"]:
        raise ObserverError("CGEvent unused cleanup evidence is inconsistent")
    sequence=payload.get("eventSequence")
    if (type(sequence) is not list or len(sequence) != 26
            or sequence[0] != "leftMouseDown" or sequence[-1] != "leftMouseUp"
            or any(item != "leftMouseDragged" for item in sequence[1:-1])
            or type(payload.get("eventCount")) is not int or payload["eventCount"] != 26
            or type(payload.get("dragSteps")) is not int or payload["dragSteps"] != 24):
        raise ObserverError("CGEvent sequence evidence is not exact")
    if intermediate != before or after != requested:
        raise ObserverError("CGEvent intermediate/final geometry is not exact")
    post_bounds=strict_bounds(payload.get("postBounds"),"CGEvent post bounds")
    if post_bounds != requested:
        raise ObserverError("CGEvent post CoreGraphics bounds are not exact")
    return {"sourcePoint":source,"destinationPoint":destination,"delta":delta,
            "safePoint":True,"axHitTest":ax_hit,"topmostProof":{
                **copy.deepcopy(top),"eligibleRecords":normalized_records},
            "buttonStateBeforeWarp":button_before_warp,
            "buttonStateBeforeMouseDown":button_before_down,
            "preMouseDownBounds":pre_bounds,
            "preMouseDownTopmostProof":pre_top,
            "preMouseDownAXHitTest":pre_ax,
            "inputReattested":True,
            "cursorBefore":cursor_before,"cursorAfter":cursor_after,
            "cursorRestored":True,"eventSequence":list(sequence),"eventCount":26,
            "dragSteps":24,"postBounds":post_bounds,
            "cleanupUpAttempted":payload.get("cleanupUpAttempted"),
            "cleanupUpSucceeded":payload.get("cleanupUpSucceeded"),
            "cleanupUpPoint":cleanup_point,
            "leftMouseUpConfirmed":payload.get("leftMouseUpConfirmed")}

def _build_cgevent_backend_proof(records: list[dict[str,Any]], *, source: dict[str,int],
                                 before: dict[str,int], pid: int, window_id: int,
                                 native_title: str, label: str) -> dict[str,Any]:
    """Validate a complete injected CG z-order snapshot at one source point."""
    if type(records) is not list:
        raise ObserverError(f"CGEvent backend {label} z-order records are malformed")
    eligible=[];target_indexes=[]
    for index, record in enumerate(records):
        if type(record) is not dict:
            raise ObserverError(f"CGEvent backend {label} z-order record is malformed")
        if type(record.get("layer")) is not int or isinstance(record.get("layer"),bool):
            raise ObserverError(f"CGEvent backend {label} z-order layer is malformed")
        if (type(record.get("alpha")) not in {int,float}
                or isinstance(record.get("alpha"),bool)
                or not math.isfinite(float(record["alpha"]))):
            raise ObserverError(f"CGEvent backend {label} z-order alpha is malformed")
        if record["alpha"] <= 0:
            continue
        record_bounds=strict_bounds(record.get("bounds"),
                                    f"CGEvent backend {label} z-order bounds")
        if not _cgevent_point_inside(source,record_bounds):
            continue
        owner=record.get("owner");title=record.get("title")
        record_pid=record.get("pid");record_window=record.get("windowId")
        for value, expected_type in ((owner,str),(title,str)):
            if value is not None and type(value) is not expected_type:
                raise ObserverError(f"CGEvent backend {label} z-order identity is malformed")
        for value in (record_pid,record_window):
            if value is not None and (type(value) is not int or isinstance(value,bool)):
                raise ObserverError(f"CGEvent backend {label} z-order identity is malformed")
        normalized={"index":len(eligible),"cgIndex":index,"layer":record["layer"],
                    "alpha":record["alpha"],"owner":owner,"pid":record_pid,
                    "windowId":record_window,"title":title,"bounds":record_bounds}
        if (not eligible
                and (owner is None or title is None or record_pid is None
                     or record_window is None)):
            raise ObserverError(f"CGEvent backend {label} unknown frontmost covering record")
        eligible.append(normalized)
        if (owner == "Safari Technology Preview" and record_pid == pid
                and record_window == window_id and title == native_title
                and record_bounds == before):
            target_indexes.append(len(eligible)-1)
    if len(target_indexes) != 1 or target_indexes[0] != 0:
        raise ObserverError(f"CGEvent backend {label} target is not the unique topmost eligible window")
    return {"targetPid":pid,"targetWindowId":window_id,"targetTitle":native_title,
            "sourcePoint":dict(source),"targetBounds":dict(before),"targetIndex":0,
            "eligibleCount":len(eligible),"overlayAbove":0,
            "eligibleRecords":copy.deepcopy(eligible)}

def run_cgevent_backend(before: dict[str,int], requested: dict[str,int], *, pid: int,
                        window_id: int, native_title: str,
                        records: list[dict[str,Any]], cursor_before: dict[str,int],
                        can_post: Callable[[],bool], warp: Callable[[dict[str,int]],None],
                        post: Callable[[str,dict[str,int]],None],
                        restore: Callable[[dict[str,int]],None],
                        cursor_after: Callable[[],dict[str,int]],
                        observed_bounds: Callable[[],dict[str,int]],
                        ax_hit_test: Callable[[list[dict[str,int]]],dict[str,Any]]|None=None,
                        target_ax_object: object|None=None,
                        button_state: Callable[[],Any]|None=None,
                        records_after_warp: Callable[[],list[dict[str,Any]]]|None=None,
                        bounds_after_warp: Callable[[],dict[str,int]]|None=None) -> dict[str,Any]:
    """Deterministic injectable CGEvent seam used by adversarial unit tests.

    Production placement executes the equivalent policy in the descriptor-bound
    Swift helper.  This seam intentionally accepts only typed records/callbacks
    so tests can prove ordering, topmost selection, and restoration without
    posting real events.
    """
    before=strict_bounds(before,"CGEvent backend before bounds")
    requested=strict_bounds(requested,"CGEvent backend requested bounds")
    if not bounds_inside(requested):
        raise ObserverError("CGEvent backend requested bounds are outside KG271U")
    if (before["width"],before["height"]) != (requested["width"],requested["height"]):
        raise ObserverError("CGEvent backend requires an already exact size")
    if before["width"] < 260 or before["height"] < 40:
        raise ObserverError("CGEvent backend target is too small for a safe title-bar point")
    candidate_points=_cgevent_candidate_points(before)
    if target_ax_object is None:
        target_ax_object=object()
    if ax_hit_test is None:
        # The default is only the deterministic injected seam.  Production
        # placement obtains this evidence from AXUIElementCopyElementAtPosition
        # in the descriptor-bound Swift helper.
        ax_hit={"candidatePoints":copy.deepcopy(candidate_points),"candidateIndex":0,
                "chosenPoint":dict(candidate_points[0]),"role":"AXGroup",
                "subrole":"AXTitleBar","actions":[],"enabled":True,"pid":pid,
                "ancestorPid":pid,"ancestorRole":"AXWindow",
                "ancestorSubrole":"AXStandardWindow","ancestorMethod":"injected",
                "targetWindowMatched":True,
                "targetAxWindowNumber":window_id,"mappingMethod":"ax-window-number",
                "sourceMethod":"injected",
                "receiverOutcomes":[{"candidateIndex":index,"receiver":"injected",
                                     "result":"hit","status":0}
                                    for index in range(len(candidate_points))],
                "_ancestorObject":target_ax_object}
    else:
        ax_hit=ax_hit_test(copy.deepcopy(candidate_points))
    if type(ax_hit) is not dict:
        raise ObserverError("CGEvent backend AX hit-test result is malformed")
    ax_hit=dict(ax_hit)
    ancestor_object=ax_hit.pop("_ancestorObject",None)
    if ancestor_object is not target_ax_object:
        raise ObserverError("CGEvent backend AX ancestry object identity is not exact")
    ax_hit=_parse_ax_hit_evidence(ax_hit,before,pid,window_id,allow_injected=True)
    source=dict(ax_hit["chosenPoint"])
    delta={"x":requested["x"]-before["x"],"y":requested["y"]-before["y"]}
    if delta == {"x":0,"y":0}:
        raise ObserverError("CGEvent backend requires a nonzero position delta")
    destination={"x":source["x"]+delta["x"],"y":source["y"]+delta["y"]}
    if button_state is None:
        button_state=lambda: {name:False for name in sorted(_CGEVENT_BUTTON_NAMES)}
    button_before_warp=_strict_quiescent_button_state(
        button_state(),"CGEvent backend button state before warp")
    proof=_build_cgevent_backend_proof(records,source=source,before=before,pid=pid,
                                        window_id=window_id,native_title=native_title,
                                        label="initial")
    records_after_warp_fn=records_after_warp or (lambda:records)
    bounds_after_warp_fn=bounds_after_warp or (lambda:before)
    cursor_before=_strict_cgevent_point(cursor_before,"CGEvent backend cursor before")
    restored=False
    restore_attempted=False
    def restore_once() -> None:
        nonlocal restore_attempted
        if restore_attempted:
            raise ObserverError("CGEvent backend cursor restoration was attempted more than once")
        restore_attempted=True
        restore(dict(cursor_before))
    try:
        if not can_post():
            raise ObserverError("CGEvent backend post permission is unavailable")
        left_down_posted=False
        left_up_confirmed=False
        cleanup_up_attempted=False
        cleanup_up_succeeded=False
        cleanup_up_point=None
        last_event_point=dict(cursor_before)

        def post_tracked(kind: str, point: dict[str,int]) -> None:
            nonlocal left_down_posted,left_up_confirmed,last_event_point
            post(kind,dict(point))
            last_event_point=dict(point)
            if kind == "leftMouseDown":
                left_down_posted=True
            elif kind == "leftMouseUp":
                left_up_confirmed=True

        warp(dict(source))
        pre_bounds=strict_bounds(bounds_after_warp_fn(),
                                 "CGEvent backend pre-mouse-down bounds")
        if pre_bounds != before:
            raise ObserverError("CGEvent backend target changed after cursor warp")
        pre_records=records_after_warp_fn()
        pre_proof=_build_cgevent_backend_proof(
            pre_records,source=source,before=before,pid=pid,
            window_id=window_id,native_title=native_title,label="pre-mouse-down")
        if pre_proof != proof:
            raise ObserverError("CGEvent backend topmost target changed after cursor warp")
        # Only the production native-window-ID binding needs a second hit-test
        # transcript: ordinary injected/direct ancestry already carries an
        # exact object seam and has no native-ID claim to re-prove.
        if ax_hit.get("ancestorMethod") != "system-wide-native-window-id" or ax_hit_test is None:
            pre_ax_hit=dict(ax_hit)
        else:
            raw_pre_ax=ax_hit_test(copy.deepcopy(candidate_points))
            if type(raw_pre_ax) is not dict:
                raise ObserverError("CGEvent backend pre-mouse-down AX hit result is malformed")
            raw_pre_ax=dict(raw_pre_ax)
            pre_ancestor_object=raw_pre_ax.pop("_ancestorObject",None)
            if pre_ancestor_object is not target_ax_object:
                raise ObserverError("CGEvent backend pre-mouse-down AX object identity is not exact")
            pre_ax_hit=_parse_ax_hit_evidence(raw_pre_ax,before,pid,window_id,
                                              allow_injected=True)
        if not _same_native_window_binding_evidence(ax_hit, pre_ax_hit):
            raise ObserverError("CGEvent backend AX source changed after cursor warp")
        button_before_down=_strict_quiescent_button_state(
            button_state(),"CGEvent backend button state before mouse-down")
        post_tracked("leftMouseDown",dict(source))
        for step in range(1,25):
            point={"x":source["x"]+(delta["x"]*step)//24,
                   "y":source["y"]+(delta["y"]*step)//24}
            post_tracked("leftMouseDragged",point)
        post_tracked("leftMouseUp",dict(destination))
        post_bounds=strict_bounds(observed_bounds(),"CGEvent backend post bounds")
        if post_bounds != requested:
            raise ObserverError("CGEvent backend post bounds are not exact")
        restore_once();restored=True
        after_cursor=_strict_cgevent_point(cursor_after(),"CGEvent backend cursor after")
        if after_cursor != cursor_before:
            raise ObserverError("CGEvent backend cursor restoration is not exact")
        sequence=["leftMouseDown"]+["leftMouseDragged"]*24+["leftMouseUp"]
        return {"sourcePoint":source,"destinationPoint":destination,"delta":delta,
                "safePoint":True,"axHitTest":ax_hit,"topmostProof":proof,
                "buttonStateBeforeWarp":button_before_warp,
                "buttonStateBeforeMouseDown":button_before_down,
                "preMouseDownBounds":pre_bounds,
                "preMouseDownTopmostProof":pre_proof,
                "preMouseDownAXHitTest":pre_ax_hit,
                "inputReattested":True,"cursorBefore":cursor_before,
                "cursorAfter":after_cursor,"cursorRestored":True,"eventSequence":sequence,
                "eventCount":26,"dragSteps":24,"postBounds":post_bounds,
                "cleanupUpAttempted":cleanup_up_attempted,
                "cleanupUpSucceeded":cleanup_up_succeeded,
                "cleanupUpPoint":cleanup_up_point,
                "leftMouseUpConfirmed":left_up_confirmed}
    finally:
        # This finally block is deliberately ordered: if a down was posted
        # but no up was confirmed, compensate at the most recent event point
        # before restoring the user's cursor.  A cleanup failure remains
        # terminal; the path is never converted into placement evidence.
        if 'left_down_posted' in locals() and left_down_posted and not left_up_confirmed:
            cleanup_up_attempted=True
            cleanup_up_point=dict(last_event_point)
            try:
                post("leftMouseUp",dict(cleanup_up_point))
                cleanup_up_succeeded=True
                left_up_confirmed=True
            except Exception:
                cleanup_up_succeeded=False
        if not restored and not restore_attempted:
            restore_once()

def _parse_ax_position_ignored_result(result: Any, payload: dict[str,Any], pid: int,
                                      window_id: int, nonce: str,
                                      requested: dict[str,int], native_title: str,
                                      expected_before_bounds: dict[str,int]|None) -> None:
    """Accept only an AX success followed by a typed, exact position readback miss."""
    mapping_keys={"ok","method","errorCode","error","attribute","status","helperUid",
                  "pid","windowId","axWindowNumber","titleNonce","nativeTitle","mappingMethod",
                  "cgBefore","candidateCount","matchedCount","candidates","before"}
    expected_extra={"operation","positionSettable","sizeSettable","resizeMethod","moveMethod",
                    "requestedBounds","beforePosition","beforeSize","intermediateBounds","after"}
    if result.returncode != 1 or set(payload) != mapping_keys | expected_extra:
        raise ObserverError("native AX position readback response is malformed")
    operation=payload.get("operation")
    if (payload.get("ok") is not False or payload.get("errorCode") != "position-ignored"
            or payload.get("error") != "AX position write readback is not exact"
            or payload.get("attribute") != "AXPosition" or payload.get("status") != 0
            or operation not in {"split","move-only"}
            or payload.get("positionSettable") is not True
            or type(payload.get("sizeSettable")) is not bool
            or payload.get("moveMethod") != "AX"
            or payload.get("resizeMethod") != ("webDriver-existing" if operation == "split" else "pre-resized")):
        raise ObserverError("native AX position readback failure is not an eligible CGEvent fallback")
    if strict_bounds(payload.get("requestedBounds"),"native AX position requested bounds") != requested:
        raise ObserverError("native AX position requested bounds are not exact")
    before=strict_bounds(payload.get("before"),"native AX position before bounds")
    cg_before=strict_bounds(payload.get("cgBefore"),"native AX position CoreGraphics before bounds")
    expected_before=(strict_bounds(expected_before_bounds,"expected CoreGraphics before bounds")
                     if expected_before_bounds is not None else cg_before)
    if before != cg_before or before != expected_before:
        raise ObserverError("native AX position readback pre-bounds do not match target")
    after=strict_bounds(payload.get("after"),"native AX position readback bounds")
    intermediate=strict_bounds(payload.get("intermediateBounds"),"native AX position intermediate bounds")
    before_position=_strict_position(payload.get("beforePosition"),"native AX position before position")
    before_size=_strict_size(payload.get("beforeSize"),"native AX position before size")
    if (before_position != {"x":before["x"],"y":before["y"]}
            or before_size != {"width":before["width"],"height":before["height"]}
            or intermediate != before
            or before["width"] != requested["width"]
            or before["height"] != requested["height"]
            or after["width"] != requested["width"]
            or after["height"] != requested["height"]
            or after == requested):
        raise ObserverError("native AX position readback geometry is not an exact move miss")
    mapping_payload={key:copy.deepcopy(payload[key]) for key in mapping_keys}
    mapping_payload["errorCode"]="not-settable"
    mapping_payload["error"]="AX attribute is not settable: AXPosition status=0"
    mapping_payload["attribute"]="AXPosition"
    mapping_payload["status"]=0
    mapping=_parse_ax_not_settable_mapping(mapping_payload,pid,window_id,nonce,native_title,expected_before)
    mapping.update({"operation":operation,"errorCode":"position-ignored",
                    "error":payload["error"],"attribute":"AXPosition","status":0,
                    "positionSettable":True,"sizeSettable":payload["sizeSettable"],
                    "resizeMethod":payload["resizeMethod"],"moveMethod":"AX",
                    "requestedBounds":requested,"beforePosition":before_position,
                    "beforeSize":before_size,"intermediateBounds":intermediate,
                    "before":before,"after":after})
    raise AXPositionIgnoredError("native AX position setter returned an inexact readback",mapping)

def _split_legacy_result(payload: dict[str,Any]) -> dict[str,Any]:
    legacy_keys={"ok","method","helperUid","pid","windowId","axWindowNumber",
                 "titleNonce","nativeTitle","mappingMethod","cgBefore","candidateCount",
                 "matchedCount","candidates","before","requestedBounds","after"}
    return {key:copy.deepcopy(payload[key]) for key in legacy_keys}

def _parse_ax_split_result(result: Any, payload: dict[str,Any], pid: int, window_id: int,
                           nonce: str, requested_bounds: dict[str,int],
                           native_title: str,
                           expected_before_bounds: dict[str,int]|None) -> dict[str,Any]:
    """Validate the split AX protocol and keep the direct fallback resize-only."""
    try:
        returncode,stderr=result.returncode,result.stderr
    except AttributeError as exc:
        raise ObserverError("native AX helper returned a malformed result") from exc
    requested=strict_bounds(requested_bounds,"requestedBounds")
    if type(returncode) is not int or type(stderr) is not str or stderr != "":
        raise ObserverError("native AX helper split response is malformed")
    operation=payload.get("operation")
    if operation not in {"split","resize-only","move-only","cgevent-titlebar"}:
        raise ObserverError("native AX helper split operation is malformed")
    if payload.get("ok") is True:
        expected_extra={"operation","positionSettable","sizeSettable","resizeMethod",
                        "moveMethod","beforePosition","beforeSize","intermediateBounds"}
        if operation == "cgevent-titlebar":
            expected_extra |= {"sourcePoint","destinationPoint","delta","safePoint",
                               "topmostProof","cursorBefore","cursorAfter","cursorRestored",
                               "eventSequence","eventCount","dragSteps","postBounds",
                               "axHitTest","cleanupUpAttempted","cleanupUpSucceeded",
                               "cleanupUpPoint","leftMouseUpConfirmed",
                               "buttonStateBeforeWarp","buttonStateBeforeMouseDown",
                               "preMouseDownBounds","preMouseDownTopmostProof",
                               "preMouseDownAXHitTest","inputReattested"}
        legacy_keys={"ok","method","helperUid","pid","windowId","axWindowNumber",
                     "titleNonce","nativeTitle","mappingMethod","cgBefore","candidateCount",
                     "matchedCount","candidates","before","requestedBounds","after"}
        if returncode != 0 or set(payload) != legacy_keys | expected_extra:
            raise ObserverError("native AX helper split success response is malformed")
        if (type(payload.get("positionSettable")) is not bool
                or type(payload.get("sizeSettable")) is not bool
                or payload.get("moveMethod") not in {"AX","cgevent-titlebar"}
                or payload.get("resizeMethod") not in {"webDriver-existing","AX","pre-resized"}):
            raise ObserverError("native AX helper split mutability evidence is malformed")
        # Reuse the established full mapping/identity/CG validation for every
        # success.  The transformed response has no split-only keys, so this
        # cannot accidentally bypass the legacy exact candidate checks.
        legacy_payload=_split_legacy_result(payload)
        # The resize-only stage intentionally reports its intermediate
        # geometry as ``after``.  Feed a request-shaped value to the existing
        # mapping validator, then validate and restore the real intermediate
        # below before returning evidence.
        if operation == "resize-only":
            legacy_payload["after"]=copy.deepcopy(payload.get("requestedBounds"))
        legacy_result=type("SplitLegacyResult",(),{
            "returncode":returncode,
            "stdout":json.dumps(legacy_payload,separators=(",",":"))+"\n",
            "stderr":stderr})()
        legacy=parse_ax_helper_result(legacy_result,pid,window_id,nonce,requested,
                                      expected_native_title=native_title,
                                      expected_before_bounds=expected_before_bounds)
        before=strict_bounds(payload.get("before"),"native AX before bounds")
        after=strict_bounds(payload.get("after"),"native AX after bounds")
        intermediate=strict_bounds(payload.get("intermediateBounds"),"native AX intermediate bounds")
        before_position=_strict_position(payload.get("beforePosition"),"native AX before position")
        before_size=_strict_size(payload.get("beforeSize"),"native AX before size")
        if before_position != {"x":before["x"],"y":before["y"]} or before_size != {"width":before["width"],"height":before["height"]}:
            raise ObserverError("native AX split pre-geometry evidence is inconsistent")
        if operation not in {"resize-only","cgevent-titlebar"} and (after != requested or legacy.get("after") != requested):
            raise ObserverError("native AX split after bounds are not exact")
        if operation == "resize-only":
            expected_intermediate={"x":before["x"],"y":before["y"],
                                   "width":requested["width"],"height":requested["height"]}
            if after != expected_intermediate or intermediate != expected_intermediate:
                raise ObserverError("native AX resize-only after bounds are not exact")
            if payload.get("resizeMethod") != "AX" or payload.get("sizeSettable") is not True:
                raise ObserverError("native AX resize-only mutability evidence is not exact")
        if payload.get("positionSettable") is not True:
            raise ObserverError("native AX position is not settable")
        if operation == "resize-only":
            # Size was changed, but position has not yet been touched.  The
            # caller must independently rebind CoreGraphics/process identity
            # before it may issue the follow-up AX move-only operation.
            if before_size == {"width":requested["width"],"height":requested["height"]}:
                raise ObserverError("native AX resize-only claims a size mutation without a size change")
        elif operation == "move-only":
            if payload.get("resizeMethod") != "pre-resized" or intermediate != before:
                raise ObserverError("native AX move-only resize evidence is not exact")
            if before_size != {"width":requested["width"],"height":requested["height"]}:
                raise ObserverError("native AX move-only size is not already requested")
        elif operation == "cgevent-titlebar":
            if (payload.get("resizeMethod") != "pre-resized"
                    or payload.get("moveMethod") != "cgevent-titlebar"
                    or intermediate != before
                    or before_size != {"width":requested["width"],"height":requested["height"]}):
                raise ObserverError("native CGEvent move geometry evidence is not exact")
            payload.update(_parse_cgevent_evidence(payload,pid,window_id,native_title,requested,
                                                   before,after,intermediate))
        else:
            current_size={"width":before["width"],"height":before["height"]}
            requested_size={"width":requested["width"],"height":requested["height"]}
            if current_size == requested_size:
                if payload.get("resizeMethod") != "webDriver-existing" or intermediate != before:
                    raise ObserverError("native AX split existing-size evidence is not exact")
            else:
                raise ObserverError("native AX split size mutation requires a separate resize-only stage")
        legacy.update({"operation":operation,
                       "positionSettable":payload["positionSettable"],
                       "sizeSettable":payload["sizeSettable"],
                       "resizeMethod":payload["resizeMethod"],
                       "moveMethod":payload["moveMethod"],
                       "beforePosition":before_position,"beforeSize":before_size,
                       "intermediateBounds":intermediate})
        if operation == "resize-only":
            legacy["after"] = after
        elif operation == "cgevent-titlebar":
            legacy.update(_parse_cgevent_evidence(payload,pid,window_id,native_title,requested,
                                                  before,after,intermediate))
        return legacy
    if payload.get("errorCode") == "position-ignored":
        _parse_ax_position_ignored_result(result,payload,pid,window_id,nonce,requested,
                                           native_title,expected_before_bounds)
        raise ObserverError("native AX position readback parser returned unexpectedly")
    # A resize-not-settable result is the only split failure that may reach
    # the fixed STP direct resize fallback.  It must prove AXPosition is
    # settable and that the current dimensions really differ.
    expected_extra={"operation","positionSettable","sizeSettable","resizeMethod",
                    "moveMethod","requestedBounds","beforePosition","beforeSize"}
    mapping_keys={"ok","method","errorCode","error","attribute","status","helperUid",
                  "pid","windowId","axWindowNumber","titleNonce","nativeTitle","mappingMethod",
                  "cgBefore","candidateCount","matchedCount","candidates","before"}
    if returncode != 1 or set(payload) != mapping_keys | expected_extra:
        raise ObserverError("native AX helper split failure response is malformed")
    if (payload.get("errorCode") != "resize-not-settable"
            or payload.get("error") != "AX attribute is not settable: AXSize status=0"
            or payload.get("attribute") != "AXSize" or payload.get("status") != 0
            or payload.get("operation") not in {"split", "resize-only"}
            or payload.get("positionSettable") is not True
            or payload.get("sizeSettable") is not False
            or payload.get("resizeMethod") != "stp-direct"
            or payload.get("moveMethod") != "AX"):
        raise ObserverError("native AX helper split failure is not an eligible resize result")
    if strict_bounds(payload.get("requestedBounds"),"native AX requestedBounds") != requested:
        raise ObserverError("native AX split requested bounds are not exact")
    mapping_payload={key:copy.deepcopy(payload[key]) for key in mapping_keys}
    mapping_payload["errorCode"]="not-settable"
    mapping_payload["error"]="AX attribute is not settable: AXSize status=0"
    mapping=_parse_ax_not_settable_mapping(mapping_payload,pid,window_id,nonce,native_title,
                                           requested if expected_before_bounds is None else expected_before_bounds)
    before=strict_bounds(payload.get("before"),"native AX split before bounds")
    before_position=_strict_position(payload.get("beforePosition"),"native AX split before position")
    before_size=_strict_size(payload.get("beforeSize"),"native AX split before size")
    if before_position != {"x":before["x"],"y":before["y"]} or before_size != {"width":before["width"],"height":before["height"]}:
        raise ObserverError("native AX split failure pre-geometry evidence is inconsistent")
    if before_size == {"width":requested["width"],"height":requested["height"]}:
        raise ObserverError("native AX split resize failure claims an already exact size")
    mapping.update({"operation":payload.get("operation"),"positionSettable":True,"sizeSettable":False,
                    "resizeMethod":"stp-direct","moveMethod":"AX",
                    "requestedBounds":requested,"beforePosition":before_position,
                    "beforeSize":before_size})
    raise AXResizeNotSettableError("native AX helper reported resize-only not-settable geometry",mapping)

def parse_ax_helper_result(result: Any, pid: int, window_id: int, nonce: str,
                           requested_bounds: dict[str,int],
                           expected_native_title: str|None = None,
                           expected_before_bounds: dict[str,int]|None = None) -> dict[str,Any]:
    """Strictly validate one native helper response before accepting a move."""
    try:
        returncode,stdout,stderr=result.returncode,result.stdout,result.stderr
    except AttributeError as exc:
        raise ObserverError("native AX helper returned a malformed result") from exc
    if type(returncode) is not int or type(stdout) is not str or type(stderr) is not str:
        raise ObserverError("native AX helper returned a malformed result")
    if type(pid) is not int or pid < 1 or type(window_id) is not int or window_id < 1:
        raise ObserverError("native AX helper target identity is malformed")
    requested_bounds = strict_bounds(requested_bounds,"requestedBounds")
    if stderr != "":
        raise ObserverError("native AX helper emitted diagnostics")
    nonce = strict_title_nonce(nonce)
    native_title = strict_native_title(expected_native_title if expected_native_title is not None else nonce)
    payload=strict_helper_json_loads(stdout)
    if type(payload) is not dict:
        raise ObserverError("native AX helper response must be an object")
    if payload.get("operation") in {"split","resize-only","move-only","cgevent-titlebar"}:
        return _parse_ax_split_result(result,payload,pid,window_id,nonce,requested_bounds,
                                      native_title,expected_before_bounds)
    if payload.get("ok") is not True:
        if returncode != 1 or payload.get("method")!="application-services-ax":
            raise ObserverError("native AX helper response is ambiguous")
        if payload.get("errorCode") == "not-settable":
            mapping=_parse_ax_not_settable_mapping(payload,pid,window_id,nonce,native_title,
                                                    requested_bounds if expected_before_bounds is None else expected_before_bounds)
            raise AXNotSettableError("native AX helper reported exact not-settable geometry",mapping)
        if set(payload) != {"ok","method","error"} or type(payload.get("error")) is not str or not payload["error"].strip():
            raise ObserverError("native AX helper response is ambiguous")
        raise ObserverError("native AX helper rejected placement: "+payload["error"])
    expected={"ok","method","helperUid","pid","windowId","axWindowNumber","titleNonce","nativeTitle","mappingMethod","cgBefore","candidateCount","matchedCount","candidates","before","requestedBounds","after"}
    if returncode != 0 or set(payload) != expected:
        raise ObserverError("native AX helper success response is malformed")
    mapping_method=payload.get("mappingMethod")
    if (type(mapping_method) is not str
            or mapping_method not in {"ax-window-number","title-geometry"}):
        raise ObserverError("native AX helper mapping method is not exact")
    if (payload.get("method")!="application-services-ax"
            or type(payload.get("helperUid")) is not int or payload["helperUid"]!=os.getuid()
            or type(payload.get("pid")) is not int or payload["pid"]!=pid
            or type(payload.get("windowId")) is not int or payload["windowId"]!=window_id
            or (payload.get("axWindowNumber") is not None
                and (type(payload.get("axWindowNumber")) is not int or payload["axWindowNumber"]!=window_id))
            or type(payload.get("titleNonce")) is not str or payload["titleNonce"]!=nonce
            or type(payload.get("nativeTitle")) is not str or payload["nativeTitle"]!=native_title):
        raise ObserverError("native AX helper identity evidence is not exact")
    if mapping_method == "ax-window-number" and payload.get("axWindowNumber") != window_id:
        raise ObserverError("native AX helper AXWindowNumber evidence is not exact")
    if mapping_method == "title-geometry" and payload.get("axWindowNumber") is not None:
        raise ObserverError("native AX helper title-geometry mapping has an AX number")
    before=strict_bounds(payload.get("before"),"native AX before bounds")
    cg_before=strict_bounds(payload.get("cgBefore"),"native AX CoreGraphics before bounds")
    if expected_before_bounds is not None and cg_before != strict_bounds(expected_before_bounds,"expected CoreGraphics before bounds"):
        raise ObserverError("native AX helper CoreGraphics before bounds do not match target")
    if before != cg_before:
        raise ObserverError("native AX helper before bounds do not match CoreGraphics")
    candidate_count=payload.get("candidateCount");matched_count=payload.get("matchedCount")
    if (type(candidate_count) is not int or candidate_count < 1
            or type(matched_count) is not int or matched_count != 1):
        raise ObserverError("native AX helper candidate counts are malformed")
    candidates=payload.get("candidates")
    if type(candidates) is not list or len(candidates)!=candidate_count:
        raise ObserverError("native AX helper candidate evidence is malformed")
    seen:set[int]=set();matching=[]
    for candidate in candidates:
        if type(candidate) is not dict or set(candidate)!={"pid","windowId","axWindowNumber","title","bounds"}:
            raise ObserverError("native AX helper candidate evidence is malformed")
        if (type(candidate.get("pid")) is not int or candidate["pid"]!=pid
                or type(candidate.get("windowId")) is not int or candidate["windowId"]<1
                or (candidate.get("axWindowNumber") is not None
                    and (type(candidate.get("axWindowNumber")) is not int or candidate["axWindowNumber"]<1))
                or type(candidate.get("title")) is not str or candidate["title"]!=native_title
                or candidate["windowId"] != window_id):
            raise ObserverError("native AX helper candidate identity is not exact")
        if mapping_method == "ax-window-number" and candidate.get("axWindowNumber") is None:
            raise ObserverError("native AX helper AXWindowNumber is missing")
        if mapping_method == "title-geometry" and candidate.get("axWindowNumber") is not None:
            raise ObserverError("native AX helper title-geometry candidate has an AX number")
        if candidate.get("axWindowNumber") is not None:
            if candidate["axWindowNumber"] in seen:
                raise ObserverError("native AX helper AXWindowNumber is duplicated")
            seen.add(candidate["axWindowNumber"])
        candidate_bounds=strict_bounds(candidate["bounds"],"native AX candidate bounds")
        if candidate_bounds == before and (
                mapping_method == "title-geometry"
                or candidate.get("axWindowNumber") == window_id):
            matching.append(candidate)
        candidate["bounds"]=candidate_bounds
    if len(matching)!=1:
        raise ObserverError("native AX helper target mapping is not unique")
    requested=strict_bounds(payload.get("requestedBounds"),"native AX requestedBounds")
    after=strict_bounds(payload.get("after"),"native AX after bounds")
    if requested != requested_bounds or after != requested_bounds or matching[0]["bounds"] != before:
        raise ObserverError("native AX helper geometry evidence is not exact")
    if mapping_method == "ax-window-number" and matching[0].get("axWindowNumber") != window_id:
        raise ObserverError("native AX helper selected AX number is not exact")
    if mapping_method == "title-geometry" and matching[0].get("axWindowNumber") is not None:
        raise ObserverError("native AX helper selected title-geometry candidate has a number")
    payload["before"]=before;payload["requestedBounds"]=requested;payload["after"]=after
    payload["candidates"]=candidates;payload["verified"]=True
    return payload

def parse_empty_title_ax_helper_result(result:Any,pid:int,window_id:int,nonce:str,
                                       before_bounds:dict[str,int],operation:str,
                                       requested_bounds:dict[str,int]|None=None)->dict[str,Any]:
    """Validate the pinned helper's exact empty-CoreGraphics-title AX mapping."""
    try:returncode,stdout,stderr=result.returncode,result.stdout,result.stderr
    except AttributeError as exc:raise ObserverError("native AX helper returned a malformed result") from exc
    if type(returncode) is not int or type(stdout) is not str or type(stderr) is not str or stderr:
        raise ObserverError("native AX helper returned a malformed result")
    nonce=strict_title_nonce(nonce);before=strict_bounds(before_bounds,"empty-title CoreGraphics bounds")
    payload=strict_helper_json_loads(stdout)
    if type(payload) is not dict or returncode!=0 or payload.get("ok") is not True:
        if returncode==1 and type(payload) is dict and set(payload)=={"ok","method","error"} \
                and payload.get("ok") is False and payload.get("method")=="application-services-ax":
            helper_error=payload.get("error")
            if safe_empty_title_ax_helper_error(helper_error):
                raise ObserverError("empty-title AX helper failure: "+helper_error)
        raise ObserverError("empty-title AX helper rejected exact mapping")
    unmapped={"ok","method","operation","bindingMode","mappingStatus","helperUid","pid","windowId",
              "titleNonce","nativeTitle","cgBefore","candidateCount","matchedCount","candidates","mutationAttempted"}
    if operation=="inspect-empty-cg-title" and payload.get("mappingStatus")=="unmapped":
        if set(payload)!=unmapped:
            raise ObserverError("empty-title AX helper unmapped response shape is not exact")
        if (payload.get("method")!="application-services-ax" or payload.get("operation")!=operation
                or payload.get("bindingMode")!=EMPTY_CG_BINDING_MODE
                or type(payload.get("helperUid")) is not int or payload["helperUid"]!=os.getuid()
                or payload.get("pid")!=pid or payload.get("windowId")!=window_id
                or payload.get("titleNonce")!=nonce or payload.get("nativeTitle")!=""
                or payload.get("matchedCount")!=0 or payload.get("mutationAttempted") is not False):
            raise ObserverError("empty-title AX helper unmapped identity evidence is not exact")
        cg_before=strict_bounds(payload.get("cgBefore"),"empty-title helper CoreGraphics before")
        candidates=payload.get("candidates");candidate_count=payload.get("candidateCount")
        if (cg_before!=before or type(candidate_count) is not int or candidate_count<1
                or type(candidates) is not list or len(candidates)!=candidate_count):
            raise ObserverError("empty-title AX helper unmapped candidate evidence is malformed")
        seen:set[int]=set();normalized=[]
        for candidate in candidates:
            if type(candidate) is not dict or set(candidate)!={"pid","axWindowNumber","title","bounds"}:
                raise ObserverError("empty-title AX helper unmapped candidate evidence is malformed")
            number=candidate.get("axWindowNumber");title=candidate.get("title")
            candidate_bounds=strict_bounds(candidate.get("bounds"),"empty-title AX unmapped candidate bounds")
            if (candidate.get("pid")!=pid or type(number) is not int or number<1 or number in seen
                    or type(title) is not str or any(ord(char)<0x20 or ord(char)==0x7f for char in title)
                    or number==window_id):
                raise ObserverError("empty-title AX helper unmapped candidate is not an exact non-match")
            seen.add(number);normalized.append({**candidate,"bounds":candidate_bounds})
        payload["cgBefore"]=cg_before;payload["candidates"]=normalized;payload["verified"]=True
        return payload
    common={"ok","method","operation","bindingMode","mappingStatus","helperUid","pid","windowId","axWindowNumber",
            "titleNonce","nativeTitle","mappingMethod","cgBefore","candidateCount","matchedCount",
            "candidates","before","titleEvidence","mutationAttempted"}
    placement_extra={"requestedBounds","after","positionSettable","sizeSettable","resizeMethod","moveMethod",
                     "beforePosition","beforeSize","intermediateBounds"}
    expected=common if operation=="inspect-empty-cg-title" else common|placement_extra
    if set(payload)!=expected or payload.get("operation")!=operation:
        raise ObserverError("empty-title AX helper response shape is not exact")
    if (payload.get("method")!="application-services-ax" or payload.get("bindingMode")!=EMPTY_CG_BINDING_MODE
            or payload.get("mappingStatus")!="mapped"
            or type(payload.get("helperUid")) is not int or payload["helperUid"]!=os.getuid()
            or type(payload.get("pid")) is not int or payload["pid"]!=pid
            or type(payload.get("windowId")) is not int or payload["windowId"]!=window_id
            or type(payload.get("axWindowNumber")) is not int or payload["axWindowNumber"]!=window_id
            or payload.get("titleNonce")!=nonce or payload.get("nativeTitle")!=""
            or payload.get("mappingMethod")!="ax-window-number-empty-cg-title"
            or payload.get("mutationAttempted") is not (operation!="inspect-empty-cg-title")):
        raise ObserverError("empty-title AX helper identity evidence is not exact")
    cg_before=strict_bounds(payload.get("cgBefore"),"empty-title helper CoreGraphics before")
    ax_before=strict_bounds(payload.get("before"),"empty-title helper AX before")
    if cg_before!=before or ax_before!=before:
        raise ObserverError("empty-title AX helper geometry is not exact")
    if payload.get("candidateCount")!=1 or payload.get("matchedCount")!=1:
        raise ObserverError("empty-title AX helper candidate counts are not exact")
    candidates=payload.get("candidates")
    if type(candidates) is not list or len(candidates)!=1:
        raise ObserverError("empty-title AX helper candidate evidence is malformed")
    candidate=candidates[0]
    if type(candidate) is not dict or set(candidate)!={"pid","windowId","axWindowNumber","title","bounds"}:
        raise ObserverError("empty-title AX helper candidate evidence is malformed")
    ax_title=candidate.get("title");title_evidence=payload.get("titleEvidence")
    if ((title_evidence=="ax-title" and ax_title!=nonce)
            or (title_evidence=="webdriver-document-title" and ax_title!="")
            or title_evidence not in {"ax-title","webdriver-document-title"}
            or candidate.get("pid")!=pid or candidate.get("windowId")!=window_id
            or candidate.get("axWindowNumber")!=window_id
            or strict_bounds(candidate.get("bounds"),"empty-title AX candidate bounds")!=before):
        raise ObserverError("empty-title AX title or window mapping is not exact")
    if operation!="inspect-empty-cg-title":
        requested=strict_bounds(payload.get("requestedBounds"),"empty-title requestedBounds")
        after=strict_bounds(payload.get("after"),"empty-title after bounds")
        if requested_bounds is None or requested!=strict_bounds(requested_bounds,"expected empty-title requestedBounds") or not bounds_inside(requested) or after!=requested:
            raise ObserverError("empty-title AX placement geometry is not exact")
        if payload.get("positionSettable") is not True or payload.get("resizeMethod")!="webDriver-existing" or payload.get("moveMethod")!="AX":
            raise ObserverError("empty-title AX placement method is not exact")
        if strict_bounds(payload.get("intermediateBounds"),"empty-title intermediate bounds")!=before:
            raise ObserverError("empty-title AX placement intermediate bounds changed")
    payload["cgBefore"]=cg_before;payload["before"]=ax_before;payload["candidates"]=[{**candidate,"bounds":before}]
    payload["verified"]=True
    return payload

def inspect_empty_title_ax_helper(helper_fd:int,helper_digest:str,helper_device:int,helper_inode:int,
                                  pid:int,window_id:int,nonce:str,bounds:dict[str,int])->dict[str,Any]:
    bounds=strict_bounds(bounds,"empty-title inspection bounds")
    argv=["improvedtube-aqua-ax-helper",str(pid),str(window_id),strict_title_nonce(nonce),"",
          str(bounds["x"]),str(bounds["y"]),str(bounds["width"]),str(bounds["height"]),
          "inspect-empty-cg-title",EMPTY_CG_BINDING_MODE]
    _validate_helper_fd(helper_fd,helper_digest,helper_device,helper_inode)
    result=_run_helper_fd(helper_fd,helper_digest,helper_device,helper_inode,argv)
    _validate_helper_fd(helper_fd,helper_digest,helper_device,helper_inode)
    return parse_empty_title_ax_helper_result(result,pid,window_id,nonce,bounds,"inspect-empty-cg-title")

def _strict_decimal_integer_text(value: Any, label: str) -> int:
    """Parse one canonical decimal field from the fixed direct-script protocol."""
    if type(value) is not str or not value:
        raise ObserverError(f"{label} is malformed")
    digits=value[1:] if value.startswith("-") else value
    if not digits or any(char < "0" or char > "9" for char in digits):
        raise ObserverError(f"{label} is malformed")
    if value.startswith("-") and digits == "0":
        raise ObserverError(f"{label} is not canonical")
    try:
        parsed=int(value,10)
    except (TypeError,ValueError,OverflowError) as exc:
        raise ObserverError(f"{label} is malformed") from exc
    if str(parsed) != value:
        raise ObserverError(f"{label} is not canonical")
    return parsed

def _validate_ax_mapping_evidence(mapping: Any, pid: int, window_id: int,
                                  native_title: str,
                                  expected_before_bounds: dict[str,int]) -> dict[str,Any]:
    """Validate the evidence-bearing AX mapping used by the direct fallback."""
    if type(mapping) is not dict or mapping.get("verified") is not True:
        raise ObserverError("AX fallback requires verified mapping evidence")
    expected_before=strict_bounds(expected_before_bounds,"expected CoreGraphics before bounds")
    if (type(mapping.get("pid")) is not int or mapping.get("pid") != pid
            or type(mapping.get("windowId")) is not int or mapping.get("windowId") != window_id
            or type(mapping.get("title")) is not str or mapping.get("title") != native_title):
        raise ObserverError("AX fallback mapping identity is not exact")
    if strict_bounds(mapping.get("before"),"AX fallback before bounds") != expected_before:
        raise ObserverError("AX fallback mapping geometry is not exact")
    method=mapping.get("mappingMethod")
    if method not in {"ax-window-number","title-geometry"}:
        raise ObserverError("AX fallback mapping method is not exact")
    number=mapping.get("axWindowNumber")
    if method == "ax-window-number":
        if type(number) is not int or number != window_id:
            raise ObserverError("AX fallback AXWindowNumber is not exact")
    elif number is not None:
        raise ObserverError("AX fallback title-geometry mapping has an AX number")
    candidates=mapping.get("candidates")
    if type(candidates) is not list or len(candidates) < 1:
        raise ObserverError("AX fallback candidate evidence is missing")
    if type(mapping.get("candidateCount")) is not int or mapping["candidateCount"] != len(candidates):
        raise ObserverError("AX fallback candidate count is malformed")
    if type(mapping.get("matchedCount")) is not int or mapping["matchedCount"] != 1:
        raise ObserverError("AX fallback match count is malformed")
    if type(mapping.get("cgBefore")) is not dict or strict_bounds(mapping["cgBefore"],"AX fallback CoreGraphics before bounds") != expected_before:
        raise ObserverError("AX fallback CoreGraphics before bounds are not exact")
    if mapping.get("nativeTitle") is not None and mapping.get("nativeTitle") != native_title:
        raise ObserverError("AX fallback native title evidence is not exact")
    seen:set[int]=set();matches=[]
    for candidate in candidates:
        if type(candidate) is not dict or set(candidate) != {"pid","windowId","axWindowNumber","title","bounds"}:
            raise ObserverError("AX fallback candidate evidence is malformed")
        candidate_number=candidate.get("axWindowNumber")
        if candidate_number is not None:
            if type(candidate_number) is not int or candidate_number < 1 or candidate_number in seen:
                raise ObserverError("AX fallback AXWindowNumber is malformed or duplicated")
            seen.add(candidate_number)
        if (type(candidate.get("pid")) is not int or candidate.get("pid") != pid
                or type(candidate.get("windowId")) is not int or candidate.get("windowId") != window_id
                or type(candidate.get("title")) is not str or candidate.get("title") != native_title):
            raise ObserverError("AX fallback candidate identity is not exact")
        candidate_bounds=strict_bounds(candidate.get("bounds"),"AX fallback candidate bounds")
        if candidate_bounds == expected_before and (method == "title-geometry" or candidate_number == window_id):
            matches.append(candidate)
    if method == "ax-window-number" and any(candidate.get("axWindowNumber") is None for candidate in candidates):
        raise ObserverError("AX fallback AXWindowNumber support is inconsistent")
    if method == "title-geometry" and any(candidate.get("axWindowNumber") is not None for candidate in candidates):
        raise ObserverError("AX fallback AXWindowNumber support is inconsistent")
    if len(matches) != 1:
        raise ObserverError("AX fallback target mapping is not unique")
    return copy.deepcopy(mapping)

def parse_direct_stp_result(result: Any, pid: int, window_id: int,
                            native_title: str,
                            expected_before_bounds: dict[str,int],
                            requested_bounds: dict[str,int],
                            operation: str = "full") -> dict[str,Any]:
    """Strictly parse the fixed STP Apple Event helper's typed output."""
    try:
        returncode,stdout,stderr=result.returncode,result.stdout,result.stderr
    except AttributeError as exc:
        raise ObserverError("direct STP helper returned a malformed result") from exc
    if type(returncode) is not int or type(stdout) is not str or type(stderr) is not str:
        raise ObserverError("direct STP helper returned a malformed result")
    if type(pid) is not int or pid < 1 or type(window_id) is not int or window_id < 1:
        raise ObserverError("direct STP helper target identity is malformed")
    native_title=strict_native_title(native_title,"direct native title")
    before_expected=strict_bounds(expected_before_bounds,"expected CoreGraphics before bounds")
    requested_expected=strict_bounds(requested_bounds,"requestedBounds")
    if type(operation) is not str or operation not in {"full", "resize-only"}:
        raise ObserverError("direct STP helper operation is malformed")
    if not bounds_inside(requested_expected):
        raise ObserverError("requested bounds are outside KG271U")
    if stderr != "" or not stdout.endswith("\n") or stdout.count("\n") != 1 or "\r" in stdout:
        raise ObserverError("direct STP helper output is malformed")
    raw=stdout[:-1]
    if not raw or any(ord(char) < 0x20 or ord(char) > 0x7e for char in raw if char != "\t"):
        raise ObserverError("direct STP helper output is malformed")
    fields=raw.split("\t")
    if not fields or fields[0] != DIRECT_STP_PROTOCOL:
        raise ObserverError("direct STP helper protocol marker is invalid")
    if len(fields) == 4 and fields[1] == "ERROR":
        if returncode not in {0,1} or fields[2] not in {
                "candidate-count","app-window-id-malformed","app-window-id-mismatch",
                "bounds-write","bounds-readback"}:
            raise ObserverError("direct STP helper error response is malformed")
        count=_strict_decimal_integer_text(fields[3],"direct STP error count")
        if count < 0:
            raise ObserverError("direct STP error count is malformed")
        raise ObserverError("direct STP helper rejected exact STP target mapping or bounds")
    if returncode != 0 or len(fields) != 13 or fields[1] != "OK":
        raise ObserverError("direct STP helper response is malformed")
    app_id_status=fields[2]
    if app_id_status not in {"EXACT","UNAVAILABLE"}:
        raise ObserverError("direct STP app-window ID status is malformed")
    app_id=_strict_decimal_integer_text(fields[3],"direct STP app-window ID")
    candidate_count=_strict_decimal_integer_text(fields[4],"direct STP candidate count")
    if candidate_count != 1:
        raise ObserverError("direct STP candidate count is not exact")
    values=[_strict_decimal_integer_text(value,f"direct STP bounds field {index}")
            for index,value in enumerate(fields[5:],5)]
    if len(values) != 8:
        raise ObserverError("direct STP bounds response is malformed")
    before={"x":values[0],"y":values[1],"width":values[2],"height":values[3]}
    after={"x":values[4],"y":values[5],"width":values[6],"height":values[7]}
    if strict_bounds(before,"direct STP before bounds") != before_expected:
        raise ObserverError("direct STP pre-bounds do not match AX/CoreGraphics evidence")
    expected_after = requested_expected
    if operation == "resize-only":
        expected_after = {"x":before_expected["x"], "y":before_expected["y"],
                          "width":requested_expected["width"], "height":requested_expected["height"]}
    if strict_bounds(after,"direct STP after bounds") != expected_after:
        raise ObserverError("direct STP readback bounds are not exact")
    # The size-only operation intentionally preserves Safari's current
    # (possibly clamped/out-of-KG) position.  KG containment is required only
    # after the subsequent AX position write and final CoreGraphics check.
    if operation != "resize-only" and not bounds_inside(after):
        raise ObserverError("direct STP readback bounds are outside KG271U")
    if app_id_status == "EXACT":
        if app_id < 1 or app_id != window_id:
            raise ObserverError("direct STP app-window ID does not map to CoreGraphics ID")
        mapping_method="app-window-id"
    else:
        if app_id != 0:
            raise ObserverError("direct STP unavailable app-window ID is not zero")
        mapping_method="title-geometry"
    return {"verified":True,"method":"safari-direct-apple-event",
            "applicationId":STP_BUNDLE_ID,"pid":pid,"windowId":window_id,
            "appWindowId":None if app_id_status=="UNAVAILABLE" else app_id,
            "mappingMethod":mapping_method,"candidateCount":candidate_count,
            "nativeTitle":native_title,"before":before,
            "requestedBounds":requested_expected,"after":after,
            "operation":operation,
            "positionMutated":operation != "resize-only",
            "directProtocol":DIRECT_STP_PROTOCOL}

def direct_stp_window(pid: int, window_id: int, nonce: str,
                      requested_bounds: dict[str,int], *, native_title: str,
                      expected_before_bounds: dict[str,int],
                      ax_mapping: dict[str,Any], runner: Callable[...,Any]|None = None,
                      resize_only: bool = False) -> dict[str,Any]:
    """Resize the already AX-mapped STP window through a fixed Apple Event.

    The script contains the only application selector.  Title and geometry
    are separate argv values; no user value is interpolated into executable
    source and no shell or System Events target is reachable.  ``resize_only``
    is the only fallback mode used by placement and preserves the existing
    position; negative-position movement is performed by AX.
    """
    if type(pid) is not int or pid < 1 or type(window_id) is not int or window_id < 1:
        raise ObserverError("direct STP target identity is malformed")
    if type(resize_only) is not bool:
        raise ObserverError("direct STP resize mode is malformed")
    nonce=strict_title_nonce(nonce)
    native_title=strict_native_title(native_title,"direct native title")
    derive_native_title_prefix(native_title,nonce)
    before=strict_bounds(expected_before_bounds,"expected CoreGraphics before bounds")
    requested=strict_bounds(requested_bounds,"requestedBounds")
    if not bounds_inside(requested):
        raise ObserverError("requested bounds are outside KG271U")
    ax_evidence=_validate_ax_mapping_evidence(ax_mapping,pid,window_id,native_title,before)
    arguments=["/usr/bin/osascript","-e",DIRECT_STP_APPLESCRIPT,"--",str(pid),str(window_id),native_title,
               str(before["x"]),str(before["y"]),str(before["width"]),str(before["height"]),
               str(requested["x"]),str(requested["y"]),str(requested["width"]),str(requested["height"])]
    if resize_only:
        arguments.append("resize-only")
    try:
        if runner is None:
            result=subprocess.run(arguments,capture_output=True,text=True,timeout=45)
        else:
            result=runner(arguments)
    except (OSError,subprocess.SubprocessError,TypeError,ValueError) as exc:
        raise ObserverError("direct STP Apple Event invocation failed") from exc
    operation="resize-only" if resize_only else "full"
    evidence=parse_direct_stp_result(result,pid,window_id,native_title,before,requested,operation)
    evidence["axBefore"]=ax_evidence
    evidence["fallbackReason"]="AXSize is not settable while AXPosition is settable; direct operation is resize-only"
    return evidence

def _identity_records_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not dict or type(expected) is not dict:
        return False
    fields=("pid","startTime","uid","commandDigest","bundleId","executable","signature")
    return all(type(actual.get(key)) is type(expected.get(key))
               and actual.get(key) == expected.get(key) for key in fields)

def _verify_direct_resize_target(windows_fn: Callable[[],list[dict[str,Any]]],
                                 process_fn: Callable[[int],dict[str,Any]],
                                 pid: int, window_id: int, native_title: str,
                                 expected_bounds: dict[str,int],
                                 expected_identity: dict[str,Any]|None) -> dict[str,Any]:
    """Prove the direct size-only write affected the same CG/started process."""
    records=windows_fn()
    if type(records) is not list:
        raise ObserverError("direct STP resize CoreGraphics response is malformed")
    matches=[]
    for record in records:
        if type(record) is not dict:
            raise ObserverError("direct STP resize CoreGraphics record is malformed")
        if record.get("pid") != pid or record.get("windowId") != window_id:
            continue
        if record.get("owner") != "Safari Technology Preview" or not visible_alpha(record):
            continue
        if record.get("name") != native_title:
            continue
        matches.append(record)
    if len(matches) != 1:
        raise ObserverError("direct STP resize target disappeared or became ambiguous")
    observed=strict_window_bounds(matches[0],"direct STP resize bounds")
    expected=strict_bounds(expected_bounds,"expected direct STP resize bounds")
    if observed != expected:
        raise ObserverError("direct STP resize readback is not exact")
    if expected_identity is None:
        raise ObserverError("direct STP resize requires immutable process identity")
    identity=process_fn(pid)
    if (type(identity) is not dict or identity.get("pid") != pid
            or type(identity.get("startTime")) is not str or not identity.get("startTime")):
        raise ObserverError("direct STP resize process identity is incomplete")
    if expected_identity is not None and not _identity_records_equal(identity,expected_identity):
        raise ObserverError("direct STP resize process identity changed or PID was reused")
    return {"window":copy.deepcopy(matches[0]),"bounds":observed,"identity":copy.deepcopy(identity)}

def _run_cgevent_move(helper_fd: int, helper_digest: str, helper_device: int,
                      helper_inode: int, pid: int, window_id: int, nonce: str,
                      native_title: str, requested: dict[str,int],
                      position_before: dict[str,int], expected_identity: dict[str,Any]|None,
                      windows_fn: Callable[[],list[dict[str,Any]]] | None,
                      process_fn: Callable[[int],dict[str,Any]] | None) -> tuple[dict[str,Any],dict[str,Any]]:
    """Run one typed CGEvent fallback and immediately rebind its post-state."""
    if expected_identity is None:
        raise ObserverError("CGEvent fallback requires immutable process identity")
    before=strict_bounds(position_before,"CGEvent fallback before bounds")
    requested=strict_bounds(requested,"CGEvent fallback requested bounds")
    identity_reader=process_fn or process_identity
    current_identity=identity_reader(pid)
    if not _identity_records_equal(current_identity,expected_identity):
        raise ObserverError("CGEvent fallback process identity changed or PID was reused")
    move_argv=["improvedtube-aqua-ax-helper",str(pid),str(window_id),nonce,native_title,
               str(requested["x"]),str(requested["y"]),str(requested["width"]),
               str(requested["height"]),"cgevent-titlebar"]
    _validate_helper_fd(helper_fd,helper_digest,helper_device,helper_inode)
    move_result=_run_helper_fd(helper_fd,helper_digest,helper_device,helper_inode,move_argv)
    _validate_helper_fd(helper_fd,helper_digest,helper_device,helper_inode)
    move_evidence=parse_ax_helper_result(move_result,pid,window_id,nonce,requested,native_title,before)
    if move_evidence.get("operation") != "cgevent-titlebar":
        raise ObserverError("native CGEvent fallback response is not exact")
    post_windows=windows_fn or _swift_windows
    post_process=process_fn or process_identity
    post_check=_verify_direct_resize_target(post_windows,post_process,pid,window_id,native_title,
                                            requested,expected_identity)
    return move_evidence,post_check

def place_stp_window(pid: int, window_id: int, nonce: str, requested_bounds: dict[str, int],
                     helper_fd: int|None=None, helper_digest: str|None=None,
                     helper_device: int|None=None, helper_inode: int|None=None,
                     helper_path: Path|str|None=None,
                     expected_native_title: str|None=None,
                     expected_before_bounds: dict[str,int]|None=None,
                     direct_placer: Callable[...,dict[str,Any]]|None=None,
                     windows_fn: Callable[[],list[dict[str,Any]]]|None=None,
                     process_fn: Callable[[int],dict[str,Any]]|None=None,
                     expected_identity: dict[str,Any]|None=None,
                     empty_cg_title:bool=False) -> dict[str, Any]:
    """Split size and position placement for one exact STP AX window.

    The native helper always authenticates the title/geometry/identity before
    mutation.  It writes position through AX.  If and only if AX reports that
    the dimensions differ and AXSize is explicitly not settable, the fixed
    STP Apple Event changes dimensions at the existing position; a second
    native helper invocation then performs the AX position write.
    """
    if type(pid) is not int or pid < 1:
        raise ObserverError("placement PID must be a positive integer")
    if type(window_id) is not int or window_id < 1:
        raise ObserverError("placement window ID must be a positive integer")
    nonce = strict_title_nonce(nonce)
    if type(empty_cg_title) is not bool:raise ObserverError("empty-title placement flag is malformed")
    if empty_cg_title:
        if expected_native_title!="":raise ObserverError("empty-title placement requires exact empty native title")
        native_title=""
    else:native_title = strict_native_title(expected_native_title if expected_native_title is not None else nonce)
    bounds = strict_bounds(requested_bounds, "requestedBounds")
    if not bounds_inside(bounds):
        raise ObserverError("requested bounds are outside KG271U")
    owned_fd=False;owned_path:Path|None=None
    if helper_fd is None:
        if helper_path is None:
            raise ObserverError("native AX helper fd is required")
        helper_fd,helper_digest,helper_device,helper_inode=_open_helper_path(helper_path)
        owned_fd=True;owned_path=Path(helper_path)
    elif helper_path is not None:
        raise ObserverError("native AX helper fd and path are mutually exclusive")
    if helper_digest is None or helper_device is None or helper_inode is None:
        if owned_fd:
            try:os.close(helper_fd)
            except OSError:pass
        raise ObserverError("native AX helper identity is required")
    execution_method="fd-memory-bundle"
    helper_digest=_strict_helper_digest(helper_digest)
    helper_operation="split"
    if expected_before_bounds is not None:
        expected_before=strict_bounds(expected_before_bounds,"expected CoreGraphics before bounds")
        if empty_cg_title and (expected_before["width"],expected_before["height"])!=(bounds["width"],bounds["height"]):
            raise ObserverError("empty-title placement forbids a resize fallback")
        if (expected_before["width"],expected_before["height"]) != (bounds["width"],bounds["height"]):
            helper_operation="resize-only"
    argv=["improvedtube-aqua-ax-helper",str(pid),str(window_id),nonce,native_title,
          str(bounds["x"]),str(bounds["y"]),str(bounds["width"]),str(bounds["height"]),helper_operation]
    if empty_cg_title:argv.append(EMPTY_CG_BINDING_MODE)
    try:
        _validate_helper_fd(helper_fd,helper_digest,helper_device,helper_inode)
        result=_run_helper_fd(helper_fd,helper_digest,helper_device,helper_inode,argv)
        _validate_helper_fd(helper_fd,helper_digest,helper_device,helper_inode)
        try:
            evidence=(parse_empty_title_ax_helper_result(result,pid,window_id,nonce,
                      strict_bounds(expected_before_bounds,"expected CoreGraphics before bounds"),helper_operation,bounds)
                      if empty_cg_title else
                      parse_ax_helper_result(result,pid,window_id,nonce,bounds,native_title,expected_before_bounds))
            if helper_operation == "resize-only":
                if evidence.get("operation") != "resize-only":
                    raise ObserverError("native AX resize-only response is not exact")
                intermediate=strict_bounds(evidence.get("intermediateBounds"),
                                           "native AX resize-only intermediate bounds")
                before=strict_bounds(evidence.get("before"),"native AX resize-only before bounds")
                if expected_before_bounds is None or before != strict_bounds(expected_before_bounds,"expected CoreGraphics before bounds"):
                    raise ObserverError("native AX resize-only pre-bounds are not exact")
                if intermediate != {"x":before["x"],"y":before["y"],
                                    "width":bounds["width"],"height":bounds["height"]}:
                    raise ObserverError("native AX resize-only intermediate bounds are not exact")
                resize_windows_fn=windows_fn or _swift_windows
                resize_process_fn=process_fn or process_identity
                resize_check=_verify_direct_resize_target(resize_windows_fn,resize_process_fn,pid,window_id,
                                                           native_title,intermediate,expected_identity)
                try:
                    move_argv=["improvedtube-aqua-ax-helper",str(pid),str(window_id),nonce,native_title,
                               str(bounds["x"]),str(bounds["y"]),str(bounds["width"]),str(bounds["height"]),"move-only"]
                    _validate_helper_fd(helper_fd,helper_digest,helper_device,helper_inode)
                    move_result=_run_helper_fd(helper_fd,helper_digest,helper_device,helper_inode,move_argv)
                    _validate_helper_fd(helper_fd,helper_digest,helper_device,helper_inode)
                    move_evidence=parse_ax_helper_result(move_result,pid,window_id,nonce,bounds,native_title,intermediate)
                    if move_evidence.get("operation") != "move-only":
                        raise ObserverError("native AX move-only response is not exact")
                    move_method="AX";cgevent_check=None;ax_move_evidence=move_evidence;cgevent_evidence=None
                except AXPositionIgnoredError as exc:
                    if exc.mapping.get("operation") != "move-only":
                        raise ObserverError("native AX position fallback operation is not exact") from exc
                    cgevent_evidence,cgevent_check=_run_cgevent_move(
                        helper_fd,helper_digest,helper_device,helper_inode,pid,window_id,nonce,
                        native_title,bounds,intermediate,expected_identity,windows_fn,process_fn)
                    move_evidence=cgevent_evidence;move_method="cgevent-titlebar";ax_move_evidence=exc.mapping
                evidence={"verified":True,"method":"split-placement","operation":"split",
                          "pid":pid,"windowId":window_id,"nativeTitle":native_title,
                          "requestedBounds":dict(bounds),"before":dict(before),
                          "intermediateBounds":dict(intermediate),"after":dict(move_evidence["after"]),
                          "resizeMethod":"AX","moveMethod":move_method,
                          "positionSettable":evidence.get("positionSettable"),
                          "sizeSettable":evidence.get("sizeSettable"),
                          "axResize":copy.deepcopy(evidence),"resizeRebind":copy.deepcopy(resize_check),
                          "axMove":copy.deepcopy(ax_move_evidence),
                          "mappingMethod":evidence.get("mappingMethod"),
                          "axWindowNumber":evidence.get("axWindowNumber"),
                          "candidateCount":evidence.get("candidateCount"),
                          "matchedCount":evidence.get("matchedCount"),
                          "fallbackReason":("AX size mutation rebound through CoreGraphics before AX move"
                                            if move_method == "AX" else
                                            "AX position setter returned success but exact readback was clamped or ignored"),
                          **({"cgeventMove":copy.deepcopy(cgevent_evidence),"cgeventPost":copy.deepcopy(cgevent_check)}
                             if cgevent_evidence is not None else {})}
            elif evidence.get("operation") is None:
                # Legacy helper responses are retained only for diagnostics;
                # they may be accepted without a rebind only when the helper
                # proved that no size mutation was needed.
                legacy_before=strict_bounds(evidence.get("before"),"legacy AX before bounds")
                if (legacy_before["width"],legacy_before["height"]) != (bounds["width"],bounds["height"]):
                    raise ObserverError("legacy AX response cannot resize without an intermediate rebind")
        except AXPositionIgnoredError as exc:
            # AX must have returned success and a typed, exact readback miss;
            # permission, mapping, and malformed results never reach this
            # narrow one-shot CGEvent fallback.
            if helper_operation != "split" or exc.mapping.get("operation") != "split":
                raise ObserverError("native AX position fallback phase is not exact") from exc
            position_before=strict_bounds(exc.mapping.get("before"),"AX fallback before bounds")
            cgevent_evidence,cgevent_check=_run_cgevent_move(
                helper_fd,helper_digest,helper_device,helper_inode,pid,window_id,nonce,
                native_title,bounds,position_before,expected_identity,windows_fn,process_fn)
            evidence={"verified":True,"method":"split-placement","operation":"split",
                      "pid":pid,"windowId":window_id,"nativeTitle":native_title,
                      "requestedBounds":dict(bounds),"before":dict(position_before),
                      "intermediateBounds":dict(position_before),"after":dict(cgevent_evidence["after"]),
                      "resizeMethod":"webDriver-existing","moveMethod":"cgevent-titlebar",
                      "positionSettable":True,"sizeSettable":exc.mapping.get("sizeSettable"),
                      "axMove":copy.deepcopy(exc.mapping),"cgeventMove":copy.deepcopy(cgevent_evidence),
                      "cgeventPost":copy.deepcopy(cgevent_check),
                      "mappingMethod":exc.mapping.get("mappingMethod"),
                      "axWindowNumber":exc.mapping.get("axWindowNumber"),
                      "candidateCount":exc.mapping.get("candidateCount"),
                      "matchedCount":exc.mapping.get("matchedCount"),
                      "fallbackReason":"AX position setter returned success but exact readback was clamped or ignored"}
        except AXResizeNotSettableError as exc:
            # Only a size mismatch with an explicitly settable AXPosition is
            # eligible.  The direct script is invoked in resize-only mode;
            # it is never allowed to establish or imply a negative position.
            resize_mapping=copy.deepcopy(exc.mapping)
            if expected_before_bounds is None:
                raise ObserverError("AX size is not settable and no immutable pre-bounds are available") from exc
            if resize_mapping.get("operation") != helper_operation:
                raise ObserverError("native AX resize failure operation is not exact") from exc
            fallback=direct_placer or direct_stp_window
            try:
                direct_evidence=fallback(pid,window_id,nonce,bounds,native_title=native_title,
                                         expected_before_bounds=expected_before_bounds,
                                         ax_mapping=resize_mapping,resize_only=True)
            except ObserverError:
                raise
            except Exception as fallback_exc:
                raise ObserverError("direct STP size-only fallback failed") from fallback_exc
            if (type(direct_evidence) is not dict or direct_evidence.get("verified") is not True
                    or direct_evidence.get("method") != "safari-direct-apple-event"
                    or direct_evidence.get("operation") != "resize-only"
                    or direct_evidence.get("positionMutated") is not False):
                raise ObserverError("direct STP fallback did not prove size-only mutation")
            before=strict_bounds(expected_before_bounds,"expected CoreGraphics before bounds")
            intermediate={"x":before["x"],"y":before["y"],
                          "width":bounds["width"],"height":bounds["height"]}
            if strict_bounds(direct_evidence.get("before"),"direct STP resize before bounds") != before:
                raise ObserverError("direct STP resize pre-bounds are not exact")
            if strict_bounds(direct_evidence.get("after"),"direct STP resize after bounds") != intermediate:
                raise ObserverError("direct STP resize did not preserve the existing position")
            if windows_fn is None:
                resize_windows_fn=_swift_windows
            else:
                resize_windows_fn=windows_fn
            if process_fn is None:
                resize_process_fn=process_identity
            else:
                resize_process_fn=process_fn
            resize_check=_verify_direct_resize_target(resize_windows_fn,resize_process_fn,pid,window_id,
                                                       native_title,intermediate,expected_identity)
            try:
                move_argv=["improvedtube-aqua-ax-helper",str(pid),str(window_id),nonce,native_title,
                           str(bounds["x"]),str(bounds["y"]),str(bounds["width"]),str(bounds["height"]),"move-only"]
                _validate_helper_fd(helper_fd,helper_digest,helper_device,helper_inode)
                move_result=_run_helper_fd(helper_fd,helper_digest,helper_device,helper_inode,move_argv)
                _validate_helper_fd(helper_fd,helper_digest,helper_device,helper_inode)
                move_evidence=parse_ax_helper_result(move_result,pid,window_id,nonce,bounds,native_title,intermediate)
                if move_evidence.get("operation") != "move-only":
                    raise ObserverError("native AX move-only response is not exact")
                move_method="AX";cgevent_check=None;ax_move_evidence=move_evidence;cgevent_evidence=None
            except AXPositionIgnoredError as exc:
                if exc.mapping.get("operation") != "move-only":
                    raise ObserverError("native AX position fallback operation is not exact") from exc
                cgevent_evidence,cgevent_check=_run_cgevent_move(
                    helper_fd,helper_digest,helper_device,helper_inode,pid,window_id,nonce,
                    native_title,bounds,intermediate,expected_identity,windows_fn,process_fn)
                move_evidence=cgevent_evidence;move_method="cgevent-titlebar";ax_move_evidence=exc.mapping
            evidence={"verified":True,"method":"split-placement","operation":"split",
                      "pid":pid,"windowId":window_id,"nativeTitle":native_title,
                      "requestedBounds":dict(bounds),"before":dict(before),
                      "intermediateBounds":dict(intermediate),"after":dict(move_evidence["after"]),
                      "resizeMethod":"stp-direct","moveMethod":move_method,
                      "positionSettable":True,"sizeSettable":False,
                      "axBefore":copy.deepcopy(resize_mapping),"directResize":copy.deepcopy(direct_evidence),
                      "directResizeCheck":copy.deepcopy(resize_check),"axMove":copy.deepcopy(ax_move_evidence),
                      "mappingMethod":resize_mapping.get("mappingMethod"),
                      "axWindowNumber":resize_mapping.get("axWindowNumber"),
                      "candidateCount":resize_mapping.get("candidateCount"),
                      "matchedCount":resize_mapping.get("matchedCount"),
                      "fallbackReason":("AXSize is not settable while AXPosition is settable"
                                        if move_method == "AX" else
                                        "AX position setter returned success but exact readback was clamped or ignored"),
                      **({"cgeventMove":copy.deepcopy(cgevent_evidence),"cgeventPost":copy.deepcopy(cgevent_check)}
                         if cgevent_evidence is not None else {})}
        except AXNotSettableError as exc:
            # The legacy combined not-settable result does not identify which
            # geometry component is safe.  Never use it to authorize a write.
            raise ObserverError("legacy AX not-settable response cannot authorize split placement") from exc
        if type(evidence) is not dict or evidence.get("verified") is not True:
            raise ObserverError("native AX placement evidence is incomplete")
        evidence["helperDigest"]=helper_digest
        evidence["helperDevice"] = helper_device
        evidence["helperInode"] = helper_inode
        evidence["helperExecution"] = execution_method
        return evidence
    except (OSError,subprocess.SubprocessError,UnicodeError) as exc:
        raise ObserverError("native STP AX helper invocation failed") from exc
    finally:
        if owned_fd:
            if owned_path is not None:
                _clear_helper_flags_if_same_path(owned_path,helper_device,helper_inode)
            try:os.close(helper_fd)
            except OSError:pass

def _swift_windows() -> list[dict[str, Any]]:
    swift=r'''import CoreGraphics
import Foundation
let raw=CGWindowListCopyWindowInfo([.optionOnScreenOnly,.excludeDesktopElements],kCGNullWindowID) as? [[String:Any]] ?? []
let windows=raw.compactMap { item -> [String:Any]? in
 guard let owner=item[kCGWindowOwnerName as String] as? String,owner=="Safari Technology Preview" else{return nil}
 guard (item[kCGWindowLayer as String] as? NSNumber)?.intValue == 0 else{return nil}
 guard let b=item[kCGWindowBounds as String] as? [String:Any] else{return nil}
 func n(_ k:String)->Double{(b[k] as? NSNumber)?.doubleValue ?? 0}
 return ["owner":owner,"name":item[kCGWindowName as String] as? String ?? "","pid":(item[kCGWindowOwnerPID as String] as? NSNumber)?.intValue ?? -1,"windowId":(item[kCGWindowNumber as String] as? NSNumber)?.intValue ?? -1,"layer":0,"alpha":(item[kCGWindowAlpha as String] as? NSNumber)?.doubleValue ?? 0,"x":n("X"),"y":n("Y"),"width":n("Width"),"height":n("Height")]
}
let d=try! JSONSerialization.data(withJSONObject:windows);print(String(data:d,encoding:.utf8)!)'''
    p=subprocess.run(["/usr/bin/swift","-e",swift],capture_output=True,text=True,timeout=45)
    if p.returncode:
        raise ObserverError("CoreGraphics inspection failed")
    value=json.loads(p.stdout)
    if not isinstance(value,list): raise ObserverError("CoreGraphics returned no window list")
    return value

def _stp_pids() -> list[int]:
    result=subprocess.run(["/usr/bin/pgrep","-x","Safari Technology Preview"],capture_output=True,text=True,timeout=10)
    if result.returncode not in {0,1} or result.stderr!="":raise ObserverError("STP process inventory failed")
    if result.returncode==1:
        if result.stdout!="":raise ObserverError("STP process inventory is malformed")
        return []
    pids=[]
    for line in result.stdout.splitlines():
        if not line or not line.isascii() or not line.isdecimal() or str(int(line))!=line or int(line)<1:
            raise ObserverError("STP process inventory is malformed")
        pids.append(int(line))
    if len(pids)!=len(set(pids)):raise ObserverError("STP process inventory contains duplicates")
    return sorted(pids)

def process_executable_path(pid: int) -> str:
    """Return the kernel-reported executable path for *pid* on macOS.

    The command line is not an identity boundary: an unrelated process can
    put the expected executable path in an argument. ``proc_pidpath`` is the
    independent process API that gives us the path of the executable actually
    associated with the PID.
    """
    if sys.platform != "darwin":
        raise ObserverError("macOS proc_pidpath is required")
    try:
        libproc=ctypes.CDLL("/usr/lib/libproc.dylib")
        fn=libproc.proc_pidpath
        fn.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32]
        fn.restype=ctypes.c_int
        buffer=ctypes.create_string_buffer(4096)
        length=fn(pid,buffer,len(buffer))
    except (AttributeError,OSError):
        raise ObserverError("process executable lookup failed")
    if type(length) is not int or length <= 0:
        raise ObserverError("process executable lookup failed")
    try:
        path=os.fsdecode(buffer.value)
    except (TypeError,UnicodeDecodeError):
        raise ObserverError("process executable lookup failed")
    if not path or "\x00" in path:
        raise ObserverError("process executable lookup failed")
    return path

def process_bundle_signature(executable_path: str) -> dict[str,Any]:
    """Verify the exact STP bundle, executable, and Apple designated requirement."""
    try:
        executable=Path(executable_path)
        if executable.parent.name!="MacOS" or executable.parent.parent.name!="Contents":
            raise ObserverError("process executable is not inside an app bundle")
        bundle=executable.parent.parent.parent
        if bundle.suffix!=".app":
            raise ObserverError("process executable is not inside an app bundle")
        with (bundle/"Contents"/"Info.plist").open("rb") as handle:
            info=plistlib.load(handle)
        plist_id=info.get("CFBundleIdentifier") if isinstance(info,dict) else None
        if type(plist_id) is not str or not plist_id:
            raise ObserverError("process bundle identity is unavailable")
        display=subprocess.run(["/usr/bin/codesign","--display","--verbose=4",str(bundle)],capture_output=True,text=True,timeout=10)
        verify_bundle=subprocess.run(["/usr/bin/codesign","--verify","--deep","--strict","--all-architectures","--verbose=4",str(bundle)],capture_output=True,text=True,timeout=30)
        verify_executable=subprocess.run(["/usr/bin/codesign","--verify","--strict","--all-architectures","--verbose=4",str(executable)],capture_output=True,text=True,timeout=10)
        verify_requirement=subprocess.run(["/usr/bin/codesign","--verify","--deep","--strict","--all-architectures",
                                          "-R="+STP_DESIGNATED_REQUIREMENT,str(bundle)],capture_output=True,text=True,timeout=30)
        requirement=subprocess.run(["/usr/bin/codesign","-d","-r-",str(bundle)],capture_output=True,text=True,timeout=10)
        display_lines=(display.stderr or "").splitlines()
        signed_id=display_executable=team_identifier=None
        authorities=[]
        for line in display_lines:
            if line.startswith("Executable="):display_executable=line.split("=",1)[1]
            elif line.startswith("Identifier="):signed_id=line.split("=",1)[1]
            elif line.startswith("Authority="):authorities.append(line.split("=",1)[1])
            elif line.startswith("TeamIdentifier="):team_identifier=line.split("=",1)[1]
        # ``codesign -d -r-`` has emitted the requirement on stdout on the
        # installed STP image (while other display fields are on stderr), so
        # inspect both streams and require exactly one designated expression.
        designated_lines=[line.strip() for line in ((requirement.stdout or "")+"\n"+(requirement.stderr or "")).splitlines() if line.strip().startswith("designated => ")]
        designated=designated_lines[0][len("designated => "):] if len(designated_lines)==1 else None
        signature={"bundlePath":str(bundle),"executablePath":str(executable),"plistIdentifier":plist_id,
                   "signedIdentifier":signed_id,"displayExecutable":display_executable,
                   "authorities":list(authorities),"teamIdentifier":team_identifier,
                   "designatedRequirement":designated,
                   "bundleVerified":type(verify_bundle.returncode) is int and verify_bundle.returncode==0,
                   "executableVerified":type(verify_executable.returncode) is int and verify_executable.returncode==0,
                   "requirementVerified":type(verify_requirement.returncode) is int and verify_requirement.returncode==0,
                   "strict":True,"deep":True,"allArchitectures":True}
        if (type(display.returncode) is not int or display.returncode!=0
                or not signature["bundleVerified"] or not signature["executableVerified"] or not signature["requirementVerified"]
                or display_executable!=str(executable) or signed_id!=plist_id or plist_id!=STP_BUNDLE_ID
                or designated!=STP_DESIGNATED_REQUIREMENT
                or any(authority not in authorities for authority in STP_REQUIRED_AUTHORITIES)
                or authorities[:1]!=["Software Signing"] or team_identifier!="not set"):
            raise ObserverError("STP bundle signature verification or designated requirement failed")
        signature["valid"]=True
        return signature
    except ObserverError:
        raise
    except (AttributeError,OSError,ValueError,TypeError,plistlib.InvalidFileException,subprocess.SubprocessError):
        raise ObserverError("process bundle identity lookup failed")

def process_bundle_identifier(executable_path: str) -> str:
    """Return the plist identifier only after strict Apple signature verification."""
    return process_bundle_signature(executable_path)["plistIdentifier"]

def signature_evidence_valid(signature: Any) -> bool:
    return (type(signature) is dict and signature.get("valid") is True
            and signature.get("bundlePath")==str(STP_APP)
            and signature.get("executablePath")==STP_EXECUTABLE
            and signature.get("plistIdentifier")==STP_BUNDLE_ID
            and signature.get("signedIdentifier")==STP_BUNDLE_ID
            and signature.get("displayExecutable")==STP_EXECUTABLE
            and signature.get("designatedRequirement")==STP_DESIGNATED_REQUIREMENT
            and signature.get("bundleVerified") is True
            and signature.get("executableVerified") is True
            and signature.get("requirementVerified") is True
            and signature.get("strict") is True and signature.get("deep") is True
            and signature.get("allArchitectures") is True
            and signature.get("teamIdentifier")=="not set"
            and type(signature.get("authorities")) is list
            and signature["authorities"][:1]==["Software Signing"]
            and all(authority in signature["authorities"] for authority in STP_REQUIRED_AUTHORITIES))

def process_identity(pid: int) -> dict[str, Any]:
    if type(pid) is not int or pid < 1: raise ObserverError("invalid Safari PID")
    try:
        p=subprocess.run(["/bin/ps","-p",str(pid),"-o","lstart=","-o","command="],capture_output=True,text=True,timeout=10)
    except (OSError,subprocess.SubprocessError) as exc:
        raise ObserverError("Safari PID identity lookup failed") from exc
    try:
        returncode,stdout,stderr=p.returncode,p.stdout,p.stderr
    except AttributeError:
        raise ObserverError("Safari PID identity lookup returned malformed result")
    if type(returncode) is not int or type(stdout) is not str or type(stderr) is not str:
        raise ObserverError("Safari PID identity lookup returned malformed result")
    if returncode != 0:
        if returncode == 1 and stdout == "" and stderr == "":
            raise ProcessExitedError("Safari PID is not running")
        raise ObserverError("Safari PID identity lookup failed")
    if stderr != "": raise ObserverError("Safari PID identity lookup returned diagnostic output")
    if not stdout.strip(): raise ObserverError("Safari PID identity lookup returned empty result")
    line=stdout.strip()
    parts=line.split(None,5)
    start=" ".join(parts[:5]) if len(parts)>=5 else ""
    command=parts[5] if len(parts)>=6 else line
    if len(parts)<6 or not start.strip() or not command.strip():
        raise ObserverError("Safari PID identity lookup returned malformed result")
    try:
        uidp=subprocess.run(["/bin/ps","-p",str(pid),"-o","uid="],capture_output=True,text=True,timeout=10)
    except (OSError,subprocess.SubprocessError) as exc:
        raise ObserverError("Safari PID UID lookup failed") from exc
    try:
        if (type(uidp.returncode) is not int or uidp.returncode != 0 or type(uidp.stdout) is not str
                or type(uidp.stderr) is not str or uidp.stderr != "" or not uidp.stdout.strip()):
            raise ObserverError("Safari PID UID lookup failed")
        uid=int(uidp.stdout.strip())
    except AttributeError:
        raise ObserverError("Safari PID UID lookup returned malformed result")
    except ValueError:
        raise ObserverError("Safari PID UID lookup returned malformed result")
    executable=process_executable_path(pid)
    if executable != STP_EXECUTABLE: raise ObserverError("PID is not the Safari Technology Preview executable")
    signature=process_bundle_signature(executable)
    if not signature_evidence_valid(signature): raise ObserverError("PID is not backed by a verified Apple STP signature")
    bundle_id=signature["plistIdentifier"]
    if bundle_id != STP_BUNDLE_ID: raise ObserverError("PID is not the Safari Technology Preview bundle")
    return {"pid":pid,"startTime":start,"uid":uid,"commandDigest":hashlib.sha256(command.encode()).hexdigest(),
            "bundleId":bundle_id,"executable":executable,"signature":copy.deepcopy(signature)}

def peer_uid(conn: socket.socket) -> int:
    if sys.platform != "darwin":
        raise ObserverError("macOS getpeereid is required")
    libc=ctypes.CDLL(None)
    fn=getattr(libc,"getpeereid",None)
    if fn is None: raise ObserverError("getpeereid is unavailable")
    euid=ctypes.c_uint(0);egid=ctypes.c_uint(0)
    fn.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_uint),ctypes.POINTER(ctypes.c_uint)]
    fn.restype=ctypes.c_int
    if fn(conn.fileno(),ctypes.byref(euid),ctypes.byref(egid)) != 0: raise ObserverError("peer credential lookup failed")
    return int(euid.value)

def write_capability(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True,exist_ok=True)
    old=os.umask(0o177)
    try:
        path.write_text(value+"\n")
        os.chmod(path,0o600)
    finally: os.umask(old)

def validate_socket_placement(socket_path: Path) -> None:
    """Only use a one-run socket directly in the root-owned sticky /tmp."""
    path=Path(socket_path)
    if path.parent != Path("/tmp") or not path.name or path.name in {".",".."}:
        raise ObserverError("observer socket must be directly under /tmp")
    try:
        stat=os.stat(path.parent)
    except OSError as exc:
        raise ObserverError("observer socket directory is unavailable") from exc
    mode=stat.st_mode
    if stat.st_uid != 0 or not (mode & 0o1000) or not (mode & 0o0002):
        raise ObserverError("observer socket directory is not root-owned sticky /tmp")

class AquaObserver:
    def __init__(self, socket_path: Path, run_id: str, capability: str, peer_uid_expected: int,
                 peer_gid: int|None=None, windows_fn: Callable[[],list[dict[str,Any]]]|None=None,
                 process_fn: Callable[[int],dict[str,Any]]|None=None,
                 peer_fn: Callable[[socket.socket],int]|None=None,
                 placer: Callable[[int,int,str,dict[str,int]],dict[str,Any]]|None=None,
                 ax_windows_fn: Callable[[int,int,str],list[dict[str,Any]]]|None=None,
                 ax_helper: Path|str|None=None, ax_helper_fd: int|None=None,
                 ax_helper_digest: str|None=None, ax_helper_device: int|None=None,
                 ax_helper_inode: int|None=None,
                 direct_placer: Callable[...,dict[str,Any]]|None=None,
                 stp_pids_fn:Callable[[],list[int]]|None=None):
        if not run_id or not capability: raise ValueError("run id and capability are required")
        if type(peer_uid_expected) is not int or peer_uid_expected < 1: raise ValueError("expected peer UID is required")
        self.socket_path=socket_path;self.run_id=run_id;self.capability=capability
        self.peer_uid_expected=peer_uid_expected;self.peer_gid=peer_gid
        self.windows_fn=windows_fn or _swift_windows;self.process_fn=process_fn or process_identity;self.peer_fn=peer_fn or peer_uid
        self.ax_helper=ax_helper;self.ax_windows_fn=ax_windows_fn
        self.ax_helper_fd=ax_helper_fd;self.ax_helper_digest=ax_helper_digest
        self.ax_helper_device=ax_helper_device;self.ax_helper_inode=ax_helper_inode
        self.direct_placer=direct_placer or direct_stp_window
        # Production inventories the process namespace as well as CG windows.
        # Injected window inventories are test seams and default to no process;
        # callers can inject stp_pids_fn when process inventory is under test.
        self.stp_pids_fn=stp_pids_fn or (_stp_pids if windows_fn is None else lambda:[])
        self._placement_native_title: str|None = None
        self._placement_before_bounds: dict[str,int]|None = None
        self._placement_identity_before: dict[str,Any]|None = None
        self._placement_empty_cg_title=False
        self.placer=placer or (lambda pid,window_id,title,bounds:place_stp_window(
            pid,window_id,title,bounds,helper_fd=self.ax_helper_fd,
            helper_digest=self.ax_helper_digest,helper_device=self.ax_helper_device,
            helper_inode=self.ax_helper_inode,helper_path=self.ax_helper,
            expected_native_title=self._placement_native_title,
            expected_before_bounds=self._placement_before_bounds,
            direct_placer=self.direct_placer,windows_fn=self.windows_fn,
            process_fn=self.process_fn,expected_identity=self._placement_identity_before,
            empty_cg_title=self._placement_empty_cg_title))
        self.active_uid=os.getuid()
        self.request_sequence=1;self.response_sequence=0;self.phase="created";self.lease:dict[str,Any]|None=None
        self.baseline_nonce:str|None=None;self.baseline_clear=False
        self.baseline_binding_mode:str|None=None
        self.baseline_inventory:list[dict[str,Any]]=[]
        self.baseline_stp_inventory:list[dict[str,Any]]=[]
        self.baseline_stp_process_inventory:list[dict[str,Any]]=[]
        self.title_probe_count=0
        self.title_probe_nonce:str|None=None
        self.title_probe_candidate:dict[str,Any]|None=None
        self.title_probe:dict[str,Any]|None=None
        self.empty_title_selection_attempted=False
        self.provisional:dict[str,Any]|None=None
        self.placement_count=0
        self.finalized=False;self.failed=False;self.server:socket.socket|None=None;self.peer_uid_actual: int|None=None

    def _canonical(self, operation: str, ok: bool, reason: str|None=None, *,
                   matching_count: int=0, target: dict[str,Any]|None=None,
                   contained: bool=False, identity: dict[str,Any]|None=None, expired: bool=False) -> dict[str,Any]:
        self.response_sequence += 1
        mono,wall=now()
        lease=self.lease or {}
        bound_identity=identity if type(identity) is dict else lease.get("identity")
        item={"runId":self.run_id,"sequence":self.response_sequence,"monotonicNs":mono,"wallTime":wall,
              "operation":operation,"ok":ok,"expired":expired,"peerUid":self.peer_uid_actual,
              "pid":lease.get("pid"),"processStartTime":lease.get("processStartTime"),
              "windowId":lease.get("windowId"),"titleNonce":lease.get("titleNonce"),
              "nativeTitle":lease.get("nativeTitle"),"derivedPrefix":lease.get("derivedPrefix"),
              "bindingMode":lease.get("bindingMode"),
              "bounds":dict(target) if type(target) is dict else target,
              "requestedBounds":dict(lease["requestedBounds"]) if type(lease.get("requestedBounds")) is dict else lease.get("requestedBounds"),
              "displayContained":contained,"matchingCount":matching_count,
              "identity":copy.deepcopy(bound_identity) if type(bound_identity) is dict else bound_identity}
        if reason: item["reason"]=reason
        return item

    def _send(self, conn: socket.socket, item: dict[str,Any]) -> None:
        authenticated=dict(item)
        authenticated.pop("responseMac",None)
        unsigned=json.dumps(authenticated,separators=(",",":"),sort_keys=True).encode()
        authenticated["responseMac"]=hmac.new(self.capability.encode(),unsigned,hashlib.sha256).hexdigest()
        data=(json.dumps(authenticated,separators=(",",":"))+"\n").encode()
        if len(data)>MAX_FRAME: raise ObserverError("response too large")
        conn.sendall(data)

    def _receive(self, conn: socket.socket) -> dict[str,Any]:
        data=b""
        while b"\n" not in data:
            chunk=conn.recv(8192)
            if not chunk: raise ObserverError("peer disconnected")
            data+=chunk
            if len(data)>MAX_FRAME: raise ObserverError("request too large")
        line=data.split(b"\n",1)[0]
        try: value=json.loads(line.decode())
        except (UnicodeDecodeError,json.JSONDecodeError): raise ObserverError("malformed request")
        if not isinstance(value,dict): raise ObserverError("request must be an object")
        return value

    def _auth(self, request: dict[str,Any]) -> None:
        if request.get("runId") != self.run_id: raise ObserverError("run id mismatch")
        supplied=request.get("capability")
        if type(supplied) is not str or not hmac.compare_digest(supplied,self.capability): raise ObserverError("capability mismatch")
        sequence=request.get("sequence")
        if type(sequence) is not int or sequence != self.request_sequence: raise ObserverError("stale or out-of-order request sequence")
        self.request_sequence += 1

    def authenticate_peer(self, conn: socket.socket) -> None:
        actual=self.peer_fn(conn);self.peer_uid_actual=actual
        if type(actual) is not int or actual!=self.peer_uid_expected:raise ObserverError("peer UID mismatch")

    def _windows(self) -> list[dict[str,Any]]:
        value=self.windows_fn()
        if not isinstance(value,list): raise ObserverError("malformed CoreGraphics window response")
        return value

    def _identity(self, pid:int)->dict[str,Any]:
        identity=self.process_fn(pid)
        if type(identity) is not dict or type(identity.get("pid")) is not int or identity.get("pid")!=pid:
            raise ObserverError("incomplete PID start identity")
        if type(identity.get("startTime")) is not str or not identity["startTime"].strip():
            raise ObserverError("incomplete PID start identity")
        if type(identity.get("commandDigest")) is not str or not identity["commandDigest"].strip():
            raise ObserverError("incomplete process identity")
        if identity.get("bundleId")!=STP_BUNDLE_ID or identity.get("executable")!=STP_EXECUTABLE:
            raise ObserverError("normal Safari or non-STP process is not eligible")
        if not signature_evidence_valid(identity.get("signature")):
            raise ObserverError("STP process signature evidence is incomplete or invalid")
        if type(identity.get("uid")) is not int or identity.get("uid")!=self.active_uid:
            raise ObserverError("STP process is not owned by active Aqua user")
        return identity

    def _same_identity(self, identity: Any, expected: Any) -> bool:
        if type(identity) is not dict or type(expected) is not dict:
            return False
        fields=("pid","startTime","uid","commandDigest","bundleId","executable","signature")
        return all(type(identity.get(key)) is type(expected.get(key)) and identity.get(key)==expected.get(key) for key in fields)

    def _stp_processes(self)->list[dict[str,Any]]:
        pids=self.stp_pids_fn()
        if (type(pids) is not list or any(type(pid) is not int or pid<1 for pid in pids)
                or len(pids)!=len(set(pids)) or pids!=sorted(pids)):
            raise ObserverError("STP process inventory is malformed")
        return [copy.deepcopy(self._identity(pid)) for pid in pids]

    def _webdriver_binding(self,request:dict[str,Any],nonce:str)->dict[str,Any]:
        pid=request.get("webdriverBrowserPid");handle=request.get("webdriverWindowHandle")
        handles=request.get("webdriverWindowHandles");document_title=request.get("webdriverDocumentTitle")
        if (type(pid) is not int or pid<1 or type(handle) is not str or not handle
                or type(handles) is not list or handles!=[handle]
                or type(document_title) is not str or document_title!=nonce):
            raise ObserverError("empty-CG-title binding requires exact one-handle WebDriver PID and document title")
        return {"browserPid":pid,"windowHandle":handle,"windowHandles":[handle],"documentTitle":document_title}

    def _empty_title_ax_evidence(self,pid:int,window_id:int,nonce:str,bounds:dict[str,int])->dict[str,Any]:
        bounds=strict_bounds(bounds,"empty-title CoreGraphics bounds")
        if self.ax_windows_fn is not None:
            records=self.ax_windows_fn(pid,window_id,nonce)
            if type(records) is not list or not records:raise ObserverError("empty-title AX enumeration is unavailable")
            seen:set[int]=set();normalized=[];matches=[]
            for record in records:
                raw_bounds=record.get("bounds") if type(record) is dict else None
                if raw_bounds is None and type(record) is dict and set(record)>=BOUND_KEYS:
                    raw_bounds={key:record.get(key) for key in BOUND_KEYS}
                title=record.get("title") if type(record) is dict else None
                number=record.get("axWindowNumber") if type(record) is dict else None
                if (type(record) is not dict or record.get("owner")!="Safari Technology Preview"
                        or record.get("bundleId")!=STP_BUNDLE_ID or record.get("pid")!=pid
                        or type(number) is not int or number<1 or number in seen or type(title) is not str
                        or any(ord(char)<0x20 or ord(char)==0x7f for char in title)):
                    raise ObserverError("empty-title AX window identity is not exact")
                seen.add(number);record_bounds=strict_bounds(raw_bounds,"empty-title AX test bounds")
                normalized.append({"pid":pid,"axWindowNumber":number,"title":title,"bounds":record_bounds})
                if number==window_id and title not in {"",nonce}:
                    raise ObserverError("empty-title AX title contradicts WebDriver document title")
                if number==window_id and record_bounds!=bounds:
                    raise ObserverError("empty-title AX geometry contradicts CoreGraphics")
                if number==window_id and record_bounds==bounds and title in {"",nonce}:
                    matches.append((record,title))
            if not matches:
                return {"verified":True,"operation":"inspect-empty-cg-title","bindingMode":EMPTY_CG_BINDING_MODE,
                        "mappingStatus":"unmapped","pid":pid,"windowId":window_id,"titleNonce":nonce,
                        "nativeTitle":"","cgBefore":dict(bounds),"candidateCount":len(normalized),
                        "matchedCount":0,"candidates":copy.deepcopy(normalized),"mutationAttempted":False}
            if len(matches)!=1:raise ObserverError("empty-title AX mapping is ambiguous")
            record,title=matches[0]
            return {"verified":True,"operation":"inspect-empty-cg-title","bindingMode":EMPTY_CG_BINDING_MODE,
                    "mappingStatus":"mapped",
                    "pid":pid,"windowId":window_id,"axWindowNumber":window_id,
                    "mappingMethod":"ax-window-number-empty-cg-title","titleNonce":nonce,
                    "nativeTitle":"","titleEvidence":"ax-title" if title==nonce else "webdriver-document-title",
                    "before":dict(bounds),"cgBefore":dict(bounds),"candidateCount":1,"matchedCount":1,
                    "candidates":[copy.deepcopy(record)],"mutationAttempted":False}
        if None in {self.ax_helper_fd,self.ax_helper_digest,self.ax_helper_device,self.ax_helper_inode}:
            raise ObserverError("native STP AX helper identity is required for empty-title binding")
        return inspect_empty_title_ax_helper(self.ax_helper_fd,self.ax_helper_digest,
            self.ax_helper_device,self.ax_helper_inode,pid,window_id,nonce,bounds)

    def _empty_title_candidate_selection(self,request:dict[str,Any],nonce:str,phase:str)->dict[str,Any]:
        """Select one unnamed CG record only through exact AXWindowNumber mapping."""
        webdriver=self._webdriver_binding(request,nonce)
        before=self._stp_windows()
        evidence={"phase":phase,"decision":"rejected","mappedCount":0,"stableInventory":False,
                  "webdriver":copy.deepcopy(webdriver),"inventoryBefore":copy.deepcopy(before),
                  "inventoryAfter":None,"candidateOutcomes":[],"selected":None}
        if not before:
            evidence.update({"decision":"pending","stableInventory":True,"inventoryAfter":[]})
            return evidence
        keys=[]
        for item in before:
            key=(item.get("pid"),item.get("windowId"))
            if key in keys:
                evidence["reason"]="duplicate unnamed CoreGraphics candidate identity"
                return evidence
            keys.append(key)
            if item.get("name")!="":
                evidence["reason"]="named STP record is ambiguous during empty-title binding"
                return evidence
            if item.get("pid")!=webdriver["browserPid"]:
                evidence["reason"]="unnamed STP record PID differs from WebDriver browser PID"
                return evidence
            if not self._same_identity(item.get("identity"),self._identity(item["pid"])):
                evidence["reason"]="empty-title candidate process identity changed"
                return evidence
        hard_error=False
        for item in sorted(before,key=lambda value:(value["pid"],value["windowId"])):
            bounds=strict_window_bounds(item,"empty-title selection candidate bounds")
            outcome={"pid":item["pid"],"windowId":item["windowId"],"cgBounds":dict(bounds),
                     "processIdentity":copy.deepcopy(item["identity"])}
            try:
                mapping=self._empty_title_ax_evidence(item["pid"],item["windowId"],nonce,bounds)
            except ObserverError as exc:
                hard_error=True;outcome.update({"mappingStatus":"error",
                    "helperFailure":{"type":type(exc).__name__,"message":str(exc)}})
            else:
                status=mapping.get("mappingStatus")
                if status not in {"mapped","unmapped"}:raise ObserverError("empty-title AX mapping status is malformed")
                outcome.update({"mappingStatus":status,"axEvidence":copy.deepcopy(mapping)})
            evidence["candidateOutcomes"].append(outcome)
        after=self._stp_windows();evidence["inventoryAfter"]=copy.deepcopy(after)
        canonical=lambda items:sorted(json.dumps(item,separators=(",",":"),sort_keys=True) for item in items)
        evidence["stableInventory"]=canonical(before)==canonical(after)
        mapped=[item for item in evidence["candidateOutcomes"] if item.get("mappingStatus")=="mapped"]
        evidence["mappedCount"]=len(mapped)
        if hard_error:
            evidence["reason"]="empty-title AX candidate inspection failed"
        elif not evidence["stableInventory"]:
            evidence.update({"decision":"pending" if phase=="title-probe" else "rejected",
                             "reason":"empty-title candidate inventory changed during AX scan"})
        elif len(mapped)==0:
            evidence.update({"decision":"pending" if phase=="title-probe" else "rejected",
                             "reason":"no unnamed CoreGraphics candidate maps to one AX window"})
        elif len(mapped)>1:
            evidence["reason"]="multiple unnamed CoreGraphics candidates map to AX windows"
        else:
            chosen=mapped[0];candidate=next(item for item in before
                if item["pid"]==chosen["pid"] and item["windowId"]==chosen["windowId"])
            evidence.update({"decision":"selected","selected":{"candidate":copy.deepcopy(candidate),
                             "axMapping":copy.deepcopy(chosen["axEvidence"])}})
        return evidence

    def _stp_windows(self) -> list[dict[str,Any]]:
        """Return the complete visible signed-STP layer-0 inventory.

        This is deliberately independent of the document nonce.  A late run
        must establish that no pre-existing STP main window can be confused
        with the driver-created instance, then authenticate every discovered
        STP owner before title binding.
        """
        windows=self._windows();inventory=[];identities:dict[int,dict[str,Any]]={}
        for window in windows:
            if type(window) is not dict:
                raise ObserverError("malformed CoreGraphics window record")
            owner=window.get("owner")
            if type(owner) is not str:
                raise ObserverError("window owner must be a string")
            if owner!="Safari Technology Preview":
                continue
            if type(window.get("pid")) is not int or type(window.get("windowId")) is not int:
                raise ObserverError("STP window identity fields must be integers")
            if window["pid"]<1 or window["windowId"]<1:
                raise ObserverError("STP window identity fields must be positive integers")
            layer=window.get("layer",0)
            if type(layer) is not int:raise ObserverError("STP window layer must be an integer")
            if layer!=0:continue
            if not visible_alpha(window):
                continue
            raw_name=window.get("name")
            if type(raw_name) is not str or any(ord(char) < 0x20 or ord(char)==0x7f for char in raw_name):
                raise ObserverError("STP native title is malformed")
            # CoreGraphics exposes unnamed layer-0 chrome/desktop records for
            # a live STP process.  Preserve those records in the immutable
            # inventory, but never allow an unnamed auxiliary record to be a
            # title/geometry target.
            name=raw_name
            if name:
                name=strict_native_title(name,"STP native title")
            bounds=strict_window_bounds(window,"STP window bounds")
            pid=window["pid"]
            identity=identities.get(pid)
            if identity is None:
                identity=self._identity(pid);identities[pid]=copy.deepcopy(identity)
            record=copy.deepcopy(window)
            record.update({"name":name,"pid":pid,"windowId":window["windowId"],
                           "bounds":dict(bounds),"identity":copy.deepcopy(identity),
                           "targetEligible":bool(name)})
            inventory.append(record)
        return inventory

    def _derive_probe_prefix(self, native_title: Any, nonce: Any) -> str:
        return derive_native_title_prefix(native_title,nonce)

    def _visible_target(self, pid: int, window_id: int, nonce: str|None = None) -> tuple[dict[str,Any]|None,int]:
        windows=self._windows()
        candidates=[]
        for window in windows:
            if type(window) is not dict:
                raise ObserverError("malformed CoreGraphics window record")
            if type(window.get("pid")) is not int or type(window.get("windowId")) is not int:
                raise ObserverError("window identity fields must be integers")
            if window["pid"]!=pid or window["windowId"]!=window_id:
                continue
            if visible_alpha(window):
                if type(window.get("owner")) is not str or window["owner"]!="Safari Technology Preview":
                    raise ObserverError("bound target is not an exact STP window")
                strict_window_bounds(window,"bound target bounds")
                candidates.append(window)
        if nonce is None:
            return (candidates[0] if len(candidates)==1 else None),len(candidates)
        titled=[]
        for window in candidates:
            name=window.get("name","")
            if type(name) is not str:
                raise ObserverError("window title must be a string")
            if name == nonce:
                titled.append(window)
        return (titled[0] if len(titled)==1 else None),len(titled)

    def _nonce_windows(self, nonce: str) -> list[dict[str,Any]]:
        matches=[]
        for window in self._windows():
            if type(window) is not dict:
                raise ObserverError("malformed CoreGraphics window record")
            if type(window.get("pid")) is not int or type(window.get("windowId")) is not int:
                raise ObserverError("window identity fields must be integers")
            if not visible_alpha(window):
                continue
            name=window.get("name","")
            if type(name) is not str:
                raise ObserverError("window title must be a string")
            if name == nonce:
                matches.append(window)
        return matches

    def _placement_windows(self, native_title: str,allow_empty:bool=False) -> list[dict[str,Any]]:
        """Return exact native-title candidates only when they declare STP ownership.

        Production CoreGraphics records always include the owner name.  A
        missing owner is intentionally not accepted for the operation that can
        move a window; this keeps an injected or malformed record from turning
        a page/title collision into an Accessibility target.
        """
        if type(allow_empty) is not bool:raise ObserverError("empty-title placement selector is malformed")
        title="" if allow_empty and native_title=="" else strict_native_title(native_title)
        matches=[]
        for window in self._windows():
            if type(window) is not dict:
                raise ObserverError("malformed CoreGraphics window record")
            if type(window.get("pid")) is not int or type(window.get("windowId")) is not int:
                raise ObserverError("window identity fields must be integers")
            if not visible_alpha(window):
                continue
            name=window.get("name")
            if type(name) is not str:
                raise ObserverError("window title must be a string")
            if name != title:
                continue
            matches.append(window)
        for window in matches:
            if type(window.get("owner")) is not str or window["owner"]!="Safari Technology Preview":
                raise ObserverError("placement candidate is not an exact STP window")
            strict_window_bounds(window,"placement candidate bounds")
        return matches

    def _validate_ax_target(self, pid: int, window_id: int, native_title: str,
                            expected_before_bounds: dict[str,int]) -> dict[str,Any]:
        """Bind the provisional CoreGraphics ID to one exact AX window.

        The injected function is only a compatibility test seam. Production
        placement obtains equivalent records from the private native helper
        and validates them in ``parse_ax_helper_result``. Every record is
        validated before the target ID is selected so a missing, malformed,
        duplicated, inaccessible, or cross-process AX result cannot reach the
        mutator.
        """
        try:
            records=self.ax_windows_fn(pid,window_id,native_title)
        except ObserverError:
            raise
        except Exception as exc:
            raise ObserverError("STP Accessibility window inspection failed") from exc
        if type(records) is not list or not records:
            raise ObserverError("STP Accessibility window mapping is unavailable")
        expected_bounds=strict_bounds(expected_before_bounds,"expected CoreGraphics before bounds")
        seen:set[int]=set();numbered=[];number_matches=[];geometry_matches=[];normalized_records=[]
        for record in records:
            if type(record) is not dict:
                raise ObserverError("malformed Accessibility window record")
            record_title=record.get("title",record.get("titleNonce"))
            if (type(record.get("owner")) is not str or record.get("owner")!="Safari Technology Preview"
                    or type(record.get("bundleId")) is not str or record.get("bundleId")!=STP_BUNDLE_ID
                    or type(record.get("pid")) is not int or record.get("pid")!=pid
                    or type(record_title) is not str or record_title!=native_title):
                raise ObserverError("Accessibility window process or title identity is not exact")
            ax_number=record.get("axWindowNumber")
            if ax_number is not None:
                if type(ax_number) is not int or ax_number < 1:
                    raise ObserverError("Accessibility AXWindowNumber must be a positive integer or absent")
                if ax_number in seen:
                    raise ObserverError("Accessibility AXWindowNumber is duplicated")
                seen.add(ax_number);numbered.append(record)
            raw_bounds=record.get("bounds")
            if raw_bounds is None and set(record) >= BOUND_KEYS:
                raw_bounds={key:record.get(key) for key in BOUND_KEYS}
            record_bounds=strict_bounds(raw_bounds,"Accessibility window bounds")
            normalized=copy.deepcopy(record);normalized["title"]=record_title;normalized["bounds"]=record_bounds
            normalized_records.append(normalized)
            if record_bounds == expected_bounds:
                geometry_matches.append(normalized)
            if normalized.get("axWindowNumber") == window_id:
                number_matches.append(normalized)
        if numbered and len(numbered) != len(records):
            raise ObserverError("Accessibility AXWindowNumber support is inconsistent")
        if numbered:
            if len(number_matches)!=1 or number_matches[0].get("bounds") != expected_bounds:
                raise ObserverError("Accessibility AXWindowNumber does not exactly match target window")
            selected=number_matches[0]
            mapping_method="ax-window-number"
        else:
            if len(geometry_matches)!=1:
                raise ObserverError("Accessibility title and geometry mapping is not unique")
            selected=geometry_matches[0]
            mapping_method="title-geometry"
        return {"verified":True,"pid":pid,"windowId":window_id,
                "axWindowNumber":selected.get("axWindowNumber"),"mappingMethod":mapping_method,
                "title":native_title,"before":dict(expected_bounds),
                "candidateCount":len(records),"candidates":copy.deepcopy(normalized_records),
                "selected":copy.deepcopy(selected)}

    def _pid_windows(self,pid:int,nonce:str)->list[dict[str,Any]]:
        matches=[]
        for window in self._windows():
            if type(window) is not dict:
                raise ObserverError("malformed CoreGraphics window record")
            if type(window.get("pid")) is not int or type(window.get("windowId")) is not int:
                raise ObserverError("window identity fields must be integers")
            if window["pid"]!=pid:
                continue
            name=window.get("name","")
            if type(name) is not str:
                raise ObserverError("window title must be a string")
            if visible_alpha(window) and name == nonce:
                matches.append(window)
        return matches

    def _baseline(self, request:dict[str,Any])->dict[str,Any]:
        if self.phase!="created": raise ObserverError("baseline is only valid before claim")
        nonce=strict_title_nonce(request.get("titleNonce"));pid=request.get("pid")
        binding_mode=request.get("bindingMode")
        if binding_mode is not None and (type(binding_mode) is not str or binding_mode not in {"late","prebound-diagnostic"}):
            raise ObserverError("unsupported observer binding mode")
        if binding_mode == "late" and (request.get("pid") is not None or request.get("windowId") is not None):
            raise ObserverError("late baseline must not include a prebound target")
        if pid is None:
            if binding_mode == "prebound-diagnostic":
                raise ObserverError("prebound baseline requires PID and window ID")
            if binding_mode == "late":
                # Late mode proves a clean namespace by inventorying every
                # visible signed STP main window, independently of the nonce.
                inventory=self._stp_windows()
                process_inventory=self._stp_processes()
                # Keep unnamed layer-0 auxiliaries in evidence, but only
                # named main-window records can collide with a future title
                # probe or be selected as a target.
                matches=[item for item in inventory if item.get("targetEligible") is True]
                identity=None
                ok=len(matches)==0 and len(process_inventory)==0
                reason=(None if ok else
                        "a pre-existing signed STP process or visible main window prevents late binding")
            else:
                identity=None
                matches=self._nonce_windows(nonce)
                ok=len(matches)==0
                reason=None if ok else "fresh title nonce already matches a visible STP window"
        else:
            if binding_mode == "late":
                raise ObserverError("late baseline must not include a prebound PID")
            if type(pid) is not int or pid < 1: raise ObserverError("baseline PID must be a positive integer")
            identity=self._identity(pid)
            matches=self._pid_windows(pid,nonce)
            # A prebound diagnostic run has no way to put the fresh nonce on
            # its already-created window before POST /session. It only needs
            # to prove the nonce is clear; legacy callers without an explicit
            # mode retain the old candidate-window baseline behavior.
            ok=(len(matches)==0 if binding_mode=="prebound-diagnostic" else len(matches)==1)
            reason=None if ok else ("fresh title nonce already matches multiple or unexpected windows" if binding_mode=="prebound-diagnostic" else "title nonce did not uniquely identify one STP window")
        count=len(matches)
        response=self._canonical("baseline",ok,reason,
                                 matching_count=count, target=matches[0] if count==1 else None, contained=bounds_inside(matches[0]) if count==1 else False, identity=identity)
        if binding_mode is not None:
            response["bindingMode"]=binding_mode
        response["pid"]=pid if identity is not None else None
        response["processStartTime"]=identity.get("startTime") if identity is not None else None
        response["titleNonce"]=nonce;response["baselineClear"]=ok if binding_mode=="late" else count==0
        response["windowId"]=matches[0].get("windowId") if count==1 else None
        if count==1:
            response["candidateWindowId"]=matches[0].get("windowId")
        if binding_mode == "late":
            response["stpWindowInventory"]=copy.deepcopy(inventory)
            response["stpProcessInventory"]=copy.deepcopy(process_inventory)
            response["inventoryComplete"]=True
            response["processInventoryComplete"]=True
        if ok and count==0 and (pid is None or binding_mode=="prebound-diagnostic"):
            self.baseline_nonce=nonce;self.baseline_clear=True
            self.baseline_binding_mode=binding_mode
            self.baseline_inventory=[] if binding_mode=="late" else copy.deepcopy(matches)
            self.baseline_stp_inventory=copy.deepcopy(inventory) if binding_mode=="late" else []
            self.baseline_stp_process_inventory=copy.deepcopy(process_inventory) if binding_mode=="late" else []
        return response

    def _title_probe(self, request:dict[str,Any])->dict[str,Any]:
        """Bind a document nonce to the exact native STP title decoration."""
        if self.phase!="created": raise ObserverError("title probe requires an unclaimed lease")
        if request.get("bindingMode") not in {None,"late"}: raise ObserverError("title probe requires late binding")
        if request.get("pid") is not None or request.get("windowId") is not None:
            raise ObserverError("title probe must not include a prebound target")
        if self.baseline_binding_mode!="late" or self.baseline_clear is not True or self.baseline_inventory:
            raise ObserverError("title probe requires a clean late baseline")
        nonce=strict_title_nonce(request.get("titleNonce"))
        if self.title_probe is not None:
            raise ObserverError("title probe already completed")
        if self.title_probe_nonce is None:
            self.title_probe_nonce=nonce
        elif self.title_probe_nonce != nonce:
            raise ObserverError("title probe retry changed the immutable nonce")
        self.title_probe_count+=1
        if self.title_probe_count > 64:
            raise ObserverError("title probe readiness attempt limit exceeded")
        inventory=self._stp_windows()
        named_inventory=[item for item in inventory if item.get("targetEligible") is True]
        if self.empty_title_selection_attempted or (inventory and not named_inventory):
            self.empty_title_selection_attempted=True
            if self.baseline_stp_inventory or self.baseline_stp_process_inventory:
                raise ObserverError("empty-CG-title fallback requires a completely empty STP baseline")
            selection=self._empty_title_candidate_selection(request,nonce,"title-probe")
            if selection["decision"]=="selected":
                selected=selection["selected"];candidate=selected["candidate"]
                pid=candidate["pid"];window_id=candidate["windowId"];identity=candidate["identity"]
                immutable={"pid":pid,"windowId":window_id,"identity":copy.deepcopy(identity)}
                if self.title_probe_candidate is None:self.title_probe_candidate=immutable
                elif (self.title_probe_candidate.get("pid")!=pid
                        or self.title_probe_candidate.get("windowId")!=window_id
                        or not self._same_identity(self.title_probe_candidate.get("identity"),identity)):
                    raise ObserverError("title probe candidate identity changed during readiness")
                bounds=strict_window_bounds(candidate,"empty-CG-title candidate bounds")
                webdriver=selection["webdriver"];ax_evidence=selected["axMapping"]
                probe={"nonceA":nonce,"nativeTitleA":"","derivedPrefix":None,"pid":pid,
                       "processStartTime":identity["startTime"],"windowId":window_id,"preBounds":dict(bounds),
                       "identity":copy.deepcopy(identity),"candidate":copy.deepcopy(candidate),"verified":True,
                       "attempts":self.title_probe_count,"bindingMode":EMPTY_CG_BINDING_MODE,
                       "webdriver":copy.deepcopy(webdriver),"axMapping":copy.deepcopy(ax_evidence),
                       "emptyCGCandidateSelection":copy.deepcopy(selection)}
                self.title_probe=probe
                response=self._canonical("title-probe",True,matching_count=1,target=candidate,
                                         contained=bounds_inside(candidate),identity=identity)
                response.update({"bindingMode":EMPTY_CG_BINDING_MODE,"titleNonce":nonce,"nativeTitle":"",
                                 "derivedPrefix":None,"pid":pid,"processStartTime":identity["startTime"],
                                 "windowId":window_id,"preBounds":dict(bounds),"titleProbe":copy.deepcopy(probe),
                                 "ready":True,"retryable":False,"attempt":self.title_probe_count,
                                 "signedCandidateCount":1,"stpWindowInventory":copy.deepcopy(inventory),
                                 "inventoryComplete":True,"emptyCGCandidateSelection":copy.deepcopy(selection),
                                 "emptyCGTitleBinding":{"verified":True,"webdriver":copy.deepcopy(webdriver),
                                 "axMapping":copy.deepcopy(ax_evidence)}})
                return response
            if self.title_probe_candidate is not None:
                raise ObserverError("title probe candidate disappeared before binding")
            retryable=selection["decision"]=="pending"
            response=self._canonical("title-probe",False,selection.get("reason","empty-title selection pending"),
                matching_count=0,target=None,contained=False,identity=None)
            response.update({"bindingMode":EMPTY_CG_BINDING_MODE,"titleNonce":nonce,"ready":False,
                             "retryable":retryable,"attempt":self.title_probe_count,
                             "signedCandidateCount":0,"stpWindowInventory":copy.deepcopy(inventory),
                             "inventoryComplete":True,"emptyCGCandidateSelection":copy.deepcopy(selection)})
            return response
        if len(named_inventory)>1:
            raise ObserverError("title probe requires exactly one new visible signed STP window")
        if not named_inventory:
            response=self._canonical("title-probe",False,
                "title probe pending: no new visible signed STP main window",
                matching_count=0,target=None,contained=False,identity=None)
            response.update({"bindingMode":"late","titleNonce":nonce,"ready":False,
                             "retryable":True,"attempt":self.title_probe_count,
                             "signedCandidateCount":0,"stpWindowInventory":copy.deepcopy(inventory),
                             "inventoryComplete":True})
            return response
        candidate=named_inventory[0]
        pid=candidate.get("pid");window_id=candidate.get("windowId")
        if type(pid) is not int or pid<1 or type(window_id) is not int or window_id<1:
            raise ObserverError("title probe target identity is malformed")
        identity=candidate.get("identity")
        if not self._same_identity(identity,self._identity(pid)):
            raise ObserverError("title probe process identity is ambiguous")
        immutable={"pid":pid,"windowId":window_id,"identity":copy.deepcopy(identity)}
        if self.title_probe_candidate is None:
            self.title_probe_candidate=immutable
        elif (self.title_probe_candidate.get("pid")!=pid
                or self.title_probe_candidate.get("windowId")!=window_id
                or not self._same_identity(self.title_probe_candidate.get("identity"),identity)):
            raise ObserverError("title probe candidate identity changed during readiness")
        native_title=strict_native_title(candidate.get("name"),"probed native title")
        try:
            prefix=self._derive_probe_prefix(native_title,nonce)
        except ObserverError as exc:
            if str(exc)!="native title does not contain one terminal title nonce" or nonce in native_title:
                raise
            response=self._canonical("title-probe",False,
                "title probe pending: native title has not reached the exact nonce decoration",
                matching_count=0,target=None,contained=False,identity=identity)
            response.update({"bindingMode":"late","titleNonce":nonce,"ready":False,
                             "retryable":True,"attempt":self.title_probe_count,
                             "signedCandidateCount":1,"pendingPid":pid,"pendingWindowId":window_id,
                             "pendingNativeTitle":native_title,
                             "stpWindowInventory":copy.deepcopy(inventory),"inventoryComplete":True})
            return response
        probe={"nonceA":nonce,"nativeTitleA":native_title,"derivedPrefix":prefix,
               "pid":pid,"processStartTime":identity["startTime"],"windowId":window_id,
               "preBounds":dict(strict_window_bounds(candidate,"title probe bounds")),
               "identity":copy.deepcopy(identity),"candidate":copy.deepcopy(candidate),
               "verified":True,"attempts":self.title_probe_count}
        self.title_probe=probe
        response=self._canonical("title-probe",True,matching_count=1,target=candidate,
                                 contained=bounds_inside(candidate),identity=identity)
        response.update({"bindingMode":"late","titleNonce":nonce,"nativeTitle":native_title,"derivedPrefix":prefix,
                         "pid":pid,"processStartTime":identity["startTime"],"windowId":window_id,
                         "preBounds":dict(probe["preBounds"]),"titleProbe":copy.deepcopy(probe),
                         "ready":True,"retryable":False,"attempt":self.title_probe_count,
                         "signedCandidateCount":1,"stpWindowInventory":copy.deepcopy(inventory),
                         "inventoryComplete":True})
        return response

    def _place(self, request:dict[str,Any])->dict[str,Any]:
        """Perform the one authenticated late-binding placement.

        The provisional identity is captured before Accessibility is invoked
        and every field is checked again after it returns.  The observer never
        accepts a caller-supplied PID/window as proof of placement and never
        exposes a general move primitive.
        """
        if self.phase!="created": raise ObserverError("placement requires an unclaimed lease")
        if self.provisional is not None or self.placement_count != 0:
            raise ObserverError("placement is one-shot")
        placement_mode=request.get("bindingMode")
        if placement_mode not in {"late",EMPTY_CG_BINDING_MODE}: raise ObserverError("placement requires an exact late binding mode")
        if request.get("pid") is not None or request.get("windowId") is not None:
            raise ObserverError("late placement must not include a caller-selected target")
        nonce=strict_title_nonce(request.get("titleNonce"))
        if (self.baseline_nonce is None or self.baseline_clear is not True
                or self.baseline_binding_mode!="late" or self.title_probe is None
                or self.title_probe_count < 1):
            raise ObserverError("placement requires a successful late baseline and title probe")
        if nonce == self.title_probe.get("nonceA"):
            raise ObserverError("placement requires an independent second title nonce")
        empty_title=placement_mode==EMPTY_CG_BINDING_MODE
        expected_probe_mode=self.title_probe.get("bindingMode","late")
        if placement_mode!=expected_probe_mode:raise ObserverError("placement binding mode changed after title probe")
        if empty_title:
            webdriver=self._webdriver_binding(request,nonce);prefix=None;native_title=""
            probe_webdriver=self.title_probe.get("webdriver")
            if (webdriver["browserPid"]!=self.title_probe.get("pid")
                    or type(probe_webdriver) is not dict
                    or webdriver["browserPid"]!=probe_webdriver.get("browserPid")
                    or webdriver["windowHandle"]!=probe_webdriver.get("windowHandle")
                    or webdriver["windowHandles"]!=probe_webdriver.get("windowHandles")):
                raise ObserverError("empty-title placement WebDriver identity changed")
        else:
            webdriver=None;prefix=self.title_probe.get("derivedPrefix")
            if type(prefix) is not str or not prefix:raise ObserverError("title probe decoration is unavailable")
            native_title=strict_native_title(prefix+nonce,"expected native title")
        supplied_native=request.get("nativeTitle")
        if supplied_native is not None:
            if empty_title and supplied_native!="":raise ObserverError("caller native title is not exactly empty")
            if not empty_title and strict_native_title(supplied_native,"nativeTitle") != native_title:
                raise ObserverError("caller native title does not match immutable title decoration")
        # Consume the one-shot operation before any target or Accessibility
        # work.  A failed attempt cannot be replayed against a new window.
        self.placement_count=1
        requested=strict_bounds(request.get("requestedBounds"),"requestedBounds")
        if not bounds_inside(requested): raise ObserverError("requested bounds are outside KG271U")
        pre_selection=None
        if empty_title:
            pre_selection=self._empty_title_candidate_selection(request,nonce,"place-before")
            if pre_selection["decision"]!="selected":
                response=self._canonical("place",False,pre_selection.get("reason","empty-title placement selection failed"))
                response.update({"bindingMode":placement_mode,"emptyCGCandidateSelection":copy.deepcopy(pre_selection)})
                return response
            before=pre_selection["selected"]["candidate"]
        else:
            before_candidates=self._placement_windows(native_title)
            if len(before_candidates)!=1:
                raise ObserverError("placement target nonce is not unique")
            before=before_candidates[0]
        before_bounds=strict_window_bounds(before,"placement target bounds before move")
        pid=before.get("pid");window_id=before.get("windowId")
        if type(pid) is not int or pid<1 or type(window_id) is not int or window_id<1:
            raise ObserverError("placement target identity is malformed")
        identity_before=self._identity(pid)
        probe_identity=self.title_probe.get("identity")
        if (pid!=self.title_probe.get("pid") or window_id!=self.title_probe.get("windowId")
                or not self._same_identity(identity_before,probe_identity)):
            raise ObserverError("placement target does not match title-probe identity")
        ax_evidence=pre_selection["selected"]["axMapping"] if empty_title else None
        if not empty_title and self.ax_windows_fn is not None:
            ax_evidence=self._validate_ax_target(pid,window_id,native_title,before_bounds)
        elif not empty_title and self.ax_helper_fd is None and self.ax_helper is None:
            raise ObserverError("native STP AX helper is required")
        self._placement_native_title=native_title
        self._placement_before_bounds=dict(before_bounds)
        self._placement_identity_before=copy.deepcopy(identity_before)
        self._placement_empty_cg_title=empty_title
        try:
            method_evidence=self.placer(pid,window_id,nonce,dict(requested))
        except ObserverError:
            raise
        except Exception as exc:
            raise ObserverError("STP window placement failed") from exc
        finally:
            self._placement_native_title=None
            self._placement_before_bounds=None
            self._placement_identity_before=None
            self._placement_empty_cg_title=False
        if type(method_evidence) is not dict or type(method_evidence.get("method")) is not str or not method_evidence["method"].strip():
            raise ObserverError("placement method evidence is incomplete")
        post_selection=None
        if empty_title:
            post_selection=self._empty_title_candidate_selection(request,nonce,"place-after")
            if post_selection["decision"]!="selected":
                response=self._canonical("place",False,post_selection.get("reason","empty-title post-placement selection failed"))
                response.update({"bindingMode":placement_mode,"emptyCGCandidateSelection":copy.deepcopy(post_selection)})
                return response
            after=post_selection["selected"]["candidate"]
        else:
            after_candidates=self._placement_windows(native_title)
            if len(after_candidates)!=1:
                raise ObserverError("placement target disappeared or became ambiguous")
            after=after_candidates[0]
        if after.get("pid")!=pid or after.get("windowId")!=window_id:
            raise ObserverError("placement target identity changed")
        identity_after=self._identity(pid)
        if not self._same_identity(identity_after,identity_before):
            raise ObserverError("placement process identity changed or PID was reused")
        after_bounds=strict_window_bounds(after,"placement target bounds after move")
        if after_bounds!=requested:
            raise ObserverError("placement did not produce exact requested bounds")
        if not bounds_inside(after_bounds):
            raise ObserverError("placement target is outside KG271U")
        evidence={"method":method_evidence["method"],"before":copy.deepcopy(before),
                  "beforeBounds":dict(before_bounds),"after":copy.deepcopy(after),
                  "afterBounds":dict(after_bounds),"requestedBounds":dict(requested),
                  "nativeTitle":native_title,"derivedPrefix":prefix,
                  "bindingMode":placement_mode,"webdriver":copy.deepcopy(webdriver),
                  "titleProbe":copy.deepcopy(self.title_probe),
                  "identityBefore":copy.deepcopy(identity_before),"identityAfter":copy.deepcopy(identity_after),
                  "verified":True}
        if ax_evidence is not None:
            evidence["axBefore"]=copy.deepcopy(ax_evidence)
        if empty_title:
            evidence["emptyCGCandidateSelectionBefore"]=copy.deepcopy(pre_selection)
            evidence["emptyCGCandidateSelectionAfter"]=copy.deepcopy(post_selection)
        for key,value in method_evidence.items():
            if key not in evidence:evidence[key]=copy.deepcopy(value)
        self.provisional={"pid":pid,"processStartTime":identity_before["startTime"],"windowId":window_id,
                          "titleNonce":nonce,"nativeTitle":native_title,"derivedPrefix":prefix,
                          "bindingMode":placement_mode,"webdriver":copy.deepcopy(webdriver),
                          "requestedBounds":dict(requested),
                          "identity":copy.deepcopy(identity_before),"placementEvidence":evidence}
        response=self._canonical("place",True,matching_count=1,target=after,contained=True,identity=identity_after)
        response.update({"bindingMode":placement_mode,"pid":pid,"processStartTime":identity_before["startTime"],
                         "windowId":window_id,"titleNonce":nonce,"nativeTitle":native_title,
                         "derivedPrefix":prefix,"requestedBounds":dict(requested),
                         "placementEvidence":copy.deepcopy(evidence),"provisional":copy.deepcopy(self.provisional)})
        return response

    def _claim(self, request:dict[str,Any])->dict[str,Any]:
        if self.phase!="created": raise ObserverError("claim requires an unclaimed lease")
        pid=request.get("pid");window_id=request.get("windowId");nonce=request.get("titleNonce");requested=request.get("requestedBounds")
        nonce=strict_title_nonce(nonce)
        requested_mode=request.get("bindingMode")
        if requested_mode is not None and (type(requested_mode) is not str or requested_mode not in {"late",EMPTY_CG_BINDING_MODE,"prebound-diagnostic"}):
            raise ObserverError("unsupported observer binding mode")
        if (pid is None) != (window_id is None): raise ObserverError("claim requires both PID and window ID for prebound mode")
        if self.baseline_binding_mode=="late" and pid is not None:
            raise ObserverError("late baseline cannot be claimed in prebound mode")
        if not isinstance(requested,dict): raise ObserverError("claim requires title nonce and requested bounds")
        requested_bounds=strict_bounds(requested,"requestedBounds")
        if pid is None:
            provisional_mode=self.provisional.get("bindingMode","late") if self.provisional else None
            if requested_mode not in {None,provisional_mode}: raise ObserverError("late claim has incompatible binding mode")
            if (self.baseline_nonce is None or self.baseline_clear is not True
                    or self.title_probe is None or self.provisional is None):
                raise ObserverError("late claim requires a successful baseline, title probe, and placement")
            if nonce != self.provisional.get("titleNonce"):
                raise ObserverError("late claim title nonce does not match immutable placement")
            native_title=self.provisional.get("nativeTitle")
            if type(native_title) is not str:
                raise ObserverError("late claim native title evidence is unavailable")
            empty_title=provisional_mode==EMPTY_CG_BINDING_MODE
            if empty_title:
                webdriver=self._webdriver_binding(request,nonce)
                provisional_webdriver=self.provisional.get("webdriver")
                if (webdriver["browserPid"]!=self.provisional.get("pid")
                        or type(provisional_webdriver) is not dict
                        or webdriver["browserPid"]!=provisional_webdriver.get("browserPid")
                        or webdriver["windowHandle"]!=provisional_webdriver.get("windowHandle")
                        or webdriver["windowHandles"]!=provisional_webdriver.get("windowHandles")):
                    raise ObserverError("empty-title claim WebDriver identity changed")
                selection=self._empty_title_candidate_selection(request,nonce,"claim")
                if selection["decision"]!="selected":
                    response=self._canonical("claim",False,selection.get("reason","empty-title claim selection failed"))
                    response.update({"bindingMode":provisional_mode,"emptyCGCandidateSelection":copy.deepcopy(selection)})
                    return response
                target=selection["selected"]["candidate"];count=1
            else:
                candidates=self._placement_windows(native_title);count=len(candidates)
                if count!=1: raise ObserverError("title nonce did not uniquely identify one visible STP window")
                target=candidates[0]
            pid=target["pid"];window_id=target["windowId"];binding_mode=provisional_mode
            if (pid!=self.provisional.get("pid") or window_id!=self.provisional.get("windowId")
                    or requested_bounds!=self.provisional.get("requestedBounds")):
                raise ObserverError("late claim does not match immutable placement provisional identity")
        else:
            if requested_mode not in {None,"prebound-diagnostic"}: raise ObserverError("prebound claim has incompatible binding mode")
            if type(pid) is not int or pid < 1 or type(window_id) is not int or window_id < 1:
                raise ObserverError("prebound PID and window ID must be positive integers")
            target,count=self._visible_target(pid,window_id,nonce);binding_mode="prebound-diagnostic"
        identity=self._identity(pid)
        if target is None or count!=1: raise ObserverError("window identity or title nonce is ambiguous")
        if binding_mode in {"late",EMPTY_CG_BINDING_MODE} and (self.provisional is None or not self._same_identity(identity,self.provisional.get("identity"))):
            raise ObserverError("late claim process identity does not match placement provisional identity")
        target_bounds=strict_window_bounds(target)
        if target_bounds!=requested_bounds:
            raise ObserverError("requested bounds do not exactly match observed target bounds")
        if not bounds_inside(target_bounds):
            raise ObserverError("observed target bounds are outside KG271U")
        native_title=(self.provisional.get("nativeTitle") if binding_mode in {"late",EMPTY_CG_BINDING_MODE} and self.provisional else nonce)
        derived_prefix=(self.provisional.get("derivedPrefix") if binding_mode in {"late",EMPTY_CG_BINDING_MODE} and self.provisional else None)
        self.lease={"pid":pid,"processStartTime":identity["startTime"],"windowId":window_id,
                    "titleNonce":nonce,"nativeTitle":native_title,"derivedPrefix":derived_prefix,
                    "requestedBounds":dict(requested_bounds),"identity":copy.deepcopy(identity),"bindingMode":binding_mode}
        self.phase="claimed"
        response=self._canonical("claim",True,matching_count=count,target=target,contained=bounds_inside(target_bounds),identity=identity)
        if binding_mode==EMPTY_CG_BINDING_MODE:
            response["emptyCGCandidateSelection"]=copy.deepcopy(selection)
        return response

    def _observe(self, request:dict[str,Any])->dict[str,Any]:
        if self.phase!="claimed" or not self.lease: raise ObserverError("observe requires a claimed lease")
        lease=self.lease;identity=self._identity(lease["pid"])
        if not self._same_identity(identity,lease.get("identity")): raise ObserverError("PID reuse or process start identity changed")
        # Once the lease is immutable, YouTube may legitimately change the
        # native title.  Identity and exact bounds, not a stale nonce, select
        # the already-bound window.
        target,count=self._visible_target(lease["pid"],lease["windowId"],None)
        observed_bounds=strict_window_bounds(target) if target is not None else None
        requested_bounds=strict_bounds(lease.get("requestedBounds"),"leased requestedBounds")
        exact_bounds=observed_bounds is not None and observed_bounds==requested_bounds
        contained=bool(exact_bounds and bounds_inside(observed_bounds))
        ok=target is not None and count==1 and exact_bounds and contained
        return self._canonical("observe",ok,None if ok else "leased window missing, ambiguous, moved, resized, or outside KG271U",
                              matching_count=count,target=target,contained=contained,identity=identity)

    def _final(self, request:dict[str,Any])->dict[str,Any]:
        if self.phase!="claimed" or not self.lease: raise ObserverError("final requires a claimed lease")
        lease=self.lease
        expected=lease.get("identity")
        if (type(expected) is not dict or type(expected.get("pid")) is not int or expected.get("pid")!=lease.get("pid")
                or type(expected.get("startTime")) is not str or not expected["startTime"].strip() or expected.get("startTime")!=lease.get("processStartTime")
                or type(expected.get("uid")) is not int or expected.get("uid")!=self.active_uid
                or type(expected.get("commandDigest")) is not str or not expected["commandDigest"].strip()
                or expected.get("bundleId")!=STP_BUNDLE_ID or expected.get("executable")!=STP_EXECUTABLE
                or not signature_evidence_valid(expected.get("signature"))):
            raise ObserverError("claimed process identity is incomplete or changed")
        process_status="present"
        process_identity_verified=True
        try:
            identity=self._identity(lease["pid"])
        except ProcessExitedError:
            process_status="exited"
            process_identity_verified=False
            identity=expected
        except ObserverError as exc:
            raise ObserverError("final process identity is unavailable or ambiguous") from exc
        except Exception as exc:
            raise ObserverError("final process identity is unavailable or ambiguous") from exc
        else:
            if not self._same_identity(identity,expected):
                raise ObserverError("PID reuse or process start identity changed")
        identity_evidence={"status":process_status,"pid":lease["pid"],"expectedStartTime":lease["processStartTime"],
                           "observedStartTime":None if process_status=="exited" else identity.get("startTime"),
                           "verified":process_identity_verified}
        windows=self._windows()
        matches=[]
        for window in windows:
            if type(window) is not dict:
                raise ObserverError("malformed CoreGraphics window record")
            if type(window.get("pid")) is not int or type(window.get("windowId")) is not int:
                raise ObserverError("window identity fields must be integers")
            if window["pid"]==lease["pid"] and window["windowId"]==lease["windowId"] and visible_alpha(window):
                matches.append(window)
        self.finalized=True;self.phase="finalized"
        ok=len(matches)==0
        response=self._canonical("final",ok,None if ok else "exact leased window is still visible",matching_count=len(matches),target=None,contained=False,identity=identity,expired=True)
        response.update({"processStatus":process_status,"processIdentityVerified":process_identity_verified,"processIdentityEvidence":identity_evidence})
        return response

    def handle(self, request:dict[str,Any])->dict[str,Any]:
        if self.finalized: raise ObserverError("observer lease expired after final")
        if self.failed: raise ObserverError("observer lease is failed")
        if type(request) is not dict: raise ObserverError("request must be an object")
        operation=request.get("operation")
        if type(operation) is not str or operation not in OPERATIONS: raise ObserverError("unsupported observer operation")
        self._auth(request)
        if operation=="baseline": return self._baseline(request)
        if operation=="title-probe": return self._title_probe(request)
        if operation=="place": return self._place(request)
        if operation=="claim": return self._claim(request)
        if operation=="observe": return self._observe(request)
        return self._final(request)

    def serve_once(self, ready_path:Path|None=None) -> None:
        validate_socket_placement(self.socket_path)
        if self.socket_path.exists(): self.socket_path.unlink()
        self.socket_path.parent.mkdir(parents=True,exist_ok=True)
        old=os.umask(0o077)
        try:
            self.server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            self.server.bind(str(self.socket_path));os.chmod(self.socket_path,0o660)
            if self.peer_gid is not None:
                try:os.chown(self.socket_path,os.getuid(),self.peer_gid)
                except PermissionError:pass
            self.server.listen(1);self.server.settimeout(900)
            if ready_path:
                ready_path.write_text(json.dumps({"socket":str(self.socket_path),"runId":self.run_id,"capabilityFile":None})+"\n");os.chmod(ready_path,0o600)
        finally: os.umask(old)
        try:
            conn,_=self.server.accept();conn.settimeout(CONNECTION_IDLE_TIMEOUT_SECONDS)
            with conn:
                try:self.authenticate_peer(conn)
                except Exception as exc:
                    self.failed=True;self._send(conn,self._canonical("auth",False,str(exc)));return
                while not self.finalized:
                    try:request=self._receive(conn);response=self.handle(request);self._send(conn,response)
                    except ObserverError as exc:
                        self.failed=True
                        try:self._send(conn,self._canonical(str(request.get("operation","unknown")) if "request" in locals() and isinstance(request,dict) else "unknown",False,str(exc)))
                        except Exception:pass
                        break
        finally:
            if self.server:self.server.close()
            try:self.socket_path.unlink()
            except FileNotFoundError:pass

def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser();p.add_argument("--socket",required=True);p.add_argument("--run-id",default="");p.add_argument("--capability-file");p.add_argument("--capability",default="");p.add_argument("--peer-uid",required=True,type=int);p.add_argument("--peer-gid",type=int);p.add_argument("--ready-file");p.add_argument("--ax-helper-fd",type=int);p.add_argument("--ax-helper-digest");p.add_argument("--ax-helper-device",type=int);p.add_argument("--ax-helper-inode",type=int)
    a=p.parse_args(argv);run_id=a.run_id or secrets.token_urlsafe(12)
    cap=a.capability or os.environ.get(CAP_ENV,"")
    if a.capability_file:cap=Path(a.capability_file).read_text().strip()
    if not cap:raise SystemExit("capability must come from a protected file or environment")
    if (a.ax_helper_fd is None or a.ax_helper_digest is None or a.ax_helper_device is None
            or a.ax_helper_inode is None):
        raise SystemExit("native AX helper fd identity is required")
    _validate_helper_fd(a.ax_helper_fd,a.ax_helper_digest,a.ax_helper_device,a.ax_helper_inode)
    os.set_inheritable(a.ax_helper_fd,False)
    try:
        AquaObserver(Path(a.socket),run_id,cap,a.peer_uid,a.peer_gid,
                     ax_helper_fd=a.ax_helper_fd,ax_helper_digest=a.ax_helper_digest,
                     ax_helper_device=a.ax_helper_device,ax_helper_inode=a.ax_helper_inode).serve_once(
                         Path(a.ready_file) if a.ready_file else None)
    finally:
        try:os.close(a.ax_helper_fd)
        except OSError:pass
    return 0

if __name__=="__main__":sys.exit(main())
