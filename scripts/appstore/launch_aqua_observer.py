#!/usr/bin/env python3
"""Bounded operator launcher for the one-run Aqua observer.

Run this as the active Aqua user. It writes only a protected descriptor and
capability file; the capability is never printed. The repository need not be
present in /Users/alexyang/Developer.
"""
from __future__ import annotations
import argparse, hashlib, json, os, secrets, stat, subprocess, sys
import tempfile
from pathlib import Path

OBSERVER=Path(__file__).with_name("aqua_window_observer.py")
IMMUTABLE_HELPER_FLAGS= getattr(stat,"UF_IMMUTABLE",2) | getattr(stat,"UF_NOUNLINK",16)

# This helper is intentionally compiled as one MH_BUNDLE for one observer run
# and kept in a private 0700 directory owned by the active Aqua user. The
# launcher opens and hashes that exact object once, then passes only its
# inherited descriptor and immutable dev/inode/digest identity to the
# observer. Production never passes a mutable helper pathname across the
# observer boundary; the observer loads the authenticated bytes from that fd.
AX_HELPER_SOURCE=r'''import ApplicationServices
import AppKit
import CoreGraphics
import Darwin
import Foundation

enum HelperFailure: Error {
    case message(String)
    case notSettable(String)
    case notSettableWithEvidence(String, [String: Any])
    case resizeNotSettableWithEvidence([String: Any])
    case positionIgnoredWithEvidence([String: Any])
    case cgeventFailure(String, [String: Any])
}

enum AXHitTestReceiverUnavailable: Error {
    case apiFailure(Int32)
}

let method = "application-services-ax"
let expectedBundle = "com.apple.SafariTechnologyPreview"
let expectedExecutable = "/Applications/Safari Technology Preview.app/Contents/MacOS/Safari Technology Preview"
// `_AXUIElementGetWindow` is exported by the versioned inner HIServices
// Mach-O, not by the umbrella ApplicationServices framework path. Keep this
// fully versioned path as the sealed-system image allowlist. The `dladdr`
// image check below is authoritative even when the image is supplied by the
// dyld shared cache and is not a regular file on disk.
let trustedAXExportingImagePath = "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/HIServices.framework/Versions/A/HIServices"
let trustedAXResolverMethod = "_AXUIElementGetWindow@HIServices"
let trustedAXProvenanceMethod = "dladdr-exact-sealed-system-image"
typealias AXWindowIDResolver = @convention(c) (AXUIElement, UnsafeMutablePointer<CGWindowID>) -> AXError

struct AXWindowIDResolverBinding {
    let resolver: AXWindowIDResolver
    let handle: UnsafeMutableRawPointer
    let imagePath: String
    let imageBasePresent: Bool
    let provenanceMethod: String
    let verified: Bool
}

// The native window-ID compatibility route is not allowed to trust an arbitrary
// symbol resolved through the process namespace. Bind the SPI lookup to the
// exact sealed HIServices image. A successful resolver is
// retained for the life of this one-shot helper so its code cannot be
// unloaded/replaced between the pre- and post-input calls.
func canonicalSystemImagePath(_ rawPath: String) throws -> String {
    guard rawPath == trustedAXExportingImagePath else {
        throw HelperFailure.message("native window-ID resolver image path is not the pinned system image")
    }
    let standardized = URL(fileURLWithPath: rawPath).standardizedFileURL.path
    guard standardized == rawPath else {
        throw HelperFailure.message("native window-ID resolver image path is not canonical")
    }
    let parentPath = URL(fileURLWithPath: rawPath).deletingLastPathComponent().path
    var resolvedParent = [CChar](repeating: 0, count: Int(PATH_MAX))
    guard parentPath.withCString({ realpath($0, &resolvedParent) != nil }) else {
        throw HelperFailure.message("native window-ID resolver image parent cannot be canonicalized")
    }
    let canonicalParent = String(cString: resolvedParent)
    let expectedParent = URL(fileURLWithPath: trustedAXExportingImagePath)
        .deletingLastPathComponent().path
    guard canonicalParent == expectedParent else {
        throw HelperFailure.message("native window-ID resolver image parent is not the pinned system directory")
    }
    return canonicalParent + "/" + URL(fileURLWithPath: rawPath).lastPathComponent
}

// The native window-ID compatibility route is not allowed to trust an arbitrary
// symbol resolved through the process namespace. Bind the SPI lookup to the
// exact sealed HIServices image, use RTLD_FIRST so dependencies cannot satisfy
// the lookup, and verify the actual loaded image with dladdr. The handle is
// retained for the life of this one-shot helper so its code cannot be
// unloaded/replaced between the pre- and post-input calls.
func trustedAXWindowIDResolver() throws -> AXWindowIDResolverBinding {
    let flags = RTLD_NOW | RTLD_LOCAL | RTLD_FIRST
    guard let handle = dlopen(trustedAXExportingImagePath, flags) else {
        throw HelperFailure.message("pinned HIServices image could not be opened")
    }
    guard let symbol = dlsym(handle, "_AXUIElementGetWindow") else {
        dlclose(handle)
        throw HelperFailure.message("trusted _AXUIElementGetWindow SPI is unavailable")
    }
    var imageInfo = Dl_info()
    guard dladdr(symbol, &imageInfo) != 0,
          let rawImagePath = imageInfo.dli_fname,
          imageInfo.dli_fbase != nil else {
        dlclose(handle)
        throw HelperFailure.message("native window-ID resolver image provenance is unavailable")
    }
    let imagePath = String(cString: rawImagePath)
    guard let canonicalImagePath = try? canonicalSystemImagePath(imagePath),
          canonicalImagePath == trustedAXExportingImagePath else {
        dlclose(handle)
        throw HelperFailure.message("native window-ID resolver image provenance is not the pinned HIServices image")
    }
    // dlsym is intentionally scoped to the validated handle above; do not
    // use RTLD_DEFAULT or a caller-supplied symbol. On macOS the framework
    // may be represented through the dyld shared cache, so the exact dladdr
    // image path/base and retained handle are the authoritative provenance
    // checks; the function type is fixed by the ABI alias above.
    return AXWindowIDResolverBinding(
        resolver: unsafeBitCast(symbol, to: AXWindowIDResolver.self),
        handle: handle,
        imagePath: canonicalImagePath,
        imageBasePresent: true,
        provenanceMethod: trustedAXProvenanceMethod,
        verified: true)
}

func exactNativeWindowID(_ element: AXUIElement, _ binding: AXWindowIDResolverBinding,
                         _ label: String) throws -> (id: Int, status: Int) {
    guard binding.verified,
          binding.imagePath == trustedAXExportingImagePath,
          binding.imageBasePresent,
          binding.handle != UnsafeMutableRawPointer(bitPattern: 0) else {
        throw HelperFailure.message("native (label) resolver provenance is not verified")
    }
    var rawWindowID: CGWindowID = 0
    let status = binding.resolver(element, &rawWindowID)
    guard status == .success else {
        throw HelperFailure.message("native \(label) window ID lookup failed status=\(status.rawValue)")
    }
    let windowID = Int(rawWindowID)
    guard windowID > 0 else {
        throw HelperFailure.message("native \(label) window ID is missing or zero")
    }
    return (windowID, Int(status.rawValue))
}

@discardableResult
func emit(_ payload: [String: Any], _ status: Int32) -> Int32 {
    if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]),
       let text = String(data: data, encoding: .utf8),
       let bytes = (text + "\n").data(using: .utf8) {
        FileHandle.standardOutput.write(bytes)
    }
    return status
}

func fail(_ message: String) -> Int32 {
    return emit(["ok": false, "method": method, "error": message], 1)
}

func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw HelperFailure.message(message) }
}

func parseInteger(_ raw: String, positive: Bool = false) throws -> Int {
    try require(!raw.isEmpty, "integer argument is empty")
    let ascii = raw.utf8
    let valid = ascii.enumerated().allSatisfy { offset, byte in
        if byte >= 48 && byte <= 57 { return true }
        return offset == 0 && byte == 45
    }
    try require(valid, "integer argument is malformed")
    guard let value = Int(raw), String(value) == raw else {
        throw HelperFailure.message("integer argument is not canonical")
    }
    if positive && value < 1 { throw HelperFailure.message("integer argument is not positive") }
    return value
}

func copyAttribute(_ element: AXUIElement, _ name: String) throws -> CFTypeRef {
    var value: CFTypeRef?
    let status = AXUIElementCopyAttributeValue(element, name as CFString, &value)
    guard status == .success, let value else {
        throw HelperFailure.message("AX attribute unavailable: \(name) status=\(status.rawValue)")
    }
    return value
}

func exactInteger(_ value: CFTypeRef, _ label: String) throws -> Int {
    guard CFGetTypeID(value) == CFNumberGetTypeID(), let number = value as? NSNumber else {
        throw HelperFailure.message("\(label) is not an integer")
    }
    let typeCode = String(cString: number.objCType)
    let integerTypes = ["c", "s", "i", "l", "q", "C", "S", "I", "L", "Q"]
    guard integerTypes.contains(typeCode) else {
        throw HelperFailure.message("\(label) is not an integer")
    }
    let result = number.int64Value
    guard result >= Int64(Int.min) && result <= Int64(Int.max) else {
        throw HelperFailure.message("\(label) is out of range")
    }
    return Int(result)
}

func exactCoordinate(_ value: CGFloat, _ label: String) throws -> Int {
    guard value.isFinite, value.rounded(.towardZero) == value else {
        throw HelperFailure.message("\(label) is not a finite integer")
    }
    guard value >= CGFloat(Int.min), value <= CGFloat(Int.max) else {
        throw HelperFailure.message("\(label) is out of range")
    }
    return Int(value)
}

func readGeometry(_ element: AXUIElement) throws -> [String: Any] {
    let positionValue = try copyAttribute(element, kAXPositionAttribute as String)
    let sizeValue = try copyAttribute(element, kAXSizeAttribute as String)
    guard CFGetTypeID(positionValue) == AXValueGetTypeID(),
          CFGetTypeID(sizeValue) == AXValueGetTypeID() else {
        throw HelperFailure.message("AX geometry has the wrong type")
    }
    let position = positionValue as! AXValue
    let size = sizeValue as! AXValue
    guard AXValueGetType(position) == .cgPoint, AXValueGetType(size) == .cgSize else {
        throw HelperFailure.message("AX geometry has the wrong shape")
    }
    var point = CGPoint.zero
    var dimensions = CGSize.zero
    guard AXValueGetValue(position, .cgPoint, &point), AXValueGetValue(size, .cgSize, &dimensions) else {
        throw HelperFailure.message("AX geometry could not be decoded")
    }
    let x = try exactCoordinate(point.x, "AX position x")
    let y = try exactCoordinate(point.y, "AX position y")
    let width = try exactCoordinate(dimensions.width, "AX size width")
    let height = try exactCoordinate(dimensions.height, "AX size height")
    guard width > 0, height > 0 else { throw HelperFailure.message("AX size is not positive") }
    return ["x": x, "y": y, "width": width, "height": height]
}

func windowNumber(_ element: AXUIElement) throws -> Int? {
    for attribute in ["AXWindowNumber", "_AXWindowNumber"] {
        var value: CFTypeRef?
        let status = AXUIElementCopyAttributeValue(element, attribute as CFString, &value)
        if status == .attributeUnsupported || status == .noValue { continue }
        guard status == .success, let value else {
            throw HelperFailure.message("AX window number unavailable: \(attribute) status=\(status.rawValue)")
        }
        if CFGetTypeID(value) == CFNullGetTypeID() { continue }
        let number = try exactInteger(value, "AXWindowNumber")
        guard number > 0 else { throw HelperFailure.message("AXWindowNumber is not positive") }
        return number
    }
    return nil
}

func coreGraphicsBefore(_ pid: Int, _ windowId: Int, _ expectedTitle: String) throws -> [String: Int] {
    let raw = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
    var matches: [[String: Int]] = []
    for item in raw {
        guard let owner = item[kCGWindowOwnerName as String] as? String,
              owner == "Safari Technology Preview",
              let layer = item[kCGWindowLayer as String] as? NSNumber,
              layer.intValue == 0,
              let alpha = item[kCGWindowAlpha as String] as? NSNumber,
              alpha.doubleValue > 0,
              let ownerPid = item[kCGWindowOwnerPID as String] as? NSNumber,
              ownerPid.intValue == pid,
              let number = item[kCGWindowNumber as String] as? NSNumber,
              number.intValue == windowId,
              (item[kCGWindowName as String] as? String ?? "") == expectedTitle,
              let rawBounds = item[kCGWindowBounds as String] as? [String: Any] else { continue }
        func coordinate(_ key: String) throws -> Int {
            guard let value = rawBounds[key] as? NSNumber else {
                throw HelperFailure.message("CoreGraphics bounds are malformed")
            }
            return try exactCoordinate(value.doubleValue, "CoreGraphics \(key)")
        }
        let bounds = ["x": try coordinate("X"), "y": try coordinate("Y"),
                      "width": try coordinate("Width"), "height": try coordinate("Height")]
        try require(bounds["width"]! > 0 && bounds["height"]! > 0, "CoreGraphics bounds are not positive")
        matches.append(bounds)
    }
    guard matches.count == 1, let result = matches.first else {
        throw HelperFailure.message("CoreGraphics target window mapping is not unique")
    }
    return result
}

func pointInside(_ point: CGPoint, _ bounds: [String: Int]) -> Bool {
    let left = CGFloat(bounds["x"]!)
    let top = CGFloat(bounds["y"]!)
    let right = left + CGFloat(bounds["width"]!)
    let bottom = top + CGFloat(bounds["height"]!)
    return point.x >= left && point.x < right && point.y >= top && point.y < bottom
}

func topmostProof(_ pid: Int, _ windowId: Int, _ expectedTitle: String,
                  _ sourcePoint: CGPoint, _ targetBounds: [String: Int]) throws -> [String: Any] {
    let raw = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
    var eligible: [[String: Any]] = []
    var targetIndexes: [Int] = []
    for (rawIndex, item) in raw.enumerated() {
        guard let layerValue = item[kCGWindowLayer as String] as? NSNumber,
              CFGetTypeID(layerValue) == CFNumberGetTypeID() else {
            throw HelperFailure.message("CGEvent z-order record layer is malformed")
        }
        let layer = try exactInteger(layerValue, "CGEvent z-order layer")
        guard let alphaValue = item[kCGWindowAlpha as String] as? NSNumber,
              CFGetTypeID(alphaValue) == CFNumberGetTypeID(),
              alphaValue.doubleValue.isFinite else {
            throw HelperFailure.message("CGEvent z-order record alpha is malformed")
        }
        if alphaValue.doubleValue <= 0 { continue }
        guard let rawBounds = item[kCGWindowBounds as String] as? [String: Any] else {
            throw HelperFailure.message("CGEvent z-order record bounds are malformed")
        }
        func coordinate(_ key: String) throws -> Int {
            guard let value = rawBounds[key] as? NSNumber else {
                throw HelperFailure.message("CGEvent z-order record coordinate is malformed")
            }
            return try exactCoordinate(value.doubleValue, "CGEvent z-order \(key)")
        }
        let bounds = ["x": try coordinate("X"), "y": try coordinate("Y"),
                      "width": try coordinate("Width"), "height": try coordinate("Height")]
        guard bounds["width"]! > 0, bounds["height"]! > 0 else {
            throw HelperFailure.message("CGEvent z-order record bounds are not positive")
        }
        guard pointInside(sourcePoint, bounds) else { continue }
        func optionalString(_ key: String) throws -> String? {
            guard let rawValue = item[key] else { return nil }
            if rawValue is NSNull { return nil }
            guard let value = rawValue as? String else {
                throw HelperFailure.message("CGEvent z-order record \(key) is malformed")
            }
            return value
        }
        func optionalInteger(_ key: String) throws -> Int? {
            guard let rawValue = item[key] else { return nil }
            if rawValue is NSNull { return nil }
            guard let value = rawValue as? NSNumber,
                  CFGetTypeID(value) == CFNumberGetTypeID() else {
                throw HelperFailure.message("CGEvent z-order record \(key) is malformed")
            }
            return try exactInteger(value, "CGEvent z-order \(key)")
        }
        let owner = try optionalString(kCGWindowOwnerName as String)
        let ownerPid = try optionalInteger(kCGWindowOwnerPID as String)
        let number = try optionalInteger(kCGWindowNumber as String)
        let title = try optionalString(kCGWindowName as String)
        let record: [String: Any] = ["index": eligible.count, "cgIndex": rawIndex,
                                     "layer": layer, "alpha": alphaValue.doubleValue,
                                     "owner": owner ?? NSNull(), "pid": ownerPid ?? NSNull(),
                                     "windowId": number ?? NSNull(), "title": title ?? NSNull(),
                                     "bounds": bounds]
        // The list is front-to-back.  An unknown covering record before the
        // authenticated target cannot be treated as harmless decoration.
        if targetIndexes.isEmpty && (owner == nil || ownerPid == nil || number == nil || title == nil) {
            throw HelperFailure.message("CGEvent z-order has an unknown frontmost covering record")
        }
        eligible.append(record)
        if owner == "Safari Technology Preview" && ownerPid == pid && number == windowId
                && title == expectedTitle && bounds == targetBounds {
            targetIndexes.append(eligible.count - 1)
        }
    }
    guard targetIndexes.count == 1, targetIndexes[0] == 0 else {
        throw HelperFailure.message("CGEvent target is not the unique topmost eligible window")
    }
    let source = ["x": try exactCoordinate(sourcePoint.x, "CGEvent source x"),
                  "y": try exactCoordinate(sourcePoint.y, "CGEvent source y")]
    return ["targetPid": pid, "targetWindowId": windowId, "targetTitle": expectedTitle,
            "sourcePoint": source, "targetBounds": targetBounds, "targetIndex": 0,
            "eligibleCount": eligible.count, "overlayAbove": 0,
            "eligibleRecords": eligible]
}

let allowedSourceRolePairs: Set<String> = [
    "AXWindow\u{001F}AXStandardWindow",
    "AXGroup\u{001F}AXTitleBar"
]
let nonWindowSourceRolePairs: Set<String> = [
    "AXGroup\u{001F}AXTitleBar"
]
let axActionNamesAttribute = "AXActionNames"
let rejectedSourceActions: Set<String> = ["AXPress", "AXShowMenu", "AXConfirm",
    "AXCancel", "AXPick", "AXIncrement", "AXDecrement", "AXRaise", "AXOpen", "AXClose"]

func deterministicAXCandidatePoints(_ bounds: [String: Int]) throws -> [[String: Int]] {
    guard bounds["width"]! >= 260, bounds["height"]! >= 40 else {
        throw HelperFailure.message("CGEvent target is too small for AX title-bar hit testing")
    }
    let offsets = [220, bounds["width"]! / 2, bounds["width"]! - 220]
    var points: [[String: Int]] = []
    for offset in offsets {
        let point = ["x": bounds["x"]! + offset, "y": bounds["y"]! + 18]
        if !points.contains(where: { $0 == point }) { points.append(point) }
    }
    return points
}

func copyAXString(_ element: AXUIElement, _ attribute: String, _ label: String) throws -> String {
    let value = try copyAttribute(element, attribute)
    guard let text = value as? String, !text.isEmpty else {
        throw HelperFailure.message("AX \(label) is missing or malformed")
    }
    return text
}

func copyAXEnabled(_ element: AXUIElement) throws -> Bool {
    let value = try copyAttribute(element, kAXEnabledAttribute as String)
    guard CFGetTypeID(value) == CFBooleanGetTypeID() else {
        throw HelperFailure.message("AX enabled attribute is malformed")
    }
    let boolValue = unsafeBitCast(value, to: CFBoolean.self)
    return CFBooleanGetValue(boolValue)
}

func copyAXActions(_ element: AXUIElement) throws -> [String] {
    let value = try copyAttribute(element, axActionNamesAttribute)
    guard CFGetTypeID(value) == CFArrayGetTypeID(), let rawActions = value as? [Any] else {
        throw HelperFailure.message("AX action names are malformed")
    }
    var actions: [String] = []
    for rawAction in rawActions {
        guard let action = rawAction as? String, !action.isEmpty else {
            throw HelperFailure.message("AX action name is malformed")
        }
        actions.append(action)
    }
    return actions
}

struct AXWindowAncestorProof {
    let element: AXUIElement
    let method: String
}

func exactTargetAXWindow(_ candidate: AXUIElement, _ expectedPid: Int,
                         _ target: AXUIElement, _ method: String,
                         _ label: String) throws -> AXWindowAncestorProof {
    var candidatePid: pid_t = 0
    guard AXUIElementGetPid(candidate, &candidatePid) == .success,
          Int(candidatePid) == expectedPid,
          CFEqual(candidate, target) else {
        throw HelperFailure.message("AX \(label) is not the exact target")
    }
    let role = try copyAXString(candidate, kAXRoleAttribute as String, "\(label) role")
    let subrole = try copyAXString(candidate, kAXSubroleAttribute as String,
                                   "\(label) subrole")
    guard role == "AXWindow", subrole == "AXStandardWindow" else {
        throw HelperFailure.message("AX \(label) has a nonstandard role")
    }
    return AXWindowAncestorProof(element: candidate, method: method)
}

// AXTopLevelUIElement is not consistently exposed as a window object by
// Safari Technology Preview.  When its direct AXWindow and bounded parent
// relations are unavailable, prove the relation in the other direction:
// walk the actual children graph rooted at the already-mapped target window
// and accept only when that exact top-level object is encountered by CFEqual.
// This is an identity-membership proof, never a geometry or title
// approximation.  The graph is deliberately small and bounded; any
// unavailable, malformed, cross-process, duplicate, cyclic, or unresolved
// branch is terminal rather than silently treated as a leaf.
func targetContainsTopLevel(_ target: AXUIElement, _ topLevel: AXUIElement,
                            _ expectedPid: Int) throws -> AXWindowAncestorProof {
    var targetPid: pid_t = 0
    guard AXUIElementGetPid(target, &targetPid) == .success,
          Int(targetPid) == expectedPid else {
        throw HelperFailure.message("AX target children proof target PID is missing or mismatched")
    }
    var topLevelPid: pid_t = 0
    guard AXUIElementGetPid(topLevel, &topLevelPid) == .success,
          Int(topLevelPid) == expectedPid else {
        throw HelperFailure.message("AX target children proof top-level PID is missing or mismatched")
    }
    // Validate the carried target's actual window role/subrole before any
    // child graph result can authorize input.
    let targetProof = try exactTargetAXWindow(target, expectedPid, target,
                                              "top-level-target-descendant",
                                              "target children proof")
    let maxDepth = 8
    let maxNodes = 128
    var queue: [(element: AXUIElement, depth: Int)] = [(target, 0)]
    var seen: [AXUIElement] = [target]
    while !queue.isEmpty {
        let current = queue.removeFirst()
        guard current.depth < maxDepth else {
            throw HelperFailure.message("AX target children proof exceeded bounded depth")
        }
        var childrenValue: CFTypeRef?
        let childrenStatus = AXUIElementCopyAttributeValue(
            current.element, kAXChildrenAttribute as CFString, &childrenValue)
        if childrenStatus == .attributeUnsupported || childrenStatus == .noValue {
            guard childrenValue == nil else {
                throw HelperFailure.message("AX target children proof has malformed unavailable children")
            }
            throw HelperFailure.message("AX target children proof children are unavailable")
        }
        guard childrenStatus == .success, let childrenValue,
              CFGetTypeID(childrenValue) == CFArrayGetTypeID(),
              let children = childrenValue as? [AXUIElement] else {
            throw HelperFailure.message("AX target children proof children are missing or malformed status=\(childrenStatus.rawValue)")
        }
        guard children.count <= maxNodes,
              seen.count + children.count <= maxNodes else {
            throw HelperFailure.message("AX target children proof exceeded node cap")
        }
        var matchedTopLevel = false
        for child in children {
            guard CFGetTypeID(child) == AXUIElementGetTypeID() else {
                throw HelperFailure.message("AX target children proof child type is malformed")
            }
            var childPid: pid_t = 0
            guard AXUIElementGetPid(child, &childPid) == .success,
                  Int(childPid) == expectedPid else {
                throw HelperFailure.message("AX target children proof child PID is missing or mismatched")
            }
            guard !seen.contains(where: { CFEqual($0, child) }) else {
                throw HelperFailure.message("AX target children proof graph is cyclic or duplicated")
            }
            seen.append(child)
            guard seen.count <= maxNodes else {
                throw HelperFailure.message("AX target children proof exceeded node cap")
            }
            if CFEqual(child, topLevel) {
                matchedTopLevel = true
                continue
            }
            queue.append((child, current.depth + 1))
        }
        if matchedTopLevel {
            return targetProof
        }
    }
    throw HelperFailure.message("AX target children proof found no exact top-level object")
}

// This is a deliberately narrow, production-only compatibility transcript
// for STP builds that expose none of the AX ancestry relations.  It does not
// claim that a coordinate is an AX title-bar element.  Instead, the later
// CGWindowList proof attests that the deterministic system-wide hit point is
// inside the exact, unique target window at the front of the full stack.
// Every relation below is queried in this exact order and must return the
// typed unavailable status with a nil value.  Any partial or successful
// relation is unsafe and remains terminal in axWindowAncestor.
func systemWideNativeWindowBinding(_ hit: AXUIElement, _ expectedPid: Int,
                                   _ expectedWindowId: Int,
                                   _ target: AXUIElement) throws -> [String: Any] {
    let resolverBinding = try trustedAXWindowIDResolver()
    let hitNativeWindow = try exactNativeWindowID(hit, resolverBinding, "system-wide hit")
    guard hitNativeWindow.id == expectedWindowId else {
        throw HelperFailure.message("native system-wide hit window ID does not match CoreGraphics target")
    }
    let targetNativeWindow = try exactNativeWindowID(target, resolverBinding, "mapped target")
    guard targetNativeWindow.id == expectedWindowId else {
        throw HelperFailure.message("native mapped target window ID does not match CoreGraphics target")
    }
    var hitPid: pid_t = 0
    guard AXUIElementGetPid(hit, &hitPid) == .success,
          Int(hitPid) == expectedPid else {
        throw HelperFailure.message("CGEvent native window-ID hit PID is missing or mismatched")
    }
    let hitRole = try copyAXString(hit, kAXRoleAttribute as String, "native window-ID hit role")
    let hitSubrole = try copyAXString(hit, kAXSubroleAttribute as String, "native window-ID hit subrole")
    let hitActions = try copyAXActions(hit)
    let hitEnabled = try copyAXEnabled(hit)
    let hitPair = hitRole + "\u{001F}" + hitSubrole
    var hitMatchedTarget = false
    if hitPair == "AXWindow\u{001F}AXStandardWindow" {
        guard CFEqual(hit, target) else {
            throw HelperFailure.message("CGEvent native window-ID hit window is not the exact target")
        }
        hitMatchedTarget = true
    } else {
        guard nonWindowSourceRolePairs.contains(hitPair) else {
            throw HelperFailure.message("CGEvent native window-ID hit role is not allowed")
        }
    }
    guard hitActions.isEmpty, hitEnabled else {
        throw HelperFailure.message("CGEvent native window-ID hit is not inert title-bar chrome")
    }

    func unavailableStatus(_ status: AXError, _ value: CFTypeRef?, _ label: String) throws -> Int {
        guard status == .attributeUnsupported || status == .noValue else {
            throw HelperFailure.message("CGEvent native window-ID \(label) has unsafe status=\(status.rawValue)")
        }
        guard value == nil else {
            throw HelperFailure.message("CGEvent native window-ID \(label) has a malformed unavailable value")
        }
        return Int(status.rawValue)
    }

    var hitWindowValue: CFTypeRef?
    let hitWindowStatus = AXUIElementCopyAttributeValue(
        hit, kAXWindowAttribute as CFString, &hitWindowValue)
    let hitWindowRaw = try unavailableStatus(hitWindowStatus, hitWindowValue, "hit AXWindow")

    var topLevelValue: CFTypeRef?
    let topLevelStatus = AXUIElementCopyAttributeValue(
        hit, kAXTopLevelUIElementAttribute as CFString, &topLevelValue)
    guard topLevelStatus == .success, let topLevelValue,
          CFGetTypeID(topLevelValue) == AXUIElementGetTypeID() else {
        throw HelperFailure.message("CGEvent native window-ID top-level object is missing or malformed status=\(topLevelStatus.rawValue)")
    }
    let topLevel = topLevelValue as! AXUIElement
    var topLevelPid: pid_t = 0
    guard AXUIElementGetPid(topLevel, &topLevelPid) == .success,
          Int(topLevelPid) == expectedPid,
          !CFEqual(topLevel, target) else {
        throw HelperFailure.message("CGEvent native window-ID top-level object is wrong or equals target")
    }
    let topLevelNativeWindow = try exactNativeWindowID(topLevel, resolverBinding, "top-level hit")
    guard topLevelNativeWindow.id == expectedWindowId else {
        throw HelperFailure.message("native top-level hit window ID does not match CoreGraphics target")
    }
    let topLevelRole = try copyAXString(topLevel, kAXRoleAttribute as String,
                                        "native window-ID top-level role")
    let topLevelSubrole = try copyAXString(topLevel, kAXSubroleAttribute as String,
                                           "native window-ID top-level subrole")
    let topLevelPair = topLevelRole + "\u{001F}" + topLevelSubrole
    guard nonWindowSourceRolePairs.contains(topLevelPair) else {
        throw HelperFailure.message("CGEvent native window-ID top-level role is a window or unsafe pair")
    }
    let topLevelActions = try copyAXActions(topLevel)
    let topLevelEnabled = try copyAXEnabled(topLevel)
    guard topLevelActions.isEmpty, topLevelEnabled else {
        throw HelperFailure.message("CGEvent native window-ID top-level object is interactive")
    }

    var topLevelWindowValue: CFTypeRef?
    let topLevelWindowStatus = AXUIElementCopyAttributeValue(
        topLevel, kAXWindowAttribute as CFString, &topLevelWindowValue)
    let topLevelWindowRaw = try unavailableStatus(
        topLevelWindowStatus, topLevelWindowValue, "top-level AXWindow")

    var topLevelParentValue: CFTypeRef?
    let topLevelParentStatus = AXUIElementCopyAttributeValue(
        topLevel, kAXParentAttribute as CFString, &topLevelParentValue)
    let topLevelParentRaw = try unavailableStatus(
        topLevelParentStatus, topLevelParentValue, "top-level AXParent")

    var targetChildrenValue: CFTypeRef?
    let targetChildrenStatus = AXUIElementCopyAttributeValue(
        target, kAXChildrenAttribute as CFString, &targetChildrenValue)
    let targetChildrenRaw = try unavailableStatus(
        targetChildrenStatus, targetChildrenValue, "target AXChildren")
    _ = try exactTargetAXWindow(target, expectedPid, target,
                                "system-wide-native-window-id", "native window-ID target")

    return ["version": "system-wide-native-window-id-v1",
            "candidateIndex": 0, "receiver": "system-wide",
            "hitPid": Int(hitPid), "hitRole": hitRole, "hitSubrole": hitSubrole,
            "hitActions": hitActions, "hitEnabled": hitEnabled,
            "hitMatchedTarget": hitMatchedTarget,
            "nativeWindowIDMethod": trustedAXResolverMethod,
            "nativeWindowIDStatus": hitNativeWindow.status,
            "nativeWindowID": hitNativeWindow.id,
            "targetNativeWindowIDStatus": targetNativeWindow.status,
            "targetNativeWindowID": targetNativeWindow.id,
            "hitWindowStatus": hitWindowRaw, "topLevelStatus": 0,
            "topLevelType": "AXUIElement", "topLevelPid": Int(topLevelPid),
            "topLevelRole": topLevelRole, "topLevelSubrole": topLevelSubrole,
            "topLevelActions": topLevelActions, "topLevelEnabled": topLevelEnabled,
            "topLevelMatchedTarget": false,
            "topLevelNativeWindowIDStatus": topLevelNativeWindow.status,
            "topLevelNativeWindowID": topLevelNativeWindow.id,
            "nativeWindowIDProvenanceMethod": resolverBinding.provenanceMethod,
            "nativeWindowIDProvenanceImage": resolverBinding.imagePath,
            "nativeWindowIDProvenanceExpectedImage": trustedAXExportingImagePath,
            "nativeWindowIDProvenanceVerified": resolverBinding.verified,
            "nativeWindowIDProvenanceBasePresent": resolverBinding.imageBasePresent,
            "nativeWindowIDProvenanceHandlePresent": true,
            "topLevelWindowStatus": topLevelWindowRaw,
            "topLevelParentStatus": topLevelParentRaw,
            "targetChildrenStatus": targetChildrenRaw,
            "targetType": "AXUIElement", "targetPid": expectedPid,
            "targetRole": "AXWindow", "targetSubrole": "AXStandardWindow",
            "targetMatched": true]
}

func axWindowAncestor(_ element: AXUIElement, _ expectedPid: Int,
                      _ target: AXUIElement) throws -> AXWindowAncestorProof {
    // Bind every ancestry route to the successful hit's exact process before
    // trying a compatibility attribute.  A malformed/cross-process hit is
    // terminal and cannot reach a weaker fallback.
    var elementPid: pid_t = 0
    guard AXUIElementGetPid(element, &elementPid) == .success,
          Int(elementPid) == expectedPid else {
        throw HelperFailure.message("AX hit-test element PID is missing or mismatched")
    }
    var value: CFTypeRef?
    let status = AXUIElementCopyAttributeValue(element, kAXWindowAttribute as CFString, &value)
    if status == .success {
        guard let value, CFGetTypeID(value) == AXUIElementGetTypeID() else {
            throw HelperFailure.message("AX direct window attribute is missing or malformed")
        }
        return try exactTargetAXWindow(value as! AXUIElement, expectedPid, target,
                                       "kAXWindowAttribute", "direct window attribute")
    }
    if status == .attributeUnsupported {
        guard value == nil else {
            throw HelperFailure.message("AX direct window attribute has malformed unavailable value")
        }
    } else {
        guard status == .noValue else {
            throw HelperFailure.message("AX direct window attribute failed status=\(status.rawValue)")
        }
        guard value == nil else {
            throw HelperFailure.message("AX direct window attribute has malformed no-value result")
        }
    }

    // AXWindow is unavailable on some STP builds.  The top-level element is
    // an equally authoritative, typed alternative.  If it is another AX
    // object, resolve only its exact window relation; never relax CFEqual.
    var topLevelValue: CFTypeRef?
    let topLevelStatus = AXUIElementCopyAttributeValue(
        element, kAXTopLevelUIElementAttribute as CFString, &topLevelValue)
    if topLevelStatus == .success {
        guard let topLevelValue,
              CFGetTypeID(topLevelValue) == AXUIElementGetTypeID() else {
            throw HelperFailure.message("AX top-level element is missing or malformed")
        }
        let topLevel = topLevelValue as! AXUIElement
        var topLevelPid: pid_t = 0
        guard AXUIElementGetPid(topLevel, &topLevelPid) == .success,
              Int(topLevelPid) == expectedPid else {
            throw HelperFailure.message("AX top-level element PID is missing or mismatched")
        }
        if CFEqual(topLevel, target) {
            return try exactTargetAXWindow(topLevel, expectedPid, target,
                                           "kAXTopLevelUIElement", "top-level element")
        }

        // First ask the returned top-level object for its actual window
        // attribute.  A successful but non-target/malformed result is
        // terminal; only explicit unavailable statuses may advance.
        var relatedWindowValue: CFTypeRef?
        let relatedWindowStatus = AXUIElementCopyAttributeValue(
            topLevel, kAXWindowAttribute as CFString, &relatedWindowValue)
        if relatedWindowStatus == .success {
            guard let relatedWindowValue,
                  CFGetTypeID(relatedWindowValue) == AXUIElementGetTypeID() else {
                throw HelperFailure.message("AX top-level window relation is missing or malformed")
            }
            return try exactTargetAXWindow(relatedWindowValue as! AXUIElement,
                                           expectedPid, target,
                                           "top-level-AXWindow", "top-level window relation")
        }
        if relatedWindowStatus == .attributeUnsupported {
            guard relatedWindowValue == nil else {
                throw HelperFailure.message("AX top-level window relation has malformed unavailable value")
            }
        } else {
            guard relatedWindowStatus == .noValue else {
                throw HelperFailure.message("AX top-level window relation failed status=\(relatedWindowStatus.rawValue)")
            }
            guard relatedWindowValue == nil else {
                throw HelperFailure.message("AX top-level window relation has malformed no-value result")
            }
        }

        // If the direct relation is explicitly unavailable, use only a
        // bounded parent chain rooted at that same top-level object.  Track
        // all identities so non-adjacent cycles cannot reach input.
        var relationCurrent = topLevel
        var relationSeen: [AXUIElement] = [topLevel]
        var relationUnavailable = false
        for _ in 0..<8 {
            var relationParentValue: CFTypeRef?
            let relationParentStatus = AXUIElementCopyAttributeValue(
                relationCurrent, kAXParentAttribute as CFString, &relationParentValue)
            if relationParentStatus == .attributeUnsupported || relationParentStatus == .noValue {
                guard relationParentValue == nil else {
                    throw HelperFailure.message("AX top-level parent relation has malformed unavailable value")
                }
                relationUnavailable = true
                break
            }
            guard relationParentStatus == .success, let relationParentValue,
                  CFGetTypeID(relationParentValue) == AXUIElementGetTypeID() else {
                throw HelperFailure.message("AX top-level parent relation is missing or malformed status=\(relationParentStatus.rawValue)")
            }
            let relationParent = relationParentValue as! AXUIElement
            var relationParentPid: pid_t = 0
            guard AXUIElementGetPid(relationParent, &relationParentPid) == .success,
                  Int(relationParentPid) == expectedPid else {
                throw HelperFailure.message("AX top-level parent relation PID is missing or mismatched")
            }
            guard !relationSeen.contains(where: { CFEqual($0, relationParent) }) else {
                throw HelperFailure.message("AX top-level parent relation is cyclic")
            }
            relationSeen.append(relationParent)
            if CFEqual(relationParent, target) {
                return try exactTargetAXWindow(relationParent, expectedPid, target,
                                               "top-level-parent-chain", "top-level parent relation")
            }
            let relationParentRole = try copyAXString(
                relationParent, kAXRoleAttribute as String, "top-level parent role")
            if relationParentRole == "AXWindow" {
                return try exactTargetAXWindow(relationParent, expectedPid, target,
                                               "top-level-parent-chain", "top-level parent relation")
            }
            relationCurrent = relationParent
        }
        guard relationUnavailable else {
            throw HelperFailure.message("AX top-level parent relation exceeded bounded depth")
        }
        return try targetContainsTopLevel(target, topLevel, expectedPid)
    }
    if topLevelStatus == .attributeUnsupported {
        guard topLevelValue == nil else {
            throw HelperFailure.message("AX top-level element has malformed unavailable value")
        }
    } else {
        guard topLevelStatus == .noValue else {
            throw HelperFailure.message("AX top-level element failed status=\(topLevelStatus.rawValue)")
        }
        guard topLevelValue == nil else {
            throw HelperFailure.message("AX top-level element has malformed no-value result")
        }
    }

    // With both authoritative attributes explicitly unavailable, a hit may
    // still be the target AXWindow itself or have a bounded exact parent
    // proof.  Missing or malformed parent attributes remain terminal.
    let role = try copyAXString(element, kAXRoleAttribute as String, "role")
    if CFEqual(element, target) {
        return try exactTargetAXWindow(element, expectedPid, target,
                                       "self-AXWindow", "self window")
    }
    if role == "AXWindow" {
        return try exactTargetAXWindow(element, expectedPid, target,
                                       "self-AXWindow", "self window")
    }
    var current = element
    var seen: [AXUIElement] = [element]
    for _ in 0..<8 {
        var parentValue: CFTypeRef?
        let parentStatus = AXUIElementCopyAttributeValue(current, kAXParentAttribute as CFString, &parentValue)
        guard parentStatus == .success, let parentValue,
              CFGetTypeID(parentValue) == AXUIElementGetTypeID() else {
            throw HelperFailure.message("AX parent-chain window ancestry is missing or malformed status=\(parentStatus.rawValue)")
        }
        let parent = parentValue as! AXUIElement
        var parentPid: pid_t = 0
        guard AXUIElementGetPid(parent, &parentPid) == .success,
              Int(parentPid) == expectedPid else {
            throw HelperFailure.message("AX parent-chain window ancestry PID is missing or mismatched")
        }
        guard !seen.contains(where: { CFEqual($0, parent) }) else {
            throw HelperFailure.message("AX parent-chain window ancestry is cyclic")
        }
        seen.append(parent)
        if CFEqual(parent, target) {
            return try exactTargetAXWindow(parent, expectedPid, target,
                                           "parent-chain", "parent window")
        }
        let parentRole = try copyAXString(parent, kAXRoleAttribute as String, "parent role")
        if parentRole == "AXWindow" {
            return try exactTargetAXWindow(parent, expectedPid, target,
                                           "parent-chain", "parent window")
        }
        current = parent
    }
    throw HelperFailure.message("AX parent-chain window ancestry exceeded bounded depth")
}

func axElementAt(_ receiver: AXUIElement, _ point: CGPoint) throws -> AXUIElement {
    var element: AXUIElement?
    let status = AXUIElementCopyElementAtPosition(receiver, Float(point.x), Float(point.y), &element)
    guard status == .success else {
        throw AXHitTestReceiverUnavailable.apiFailure(status.rawValue)
    }
    guard let element else {
        throw HelperFailure.message("AX element-at-position returned success without an element")
    }
    return element
}

struct AXDescendantNode {
    let element: AXUIElement
    let bounds: [String: Int]
    let role: String
    let subrole: String
    let actions: [String]
    let enabled: Bool
}

func optionalAXChildren(_ element: AXUIElement) throws -> [AXUIElement] {
    var value: CFTypeRef?
    let status = AXUIElementCopyAttributeValue(element, kAXChildrenAttribute as CFString, &value)
    if status == .noValue { return [] }
    guard status == .success, let value,
          CFGetTypeID(value) == CFArrayGetTypeID(),
          let children = value as? [AXUIElement] else {
        throw HelperFailure.message("AX descendant children are missing or malformed status=\(status.rawValue)")
    }
    return children
}

func integerGeometry(_ raw: [String: Any], _ label: String) throws -> [String: Int] {
    guard let x = raw["x"] as? Int, let y = raw["y"] as? Int,
          let width = raw["width"] as? Int, let height = raw["height"] as? Int,
          width > 0, height > 0 else {
        throw HelperFailure.message("\(label) is malformed")
    }
    return ["x": x, "y": y, "width": width, "height": height]
}

func collectAXDescendants(_ element: AXUIElement, _ depth: Int,
                          _ seen: inout [AXUIElement],
                          _ nodes: inout [AXDescendantNode]) throws {
    let children = try optionalAXChildren(element)
    if depth == 3 {
        guard children.isEmpty else {
            throw HelperFailure.message("AX descendant depth boundary has unresolved children")
        }
        return
    }
    guard children.count <= 128 else {
        throw HelperFailure.message("AX descendant count is unbounded")
    }
    for child in children {
        guard !seen.contains(where: { CFEqual($0, child) }) else {
            throw HelperFailure.message("AX descendant identity is duplicated")
        }
        seen.append(child)
        guard seen.count <= 128 else {
            throw HelperFailure.message("AX descendant traversal is unbounded")
        }
        let bounds = try integerGeometry(try readGeometry(child), "AX descendant bounds")
        let role = try copyAXString(child, kAXRoleAttribute as String, "descendant role")
        let subrole = try copyAXString(child, kAXSubroleAttribute as String, "descendant subrole")
        let actions = try copyAXActions(child)
        let enabled = try copyAXEnabled(child)
        nodes.append(AXDescendantNode(element: child, bounds: bounds, role: role,
                                      subrole: subrole, actions: actions, enabled: enabled))
        try collectAXDescendants(child, depth + 1, &seen, &nodes)
    }
}

func descendantFrameSource(_ pid: Int, _ target: AXUIElement,
                           _ before: [String: Int],
                           _ candidatePoints: [[String: Int]],
                           _ receiverOutcomes: [[String: Any]]) throws -> [String: Any] {
    // Some macOS/STP builds reject the system-wide element-at-position call
    // even while the exact application AX object remains usable.  This
    // fallback is deliberately limited to descendants of that already
    // authenticated target object; it never accepts a caller-selected point
    // or re-resolves a window by title/geometry.
    var seen: [AXUIElement] = [target]
    var nodes: [AXDescendantNode] = []
    try collectAXDescendants(target, 0, &seen, &nodes)
    var accepted: [(index: Int, evidence: [String: Any])] = []
    // The parser receives only the chosen descendant proof and the complete
    // direct-receiver failure transcript; it cannot independently reconstruct
    // which later descendant nodes were accepted.  Keep the fallback's
    // selection rule canonical and parser-verifiable by considering only the
    // first deterministic candidate.  If that point is not uniquely safe,
    // fail closed rather than concealing a later source behind missing
    // per-candidate descendant evidence.
    for (candidateIndex, rawPoint) in candidatePoints.prefix(1).enumerated() {
        let point = pointValue(rawPoint)
        var matches: [(node: AXDescendantNode, ancestorRole: String, ancestorSubrole: String,
                       ancestorMethod: String)] = []
        var blocked = false
        for node in nodes {
            guard pointInside(point, node.bounds) else { continue }
            var nodePid: pid_t = 0
            guard AXUIElementGetPid(node.element, &nodePid) == .success,
                  Int(nodePid) == pid else {
                blocked = true
                continue
            }
            let ancestorProof: AXWindowAncestorProof
            do {
                ancestorProof = try axWindowAncestor(node.element, pid, target)
            } catch {
                blocked = true
                continue
            }
            let ancestor = ancestorProof.element
            var ancestorPid: pid_t = 0
            guard AXUIElementGetPid(ancestor, &ancestorPid) == .success,
                  Int(ancestorPid) == pid,
                  CFEqual(ancestor, target) else {
                blocked = true
                continue
            }
            let ancestorRole: String
            let ancestorSubrole: String
            do {
                ancestorRole = try copyAXString(ancestor, kAXRoleAttribute as String, "descendant ancestor role")
                ancestorSubrole = try copyAXString(ancestor, kAXSubroleAttribute as String, "descendant ancestor subrole")
            } catch {
                blocked = true
                continue
            }
            guard ancestorRole == "AXWindow", ancestorSubrole == "AXStandardWindow" else {
                blocked = true
                continue
            }
            let pair = node.role + "\u{001F}" + node.subrole
            guard allowedSourceRolePairs.contains(pair), node.actions.isEmpty, node.enabled else {
                // An interactive, unknown, or disabled descendant covering
                // this source point makes that point unsafe.
                blocked = true
                continue
            }
            matches.append((node, ancestorRole, ancestorSubrole, ancestorProof.method))
        }
        guard !blocked, matches.count == 1, let source = matches.first else { continue }
        accepted.append((candidateIndex, ["candidatePoints": candidatePoints,
                "candidateIndex": candidateIndex, "chosenPoint": rawPoint,
                "role": source.node.role, "subrole": source.node.subrole,
                "actions": source.node.actions, "enabled": source.node.enabled,
                "pid": pid, "ancestorPid": pid, "ancestorRole": source.ancestorRole,
                "ancestorSubrole": source.ancestorSubrole, "ancestorMethod": source.ancestorMethod,
                "targetWindowMatched": true,
                "sourceMethod": "descendant-frame", "receiverOutcomes": receiverOutcomes]))
    }
    if let first = accepted.first { return first.evidence }
    throw HelperFailure.message("AX descendant-frame title-bar proof found no unique inert source")
}

func draggableAXSource(_ pid: Int, _ windowId: Int, _ target: AXUIElement,
                       _ before: [String: Int]) throws -> [String: Any] {
    let candidatePoints = try deterministicAXCandidatePoints(before)
    var rejected: [String] = []
    var accepted: [(index: Int, evidence: [String: Any], sourceMethod: String)] = []
    var receiverOutcomes: [[String: Any]] = []
    // Prefer the documented system-wide receiver for true z-order hit
    // testing, then retry against the exact target application.  Both paths
    // remain bound to the carried target by CFEqual below.  If both are
    // unavailable, the exact-target descendant-frame proof is the only
    // fallback; it never becomes a generic input/control API.
    let receivers: [AXUIElement] = [AXUIElementCreateSystemWide(),
                                    AXUIElementCreateApplication(pid_t(pid))]
    let receiverNames = ["system-wide", "application"]
    for (candidateIndex, rawPoint) in candidatePoints.enumerated() {
        let point = pointValue(rawPoint)
        var acceptedForPoint = false
        for (receiverIndex, receiver) in receivers.enumerated() {
            let element: AXUIElement
            do {
                element = try axElementAt(receiver, point)
            } catch let unavailable as AXHitTestReceiverUnavailable {
                switch unavailable {
                case .apiFailure(let status):
                    receiverOutcomes.append(["candidateIndex": candidateIndex,
                            "receiver": receiverNames[receiverIndex], "result": "unavailable",
                            "status": status])
                }
                rejected.append("candidate-\(candidateIndex)-\(receiverNames[receiverIndex])-unavailable")
                continue
            }
            // A successful API result is authoritative.  Any malformed or
            // unsafe attribute below is terminal and must not fall through to
            // the weaker descendant-frame approximation.
            receiverOutcomes.append(["candidateIndex": candidateIndex,
                    "receiver": receiverNames[receiverIndex], "result": "hit", "status": 0])
            var elementPid: pid_t = 0
            guard AXUIElementGetPid(element, &elementPid) == .success,
                  Int(elementPid) == pid else {
                throw HelperFailure.message("AX hit-test returned a successful hit for the wrong PID")
            }
            let ancestorProof: AXWindowAncestorProof
            do {
                ancestorProof = try axWindowAncestor(element, pid, target)
            } catch {
                // The coordinate-attested route is strictly a production
                // compatibility escape for the first system-wide point.  It
                // is attempted only after the ordinary exact ancestry proof
                // fails, and its own transcript must prove every relation
                // was explicitly unavailable.  App-receiver hits,
                // nonzero points, partial relations, and malformed data
                // remain terminal and cannot reach this route.
                if candidateIndex == 0 && receiverIndex == 0 {
                    do {
                        let fallback = try systemWideNativeWindowBinding(element, pid, windowId, target)
                        guard let fallbackRole = fallback["hitRole"] as? String,
                              let fallbackSubrole = fallback["hitSubrole"] as? String,
                              let fallbackActions = fallback["hitActions"] as? [String],
                              let fallbackEnabled = fallback["hitEnabled"] as? Bool else {
                            throw HelperFailure.message("CGEvent native window-ID source evidence is malformed")
                        }
                        return ["candidatePoints": candidatePoints,
                                "candidateIndex": candidateIndex, "chosenPoint": rawPoint,
                                "role": fallbackRole, "subrole": fallbackSubrole,
                                "actions": fallbackActions, "enabled": fallbackEnabled,
                                "pid": pid, "ancestorPid": pid,
                                "ancestorRole": "AXWindow",
                                "ancestorSubrole": "AXStandardWindow",
                                "ancestorMethod": "system-wide-native-window-id",
                                "targetWindowMatched": true,
                                "sourceMethod": "system-wide",
                                "receiverOutcomes": receiverOutcomes,
                                "nativeWindowBinding": fallback]
                    } catch {
                        // Preserve the original ordinary ancestry error.  A
                        // fallback is valid only when its complete typed
                        // unavailability transcript succeeds.
                    }
                }
                throw error
            }
            let ancestor = ancestorProof.element
            var ancestorPid: pid_t = 0
            guard AXUIElementGetPid(ancestor, &ancestorPid) == .success,
                  Int(ancestorPid) == pid,
                  CFEqual(ancestor, target) else {
                throw HelperFailure.message("AX hit-test returned a successful hit with the wrong ancestor")
            }
            let role = try copyAXString(element, kAXRoleAttribute as String, "role")
            let subrole = try copyAXString(element, kAXSubroleAttribute as String, "subrole")
            let actions = try copyAXActions(element)
            let enabled = try copyAXEnabled(element)
            let sourceRolePair = role + "\u{001F}" + subrole
            guard allowedSourceRolePairs.contains(sourceRolePair) else {
                throw HelperFailure.message("AX hit-test returned an unsafe role/subrole pair")
            }
            guard actions.isEmpty else {
                throw HelperFailure.message("AX hit-test returned an interactive source")
            }
            guard enabled else {
                throw HelperFailure.message("AX hit-test returned a disabled source")
            }
            let ancestorRole = try copyAXString(ancestor, kAXRoleAttribute as String, "ancestor role")
            let ancestorSubrole = try copyAXString(ancestor, kAXSubroleAttribute as String, "ancestor subrole")
            guard ancestorRole == "AXWindow", ancestorSubrole == "AXStandardWindow" else {
                throw HelperFailure.message("AX hit-test returned a nonstandard ancestor")
            }
            accepted.append((candidateIndex, ["candidatePoints": candidatePoints,
                    "candidateIndex": candidateIndex, "chosenPoint": rawPoint,
                    "role": role, "subrole": subrole, "actions": actions,
                    "enabled": enabled, "pid": pid, "ancestorPid": Int(ancestorPid),
                    "ancestorRole": ancestorRole, "ancestorSubrole": ancestorSubrole,
                    "ancestorMethod": ancestorProof.method,
                    "targetWindowMatched": true], receiverNames[receiverIndex]))
            acceptedForPoint = true
            break
        }
        if !acceptedForPoint { rejected.append("candidate-\(candidateIndex)-no-receiver-proof") }
    }
    // The first safe point in deterministic order is the only canonical
    // selection.  Do not prefer a later AXWindow: its role is not carried for
    // nonchosen candidates and would make the parser unable to verify the
    // native result.
    if let first = accepted.first {
        var evidence = first.evidence
        evidence["sourceMethod"] = first.sourceMethod
        evidence["receiverOutcomes"] = receiverOutcomes
        return evidence
    }
    guard receiverOutcomes.count == candidatePoints.count * receivers.count,
          receiverOutcomes.allSatisfy({ $0["result"] as? String == "unavailable" }) else {
        throw HelperFailure.message("AX hit-test returned no accepted source after a non-API result")
    }
    do {
        return try descendantFrameSource(pid, target, before, candidatePoints, receiverOutcomes)
    } catch {
        throw HelperFailure.message("AX title-bar source proof unavailable: \(rejected.joined(separator: ",")); descendant-frame fallback failed")
    }
}

func cursorPoint() throws -> [String: Int] {
    guard let event = CGEvent(source: nil) else {
        throw HelperFailure.message("CGEvent cursor location is unavailable")
    }
    let point = event.location
    return ["x": try exactCoordinate(point.x, "CGEvent cursor x"),
            "y": try exactCoordinate(point.y, "CGEvent cursor y")]
}

func pointValue(_ point: [String: Int]) -> CGPoint {
    return CGPoint(x: CGFloat(point["x"]!), y: CGFloat(point["y"]!))
}

func restoreCursor(_ point: [String: Int]) throws {
    guard CGWarpMouseCursorPosition(pointValue(point)) == .success else {
        throw HelperFailure.message("CGEvent cursor restoration failed")
    }
}

func withCursorRestored<T>(_ point: [String: Int], _ cleanup: () -> Void,
                           _ operation: () throws -> T) throws -> T {
    var result: T?
    var operationError: Error?
    var restoreError: Error?
    do {
        defer {
            // The caller's cleanup closure performs a compensating left-up
            // first when a down was successfully posted without a confirmed
            // up.  Cursor restoration is deliberately second.
            cleanup()
            do {
                try restoreCursor(point)
            } catch {
                restoreError = error
            }
        }
        do {
            result = try operation()
        } catch {
            operationError = error
        }
    }
    if restoreError != nil {
        throw HelperFailure.message("CGEvent cursor restoration failed")
    }
    if let operationError {
        throw operationError
    }
    guard let result else {
        throw HelperFailure.message("CGEvent move did not produce evidence")
    }
    return result
}

func postMouseEvent(_ type: CGEventType, _ point: CGPoint) throws {
    guard let event = CGEvent(mouseEventSource: nil, mouseType: type,
                              mouseCursorPosition: point, mouseButton: .left) else {
        throw HelperFailure.message("CGEvent mouse event creation failed")
    }
    event.post(tap: .cghidEventTap)
}

// CGMouseButton accepts the complete representable raw range on macOS.  Treat
// every value 0...31 as part of the pre-input contract: a pre-existing click
// in any button is unsafe to combine with the synthetic title-bar drag.  A
// raw value that cannot be represented is an error, never an omitted key.
let standardMouseButtonValues = Array(0...31)

func quiescentMouseButtonState(_ label: String) throws -> [String: Any] {
    var states: [String: Any] = [:]
    for rawValue in standardMouseButtonValues {
        guard let button = CGMouseButton(rawValue: UInt32(rawValue)) else {
            throw HelperFailure.message("CGEvent \(label) button \(rawValue) is unsupported")
        }
        states[String(rawValue)] = CGEventSource.buttonState(
            .combinedSessionState, button: button)
    }
    let expectedNames = Set(standardMouseButtonValues.map { String($0) })
    guard Set(states.keys) == expectedNames else {
        throw HelperFailure.message("CGEvent \(label) button-state snapshot is incomplete")
    }
    for (name, rawState) in states {
        guard let state = rawState as? Bool else {
            throw HelperFailure.message("CGEvent \(label) button-state \(name) is malformed")
        }
        guard !state else {
            throw HelperFailure.message("CGEvent \(label) button \(name) is already pressed")
        }
    }
    return states
}

func sameAXHitEvidence(_ lhs: [String: Any], _ rhs: [String: Any]) throws -> Bool {
    // A system-wide hover can move between inert AX descendants while the
    // pointer remains over the same title-bar window.  For that one route,
    // canonicalize the hit by the native window-ID relation, but retain every
    // typed identity/status field and the safe role restrictions.  This is
    // not a scalar-coordinate fallback: both transcripts must identify the
    // exact CoreGraphics window through the trusted SPI.  Other ancestry
    // methods remain strict object/evidence equality.
    let nativeMethod = "system-wide-native-window-id"
    if let lhsMethod = lhs["ancestorMethod"] as? String,
       let rhsMethod = rhs["ancestorMethod"] as? String,
       (lhsMethod == nativeMethod || rhsMethod == nativeMethod) {
        guard lhsMethod == nativeMethod, rhsMethod == nativeMethod,
              let lhsBinding = lhs["nativeWindowBinding"] as? [String: Any],
              let rhsBinding = rhs["nativeWindowBinding"] as? [String: Any] else {
            return false
        }
        let safePairs = Set(["AXGroup\u{001F}AXTitleBar",
                             "AXWindow\u{001F}AXStandardWindow"])
        guard let lhsPair = (lhsBinding["hitRole"] as? String).flatMap({ role in
                    (lhsBinding["hitSubrole"] as? String).map { role + "\u{001F}" + $0 }
                }),
              let rhsPair = (rhsBinding["hitRole"] as? String).flatMap({ role in
                    (rhsBinding["hitSubrole"] as? String).map { role + "\u{001F}" + $0 }
                }),
              safePairs.contains(lhsPair), safePairs.contains(rhsPair),
              lhsBinding["topLevelRole"] as? String == "AXGroup",
              lhsBinding["topLevelSubrole"] as? String == "AXTitleBar",
              rhsBinding["topLevelRole"] as? String == "AXGroup",
              rhsBinding["topLevelSubrole"] as? String == "AXTitleBar",
              lhsBinding["hitActions"] as? [String] == [],
              rhsBinding["hitActions"] as? [String] == [],
              lhsBinding["topLevelActions"] as? [String] == [],
              rhsBinding["topLevelActions"] as? [String] == [],
              lhsBinding["hitEnabled"] as? Bool == true,
              rhsBinding["hitEnabled"] as? Bool == true,
              lhsBinding["topLevelEnabled"] as? Bool == true,
              rhsBinding["topLevelEnabled"] as? Bool == true else {
            return false
        }
        let stableBindingKeys = ["version", "candidateIndex", "receiver", "hitPid",
            "nativeWindowIDMethod", "nativeWindowIDStatus",
            "nativeWindowID", "targetNativeWindowIDStatus", "targetNativeWindowID",
            "topLevelNativeWindowIDStatus", "topLevelNativeWindowID", "hitWindowStatus",
            "topLevelStatus", "topLevelType", "topLevelPid", "topLevelMatchedTarget",
            "topLevelWindowStatus", "topLevelParentStatus", "targetChildrenStatus",
            "targetType", "targetPid", "targetRole", "targetSubrole", "targetMatched"]
        let stableOuterKeys = ["candidatePoints", "candidateIndex", "chosenPoint", "pid",
            "ancestorPid", "ancestorRole", "ancestorSubrole", "ancestorMethod",
            "targetWindowMatched", "targetAxWindowNumber", "mappingMethod", "sourceMethod",
            "receiverOutcomes"]
        func encoded(_ value: Any) -> Data? {
            guard JSONSerialization.isValidJSONObject(value) else { return nil }
            return try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        }
        var lhsStableBinding: [String: Any] = [:]
        var rhsStableBinding: [String: Any] = [:]
        for key in stableBindingKeys {
            guard let left = lhsBinding[key], let right = rhsBinding[key] else { return false }
            lhsStableBinding[key] = left; rhsStableBinding[key] = right
        }
        var lhsStableOuter: [String: Any] = [:]
        var rhsStableOuter: [String: Any] = [:]
        for key in stableOuterKeys {
            guard let left = lhs[key], let right = rhs[key] else { return false }
            lhsStableOuter[key] = left; rhsStableOuter[key] = right
        }
        guard let lhsBindingData = encoded(lhsStableBinding),
              let rhsBindingData = encoded(rhsStableBinding),
              let lhsOuterData = encoded(lhsStableOuter),
              let rhsOuterData = encoded(rhsStableOuter) else { return false }
        return lhsBindingData == rhsBindingData && lhsOuterData == rhsOuterData
    }
    guard JSONSerialization.isValidJSONObject(lhs), JSONSerialization.isValidJSONObject(rhs),
          let left = try? JSONSerialization.data(withJSONObject: lhs, options: [.sortedKeys]),
          let right = try? JSONSerialization.data(withJSONObject: rhs, options: [.sortedKeys]) else {
        throw HelperFailure.message("CGEvent AX reattestation evidence is not serializable")
    }
    return left == right
}

func cgeventTitlebarMove(_ pid: Int, _ windowId: Int, _ expectedTitle: String,
                         _ before: [String: Int], _ requested: [String: Int],
                         _ target: AXUIElement, _ targetAxWindowNumber: Int?,
                         _ mappingMethod: String) throws -> [String: Any] {
    guard before["width"]! >= 260, before["height"]! >= 40 else {
        throw HelperFailure.message("CGEvent target is too small for a safe title-bar point")
    }
    // AX hit-testing is the source of truth for the drag point.  The helper
    // never accepts a caller-supplied coordinate and never mutates before
    // the exact target AX window/role/ancestry proof succeeds.
    guard mappingMethod == "ax-window-number" || mappingMethod == "title-geometry" else {
        throw HelperFailure.message("AX target mapping method is malformed")
    }
    if mappingMethod == "ax-window-number" {
        guard targetAxWindowNumber == windowId else {
            throw HelperFailure.message("AX target window number is not exact")
        }
    } else {
        guard targetAxWindowNumber == nil else {
            throw HelperFailure.message("AX title-geometry mapping unexpectedly has a window number")
        }
    }
    var axHitEvidence = try draggableAXSource(pid, windowId, target, before)
    axHitEvidence["targetAxWindowNumber"] = targetAxWindowNumber ?? NSNull()
    axHitEvidence["mappingMethod"] = mappingMethod
    let boundAXHitEvidence = axHitEvidence
    guard let rawSource = axHitEvidence["chosenPoint"] as? [String: Int] else {
        throw HelperFailure.message("AX title-bar hit-test source is malformed")
    }
    let sourcePoint = pointValue(rawSource)
    let delta = ["x": requested["x"]! - before["x"]!, "y": requested["y"]! - before["y"]!]
    guard delta["x"]! != 0 || delta["y"]! != 0 else {
        throw HelperFailure.message("CGEvent fallback requires a nonzero position delta")
    }
    let topmost = try topmostProof(pid, windowId, expectedTitle, sourcePoint, before)
    let buttonStateBeforeWarp = try quiescentMouseButtonState("before-warp")
    let cursorBefore = try cursorPoint()
    var leftMouseDownPosted = false
    var leftMouseUpConfirmed = false
    var cleanupUpAttempted = false
    var cleanupUpSucceeded = false
    var cleanupUpPointEvidence: [String: Any]? = nil
    var cleanupPointValue: CGPoint? = nil
    var lastEventPoint = sourcePoint
    let moveEvidence: [String: Any]
    do {
        moveEvidence = try withCursorRestored(cursorBefore, {
            if leftMouseDownPosted && !leftMouseUpConfirmed && !cleanupUpAttempted {
                cleanupUpAttempted = true
                cleanupPointValue = (try? cursorPoint()).map(pointValue) ?? lastEventPoint
                cleanupUpPointEvidence = ["x": cleanupPointValue!.x, "y": cleanupPointValue!.y]
                do {
                    try postMouseEvent(.leftMouseUp, cleanupPointValue!)
                    cleanupUpSucceeded = true
                    leftMouseUpConfirmed = true
                    lastEventPoint = cleanupPointValue!
                } catch {
                    cleanupUpSucceeded = false
                }
            }
        }) {
            guard CGPreflightPostEventAccess() else {
                throw HelperFailure.message("CGEvent post permission is unavailable")
            }
            guard CGWarpMouseCursorPosition(sourcePoint) == .success else {
                throw HelperFailure.message("CGEvent cursor move to safe point failed")
            }
            // Cursor movement is a race boundary.  Before the first input
            // event, re-attest the exact target record and full front-to-back
            // topmost proof, rerun the read-only AX source proof, and check
            // every standard button again.  There is no intervening mutation
            // or retry between this final state gate and mouseDown.
            let preMouseDownBounds = try coreGraphicsBefore(pid, windowId, expectedTitle)
            guard preMouseDownBounds == before else {
                throw HelperFailure.message("CGEvent target changed after cursor warp")
            }
            let preMouseDownTopmost = try topmostProof(
                pid, windowId, expectedTitle, sourcePoint, before)
            var preMouseDownAXHit = try draggableAXSource(pid, windowId, target, before)
            preMouseDownAXHit["targetAxWindowNumber"] = targetAxWindowNumber ?? NSNull()
            preMouseDownAXHit["mappingMethod"] = mappingMethod
            guard try sameAXHitEvidence(axHitEvidence, preMouseDownAXHit) else {
                throw HelperFailure.message("CGEvent AX source changed after cursor warp")
            }
            let buttonStateBeforeMouseDown = try quiescentMouseButtonState("before-mouse-down")
            try postMouseEvent(.leftMouseDown, sourcePoint)
            leftMouseDownPosted = true
            lastEventPoint = sourcePoint
            let steps = 24
            for step in 1...steps {
                let fraction = CGFloat(step) / CGFloat(steps)
                let point = CGPoint(x: sourcePoint.x + CGFloat(delta["x"]!) * fraction,
                                    y: sourcePoint.y + CGFloat(delta["y"]!) * fraction)
                try postMouseEvent(.leftMouseDragged, point)
                lastEventPoint = point
            }
            let destinationPoint = CGPoint(x: sourcePoint.x + CGFloat(delta["x"]!),
                                           y: sourcePoint.y + CGFloat(delta["y"]!))
            try postMouseEvent(.leftMouseUp, destinationPoint)
            leftMouseUpConfirmed = true
            lastEventPoint = destinationPoint
            let after = try coreGraphicsBefore(pid, windowId, expectedTitle)
            guard after == requested else {
                throw HelperFailure.message("CGEvent drag did not produce exact target bounds")
            }
            let source = ["x": try exactCoordinate(sourcePoint.x, "CGEvent source x"),
                          "y": try exactCoordinate(sourcePoint.y, "CGEvent source y")]
            let destination = ["x": try exactCoordinate(destinationPoint.x, "CGEvent destination x"),
                               "y": try exactCoordinate(destinationPoint.y, "CGEvent destination y")]
            let sequence = [String](repeating: "leftMouseDragged", count: 24)
            var preMouseDownAXEvidence = preMouseDownAXHit
            preMouseDownAXEvidence["targetAxWindowNumber"] = targetAxWindowNumber ?? NSNull()
            preMouseDownAXEvidence["mappingMethod"] = mappingMethod
            return ["sourcePoint": source, "destinationPoint": destination, "delta": delta,
                    "safePoint": true, "axHitTest": boundAXHitEvidence, "topmostProof": topmost,
                    "buttonStateBeforeWarp": buttonStateBeforeWarp,
                    "buttonStateBeforeMouseDown": buttonStateBeforeMouseDown,
                    "preMouseDownBounds": preMouseDownBounds,
                    "preMouseDownTopmostProof": preMouseDownTopmost,
                    "preMouseDownAXHitTest": preMouseDownAXEvidence,
                    "inputReattested": true,
                    "eventSequence": ["leftMouseDown"] + sequence + ["leftMouseUp"],
                    "eventCount": 26, "dragSteps": 24, "postBounds": after,
                    "cleanupUpAttempted": cleanupUpAttempted,
                    "cleanupUpSucceeded": cleanupUpSucceeded,
                    "cleanupUpPoint": cleanupUpPointEvidence ?? NSNull(),
                    "leftMouseUpConfirmed": leftMouseUpConfirmed]
        }
    } catch {
        let cleanupEvidence: [String: Any] = [
            "cleanupUpAttempted": cleanupUpAttempted,
            "cleanupUpSucceeded": cleanupUpSucceeded,
            "cleanupUpPoint": cleanupUpPointEvidence ?? NSNull(),
            "leftMouseDownPosted": leftMouseDownPosted,
            "leftMouseUpConfirmed": leftMouseUpConfirmed]
        if leftMouseDownPosted && !leftMouseUpConfirmed && !cleanupUpSucceeded {
            throw HelperFailure.cgeventFailure("CGEvent cleanup mouse-up failed", cleanupEvidence)
        }
        throw HelperFailure.cgeventFailure("CGEvent drag failed: \(error)", cleanupEvidence)
    }
    let cursorAfter = try cursorPoint()
    guard cursorAfter == cursorBefore else {
        throw HelperFailure.message("CGEvent cursor restoration readback is not exact")
    }
    var evidence = moveEvidence
    evidence["cursorBefore"] = cursorBefore
    evidence["cursorAfter"] = cursorAfter
    evidence["cursorRestored"] = true
    return evidence
}

func settable(_ element: AXUIElement, _ attribute: String) throws {
    guard try isSettable(element, attribute) else { throw HelperFailure.notSettable(attribute) }
}

func isSettable(_ element: AXUIElement, _ attribute: String) throws -> Bool {
    var canSet = DarwinBoolean(false)
    let status = AXUIElementIsAttributeSettable(element, attribute as CFString, &canSet)
    guard status == .success else {
        throw HelperFailure.message("AX settable query failed: \(attribute) status=\(status.rawValue)")
    }
    return canSet.boolValue
}

func setPosition(_ element: AXUIElement, _ requested: [String: Int]) throws {
    var point = CGPoint(x: CGFloat(requested["x"]!), y: CGFloat(requested["y"]!))
    guard let position = AXValueCreate(.cgPoint, &point) else {
        throw HelperFailure.message("AX position value creation failed")
    }
    guard AXUIElementSetAttributeValue(element, kAXPositionAttribute as CFString, position) == .success else {
        throw HelperFailure.message("AX position write failed")
    }
}

func setSize(_ element: AXUIElement, _ requested: [String: Int]) throws {
    var dimensions = CGSize(width: CGFloat(requested["width"]!), height: CGFloat(requested["height"]!))
    guard let size = AXValueCreate(.cgSize, &dimensions) else {
        throw HelperFailure.message("AX size value creation failed")
    }
    guard AXUIElementSetAttributeValue(element, kAXSizeAttribute as CFString, size) == .success else {
        throw HelperFailure.message("AX size write failed")
    }
}

func setGeometry(_ element: AXUIElement, _ requested: [String: Int]) throws {
    var point = CGPoint(x: CGFloat(requested["x"]!), y: CGFloat(requested["y"]!))
    var dimensions = CGSize(width: CGFloat(requested["width"]!), height: CGFloat(requested["height"]!))
    guard let position = AXValueCreate(.cgPoint, &point), let size = AXValueCreate(.cgSize, &dimensions) else {
        throw HelperFailure.message("AX geometry value creation failed")
    }
    guard AXUIElementSetAttributeValue(element, kAXPositionAttribute as CFString, position) == .success else {
        throw HelperFailure.message("AX position write failed")
    }
    guard AXUIElementSetAttributeValue(element, kAXSizeAttribute as CFString, size) == .success else {
        throw HelperFailure.message("AX size write failed")
    }
}

func run(_ arguments: [String]) throws {
    try require(arguments.count == 9 || arguments.count == 10 || arguments.count == 11,
                "exactly eight helper arguments, an optional operation, and an optional binding mode are required")
    let pid = try parseInteger(arguments[1], positive: true)
    let windowId = try parseInteger(arguments[2], positive: true)
    let nonce = arguments[3]
    try require(!nonce.isEmpty && nonce.rangeOfCharacter(from: .whitespacesAndNewlines) == nil, "title nonce is malformed")
    let nativeTitle = arguments[4]
    let requested = ["x": try parseInteger(arguments[5]), "y": try parseInteger(arguments[6]),
                     "width": try parseInteger(arguments[7], positive: true), "height": try parseInteger(arguments[8], positive: true)]
    let effectiveOperation = arguments.count >= 10 ? arguments[9] : "legacy"
    let bindingMode = arguments.count == 11 ? arguments[10] : "native-title"
    let emptyTitleMode = bindingMode == "webdriver-pid-single-window-empty-cg-title"
    try require(["native-title", "webdriver-pid-single-window-empty-cg-title"].contains(bindingMode), "helper binding mode is malformed")
    try require(["legacy", "split", "resize-only", "move-only", "cgevent-titlebar", "inspect-empty-cg-title"].contains(effectiveOperation), "helper operation is malformed")
    try require(emptyTitleMode ? nativeTitle.isEmpty : !nativeTitle.isEmpty, "native title is malformed for binding mode")
    try require(nativeTitle.rangeOfCharacter(from: .controlCharacters) == nil, "native title is malformed")
    if emptyTitleMode { try require(["split", "inspect-empty-cg-title"].contains(effectiveOperation), "empty-title helper operation is forbidden") }
    let right = Int64(requested["x"]!) + Int64(requested["width"]!)
    let bottom = Int64(requested["y"]!) + Int64(requested["height"]!)
    if effectiveOperation != "inspect-empty-cg-title" {
        try require(requested["x"]! >= -1440 && requested["y"]! >= -940 && right <= 0 && bottom <= 1620,
                    "requested bounds are outside KG271U")
    }
    try require(AXIsProcessTrusted(), "Accessibility trust is unavailable")
    let helperUid = Int(getuid())
    guard let runningApplication = NSRunningApplication(processIdentifier: pid_t(pid)),
          runningApplication.bundleIdentifier == expectedBundle,
          runningApplication.executableURL?.path == expectedExecutable else {
        throw HelperFailure.message("target process identity is not exact STP")
    }
    let application = AXUIElementCreateApplication(pid_t(pid))
    let cgBefore = try coreGraphicsBefore(pid, windowId, nativeTitle)
    let rawWindows = try copyAttribute(application, kAXWindowsAttribute as String)
    guard let windows = rawWindows as? [AXUIElement], !windows.isEmpty else {
        throw HelperFailure.message("AX windows attribute is missing or malformed")
    }
    var seen = Set<Int>()
    var matches: [(element: AXUIElement, number: Int?, title: String, before: [String: Any])] = []
    var candidateEvidence: [[String: Any]] = []
    var sawNumber = false
    var sawMissingNumber = false
    for window in windows {
        let titleValue = try copyAttribute(window, kAXTitleAttribute as String)
        guard let title = titleValue as? String else {
            throw HelperFailure.message("AX window title is missing or malformed")
        }
        if !emptyTitleMode && title != nativeTitle { continue }
        let number = try windowNumber(window)
        if let number {
            sawNumber = true
            guard seen.insert(number).inserted else {
                throw HelperFailure.message("AXWindowNumber is duplicated")
            }
        } else {
            sawMissingNumber = true
        }
        let before = try readGeometry(window)
        if emptyTitleMode {
            try require(number != nil, "empty-CG-title AXWindowNumber is missing")
            try require(title.rangeOfCharacter(from: .controlCharacters) == nil,
                        "empty-CG-title AX title is malformed")
            candidateEvidence.append(["pid": pid, "axWindowNumber": number!, "title": title, "bounds": before])
            if number == windowId {
                try require(title.isEmpty || title == nonce,
                            "empty-CG-title AX title contradicts WebDriver document title")
                try require(NSDictionary(dictionary: before).isEqual(to: cgBefore),
                            "empty-CG-title AX geometry contradicts CoreGraphics")
            }
        } else {
            candidateEvidence.append(["pid": pid, "windowId": windowId, "axWindowNumber": number ?? NSNull(), "title": title, "bounds": before])
        }
        if (number == windowId || (!emptyTitleMode && number == nil))
                && NSDictionary(dictionary: before).isEqual(to: cgBefore)
                && (!emptyTitleMode || title.isEmpty || title == nonce) {
            matches.append((window, number, title, before))
        }
    }
    if emptyTitleMode && effectiveOperation == "inspect-empty-cg-title" && matches.isEmpty {
        let evidence: [String: Any] = ["ok": true, "method": method,
            "operation": "inspect-empty-cg-title", "bindingMode": bindingMode,
            "mappingStatus": "unmapped", "helperUid": helperUid, "pid": pid,
            "windowId": windowId, "titleNonce": nonce, "nativeTitle": nativeTitle,
            "cgBefore": cgBefore, "candidateCount": candidateEvidence.count,
            "matchedCount": 0, "candidates": candidateEvidence, "mutationAttempted": false]
        emit(evidence, 0)
        return
    }
    guard matches.count == 1 else {
        throw HelperFailure.message("AX window ID/title mapping is not unique")
    }
    guard !(sawNumber && sawMissingNumber) else {
        throw HelperFailure.message("AXWindowNumber support is inconsistent")
    }
    let target = matches[0]
    let hasNumber = matches.contains { $0.number != nil }
    let missingNumber = matches.contains { $0.number == nil }
    guard !(hasNumber && missingNumber) else {
        throw HelperFailure.message("AXWindowNumber support is inconsistent")
    }
    if emptyTitleMode { try require(target.number == windowId, "empty-CG-title AXWindowNumber mapping is unavailable") }
    let mappingMethod = emptyTitleMode ? "ax-window-number-empty-cg-title" : (target.number == nil ? "title-geometry" : "ax-window-number")
    let titleEvidence = target.title == nonce ? "ax-title" : "webdriver-document-title"
    let mappedCandidateEvidence: [[String: Any]] = [["pid": pid, "windowId": windowId,
        "axWindowNumber": target.number ?? NSNull(), "title": target.title, "bounds": target.before]]
    var mappingEvidence: [String: Any] = ["helperUid": helperUid, "pid": pid, "windowId": windowId,
        "axWindowNumber": target.number ?? NSNull(), "titleNonce": nonce,
        "nativeTitle": nativeTitle, "mappingMethod": mappingMethod, "cgBefore": cgBefore,
        "candidateCount": emptyTitleMode ? mappedCandidateEvidence.count : candidateEvidence.count,
        "matchedCount": matches.count,
        "candidates": emptyTitleMode ? mappedCandidateEvidence : candidateEvidence, "before": target.before]
    if emptyTitleMode {
        mappingEvidence["bindingMode"] = bindingMode
        mappingEvidence["mappingStatus"] = "mapped"
        mappingEvidence["titleEvidence"] = titleEvidence
        mappingEvidence["mutationAttempted"] = false
    }
    let before = target.before
    if effectiveOperation == "inspect-empty-cg-title" {
        try require(NSDictionary(dictionary: before).isEqual(to: requested), "empty-title inspection bounds are not exact")
        var evidence = mappingEvidence
        evidence["ok"] = true
        evidence["method"] = method
        evidence["operation"] = "inspect-empty-cg-title"
        emit(evidence, 0)
        return
    }
    let beforePosition: [String: Any] = ["x": before["x"]!, "y": before["y"]!]
    let beforeSize: [String: Any] = ["width": before["width"]!, "height": before["height"]!]
    let positionSettable = try isSettable(target.element, kAXPositionAttribute as String)
    let sizeSettable = try isSettable(target.element, kAXSizeAttribute as String)

    if effectiveOperation == "legacy" {
        guard before["width"] as! Int == requested["width"]!
                && before["height"] as! Int == requested["height"]! else {
            throw HelperFailure.message("legacy combined operation cannot resize a window")
        }
        guard positionSettable else { throw HelperFailure.notSettableWithEvidence("AXPosition", mappingEvidence) }
        guard sizeSettable else { throw HelperFailure.notSettableWithEvidence("AXSize", mappingEvidence) }
        try setGeometry(target.element, requested)
        let after = try readGeometry(target.element)
        guard NSDictionary(dictionary: after).isEqual(to: requested) else {
            throw HelperFailure.message("AX geometry readback does not match requested bounds")
        }
        let evidence: [String: Any] = ["ok": true, "method": method, "helperUid": helperUid,
            "pid": pid, "windowId": windowId, "axWindowNumber": target.number ?? NSNull(), "titleNonce": nonce,
            "nativeTitle": nativeTitle, "mappingMethod": mappingMethod, "cgBefore": cgBefore,
            "candidateCount": candidateEvidence.count,
            "matchedCount": matches.count, "candidates": candidateEvidence, "before": before,
            "requestedBounds": requested, "after": after]
        emit(evidence, 0)
        return
    }

    // A negative Aqua position must always be written through AX.  The STP
    // direct-event fallback is intentionally limited to the size operation.
    guard positionSettable else { throw HelperFailure.message("AX position is not settable") }
    if effectiveOperation == "cgevent-titlebar" {
        guard before["width"] as! Int == requested["width"]!
                && before["height"] as! Int == requested["height"]! else {
            throw HelperFailure.message("CGEvent move requires an already exact size")
        }
        let beforeInt = ["x": before["x"] as! Int, "y": before["y"] as! Int,
                         "width": before["width"] as! Int, "height": before["height"] as! Int]
        let moveEvidence = try cgeventTitlebarMove(pid, windowId, nativeTitle, beforeInt, requested,
                                                   target.element, target.number, mappingMethod)
        var evidence = mappingEvidence
        evidence["ok"] = true
        evidence["method"] = method
        evidence["requestedBounds"] = requested
        evidence["after"] = moveEvidence["postBounds"]!
        evidence["operation"] = "cgevent-titlebar"
        evidence["positionSettable"] = positionSettable
        evidence["sizeSettable"] = sizeSettable
        evidence["resizeMethod"] = "pre-resized"
        evidence["moveMethod"] = "cgevent-titlebar"
        evidence["beforePosition"] = beforePosition
        evidence["beforeSize"] = beforeSize
        evidence["intermediateBounds"] = before
        for (key, value) in moveEvidence { evidence[key] = value }
        emit(evidence, 0)
        return
    }
    var resizeMethod = "pre-resized"
    var intermediate = before
    if effectiveOperation == "resize-only" {
        let exactSize = before["width"] as! Int == requested["width"]! && before["height"] as! Int == requested["height"]!
        guard !exactSize else { throw HelperFailure.message("AX resize-only operation has no size mutation") }
        guard sizeSettable else {
            var failure = mappingEvidence
            failure["operation"] = "resize-only"
            failure["positionSettable"] = positionSettable
            failure["sizeSettable"] = sizeSettable
            failure["resizeMethod"] = "stp-direct"
            failure["moveMethod"] = "AX"
            failure["requestedBounds"] = requested
            failure["beforePosition"] = beforePosition
            failure["beforeSize"] = beforeSize
            throw HelperFailure.resizeNotSettableWithEvidence(failure)
        }
        try setSize(target.element, requested)
        intermediate = try readGeometry(target.element)
        guard intermediate["x"] as! Int == before["x"] as! Int
                && intermediate["y"] as! Int == before["y"] as! Int
                && intermediate["width"] as! Int == requested["width"]!
                && intermediate["height"] as! Int == requested["height"]! else {
            throw HelperFailure.message("AX size-only readback changed position or is not exact")
        }
        let evidence: [String: Any] = ["ok": true, "method": method, "helperUid": helperUid,
            "pid": pid, "windowId": windowId, "axWindowNumber": target.number ?? NSNull(), "titleNonce": nonce,
            "nativeTitle": nativeTitle, "mappingMethod": mappingMethod, "cgBefore": cgBefore,
            "candidateCount": candidateEvidence.count, "matchedCount": matches.count,
            "candidates": candidateEvidence, "before": before, "requestedBounds": requested,
            "after": intermediate, "operation": "resize-only", "positionSettable": positionSettable,
            "sizeSettable": sizeSettable, "resizeMethod": "AX", "moveMethod": "AX",
            "beforePosition": beforePosition, "beforeSize": beforeSize,
            "intermediateBounds": intermediate]
        emit(evidence, 0)
        return
    } else if effectiveOperation == "split" {
        let exactSize = before["width"] as! Int == requested["width"]! && before["height"] as! Int == requested["height"]!
        if exactSize {
            resizeMethod = "webDriver-existing"
        } else if sizeSettable {
            // A combined split write is intentionally forbidden when size
            // differs.  Python must invoke resize-only, perform its fresh
            // CoreGraphics/process rebind, and only then invoke move-only.
            throw HelperFailure.message("split operation requires a separate resize-only stage")
        } else {
            var failure = mappingEvidence
            failure["operation"] = "split"
            failure["positionSettable"] = positionSettable
            failure["sizeSettable"] = sizeSettable
            failure["resizeMethod"] = "stp-direct"
            failure["moveMethod"] = "AX"
            failure["requestedBounds"] = requested
            failure["beforePosition"] = beforePosition
            failure["beforeSize"] = beforeSize
            throw HelperFailure.resizeNotSettableWithEvidence(failure)
        }
    } else {
        guard before["width"] as! Int == requested["width"]!
                && before["height"] as! Int == requested["height"]! else {
            throw HelperFailure.message("AX move-only size is not already requested")
        }
    }
    try setPosition(target.element, requested)
    let after = try readGeometry(target.element)
    guard NSDictionary(dictionary: after).isEqual(to: requested) else {
        var failure = mappingEvidence
        failure["operation"] = effectiveOperation
        failure["positionSettable"] = positionSettable
        failure["sizeSettable"] = sizeSettable
        failure["resizeMethod"] = resizeMethod
        failure["moveMethod"] = "AX"
        failure["requestedBounds"] = requested
        failure["beforePosition"] = beforePosition
        failure["beforeSize"] = beforeSize
        failure["intermediateBounds"] = intermediate
        failure["after"] = after
        throw HelperFailure.positionIgnoredWithEvidence(failure)
    }
    var evidence: [String: Any] = ["ok": true, "method": method, "helperUid": helperUid,
        "pid": pid, "windowId": windowId, "axWindowNumber": target.number ?? NSNull(), "titleNonce": nonce,
        "nativeTitle": nativeTitle, "mappingMethod": mappingMethod, "cgBefore": cgBefore,
        "candidateCount": candidateEvidence.count, "matchedCount": matches.count,
        "candidates": candidateEvidence, "before": before, "requestedBounds": requested,
        "after": after, "operation": effectiveOperation, "positionSettable": positionSettable,
        "sizeSettable": sizeSettable, "resizeMethod": resizeMethod, "moveMethod": "AX",
        "beforePosition": beforePosition, "beforeSize": beforeSize,
        "intermediateBounds": intermediate]
    if emptyTitleMode {
        evidence["bindingMode"] = bindingMode
        evidence["titleEvidence"] = titleEvidence
        evidence["mutationAttempted"] = true
    }
    emit(evidence, 0)
}

@_cdecl("improvedtube_ax_helper_main")
public func improvedtube_ax_helper_main(_ argc: Int32,
                                        _ argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int32 {
    guard argc >= 0, let argv else { return fail("helper arguments are unavailable") }
    var arguments: [String] = []
    for index in 0..<Int(argc) {
        guard let raw = argv[index] else { return fail("helper argument is unavailable") }
        arguments.append(String(cString: raw))
    }
    do {
        try run(arguments)
        return 0
    } catch let failure as HelperFailure {
        switch failure {
        case .message(let message): return fail(message)
        case .notSettable(let attribute):
            return emit(["ok": false, "method": method, "errorCode": "not-settable",
                         "error": "AX attribute is not settable: \(attribute) status=0",
                         "attribute": attribute, "status": 0], 1)
        case .notSettableWithEvidence(let attribute, let mapping):
            var payload = mapping
            payload["ok"] = false
            payload["method"] = method
            payload["errorCode"] = "not-settable"
            payload["error"] = "AX attribute is not settable: \(attribute) status=0"
            payload["attribute"] = attribute
            payload["status"] = 0
            return emit(payload, 1)
        case .resizeNotSettableWithEvidence(let mapping):
            var payload = mapping
            payload["ok"] = false
            payload["method"] = method
            payload["errorCode"] = "resize-not-settable"
            payload["error"] = "AX attribute is not settable: AXSize status=0"
            payload["attribute"] = "AXSize"
            payload["status"] = 0
            return emit(payload, 1)
        case .positionIgnoredWithEvidence(let mapping):
            var payload = mapping
            payload["ok"] = false
            payload["method"] = method
            payload["errorCode"] = "position-ignored"
            payload["error"] = "AX position write readback is not exact"
            payload["attribute"] = "AXPosition"
            payload["status"] = 0
            return emit(payload, 1)
        case .cgeventFailure(let message, let cleanupEvidence):
            var payload = cleanupEvidence
            payload["ok"] = false
            payload["method"] = method
            payload["errorCode"] = "cgevent-failed"
            payload["error"] = message
            return emit(payload, 1)
        }
    } catch {
        return fail("native AX helper failed")
    }
}'''

def compile_ax_helper() -> tuple[Path,Path]:
    directory=Path(tempfile.mkdtemp(prefix=".improvedtube-aqua-ax-",dir="/tmp"))
    source=directory/"helper.swift";binary=directory/"helper.bundle"
    try:
        source.write_text(AX_HELPER_SOURCE,encoding="utf-8");os.chmod(source,0o600)
        result=subprocess.run(["/usr/bin/swiftc","-emit-library","-Xlinker","-bundle","-framework","ApplicationServices","-framework","AppKit","-framework","CoreGraphics","-O","-o",str(binary),str(source)],capture_output=True,text=True,timeout=90)
        if result.returncode != 0 or result.stderr:
            raise RuntimeError("native AX helper compilation failed")
        os.chmod(binary,0o700)
        return directory,binary
    except Exception:
        for path in (binary,source):
            try:path.unlink()
            except FileNotFoundError:pass
        try:directory.rmdir()
        except OSError:pass
        raise

def _hash_helper_fd(fd: int) -> str:
    digest=hashlib.sha256()
    offset=os.lseek(fd,0,os.SEEK_CUR)
    try:
        os.lseek(fd,0,os.SEEK_SET)
        while True:
            chunk=os.read(fd,1024*1024)
            if not chunk: break
            digest.update(chunk)
    finally:
        os.lseek(fd,offset,os.SEEK_SET)
    return digest.hexdigest()

def open_compiled_helper(path: Path) -> tuple[int,str,int,int]:
    """Open, validate, and pin one compiled helper object for inheritance."""
    nofollow=getattr(os,"O_NOFOLLOW",0)
    if not nofollow:
        raise RuntimeError("native AX helper requires O_NOFOLLOW")
    parent=path.parent
    parent_info=os.stat(parent)
    if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid()
            or parent_info.st_mode & 0o077):
        raise RuntimeError("native AX helper directory is not private")
    flags=os.O_RDONLY | nofollow | getattr(os,"O_CLOEXEC",0)
    fd=os.open(path,flags)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or not info.st_mode & 0o111 or info.st_mode & 0o077
                or info.st_nlink != 1):
            raise RuntimeError("native AX helper is not a private single-link executable")
        digest=_hash_helper_fd(fd)
        os.chflags(path,IMMUTABLE_HELPER_FLAGS)
        info=os.fstat(fd)
        if info.st_flags & IMMUTABLE_HELPER_FLAGS != IMMUTABLE_HELPER_FLAGS:
            raise RuntimeError("native AX helper immutability was not established")
        os.set_inheritable(fd,False)
        return fd,digest,int(info.st_dev),int(info.st_ino)
    except Exception:
        try:os.close(fd)
        except OSError:pass
        raise

def cleanup_ax_helper(directory: Path) -> None:
    for name in ("helper.bundle", "helper", "helper.swift"):
        path=directory/name
        try:
            if name in {"helper.bundle", "helper"}:
                try:os.chflags(path,0)
                except FileNotFoundError:pass
            path.unlink()
        except FileNotFoundError:pass
    directory.rmdir()

def _sanitized_loader_environment() -> dict[str,str]:
    """Remove dyld override variables before the observer's fresh exec.

    This is defense in depth only; the helper's dladdr/RTLD_FIRST provenance
    check remains authoritative because an environment cannot be trusted
    before process startup.
    """
    return {key:value for key,value in os.environ.items()
            if not key.startswith("DYLD_")}

def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser();p.add_argument("--socket",required=True);p.add_argument("--run-id",required=True);p.add_argument("--peer-uid",required=True,type=int);p.add_argument("--peer-gid",type=int);p.add_argument("--capability-file",required=True);p.add_argument("--ready-file",required=True);p.add_argument("--stp-pid",type=int);p.add_argument("--window-id",type=int)
    a=p.parse_args(argv);cap=secrets.token_urlsafe(32);cp=Path(a.capability_file);cp.parent.mkdir(parents=True,exist_ok=True);old=os.umask(0o177)
    try:cp.write_text(cap+"\n");os.chmod(cp,0o600)
    finally:os.umask(old)
    # The descriptor contains no secret; operator transfers capability through a protected env channel.
    descriptor={"socket":a.socket,"runId":a.run_id,"capabilityFile":str(cp),"stpPid":a.stp_pid,"windowId":a.window_id,"observerPid":os.getpid()}
    rp=Path(a.ready_file);rp.parent.mkdir(parents=True,exist_ok=True);rp.write_text(json.dumps(descriptor)+"\n");os.chmod(rp,0o600)
    helper_directory=None;helper_fd=None;result=1
    try:
        helper_directory,helper=compile_ax_helper()
        helper_fd,helper_digest,helper_device,helper_inode=open_compiled_helper(helper)
        descriptor.update({"axHelperDigest":helper_digest,"axHelperDevice":helper_device,"axHelperInode":helper_inode})
        rp.write_text(json.dumps(descriptor)+"\n");os.chmod(rp,0o600)
        cmd=[sys.executable,str(OBSERVER),"--socket",a.socket,"--run-id",a.run_id,"--capability-file",str(cp),"--peer-uid",str(a.peer_uid),"--ready-file",str(rp),"--ax-helper-fd",str(helper_fd),"--ax-helper-digest",helper_digest,"--ax-helper-device",str(helper_device),"--ax-helper-inode",str(helper_inode)]
        if a.peer_gid is not None:cmd += ["--peer-gid",str(a.peer_gid)]
        # PID/window identity are provided to the observer through claim; launcher retains no control API.
        result=subprocess.call(cmd,pass_fds=(helper_fd,),env=_sanitized_loader_environment())
    except Exception as exc:
        print(str(exc),file=sys.stderr)
        result=1
    finally:
        if helper_fd is not None:
            try:os.close(helper_fd)
            except OSError:result=1
        if helper_directory is not None:
            try:cleanup_ax_helper(helper_directory)
            except OSError:
                print("native AX helper cleanup failed",file=sys.stderr);result=1
    return result
if __name__=="__main__":sys.exit(main())
