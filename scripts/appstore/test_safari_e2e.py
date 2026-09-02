#!/usr/bin/env python3
import importlib.util
import hashlib
import http.server
import json
import os
import plistlib
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("safari_e2e_under_test", HERE / "safari_e2e.py")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

class _ResponseServer:
    """Small local HTTP peer for exact WebDriver response-shape tests."""
    def __init__(self, session_body=b'{"value":null}', window_body=b'{"value":null}',
                 status=200, disconnect_session=False, session_window_count=1):
        self.session_body=session_body;self.window_body=window_body
        self.status=status;self.disconnect_session=disconnect_session
        self.session_window_count=session_window_count;self.window_delete_count=0;self.session_delete_count=0
        owner=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_DELETE(self):
                if self.path.endswith("/session/fake") and owner.disconnect_session:
                    self.connection.close();return
                if self.path.endswith("/session/fake"):owner.session_delete_count+=1
                if self.path.endswith("/window"):owner.window_delete_count+=1
                body=owner.window_body if self.path.endswith("/window") else owner.session_body
                self.send_response(owner.status)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(body)))
                self.end_headers()
                if body:self.wfile.write(body)
            def log_message(self,*_args):pass
        self.httpd=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
        self.thread=threading.Thread(target=self.httpd.serve_forever,daemon=True);self.thread.start()
    @property
    def port(self):return self.httpd.server_address[1]
    @property
    def residual_session_windows(self):return max(0,self.session_window_count-self.window_delete_count)
    def close(self):
        self.httpd.shutdown();self.httpd.server_close();self.thread.join(timeout=2)

class FakeDriver:
    def __init__(self):
        self.created = 0
        self.loaded = 0
        self.session_id = "fake"
        self.timeouts = None
    def create(self):
        self.created += 1
    def load_extension(self, path):
        self.loaded += 1
        return "unpacked-id"
    def set_timeouts(self,script_ms,page_load_ms):
        self.timeouts=(script_ms,page_load_ms)

class FakeOptionsDriver:
    def __init__(self):
        self.url="https://www.youtube.com/results?search_query=ImprovedTube";self.values={};self.in_options=False;self.options_requests=0;self.fail_context_once=False;self.fail_options_once=False
        self.fail_load_once=False
        self.options_url="safari-web-extension://PROFILE-ID/menu/index.html"
    def navigate(self,url):self.in_options=False;self.url=url
    def switch_to_frame(self,frame=None):self.in_options=frame is not None
    def script(self,source,args=None):
        if source==MODULE.EXTENSION_CONTEXT_JS:
            if self.fail_context_once:
                self.fail_context_once=False;raise RuntimeError("no such window")
            return {"url":self.options_url,"protocol":"safari-web-extension:","path":"/menu/index.html","readyState":"complete",
                    "runtimeId":"com.tiendoxuan.improvedtube.Extension (76JE9YNX29)",
                    "manifestName":"Improve YouTube! for YouTube & Videos","manifestVersion":"4",
                    "manifestVersionNumber":3,"optionsPage":"menu/index.html","storage":True}
        raise AssertionError("unexpected sync script")
    def script_async(self,source,args=None):
        if source==MODULE.OPTIONS_URL_REQUEST_JS:
            self.options_requests+=1
            if self.fail_options_once:
                self.fail_options_once=False;return {"ok":False,"error":"signed options URL handshake timed out","url":""}
            if self.fail_load_once:
                self.fail_load_once=False;return {"ok":False,"error":"signed options iframe load timed out","url":"webkit-masked-url://hidden/","loaded":False}
            return {"ok":True,"url":"webkit-masked-url://hidden/","frame":{"element-6066-11e4-a52e-4f735466cecf":"options"},"loaded":True}
        if source==MODULE.DIRECT_STORAGE_GET_JS:
            keys=(args or [None])[0];value=dict(self.values) if keys is None else {key:self.values[key] for key in keys if key in self.values}
            return {"ok":True,"value":value}
        if source==MODULE.DIRECT_STORAGE_MUTATE_JS:
            request=args[0]
            if request["present"]:self.values[request["key"]]=request["value"]
            else:self.values.pop(request["key"],None)
            return {"ok":True,"present":request["key"] in self.values,"value":self.values.get(request["key"])}
        raise AssertionError("unexpected async script")

class FakeFullLiveDriver(FakeOptionsDriver):
    def __init__(self):
        super().__init__();self.actions=[];self.events=[];self.rect={"x":0,"y":0,"width":1200,"height":900};self.inner_width=1180
        self.account={"loggedIn":True,"accountId":"delegated-disposable-account","videoId":"dQw4w9WgXcQ","channelId":"UCuAXFkgsw1L7xaCfnd5JJOw"}
    def navigate(self,url):self.events.append(("navigate",url));super().navigate(url)
    def script(self,source,args=None):
        if source==MODULE.EXTENSION_CONTEXT_JS:return super().script(source,args)
        if source==MODULE.FIXTURE_EVIDENCE_JS:
            from urllib.parse import urlparse
            parsed=urlparse(self.url);return {"url":self.url,"host":parsed.netloc,"protocol":parsed.scheme+":","readyState":"complete","selectors":list((args or [[]])[0])}
        if source==MODULE.BRIDGE_JS:
            return {"improvedTube":True,"storage":True,"messages":True,"provider":True,"providerId":"it-messages-from-extension"}
        if source in {MODULE.INSTRUMENT_JS,MODULE.SET_TITLE_NONCE_JS}:return True
        if source==MODULE.STORAGE_STATE_JS:
            key=args[0];return {"present":key in self.values,"value":self.values.get(key),"mirrorOwn":key in self.values,"storageLoaded":True}
        if source==MODULE.PAGE_STORAGE_SNAPSHOT_JS:
            keys=(args or [None])[0];value=dict(self.values) if keys is None else {key:self.values[key] for key in keys if key in self.values}
            return {"ok":True,"storageLoaded":True,"value":value}
        if source==MODULE.SEND_STORAGE_JS:
            request=args[0]
            self.events.append(("storage",request["key"],request["present"],request.get("value")))
            if request["present"]:self.values[request["key"]]=request["value"]
            else:self.values.pop(request["key"],None)
            return {"sent":True,"operation":"set" if request["present"] else "delete","requested":request,"queueDepth":0}
        if source==MODULE.ACCOUNT_CONTEXT_JS:return dict(self.account)
        if source==MODULE.VIEWPORT_JS:return {"innerWidth":self.inner_width,"innerHeight":800}
        if source==MODULE.ARTIFACT_STATE_JS:return {"fullscreen":False,"pictureInPicture":False}
        if source==MODULE.SIDE_EFFECT_SNAPSHOT_JS:return {"localStorage":{},"sessionStorage":{},"cookies":{}}
        if source==MODULE.SIDE_EFFECT_RESTORE_JS:return {"ok":True,"current":args[0]}
        if source==MODULE.ERRORS_JS:return []
        if source=="return {ok:true};":return {"ok":True}
        if source=="return {visible:true};":return {"visible":True}
        if source=="return {visible:false};":return {"visible":False}
        raise AssertionError("unexpected sync script: "+source)
    def script_async(self,source,args=None):
        if "itLifecycle:true" not in source:
            if source==MODULE.DIRECT_STORAGE_MUTATE_JS:self.events.append(("storage",args[0]["key"],args[0]["present"],args[0].get("value")))
            return super().script_async(source,args)
        body=(args or [""])[0];argv=(args or [None,[]])[1];self.events.append(("lifecycle",body,self.url,argv[-1] if argv else None))
        if body=="return {ok:true};":value={"ok":True}
        elif body=="return {ok:true,verified:true};":value={"ok":True,"verified":True}
        elif body=="return {ok:true,verified:true,navigationNeutralized:true};":value={"ok":True,"verified":True,"navigationNeutralized":True}
        elif body=="return {ok:false,reason:'unavailable'};":value={"ok":False,"reason":"unavailable"}
        elif body=="return {ok:false};":value={"ok":False}
        elif body=="return {visible:true};":value={"visible":True}
        elif body=="return {visible:false};":value={"visible":False}
        elif body=="throw new Error('activation unavailable');":return {"itLifecycle":True,"ok":False,"error":{"name":"Error","message":"activation unavailable","stack":"test"}}
        elif "await Promise.resolve" in body:value={"ok":True,"awaited":True}
        else:raise AssertionError("unexpected lifecycle body: "+body)
        return {"itLifecycle":True,"ok":True,"value":value}
    def screenshot(self):return b"png"
    def key_actions(self,actions):self.actions.extend(actions)
    def window_handles(self):return ["main"]
    def current_window_handle(self):return "main"
    def alert_text(self):return "Leave this page?"
    def accept_alert(self):self.events.append(("alert","accept"))
    def dismiss_alert(self):self.events.append(("alert","dismiss"))
    def get_window_rect(self):return dict(self.rect)
    def set_window_rect(self,x,y,w,h):
        self.rect={"x":x,"y":y,"width":w,"height":h};self.inner_width=max(0,w-20);return dict(self.rect)

class HarnessTests(unittest.TestCase):
    def test_explicit_setup_unavailable_error_is_candidate_unavailable(self):
        self.assertTrue(MODULE._is_explicitly_unavailable(RuntimeError('async lifecycle failed: {"error":{"message":"fixture unavailable"}}')))
        self.assertTrue(MODULE._is_explicitly_unavailable(RuntimeError('async lifecycle failed: {"error":{"message":"channel link unavailable after activation reload"}}')))
        self.assertFalse(MODULE._is_explicitly_unavailable(RuntimeError('async lifecycle failed: {"error":{"message":"fixture crashed"}}')))
        self.assertFalse(MODULE._is_explicitly_unavailable(RuntimeError('POST /execute failed: unavailable')))

    def test_activation_may_explicitly_accept_undefined(self):
        class Driver:
            def script_async(self,source,args):
                self.source,self.args=source,args
                return {"itLifecycle":True,"ok":True,"value":None}
        driver=Driver()
        self.assertIsNone(MODULE._lifecycle(driver,{"script":"void 0"},allow_undefined=True))
        self.assertIs(driver.args[2],True)
        self.assertIn("allowUndefined",driver.source)

    def test_signed_options_adapter_preserves_false_null_and_absence(self):
        self.assertIn("data-it-e2e-options-frame",MODULE.OPTIONS_URL_REQUEST_JS)
        self.assertIn("prepend(frame)",MODULE.OPTIONS_URL_REQUEST_JS)
        self.assertIn("addEventListener('load'",MODULE.OPTIONS_URL_REQUEST_JS)
        self.assertIn("signed options iframe load timed out",MODULE.OPTIONS_URL_REQUEST_JS)
        driver=FakeOptionsDriver();identity={
            "extensionPlist":{"bundleId":"com.tiendoxuan.improvedtube.Extension"},
            "extensionSignature":{"TeamIdentifier":"76JE9YNX29"},
            "extensionManifest":{"name":"Improve YouTube! for YouTube & Videos","version":"4","manifest_version":3,"options_page":"menu/index.html"},
        }
        adapter=MODULE.BrowserStorageAdapter(driver,identity)
        context=adapter.bind_from_youtube()
        self.assertEqual(context["runtimeId"],"com.tiendoxuan.improvedtube.Extension (76JE9YNX29)")
        self.assertTrue(driver.in_options)
        self.assertEqual(adapter.options_url,driver.options_url)
        driver.fail_context_once=True
        with patch.object(MODULE.time,"sleep") as sleep:
            adapter.enter_options()
        sleep.assert_called_once_with(1)
        self.assertEqual(driver.url,"https://www.youtube.com/results?search_query=ImprovedTube")
        self.assertEqual(driver.options_requests,3)
        self.assertTrue(driver.in_options)
        driver.fail_options_once=True
        with patch.object(MODULE.time,"sleep") as sleep:
            adapter.enter_options()
        sleep.assert_called_once_with(1)
        self.assertEqual(driver.options_requests,5)
        self.assertTrue(driver.in_options)
        driver.fail_load_once=True
        with patch.object(MODULE.time,"sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError,"signed options iframe load timed out"):
                adapter.enter_options()
        sleep.assert_not_called()
        self.assertEqual(driver.options_requests,6)
        self.assertFalse(adapter.set("flag",False).value)
        self.assertTrue(adapter.set("nullable",None).present)
        self.assertFalse(adapter.remove("flag").present)
        states=adapter.snapshot(["flag","nullable"])
        self.assertFalse(states["flag"].present)
        self.assertTrue(states["nullable"].present)
        self.assertIsNone(states["nullable"].value)

    def test_contract_loader_rejects_prose_and_pseudo_oracle_targets(self):
        base={"schemaVersion":1,"menuSource":"menu/skeleton-parts/strict.js","contracts":{"strict":{
            "featureId":"IT-STRICT","storageKey":"strict","fixtureId":"watch.base","route":"watch","surface":"youtube-page",
            "applicability":"applicable","setup":{"script":"return {ok:true};"},
            "activation":{"kind":"storage","key":"strict","value":True},
            "beforeOracle":{"script":"return {visible:true};"},"afterOracle":{"script":"return {visible:false};"},
            "oracle":{"kind":"visibility","relation":"changed_to","target":"visible","expected":False},
            "prerequisites":["fixture"],"dependencyKeys":[],"dependencyValues":{},"sideEffectKeys":[],"restoreScope":["strict"],
            "sourceRefs":[{"path":"scripts/appstore/safari_e2e.py","startLine":1,"endLine":1}],
            "settle":{"timeoutMs":1000,"pollMs":50},"risk":"safe","contractVersion":1,"contractSource":"curated"}}}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"strict.json"
            prose=json.loads(json.dumps(base));prose["contracts"]["strict"]["setup"]={"action":"look at the page"};path.write_text(json.dumps(prose))
            with self.assertRaisesRegex(ValueError,"exact executable"):MODULE.load_contract_file(path)
            pseudo=json.loads(json.dumps(base));pseudo["contracts"]["strict"]["oracle"]["target"]="#player video";path.write_text(json.dumps(pseudo))
            with self.assertRaisesRegex(ValueError,"observation field path"):MODULE.load_contract_file(path)

    def test_storage_key_activation_requires_exact_w3c_actions(self):
        feature=MODULE.Feature("IT-KEY","shortcut_test","shortcut","menu/skeleton-parts/shortcuts.js","watch",{"keys":{}},storage_key="shortcut_test")
        contract={"menuSource":feature.source,"featureId":feature.feature_id,"storageKey":feature.storage_key,"fixtureId":"watch.base","route":"watch","surface":"youtube-page",
                  "applicability":"applicable","setup":{"script":"return {ok:true};"},
                  "activation":{"kind":"storage-key","key":"shortcut_test","value":{"keys":{}},"actions":[{"type":"keyDown","value":"F1"},{"type":"keyUp","value":"F1"}]},
                  "beforeOracle":{"script":"return {pressed:false};"},"afterOracle":{"script":"return {pressed:true};"},
                  "oracle":{"kind":"keyboard_interaction","relation":"changed_to","target":"pressed","expected":True},
                  "prerequisites":["key target"],"dependencyKeys":[],"sideEffectKeys":[],"restoreScope":["shortcut_test"],
                  "settle":{"timeoutMs":1000,"pollMs":50},"risk":"safe","contractVersion":1,"contractSource":"curated"}
        errors=MODULE.validate_plan([feature],"full-live",{"shortcut_test":contract})
        self.assertTrue(any("single-code-point" in error for error in errors),errors)

    def test_full_live_fake_driver_restores_empty_direct_storage_baseline(self):
        feature=MODULE.Feature("IT-FULL-FAKE","full_fake","switch","menu/skeleton-parts/appearance.js","search",True,storage_key="full_fake")
        raw={"menuSource":feature.source,"featureId":feature.feature_id,"storageKey":"full_fake","fixtureId":"search.improvedtube","route":"search","surface":"youtube-page",
             "applicability":"applicable","setup":{"script":"return {ok:true};"},
             "activation":{"kind":"storage","key":"full_fake","value":True},
             "beforeOracle":{"script":"return {visible:true};"},"afterOracle":{"script":"return {visible:false};"},
             "cleanup":{"script":"return {ok:true};"},
             "oracle":{"kind":"visibility","relation":"changed_to","target":"visible","expected":False},
             "prerequisites":["voice search"],"dependencyKeys":[],"dependencyValues":{},"sideEffectKeys":[],"restoreScope":["full_fake"],
             "sourceRefs":[{"path":"scripts/appstore/safari_e2e.py","startLine":1,"endLine":1}],
             "viewportWidth":1400,"settle":{"timeoutMs":100,"pollMs":10},"risk":"safe","contractVersion":1,"contractSource":"curated"}
        contract=MODULE.normalize_contract("full_fake",raw,feature.source);plan=MODULE.FeaturePlan(feature.feature_id,feature.key,"full_fake",feature.component,feature.source,feature.route,contract,"contracted")
        identity={"extensionPlist":{"bundleId":"com.tiendoxuan.improvedtube.Extension"},"extensionSignature":{"TeamIdentifier":"76JE9YNX29"},
                  "extensionManifest":{"name":"Improve YouTube! for YouTube & Videos","version":"4","manifest_version":3,"options_page":"menu/index.html"}}
        driver=FakeFullLiveDriver();rows=[]
        with tempfile.TemporaryDirectory() as directory:
            outcome=MODULE.run_full_live_contracts(driver,[feature],{"full_fake":plan},identity,rows,Path(directory),SimpleNamespace(allow_permission=False,allow_account=False,allow_destructive=False,account_fixture=None,account_fixture_data=None),lambda _:{"ok":True})
            self.assertEqual([path.name for path in Path(directory).glob("*.png")],["route-search.png"])
            screenshots=next(row.evidence["screenshots"] for row in rows if row.assertion_id=="IT-FULL-FAKE-EFFECT")
            self.assertTrue(all("sha256" in item and "path" not in item for item in screenshots))
        self.assertFalse(outcome["terminal"])
        self.assertEqual(driver.values,{})
        self.assertEqual(driver.rect,{"x":0,"y":0,"width":1200,"height":900})
        self.assertEqual(next(row.status for row in rows if row.assertion_id.endswith("-RESTORATION")),MODULE.PASS)
        after_index=next(i for i,event in enumerate(driver.events) if event[0]=="lifecycle" and event[1]=="return {visible:false};")
        cleanup_index=next(i for i,event in enumerate(driver.events[after_index+1:],after_index+1) if event[0]=="lifecycle" and event[1]=="return {ok:true};")
        navigation_index=next(i for i,event in enumerate(driver.events[after_index+1:],after_index+1) if event[0]=="navigate")
        self.assertLess(cleanup_index,navigation_index)
        self.assertTrue(driver.events[after_index][2].startswith("https://www.youtube.com/"))

    def test_discovery_and_contract_inventory(self):
        features = MODULE.discover_features(MODULE.INSTALLED)
        self.assertEqual(len(features), 342)
        self.assertIn("hide_voice_search_button", {f.key for f in features})
        self.assertEqual(MODULE.validate_contracts(features), [])
        self.assertEqual(MODULE.CONTRACTS["hide_voice_search_button"].observation_kind, "css_visibility")

    def test_contract_validation_rejects_missing_lifecycle(self):
        original = MODULE.CONTRACTS["hide_voice_search_button"]
        MODULE.CONTRACTS["hide_voice_search_button"] = MODULE.FeatureContract(
            original.key, original.route, "", original.activation_js, original.before_observe_js,
            original.after_observe_js, original.cleanup_js, original.prerequisites,
            original.observation_kind, original.activation_value,
        )
        try:
            self.assertTrue(MODULE.validate_contracts())
        finally:
            MODULE.CONTRACTS["hide_voice_search_button"] = original

    def test_truthy_falsy_null_and_absence_are_not_normalized(self):
        values = [True, False, 0, "", None]
        for value in values:
            requested = MODULE.StorageState(True, value)
            actual = MODULE.StorageState(True, value)
            self.assertEqual(MODULE.classify_transport(requested, actual, True, True), MODULE.PASS)
        absent = MODULE.StorageState(False, None)
        self.assertEqual(MODULE.classify_transport(MODULE.StorageState(True, False), absent, True, True), MODULE.PRODUCT_FAILURE)
        self.assertEqual(MODULE.classify_transport(MODULE.StorageState(True, None), absent, True, True), MODULE.PRODUCT_FAILURE)
        self.assertNotEqual(absent, MODULE.StorageState(True, None))
        self.assertFalse(MODULE.state_matches(MODULE.StorageState(True, 0), MODULE.StorageState(True, False)))

    def test_bridge_or_send_failures_are_harness_failures(self):
        requested = MODULE.StorageState(True, 1)
        self.assertEqual(MODULE.classify_transport(requested, MODULE.StorageState(False), False, True), MODULE.HARNESS_FAILURE)
        self.assertEqual(MODULE.classify_transport(requested, MODULE.StorageState(False), True, False), MODULE.HARNESS_FAILURE)

    def test_signed_route_requires_extension_provider(self):
        shaped = {"improvedTube": True, "storage": True, "messages": True, "provider": False}
        self.assertFalse(MODULE.bridge_ok(shaped))
        self.assertEqual(MODULE.classify_bridge(shaped), MODULE.ENVIRONMENT_FAILURE)
        shaped["provider"] = True
        shaped["providerId"] = "it-messages-from-extension"
        self.assertTrue(MODULE.bridge_ok(shaped))
        self.assertEqual(MODULE.classify_bridge(shaped), MODULE.PASS)

    def _signed_identity(self):
        return {"valid":True,"extensionPlist":{"bundleId":MODULE.EXPECTED_EXTENSION_BUNDLE_ID},
                "extensionSignature":{"CDHash":"signed-cdhash"},"extensionAssetSHA256":"signed-asset"}

    def _bound_bridge(self, identity=None):
        identity=identity or self._signed_identity();expected=MODULE.signed_provider_expectation(identity)
        return {"improvedTube":True,"storage":True,"messages":True,"provider":True,
                "providerId":"it-messages-from-extension","providerBundleId":expected["bundleId"],
                "providerCDHash":expected["cdhash"],"providerAssetSHA256":expected["assetSha256"],
                "providerProtocol":expected["protocol"],"providerContentDigest":expected["contentDigest"]}

    def test_release_gate_requires_signed_sut_and_bound_provider(self):
        identity=self._signed_identity();results=[SimpleNamespace(status=MODULE.PASS)]
        declared=MODULE.signed_provider_provenance(identity,self._bound_bridge(identity),"signed")
        self.assertTrue(declared["declaredMatch"])
        self.assertFalse(declared["bound"])
        self.assertFalse(declared["browserAuthoritative"])
        self.assertFalse(MODULE.release_gate("signed",identity,[],results,declared))
        self.assertFalse(MODULE.release_gate("unpacked",identity,[],results,declared))
        self.assertFalse(MODULE.release_gate("signed",identity,[],results,{"bound":False}))

    def test_provider_mismatch_or_unbound_is_non_release(self):
        identity=self._signed_identity();results=[SimpleNamespace(status=MODULE.PASS)]
        spoof=self._bound_bridge(identity)
        spoof_proof=MODULE.signed_provider_provenance(identity,spoof,"signed")
        self.assertTrue(spoof_proof["declaredMatch"])
        self.assertFalse(spoof_proof["bound"])
        self.assertFalse(MODULE.release_gate("signed",identity,[],results,spoof_proof))
        mismatch=self._bound_bridge(identity);mismatch["providerAssetSHA256"]="other-asset"
        proof=MODULE.signed_provider_provenance(identity,mismatch,"signed")
        self.assertFalse(proof["bound"]);self.assertFalse(MODULE.release_gate("signed",identity,[],results,proof))
        absent=MODULE.signed_provider_provenance(identity,{"provider":False},"signed")
        self.assertFalse(absent["bound"]);self.assertFalse(MODULE.release_gate("signed",identity,[],results,absent))

    def test_page_storage_uses_real_delete_wire_and_direct_falsy_authority(self):
        driver=FakeFullLiveDriver();identity={"extensionPlist":{"bundleId":"com.tiendoxuan.improvedtube.Extension"},
            "extensionSignature":{"TeamIdentifier":"76JE9YNX29"},
            "extensionManifest":{"name":"Improve YouTube! for YouTube & Videos","version":"4","manifest_version":3,"options_page":"menu/index.html"}}
        direct=MODULE.BrowserStorageAdapter(driver,identity)
        adapter=MODULE.PageBridgeStorageAdapter(driver,direct)
        self.assertEqual(adapter.set("flag",False).value,False)
        self.assertFalse(driver.in_options);self.assertEqual(driver.options_requests,1)
        self.assertFalse(adapter.remove("flag").present);self.assertEqual(driver.options_requests,1)
        self.assertIn(":{action:'set',key:q.key,value:false}",MODULE.SEND_STORAGE_JS)
        self.assertIn("__itE2EPersistedStorage",MODULE.PAGE_STORAGE_SNAPSHOT_JS)
        self.assertIn("update?.action==='storage-changed'",MODULE.PAGE_STORAGE_SNAPSHOT_JS)
        self.assertIn("mirror=window.ImprovedTube?.storage",MODULE.PAGE_STORAGE_SNAPSHOT_JS)
        self.assertIn("mirrorFallback",MODULE.PAGE_STORAGE_SNAPSHOT_JS)

    def test_page_storage_falls_back_to_signed_authority_when_the_page_is_unavailable(self):
        class Driver(FakeFullLiveDriver):
            def script(self,source,args=None):
                if source==MODULE.PAGE_STORAGE_SNAPSHOT_JS:return {"ok":False,"storageLoaded":False}
                if source==MODULE.SEND_STORAGE_JS:raise RuntimeError("page bridge unavailable")
                return super().script(source,args)
        driver=Driver();driver.values["flag"]=True
        identity={"extensionPlist":{"bundleId":"com.tiendoxuan.improvedtube.Extension"},"extensionSignature":{"TeamIdentifier":"76JE9YNX29"},"extensionManifest":{"name":"Improve YouTube! for YouTube & Videos","version":"4","manifest_version":3,"options_page":"menu/index.html"}}
        adapter=MODULE.PageBridgeStorageAdapter(driver,MODULE.BrowserStorageAdapter(driver,identity))
        self.assertTrue(adapter.snapshot(["flag"])["flag"].value)
        self.assertFalse(adapter.remove("flag").present)
        self.assertFalse(driver.in_options)

    def test_authority_roundtrip_preserves_unrelated_concurrent_storage_changes(self):
        store={"baseline":True}
        class Adapter:
            def snapshot(self,keys=None):
                selected=sorted(store) if keys is None else list(keys)
                return {key:MODULE.StorageSnapshot.capture(key,key in store,store.get(key)) for key in selected}
            def set(self,key,value):store[key]=value;store["concurrent"]="kept"
            def remove(self,key):store.pop(key,None)
            def enter_options(self):return {}
        class Driver:
            def script(self,source,args=None):
                if source==MODULE.STORAGE_STATE_JS:
                    key=args[0];return {"present":key in store,"mirrorOwn":key in store,"storageLoaded":True,"value":store.get(key)}
                if source==MODULE.PAGE_STORAGE_SNAPSHOT_JS:return {"ok":True,"value":dict(store)}
                raise AssertionError("unexpected script")
        original=MODULE._prove_youtube_fixture;MODULE._prove_youtube_fixture=lambda *_args,**_kwargs:{"ok":True}
        try:evidence=MODULE._authority_roundtrip(Driver(),Adapter(),object(),None)
        finally:MODULE._prove_youtube_fixture=original
        self.assertEqual(store,{"baseline":True,"concurrent":"kept"})
        self.assertIn("concurrent",evidence["concurrentChanges"])
        self.assertTrue(evidence["baselineRestored"] and evidence["fullMirrorMatched"])

    def test_feature_isolation_snapshots_only_declared_restore_scope(self):
        source=Path(MODULE.__file__).read_text()
        body=source[source.index("def run_full_live_contracts("):source.index("def main(")]
        self.assertNotIn("storage_adapter.snapshot(None)",body)
        self.assertEqual(body.count("storage_adapter.snapshot(list(contract.restore_scope))"),5)

    def test_cleanup_is_not_ready_until_setup_succeeds(self):
        source=Path(MODULE.__file__).read_text()
        body=source[source.index("def run_full_live_contracts("):source.index("def main(")]
        self.assertIn("cleanup_ready=False",body)
        self.assertGreater(body.index("cleanup_ready=contract.post_activation is None"),body.index("if not isinstance(setup,dict)"))

    def test_unavailable_surface_uses_anchor_only_for_restoration_proof(self):
        source=Path(MODULE.__file__).read_text()
        body=source[source.index("def run_full_live_contracts("):source.index("def main(")]
        self.assertIn("surface_unavailable=feature_unavailable and not surface_ready",body)
        self.assertIn('verification_fixture=anchor if fixture.surface=="extension-page" or surface_unavailable else fixture',body)
        self.assertEqual(body.count("contract.after_restoration is not None and not feature_unavailable"),2)
        self.assertEqual(body.count("recover=surface_unavailable"),2)

    def test_recovery_navigation_leaves_unavailable_page_before_fresh_fixture_navigation(self):
        source=Path(MODULE.__file__).read_text()
        body=source[source.index("def _prove_youtube_fixture("):source.index("def _prove_youtube_redirect(")]
        self.assertIn("phase:str,recover:bool=False",body)
        self.assertLess(body.index("ImprovedTube%20recovery"),body.index("driver.navigate(fixture.exact_url)"))
        authority=source[source.index("def _authority_roundtrip("):source.index("def _account_target(")]
        self.assertEqual(authority.count("recover=True"),2)

    def test_signed_bridge_waits_for_fresh_document_injection(self):
        ready={"provider":True,"messages":True,"storage":True,"providerId":"it-messages-from-extension","improvedTube":True}
        class Driver:
            def __init__(self):self.calls=[]
            def script(self,source,args=None):
                self.calls.append(source)
                if source==MODULE.BRIDGE_JS:return ready if self.calls.count(MODULE.BRIDGE_JS)==3 else {"provider":True}
                if source==MODULE.INSTRUMENT_JS:return True
                raise AssertionError("unexpected script")
        driver=Driver();self.assertIs(MODULE.ensure_bridge(driver,attempts=3,pause=0),ready)
        self.assertEqual(driver.calls,[MODULE.BRIDGE_JS,MODULE.BRIDGE_JS,MODULE.BRIDGE_JS,MODULE.INSTRUMENT_JS])

    def test_player_cleanup_restores_adaptive_quality_without_matching_transient_resolution(self):
        catalog=json.loads((MODULE.ROOT/".appstore/testing/full-live-contracts/player.json").read_text())
        scripts=[item["cleanup"]["script"] for item in catalog["contracts"].values() if item.get("cleanup")]
        self.assertTrue(scripts)
        for script in scripts:
            self.assertNotIn("(!expected.quality||s.quality===expected.quality)",script)
            self.assertIn('const adaptiveQuality=!expected?.quality||["unknown","auto"].includes(expected.quality);',script)
            self.assertIn('const quality=adaptiveQuality?"auto":expected.quality;',script)
            self.assertIn("(adaptiveQuality||s.quality===expected.quality)",script)

    def test_falsy_probe_states_remain_five_distinct_wire_states(self):
        self.assertEqual(len(MODULE.FALSY_PROBE_STATES),5)
        encoded={json.dumps({"present":state.present,"value":state.value},sort_keys=True) for state in MODULE.FALSY_PROBE_STATES}
        self.assertEqual(len(encoded),5)
        self.assertIn(MODULE.StorageState(False,None),MODULE.FALSY_PROBE_STATES)

    def test_falsy_probe_emits_distinct_set_null_and_delete_operations(self):
        class FalsyDriver:
            def __init__(self):
                self.state=MODULE.StorageState(False,None);self.operations=[];self.refreshes=0
            def script(self,source,args=None):
                if source==MODULE.STORAGE_STATE_JS:
                    return {"present":self.state.present,"value":self.state.value if self.state.present else None,"storageLoaded":True}
                if source==MODULE.BRIDGE_JS:
                    return {"improvedTube":True,"storage":True,"messages":True,"provider":True,"providerId":"it-messages-from-extension"}
                if source==MODULE.INSTRUMENT_JS:return True
                if source==MODULE.SEND_STORAGE_JS:
                    payload=dict(args[0]);self.operations.append(payload)
                    if payload["present"]:
                        self.state=MODULE.StorageState(True,payload.get("value"));operation="set"
                    else:
                        self.state=MODULE.StorageState(False,None);operation="delete"
                    return {"sent":True,"operation":operation,"requested":payload,"queueDepth":0}
                if source==MODULE.REAL_PAGE_JS:
                    return {"url":MODULE.ROUTES["watch"],"host":"www.youtube.com","protocol":"https:","ready":"complete","youtubeElements":1}
                raise AssertionError("unexpected script")
            def refresh(self):self.refreshes+=1
        driver=FalsyDriver();feature=MODULE.Feature("IT-FALSY","probe","switch","menu/x.js","watch",True);results=[]
        self.assertTrue(MODULE.run_falsy_probe(driver,feature,"watch",results,lambda _phase:{"ok":True}))
        item=next(value for value in results if value.assertion_id=="IT-FALSY-FALSY-TRANSPORT")
        self.assertTrue(item.evidence["allFiveRequested"])
        self.assertEqual(item.evidence["distinctEmittedOperations"],5)
        self.assertTrue(item.evidence["restoredBetweenStates"])
        self.assertEqual(driver.state,MODULE.StorageState(False,None))
        self.assertIn({"key":"probe","present":True,"value":None},driver.operations)
        self.assertIn({"key":"probe","present":False},driver.operations)
        self.assertGreaterEqual(driver.refreshes,1)

    def test_continue_flag_retains_product_failure_after_exact_restoration(self):
        first=MODULE.Feature("IT-FIRST","hide_voice_search_button","switch","menu/first.js","search",True)
        second=MODULE.Feature("IT-SECOND","add_scroll_to_top","switch","menu/second.js","watch",True)
        results=[];calls=[];checks=[];original=MODULE.run_contract
        def fake_run(_driver,feature,_contract,route,rows,_window_check):
            calls.append(feature.key)
            if feature is first:
                MODULE.record(rows,feature.feature_id+"-TRANSPORT",feature.feature_id,"exact bridge transport",MODULE.PRODUCT_FAILURE,"product",route,"feature",{"sent":True})
                MODULE.record(rows,feature.feature_id+"-EFFECT",feature.feature_id,"semantic feature effect",MODULE.NOT_RUN,"product",route,"feature",{})
                MODULE.record(rows,feature.feature_id+"-RESTORATION",feature.feature_id,"exact persisted restoration",MODULE.PASS,"live-semantic",route,"restoration",{"strict":True})
                return True
            for suffix,assertion in (("-TRANSPORT","exact bridge transport"),("-EFFECT","semantic feature effect"),("-RESTORATION","exact persisted restoration")):
                MODULE.record(rows,feature.feature_id+suffix,feature.feature_id,assertion,MODULE.PASS,"live-semantic",route,"feature",{})
            return True
        try:
            MODULE.run_contract=fake_run
            def containment(phase):checks.append(phase);return {"ok":True,"phase":phase}
            outcome=MODULE.run_feature_contracts(object(),[first,second],"watch",results,containment,
                                                 continue_after_product_failure=True,exercise_falsy=False)
        finally:MODULE.run_contract=original
        self.assertEqual(outcome,"continued");self.assertEqual(calls,["hide_voice_search_button","add_scroll_to_top"])
        self.assertEqual(checks,["before-contract:add_scroll_to_top"])
        first_restoration=next(row for row in results if row.assertion_id=="IT-FIRST-RESTORATION")
        self.assertEqual(first_restoration.status,MODULE.PASS)
        self.assertTrue(MODULE.exact_restoration_passed(results,first))
        ids=[row.assertion_id for row in results];self.assertEqual(len(ids),len(set(ids)))

    def test_continue_flag_stops_after_isolation_without_running_later_contract(self):
        first=MODULE.Feature("IT-FIRST","hide_voice_search_button","switch","menu/first.js","search",True)
        second=MODULE.Feature("IT-SECOND","add_scroll_to_top","switch","menu/second.js","watch",True)
        results=[];calls=[];checks=[];original=MODULE.run_contract
        def fake_run(_driver,feature,_contract,route,rows,_window_check):
            calls.append(feature.key)
            if feature is first:
                MODULE.record(rows,feature.feature_id+"-TRANSPORT",feature.feature_id,"exact bridge transport",MODULE.PASS,"transport",route,"feature",{"sent":True})
                MODULE.record(rows,feature.feature_id+"-EFFECT",feature.feature_id,"semantic feature effect",MODULE.PASS,"live-semantic",route,"feature",{})
                MODULE.record(rows,feature.feature_id+"-RESTORATION",feature.feature_id,"exact persisted restoration",MODULE.ISOLATION_FAILURE,"isolation",route,"restoration",{"strict":False})
                return False
            raise AssertionError("isolation failure must block later contract")
        try:
            MODULE.run_contract=fake_run
            def containment(phase):checks.append(phase);return {"ok":True,"phase":phase}
            outcome=MODULE.run_feature_contracts(object(),[first,second],"watch",results,containment,
                                                 continue_after_product_failure=True,exercise_falsy=False)
        finally:MODULE.run_contract=original
        self.assertEqual(outcome,"stopped");self.assertEqual(calls,["hide_voice_search_button"])
        self.assertEqual(checks,[])
        self.assertEqual(MODULE.feature_failure_state(results,first),"isolation")
        blocked=[row for row in results if row.feature_id==second.feature_id]
        self.assertTrue(blocked);self.assertTrue(all(row.status==MODULE.NOT_RUN for row in blocked))

    def test_falsy_only_dispatch_skips_contract_and_rejects_ambiguous_cli(self):
        feature=MODULE.Feature("IT-FALSY-ONLY","hide_voice_search_button","switch","menu/falsy.js","search",True)
        rows=[];calls=[];original_contract=MODULE.run_contract;original_falsy=MODULE.run_falsy_probe
        def forbidden_contract(*_args,**_kwargs):self.fail("falsy-only must not run the primary contract")
        def fake_falsy(_driver,selected,route,results,_window_check):
            calls.append(selected.key)
            MODULE.record(results,selected.feature_id+"-FALSY-TRANSPORT",selected.feature_id,"falsy transport regression (false, 0, empty, null, and absence)",MODULE.PASS,"transport",route,"falsy",{})
            MODULE.record(results,selected.feature_id+"-RESTORATION",selected.feature_id,"exact persisted restoration",MODULE.PASS,"live-semantic",route,"restoration",{})
            return True
        try:
            MODULE.run_contract=forbidden_contract;MODULE.run_falsy_probe=fake_falsy
            outcome=MODULE.run_feature_contracts(object(),[feature],"search",rows,lambda _phase:{"ok":True},
                                                 exercise_falsy=True,falsy_only=True)
        finally:MODULE.run_contract=original_contract;MODULE.run_falsy_probe=original_falsy
        self.assertEqual(outcome,"ok");self.assertEqual(calls,[feature.key])
        invalid=(("--falsy-only",),
                 ("--falsy-only","--exercise-falsy"),
                 ("--falsy-only","--exercise-falsy","--feature","hide_voice_search_button","--feature","add_scroll_to_top"))
        for argv in invalid:
            with self.subTest(argv=argv):
                with self.assertRaises(SystemExit):MODULE.main(list(argv))

    def test_product_failure_plus_isolation_cannot_be_relabelled_for_continuation(self):
        first=MODULE.Feature("IT-FIRST","hide_voice_search_button","switch","menu/first.js","search",True)
        second=MODULE.Feature("IT-SECOND","add_scroll_to_top","switch","menu/second.js","watch",True)
        results=[];calls=[];original=MODULE.run_contract
        def fake_run(_driver,feature,_contract,route,rows,_window_check):
            calls.append(feature.key)
            if feature is first:
                MODULE.record(rows,feature.feature_id+"-TRANSPORT",feature.feature_id,"exact bridge transport",MODULE.PRODUCT_FAILURE,"product",route,"feature",{})
                MODULE.record(rows,feature.feature_id+"-EFFECT",feature.feature_id,"semantic feature effect",MODULE.PASS,"live-semantic",route,"feature",{})
                # Deliberately use a product status on isolation-class evidence
                # to exercise the anti-relabeling guard.
                MODULE.record(rows,feature.feature_id+"-RESTORATION",feature.feature_id,"exact persisted restoration",MODULE.PRODUCT_FAILURE,"isolation",route,"restoration",{"strict":False})
                return False
            raise AssertionError("relabelled isolation must block later contract")
        try:
            MODULE.run_contract=fake_run
            outcome=MODULE.run_feature_contracts(object(),[first,second],"watch",results,lambda _phase:{"ok":True},
                                                 continue_after_product_failure=True)
        finally:MODULE.run_contract=original
        self.assertEqual(outcome,"stopped");self.assertEqual(calls,["hide_voice_search_button"])
        self.assertEqual(MODULE.feature_failure_state(results,first),"isolation")
        self.assertTrue(all(row.status==MODULE.NOT_RUN for row in results if row.feature_id==second.feature_id))

    def test_false_restoration_return_cannot_authorize_product_continuation(self):
        first=MODULE.Feature("IT-FIRST","hide_voice_search_button","switch","menu/first.js","search",True)
        second=MODULE.Feature("IT-SECOND","add_scroll_to_top","switch","menu/second.js","watch",True)
        results=[];calls=[];original=MODULE.run_contract
        def fake_run(_driver,feature,_contract,route,rows,_window_check):
            calls.append(feature.key)
            if feature is first:
                MODULE.record(rows,feature.feature_id+"-TRANSPORT",feature.feature_id,"exact bridge transport",MODULE.PRODUCT_FAILURE,"product",route,"feature",{})
                MODULE.record(rows,feature.feature_id+"-EFFECT",feature.feature_id,"semantic feature effect",MODULE.NOT_RUN,"product",route,"feature",{})
                MODULE.record(rows,feature.feature_id+"-RESTORATION",feature.feature_id,"exact persisted restoration",MODULE.PASS,"live-semantic",route,"restoration",{"strict":True})
                return False
            raise AssertionError("inconsistent restoration return must block later contract")
        try:
            MODULE.run_contract=fake_run
            outcome=MODULE.run_feature_contracts(object(),[first,second],"watch",results,lambda _phase:{"ok":True},
                                                 continue_after_product_failure=True)
        finally:MODULE.run_contract=original
        self.assertEqual(outcome,"stopped");self.assertEqual(calls,["hide_voice_search_button"])
        self.assertEqual(MODULE.feature_failure_state(results,first),"isolation")
        restoration=next(row for row in results if row.assertion_id=="IT-FIRST-RESTORATION")
        self.assertEqual(restoration.status,MODULE.ISOLATION_FAILURE)
        self.assertTrue(all(row.status==MODULE.NOT_RUN for row in results if row.feature_id==second.feature_id))

    def test_noncanonical_restoration_class_cannot_authorize_continuation(self):
        first=MODULE.Feature("IT-FIRST","hide_voice_search_button","switch","menu/first.js","search",True)
        second=MODULE.Feature("IT-SECOND","add_scroll_to_top","switch","menu/second.js","watch",True)
        results=[];calls=[];original=MODULE.run_contract
        def fake_run(_driver,feature,_contract,route,rows,_window_check):
            calls.append(feature.key)
            if feature is first:
                MODULE.record(rows,feature.feature_id+"-TRANSPORT",feature.feature_id,"exact bridge transport",MODULE.PASS,"transport",route,"feature",{})
                MODULE.record(rows,feature.feature_id+"-EFFECT",feature.feature_id,"semantic feature effect",MODULE.PASS,"live-semantic",route,"feature",{})
                MODULE.record(rows,feature.feature_id+"-RESTORATION",feature.feature_id,"exact persisted restoration",MODULE.PASS,"product",route,"restoration",{"strict":True})
                return True
            raise AssertionError("noncanonical restoration class must block later contract")
        try:
            MODULE.run_contract=fake_run
            outcome=MODULE.run_feature_contracts(object(),[first,second],"watch",results,lambda _phase:{"ok":True},
                                                 continue_after_product_failure=True)
        finally:MODULE.run_contract=original
        self.assertEqual(outcome,"stopped");self.assertEqual(calls,["hide_voice_search_button"])
        self.assertEqual(MODULE.feature_failure_state(results,first),"isolation")
        restoration=next(row for row in results if row.assertion_id=="IT-FIRST-RESTORATION")
        self.assertEqual(restoration.status,MODULE.ISOLATION_FAILURE)
        self.assertTrue(all(row.status==MODULE.NOT_RUN for row in results if row.feature_id==second.feature_id))

    def test_default_product_or_isolation_failure_stops_later_contracts(self):
        first=MODULE.Feature("IT-FIRST","hide_voice_search_button","switch","menu/first.js","search",True)
        second=MODULE.Feature("IT-SECOND","add_scroll_to_top","switch","menu/second.js","watch",True)
        results=[];calls=[];original=MODULE.run_contract
        def fake_run(_driver,feature,_contract,route,rows,_window_check):
            calls.append(feature.key)
            MODULE.record(rows,feature.feature_id+"-TRANSPORT",feature.feature_id,"exact bridge transport",MODULE.PRODUCT_FAILURE,"product",route,"feature",{})
            MODULE.record(rows,feature.feature_id+"-EFFECT",feature.feature_id,"semantic feature effect",MODULE.NOT_RUN,"product",route,"feature",{})
            MODULE.record(rows,feature.feature_id+"-RESTORATION",feature.feature_id,"exact persisted restoration",MODULE.PASS,"live-semantic",route,"restoration",{})
            return True
        try:
            MODULE.run_contract=fake_run
            outcome=MODULE.run_feature_contracts(object(),[first,second],"watch",results,lambda _phase:{"ok":True})
        finally:MODULE.run_contract=original
        self.assertEqual(outcome,"stopped");self.assertEqual(calls,["hide_voice_search_button"])
        blocked=[row for row in results if row.feature_id==second.feature_id]
        self.assertTrue(blocked);self.assertTrue(all(row.status==MODULE.NOT_RUN for row in blocked))

    def test_harness_failure_aborts_later_contracts_even_with_continue_flag(self):
        first=MODULE.Feature("IT-FIRST","hide_voice_search_button","switch","menu/first.js","search",True)
        second=MODULE.Feature("IT-SECOND","add_scroll_to_top","switch","menu/second.js","watch",True)
        results=[];calls=[];original=MODULE.run_contract
        def fake_run(_driver,feature,_contract,route,rows,_window_check):
            calls.append(feature.key)
            MODULE.record(rows,feature.feature_id+"-TRANSPORT",feature.feature_id,"exact bridge transport",MODULE.HARNESS_FAILURE,"harness",route,"feature",{})
            MODULE.record(rows,feature.feature_id+"-EFFECT",feature.feature_id,"semantic feature effect",MODULE.NOT_RUN,"harness",route,"feature",{})
            MODULE.record(rows,feature.feature_id+"-RESTORATION",feature.feature_id,"exact persisted restoration",MODULE.ISOLATION_FAILURE,"harness",route,"restoration",{})
            return False
        try:
            MODULE.run_contract=fake_run
            outcome=MODULE.run_feature_contracts(object(),[first,second],"watch",results,lambda _phase:{"ok":True},
                                                 continue_after_product_failure=True)
        finally:MODULE.run_contract=original
        self.assertEqual(outcome,"fatal");self.assertEqual(calls,["hide_voice_search_button"])
        self.assertTrue(all(row.status==MODULE.NOT_RUN for row in results if row.feature_id==second.feature_id))

    def test_continuation_requires_fresh_containment_recheck(self):
        first=MODULE.Feature("IT-FIRST","hide_voice_search_button","switch","menu/first.js","search",True)
        second=MODULE.Feature("IT-SECOND","add_scroll_to_top","switch","menu/second.js","watch",True)
        results=[];calls=[];checks=[];original=MODULE.run_contract
        def fake_run(_driver,feature,_contract,route,rows,_window_check):
            calls.append(feature.key)
            MODULE.record(rows,feature.feature_id+"-TRANSPORT",feature.feature_id,"exact bridge transport",MODULE.PRODUCT_FAILURE,"product",route,"feature",{})
            MODULE.record(rows,feature.feature_id+"-EFFECT",feature.feature_id,"semantic feature effect",MODULE.NOT_RUN,"product",route,"feature",{})
            MODULE.record(rows,feature.feature_id+"-RESTORATION",feature.feature_id,"exact persisted restoration",MODULE.PASS,"live-semantic",route,"restoration",{"strict":True})
            return True
        def containment(phase):
            checks.append(phase)
            return {"ok":False} if phase.startswith("before-contract:") else {"ok":True}
        try:
            MODULE.run_contract=fake_run
            with self.assertRaises(RuntimeError):
                MODULE.run_feature_contracts(object(),[first,second],"watch",results,containment,
                                             continue_after_product_failure=True)
        finally:MODULE.run_contract=original
        self.assertEqual(calls,["hide_voice_search_button"]);self.assertEqual(checks,["before-contract:add_scroll_to_top"])

    def test_contract_activation_failure_still_attempts_exact_cleanup_in_finally(self):
        feature=MODULE.Feature("IT-CLEANUP","hide_voice_search_button","switch","menu/cleanup.js","search",True)
        contract=MODULE.CONTRACTS[feature.key];results=[]
        class ContractDriver:
            def __init__(self):self.cleanup_calls=0;self.state=MODULE.StorageState(False,None);self.session_id="fake";self.refreshes=0;self.activation_failed=False
            def script(self,source,args=None):
                if source==MODULE.SET_PHASE_JS:return True
                if source==MODULE.BRIDGE_JS:return {"improvedTube":True,"storage":True,"messages":True,"provider":True,"providerId":"it-messages-from-extension"}
                if source==MODULE.INSTRUMENT_JS:return True
                if source==MODULE.STORAGE_STATE_JS:return {"present":self.state.present,"value":self.state.value if self.state.present else None,"storageLoaded":True}
                if source==contract.setup_js:return {"ok":True}
                if source==contract.before_observe_js:return {"present":True,"visible":True}
                if source==contract.activation_js:
                    if not self.activation_failed:self.activation_failed=True;raise RuntimeError("synthetic activation failure")
                    self.cleanup_calls+=1;self.state=MODULE.StorageState(False,None);return {"sent":True,"operation":"delete","requested":dict(args[0]),"queueDepth":0}
                if source==MODULE.REAL_PAGE_JS:
                    return {"url":MODULE.ROUTES["search"],"host":"www.youtube.com","protocol":"https:","ready":"complete","youtubeElements":1}
                raise AssertionError("unexpected script source")
            def refresh(self):self.refreshes+=1
        driver=ContractDriver();self.assertTrue(MODULE.run_contract(driver,feature,contract,"search",results,lambda _phase:{"ok":True}))
        self.assertEqual(driver.cleanup_calls,1)
        self.assertEqual(next(row for row in results if row.assertion_id=="IT-CLEANUP-TRANSPORT").status,MODULE.HARNESS_FAILURE)
        self.assertEqual(next(row for row in results if row.assertion_id=="IT-CLEANUP-RESTORATION").status,MODULE.PASS)

    def test_playback_companion_prerequisite_and_dual_restoration(self):
        feature=MODULE.Feature("IT-PLAYBACK","player_playback_speed","slider","menu/player.js","watch",1.25)
        contract=MODULE.CONTRACTS[feature.key]
        bridge={"improvedTube":True,"storage":True,"messages":True,"provider":True,"providerId":"it-messages-from-extension"}
        page={"url":MODULE.ROUTES["watch"],"host":"www.youtube.com","protocol":"https:","ready":"complete","youtubeElements":1}
        class PlaybackDriver:
            def __init__(self,fail_setup=False):
                self.states={feature.key:MODULE.StorageState(True,1.0),
                             MODULE.PLAYBACK_COMPANION_KEY:MODULE.StorageState(False,None)}
                self.rate=1.0;self.sources=[];self.payloads=[];self.refreshes=0;self.fail_setup=fail_setup
            def script(self,source,args=None):
                self.sources.append(source)
                if source==MODULE.SET_PHASE_JS or source==MODULE.INSTRUMENT_JS:return True
                if source==MODULE.BRIDGE_JS:return bridge
                if source==MODULE.REAL_PAGE_JS:return page
                if source==MODULE.SLIDER_SETUP_JS:
                    forced=self.states[MODULE.PLAYBACK_COMPANION_KEY]
                    return {"ok":forced==MODULE.StorageState(True,True),"playbackRate":self.rate,"forced":forced.value}
                if source==MODULE.SLIDER_OBSERVE_JS:return {"present":True,"value":self.rate}
                if source==MODULE.STORAGE_STATE_JS:
                    state=self.states[args[0]]
                    return {"present":state.present,"value":state.value if state.present else None,"storageLoaded":True}
                if source==MODULE.SEND_STORAGE_JS:
                    payload=dict(args[0]);self.payloads.append(payload)
                    if self.fail_setup and len(self.payloads)==1:
                        return {"sent":True,"operation":"set","requested":payload,"queueDepth":None}
                    state=MODULE.StorageState(True,payload.get("value")) if payload["present"] else MODULE.StorageState(False,None)
                    self.states[payload["key"]]=state
                    if payload["key"]==feature.key and payload["present"]:self.rate=float(payload["value"])
                    return {"sent":True,"operation":"set" if payload["present"] else "delete","requested":payload,"queueDepth":0}
                raise AssertionError("unexpected script source")
            def refresh(self):self.refreshes+=1
        driver=PlaybackDriver();rows=[]
        self.assertTrue(MODULE.run_contract(driver,feature,contract,"watch",rows,lambda _phase:{"ok":True}))
        self.assertEqual([row.status for row in rows if row.assertion_id.endswith(("-TRANSPORT","-EFFECT","-RESTORATION"))],
                         [MODULE.PASS,MODULE.PASS,MODULE.PASS])
        self.assertEqual(driver.payloads[0],{"key":MODULE.PLAYBACK_COMPANION_KEY,"present":True,"value":True})
        self.assertIn(MODULE.SLIDER_SETUP_JS,driver.sources)
        self.assertLess(driver.sources.index(MODULE.SEND_STORAGE_JS),driver.sources.index(MODULE.SLIDER_SETUP_JS))
        self.assertEqual(driver.states[feature.key],MODULE.StorageState(True,1.0))
        self.assertEqual(driver.states[MODULE.PLAYBACK_COMPANION_KEY],MODULE.StorageState(False,None))
        restoration=next(row for row in rows if row.assertion_id=="IT-PLAYBACK-RESTORATION")
        self.assertTrue(restoration.evidence["companion"]["restored"]);self.assertGreaterEqual(driver.refreshes,1)
        failed=PlaybackDriver(fail_setup=True);failed_rows=[]
        self.assertTrue(MODULE.run_contract(failed,feature,contract,"watch",failed_rows,lambda _phase:{"ok":True}))
        transport=next(row for row in failed_rows if row.assertion_id=="IT-PLAYBACK-TRANSPORT")
        effect=next(row for row in failed_rows if row.assertion_id=="IT-PLAYBACK-EFFECT")
        self.assertEqual(transport.status,MODULE.HARNESS_FAILURE);self.assertEqual(effect.status,MODULE.NOT_RUN)
        self.assertNotIn(MODULE.SLIDER_SETUP_JS,failed.sources)
        self.assertEqual(MODULE.feature_failure_state(failed_rows,feature),"fatal")
        self.assertEqual(failed.states[MODULE.PLAYBACK_COMPANION_KEY],MODULE.StorageState(False,None))

    def test_playback_storage_load_race_waits_for_authoritative_baseline(self):
        feature=MODULE.Feature("IT-PLAYBACK-RACE","player_playback_speed","slider","menu/player.js","watch",1.25)
        contract=MODULE.CONTRACTS[feature.key]
        bridge={"improvedTube":True,"storage":True,"messages":True,"provider":True,"providerId":"it-messages-from-extension"}
        page={"url":MODULE.ROUTES["watch"],"host":"www.youtube.com","protocol":"https:","ready":"complete","youtubeElements":1}
        class RacePlaybackDriver:
            def __init__(self):
                self.states={feature.key:MODULE.StorageState(True,1.0),
                             MODULE.PLAYBACK_COMPANION_KEY:MODULE.StorageState(True,False)}
                self.authoritative_keys=set();self.waiting_key=None
                self.baseline_captured=False;self.mutation_before_baseline=False
                self.storage_reads=[];self.payloads=[];self.sources=[];self.rate=1.0;self.refreshes=0
            def script(self,source,args=None):
                self.sources.append(source)
                if source==MODULE.SET_PHASE_JS or source==MODULE.INSTRUMENT_JS:return True
                if source==MODULE.BRIDGE_JS:return bridge
                if source==MODULE.REAL_PAGE_JS:return page
                if source==MODULE.STORAGE_STATE_JS:
                    key=args[0];loaded=key in self.authoritative_keys;self.storage_reads.append((key,loaded))
                    if not loaded:
                        self.waiting_key=key
                        return {"present":False,"value":None,"storageLoaded":False}
                    state=self.states[key]
                    if key==MODULE.PLAYBACK_COMPANION_KEY and not self.payloads:self.baseline_captured=True
                    return {"present":state.present,"value":state.value if state.present else None,"storageLoaded":True}
                if source==MODULE.SEND_STORAGE_JS:
                    if not self.baseline_captured:self.mutation_before_baseline=True
                    payload=dict(args[0]);self.payloads.append(payload)
                    state=MODULE.StorageState(True,payload.get("value")) if payload["present"] else MODULE.StorageState(False,None)
                    self.states[payload["key"]]=state
                    if payload["key"]==feature.key and payload["present"]:self.rate=float(payload["value"])
                    return {"sent":True,"operation":"set" if payload["present"] else "delete","requested":payload,"queueDepth":0}
                if source==MODULE.SLIDER_SETUP_JS:
                    forced=self.states[MODULE.PLAYBACK_COMPANION_KEY]
                    return {"ok":forced==MODULE.StorageState(True,True),"playbackRate":self.rate,"forced":forced.value}
                if source==MODULE.SLIDER_OBSERVE_JS:return {"present":True,"value":self.rate}
                raise AssertionError("unexpected script source")
            def refresh(self):self.refreshes+=1
        driver=RacePlaybackDriver();old_sleep=MODULE.time.sleep
        try:
            MODULE.time.sleep=lambda _seconds:driver.authoritative_keys.add(driver.waiting_key)
            rows=[]
            self.assertTrue(MODULE.run_contract(driver,feature,contract,"watch",rows,lambda _phase:{"ok":True}))
        finally:MODULE.time.sleep=old_sleep
        self.assertEqual(driver.storage_reads[:4],[(feature.key,False),(feature.key,True),
                                                   (MODULE.PLAYBACK_COMPANION_KEY,False),(MODULE.PLAYBACK_COMPANION_KEY,True)])
        self.assertTrue(driver.baseline_captured);self.assertFalse(driver.mutation_before_baseline)
        self.assertEqual(driver.states[feature.key],MODULE.StorageState(True,1.0))
        self.assertEqual(driver.states[MODULE.PLAYBACK_COMPANION_KEY],MODULE.StorageState(True,False))
        restoration=next(row for row in rows if row.assertion_id=="IT-PLAYBACK-RACE-RESTORATION")
        self.assertEqual(restoration.status,MODULE.PASS);self.assertTrue(restoration.evidence["companion"]["restored"])
        self.assertGreaterEqual(driver.refreshes,1)

    def test_cli_exposes_all_live_feature_keys_and_continuation_flag(self):
        source=MODULE.Path(MODULE.__file__).read_text()
        self.assertIn("--continue-after-product-failure",source)
        self.assertIn("isolation or harness failures stop",source)
        self.assertIn("player_playback_speed",MODULE.CONTRACTS)
        self.assertIn("shortcut_activate_captions",MODULE.CONTRACTS)
        self.assertEqual({"player_playback_speed","shortcut_activate_captions"}&set(MODULE.CONTRACTS),
                         {"player_playback_speed","shortcut_activate_captions"})

    def test_active_aqua_uid_is_console_owner_not_remote_client(self):
        original=MODULE.active_aqua_uid
        try:
            MODULE.active_aqua_uid=lambda:501
            expected,evidence=MODULE.resolve_observer_server_uid(None)
            self.assertEqual(expected,501);self.assertEqual(evidence["consoleUid"],501)
            self.assertNotEqual(503,expected)
            with self.assertRaises(RuntimeError):MODULE.resolve_observer_server_uid(503)
            with self.assertRaises(RuntimeError):MODULE.resolve_observer_server_uid(0)
            with self.assertRaises(RuntimeError):MODULE.resolve_observer_server_uid("501")
        finally:MODULE.active_aqua_uid=original

    def test_missing_console_uid_fails_closed_and_client_default_uses_it(self):
        original=MODULE.active_aqua_uid
        try:
            MODULE.active_aqua_uid=lambda:(_ for _ in ()).throw(RuntimeError("console unavailable"))
            with self.assertRaises(RuntimeError):MODULE.resolve_observer_server_uid(None)
            MODULE.active_aqua_uid=lambda:501
            client=MODULE.AquaObserverClient("/tmp/worker06.sock","run","cap",peer_uid_fn=lambda _sock:501)
            self.assertEqual(client.server_uid_expected,501)
        finally:MODULE.active_aqua_uid=original

    def test_observer_connect_failure_writes_complete_nonrelease_artifact(self):
        original_results=MODULE.RESULTS_ROOT;original_client=MODULE.AquaObserverClient;original_resolve=MODULE.resolve_observer_server_uid;original_port=MODULE.port_open;original_candidate=MODULE.candidate_surface_identity
        class FailingObserver:
            def __init__(self,*_args,**_kwargs):pass
            def connect(self):raise RuntimeError("observer connect failed")
            def close(self):pass
        try:
            with tempfile.TemporaryDirectory() as directory:
                MODULE.RESULTS_ROOT=Path(directory);MODULE.AquaObserverClient=FailingObserver
                MODULE.candidate_surface_identity=lambda _root:{"sha256":"test-candidate","paths":[]}
                MODULE.resolve_observer_server_uid=lambda explicit:(501,{"ok":True,"source":"test","consoleUid":501,"clientUid":503,"explicit":explicit is not None,"expectedUid":501})
                MODULE.port_open=lambda _host,_port:True
                feature=MODULE.Feature("IT-ARTIFACT","uncontracted","switch","menu/x.js","watch",True)
                args=SimpleNamespace(host="127.0.0.1",port=4499,feature_keys=[],limit=None,sut="signed",driver_mode="external",
                    observer_socket="/tmp/worker06.sock",observer_run_id="run",observer_capability="cap",observer_server_uid=501,
                    stp_pid=None,window_id=None,window_x=-1408,window_y=-900,window_width=1360,window_height=2480,
                    extension_path="/tmp/ignored",exercise_falsy=False)
                result=MODULE.run(args,[feature],MODULE.ROOT,{"valid":True})
                self.assertEqual(result,1)
                output=next(Path(directory).iterdir());metadata=json.loads((output/"metadata.json").read_text());rows=json.loads((output/"results.json").read_text())
                expected=MODULE.expected_assertions([feature],[]);ids=[row["assertion_id"] for row in rows]
                self.assertEqual(set(ids),expected);self.assertEqual(len(ids),len(set(ids)))
                self.assertEqual(metadata["missing"],[]);self.assertFalse(metadata["releaseGate"])
                cleanup=next(row for row in rows if row["assertion_id"]=="GLOBAL-CLEANUP")
                self.assertIn(cleanup["status"],{MODULE.PASS,MODULE.HARNESS_FAILURE})
                self.assertEqual(metadata["observerServerUID"]["status"],"failed")
        finally:
            MODULE.RESULTS_ROOT=original_results;MODULE.AquaObserverClient=original_client;MODULE.resolve_observer_server_uid=original_resolve;MODULE.port_open=original_port;MODULE.candidate_surface_identity=original_candidate

    def test_session_failure_before_late_bind_writes_complete_nonrelease_artifact(self):
        original_results=MODULE.RESULTS_ROOT;original_client=MODULE.AquaObserverClient;original_resolve=MODULE.resolve_observer_server_uid;original_port=MODULE.port_open;original_candidate=MODULE.candidate_surface_identity;original_create=MODULE.create_session
        instances=[]
        class BaselineObserver:
            def __init__(self,*_args,**_kwargs):self.closed=False;self.calls=[];self.payloads=[];instances.append(self)
            def connect(self):self.calls.append("connect")
            def call(self,operation,extra=None):
                self.calls.append(operation);self.payloads.append((operation,extra))
                if operation=="baseline":return {"ok":True,"baselineClear":True,"matchingCount":0,"bindingMode":"late","operation":"baseline"}
                raise AssertionError("late claim must not occur before session creation")
            def close(self):self.closed=True
        try:
            with tempfile.TemporaryDirectory() as directory:
                MODULE.RESULTS_ROOT=Path(directory);MODULE.AquaObserverClient=BaselineObserver
                MODULE.candidate_surface_identity=lambda _root:{"sha256":"test-candidate","paths":[]}
                MODULE.resolve_observer_server_uid=lambda explicit:(501,{"ok":True,"source":"test","consoleUid":501,"clientUid":503,"explicit":explicit is not None,"expectedUid":501})
                MODULE.port_open=lambda _host,_port:True
                MODULE.create_session=lambda *_args,**_kwargs:(_ for _ in ()).throw(RuntimeError("POST /session failed"))
                feature=MODULE.Feature("IT-ARTIFACT-SESSION","uncontracted","switch","menu/x.js","watch",True)
                args=SimpleNamespace(host="127.0.0.1",port=4499,feature_keys=[],limit=None,sut="signed",driver_mode="external",
                    observer_socket="/tmp/worker06.sock",observer_run_id="run",observer_capability="cap",observer_server_uid=501,
                    stp_pid=None,window_id=None,window_x=-1408,window_y=-900,window_width=1360,window_height=2480,
                    extension_path="/tmp/ignored",exercise_falsy=False)
                result=MODULE.run(args,[feature],MODULE.ROOT,{"valid":True})
                self.assertEqual(result,1)
                output=next(Path(directory).iterdir());metadata=json.loads((output/"metadata.json").read_text());rows=json.loads((output/"results.json").read_text())
                expected=MODULE.expected_assertions([feature],[]);ids=[row["assertion_id"] for row in rows]
                self.assertEqual(set(ids),expected);self.assertEqual(len(ids),len(set(ids)))
                self.assertEqual(metadata["missing"],[]);self.assertFalse(metadata["releaseGate"])
                self.assertEqual(next(row for row in rows if row["assertion_id"]=="GLOBAL-CLEANUP")["status"],MODULE.PASS)
                self.assertEqual(instances[0].calls,["connect","baseline"])
                self.assertNotIn("pid",instances[0].payloads[0][1]);self.assertNotIn("windowId",instances[0].payloads[0][1])
        finally:
            MODULE.RESULTS_ROOT=original_results;MODULE.AquaObserverClient=original_client;MODULE.resolve_observer_server_uid=original_resolve;MODULE.port_open=original_port;MODULE.candidate_surface_identity=original_candidate;MODULE.create_session=original_create

    class _FakeSocket:
        def __init__(self,response):self.response=response;self.closed=False;self.sent=b""
        def settimeout(self,_):pass
        def connect(self,_):pass
        def sendall(self,data):self.sent+=data
        def recv(self,_):
            value=self.response;self.response=b"";return value
        def close(self):self.closed=True

    def test_observer_client_rejects_wrong_or_missing_server_uid(self):
        original_socket=MODULE.socket.socket;original_validate=MODULE.validate_observer_socket_path
        try:
            MODULE.validate_observer_socket_path=lambda _path:None
            for uid in (None,os.getuid()+1):
                sock=self._FakeSocket(b"")
                MODULE.socket.socket=lambda *_args, sock=sock, **_kwargs:sock
                client=MODULE.AquaObserverClient("/tmp/worker05.sock","run","cap",server_uid_expected=os.getuid(),peer_uid_fn=lambda _sock,uid=uid:uid)
                with self.assertRaises(RuntimeError):client.connect()
                self.assertTrue(sock.closed)
        finally:
            MODULE.socket.socket=original_socket;MODULE.validate_observer_socket_path=original_validate

    def test_observer_client_rejects_untrusted_socket_placement(self):
        with self.assertRaises(RuntimeError):MODULE.validate_observer_socket_path(Path(tempfile.mkdtemp())/"observer.sock")

    def test_observer_client_requires_capability_authenticated_response(self):
        original_socket=MODULE.socket.socket;original_validate=MODULE.validate_observer_socket_path
        try:
            MODULE.validate_observer_socket_path=lambda _path:None
            for response in ({"runId":"run","sequence":1,"ok":True},
                             {"runId":"run","sequence":1,"ok":True,"responseMac":"wrong"}):
                raw=(json.dumps(response,separators=(",",":"))+"\n").encode();sock=self._FakeSocket(raw)
                MODULE.socket.socket=lambda *_args, sock=sock, **_kwargs:sock
                client=MODULE.AquaObserverClient("/tmp/worker05.sock","run","cap",server_uid_expected=os.getuid(),peer_uid_fn=lambda _sock:os.getuid())
                client.connect()
                with self.assertRaises(RuntimeError):client.call("baseline")
                client.close()
        finally:
            MODULE.socket.socket=original_socket;MODULE.validate_observer_socket_path=original_validate

    def test_observer_client_rejects_authenticated_wrong_operation_response(self):
        original_socket=MODULE.socket.socket;original_validate=MODULE.validate_observer_socket_path
        try:
            MODULE.validate_observer_socket_path=lambda _path:None
            response={"runId":"run","sequence":1,"operation":"claim","ok":True}
            response["responseMac"]=MODULE.observer_response_mac(response,"cap")
            raw=(json.dumps(response,separators=(",",":"))+"\n").encode();sock=self._FakeSocket(raw)
            MODULE.socket.socket=lambda *_args, sock=sock, **_kwargs:sock
            client=MODULE.AquaObserverClient("/tmp/worker05.sock","run","cap",server_uid_expected=os.getuid(),peer_uid_fn=lambda _sock:os.getuid())
            client.connect()
            with self.assertRaises(RuntimeError):client.call("baseline")
            client.close()
        finally:
            MODULE.socket.socket=original_socket;MODULE.validate_observer_socket_path=original_validate

    def test_observer_client_accepts_matching_capability_authenticated_response(self):
        original_socket=MODULE.socket.socket;original_validate=MODULE.validate_observer_socket_path
        try:
            MODULE.validate_observer_socket_path=lambda _path:None
            response={"runId":"run","sequence":1,"operation":"baseline","ok":True}
            response["responseMac"]=MODULE.observer_response_mac(response,"cap")
            raw=(json.dumps(response,separators=(",",":"))+"\n").encode();sock=self._FakeSocket(raw)
            MODULE.socket.socket=lambda *_args, sock=sock, **_kwargs:sock
            client=MODULE.AquaObserverClient("/tmp/worker05.sock","run","cap",server_uid_expected=os.getuid(),peer_uid_fn=lambda _sock:os.getuid())
            client.connect();self.assertTrue(client.call("baseline")["ok"]);client.close()
        finally:
            MODULE.socket.socket=original_socket;MODULE.validate_observer_socket_path=original_validate

    def test_coregraphics_selection_is_pid_and_window_identity_scoped(self):
        original = MODULE.coregraphics_windows
        try:
            MODULE.coregraphics_windows = lambda: [
                {"pid": 77, "windowId": 9, "alpha": 1, "width": 100, "height": 100, "x": -1400, "y": -900},
                {"pid": 77, "windowId": 10, "alpha": 1, "width": 100, "height": 100, "x": -1441, "y": -900},
                {"pid": 88, "windowId": 11, "alpha": 1, "width": 5000, "height": 5000, "x": 0, "y": 0},
            ]
            evidence = MODULE.verify_owned_windows(77, 9)
            self.assertTrue(evidence["ok"], "only the verifier-owned target window is asserted")
            self.assertEqual(evidence["targetWindow"]["windowId"], 9)
            self.assertEqual({w["windowId"] for w in evidence["ownedVisibleWindows"]}, {9})
            self.assertEqual({w["windowId"] for w in evidence["unrelatedVisibleWindows"]}, {10})
            self.assertFalse(MODULE.verify_owned_windows(77, 10)["ok"])
        finally:
            MODULE.coregraphics_windows = original

    def test_external_session_ownership_does_not_load_or_kill(self):
        driver = FakeDriver()
        session = MODULE.create_session(driver, "signed", Path("/tmp/ignored"))
        self.assertEqual(driver.created, 1)
        self.assertEqual(driver.loaded, 0)
        self.assertEqual(session["extensionLoad"], "not-requested")
        self.assertEqual(session["sut"], "signed-testflight")
        self.assertEqual(driver.timeouts,(30000,30000))
        self.assertEqual(MODULE.lifecycle_ownership("external")["driverProcess"], "external-unowned")
        self.assertEqual(MODULE.lifecycle_ownership("internal")["driverProcess"], "harness-owned")

    def test_webdriver_uses_nonblocking_page_load_before_exact_fixture_checks(self):
        class Driver(MODULE.WebDriver):
            def __init__(self):super().__init__("127.0.0.1",1);self.payload=None
            def request(self,method,path,payload=None,timeout=180,include_status=False):
                self.payload=payload;return {"sessionId":"session","capabilities":{}}
        driver=Driver();driver.create()
        self.assertEqual(driver.payload["capabilities"]["alwaysMatch"]["pageLoadStrategy"],"none")
        self.assertIn('self._navigate_fresh("/url",{"url":url})',Path(MODULE.__file__).read_text())
        self.assertIn('"/execute/sync",{"script":source,"args":args or []},timeout=40',Path(MODULE.__file__).read_text())

    def test_webdriver_navigation_waits_for_a_fresh_document(self):
        class Driver(MODULE.WebDriver):
            def __init__(self):super().__init__("127.0.0.1",1);self.session_id="session";self.marker=None;self.calls=[]
            def command(self,method,suffix,payload=None,timeout=180):
                self.calls.append((method,suffix,payload))
                if suffix=="/execute/sync":
                    if "arguments[0]" in payload["script"]:self.marker=payload["args"][0];return True
                    self.marker=None;return None
                return None
        driver=Driver();driver.navigate("https://www.youtube.com/@YouTube")
        self.assertIn(("POST","/url",{"url":"https://www.youtube.com/@YouTube"}),driver.calls)
        self.assertFalse(driver.in_frame)

    def test_webdriver_skips_redundant_top_frame_commands(self):
        class Driver(MODULE.WebDriver):
            def __init__(self):super().__init__("127.0.0.1",1);self.session_id="session";self.calls=[]
            def command(self,method,suffix,payload=None,timeout=180):self.calls.append((method,suffix,payload))
        driver=Driver();driver.switch_to_frame();self.assertEqual(driver.calls,[])
        frame={"element-6066-11e4-a52e-4f735466cecf":"frame"};driver.switch_to_frame(frame);driver.switch_to_frame();driver.switch_to_frame()
        self.assertEqual(driver.calls,[("POST","/frame",{"id":frame}),("POST","/frame",{"id":None})])

    def test_external_late_binding_is_default_and_prebound_is_diagnostic_only(self):
        late=SimpleNamespace(driver_mode="external",stp_pid=None,window_id=None)
        prebound=SimpleNamespace(driver_mode="external",stp_pid=77,window_id=9)
        invalid=SimpleNamespace(driver_mode="external",stp_pid=77,window_id=None)
        self.assertEqual(MODULE.observer_binding_mode(late), "late")
        self.assertEqual(MODULE.observer_binding_mode(prebound), "prebound-diagnostic")
        self.assertEqual(MODULE.observer_binding_mode(invalid), "invalid-prebound")
        self.assertFalse(MODULE.release_gate("signed", self._signed_identity(), [], [SimpleNamespace(status=MODULE.PASS)], {"bound":True,"browserAuthoritative":True}, "prebound-diagnostic"))

    def test_late_signed_flow_uses_driver_first_two_nonce_title_probe(self):
        source=Path(MODULE.__file__).read_text()
        self.assertIn('await_observer_title_probe(observer,title_nonce_a,',source)
        self.assertIn('title_nonce_a=fresh_title_nonce()',source)
        self.assertIn('title_nonce_b=fresh_title_nonce()',source)
        self.assertIn('data:text/html,<html><head><title>ImprovedTube%20bootstrap</title>',source)
        self.assertIn('driver.command("POST","/url",{"url":"data:text/html,',source)
        self.assertIn('observer.call("place",{"bindingMode":probe_mode,"titleNonce":title_nonce_b',source)
        self.assertIn('"/window/rect",{"x":x,"y":y,"width":w,"height":h},timeout=20',source)
        self.assertIn('webdriver-pid-single-window-empty-cg-title',source)
        self.assertNotIn('owner.contains("Safari Technology Preview")',source)

    def test_title_probe_readiness_retries_only_authenticated_pending_inventory(self):
        responses=[
            {"ok":False,"ready":False,"retryable":True,"inventoryComplete":True,"matchingCount":0,
             "signedCandidateCount":0,"titleNonce":"nonce-a","attempt":1,"stpWindowInventory":[]},
            {"ok":False,"ready":False,"retryable":True,"inventoryComplete":True,"matchingCount":0,
             "signedCandidateCount":1,"titleNonce":"nonce-a","attempt":2,
             "pendingPid":77,"pendingWindowId":9,"stpWindowInventory":[{"pid":77,"windowId":9}]},
            {"ok":True,"ready":True,"retryable":False,"inventoryComplete":True,"matchingCount":1,
             "signedCandidateCount":1,"titleNonce":"nonce-a","attempt":3,"pid":77,"windowId":9},
        ]
        class Observer:
            def __init__(self):self.calls=[]
            def call(self,operation,extra):self.calls.append((operation,extra));return responses.pop(0)
        now=[0.0];observer=Observer()
        result=MODULE.await_observer_title_probe(observer,"nonce-a",timeout=2,poll=.25,
            sleep_fn=lambda delay:now.__setitem__(0,now[0]+delay),monotonic_fn=lambda:now[0])
        self.assertTrue(result["ok"]);self.assertFalse(result["readinessTimedOut"])
        self.assertEqual(len(result["readinessAttempts"]),3);self.assertEqual(len(observer.calls),3)
        self.assertEqual(result["readinessAttempts"][1]["stpWindowInventory"][0]["pid"],77)

    def test_webdriver_empty_title_fallback_evidence_requires_exact_one_owned_handle(self):
        class Driver:
            def __init__(self):self.handles=["owned-main"];self.current="owned-main";self.titles=[]
            def window_handles(self):return list(self.handles)
            def current_window_handle(self):return self.current
            def script(self,source,args):self.titles.append((source,args));return {"title":args[0]}
        driver=Driver();evidence=MODULE.webdriver_title_binding_evidence(driver,17230,"nonce-a")
        self.assertEqual(evidence,{"webdriverBrowserPid":17230,"webdriverWindowHandle":"owned-main",
            "webdriverWindowHandles":["owned-main"],"webdriverDocumentTitle":"nonce-a"})
        self.assertEqual(driver.titles,[(MODULE.SET_TITLE_NONCE_JS,["nonce-a"])])
        for mutation in (lambda d:setattr(d,"handles",["owned-main","other"]),
                         lambda d:setattr(d,"current","other")):
            bad=Driver();mutation(bad)
            with self.assertRaises(RuntimeError):MODULE.webdriver_title_binding_evidence(bad,17230,"nonce-a")
        with self.assertRaises(RuntimeError):MODULE.webdriver_title_binding_evidence(Driver(),None,"nonce-a")

    def test_title_probe_passes_fresh_webdriver_evidence_on_every_attempt(self):
        responses=[{"ok":False,"ready":False,"retryable":True,"inventoryComplete":True,"matchingCount":0,
                    "signedCandidateCount":0,"titleNonce":"nonce-a","attempt":1},
                   {"ok":True,"ready":True,"retryable":False,"bindingMode":MODULE.__dict__.get("EMPTY_CG_BINDING_MODE","webdriver-pid-single-window-empty-cg-title"),
                    "matchingCount":1,"titleNonce":"nonce-a","attempt":2}]
        class Observer:
            def __init__(self):self.requests=[]
            def call(self,_operation,extra):self.requests.append(dict(extra));return responses.pop(0)
        calls=[];observer=Observer();now=[0.0]
        result=MODULE.await_observer_title_probe(observer,"nonce-a",timeout=1,poll=.25,
            sleep_fn=lambda delay:now.__setitem__(0,now[0]+delay),monotonic_fn=lambda:now[0],
            request_evidence_fn=lambda:(calls.append(True) or {"webdriverBrowserPid":77,
                "webdriverWindowHandle":"main","webdriverWindowHandles":["main"],"webdriverDocumentTitle":"nonce-a"}))
        self.assertTrue(result["ok"]);self.assertEqual(len(calls),2)
        self.assertTrue(all(item["webdriverBrowserPid"]==77 and item["webdriverWindowHandles"]==["main"] for item in observer.requests))

    def test_title_probe_readiness_is_bounded_and_does_not_retry_ambiguous_response(self):
        pending={"ok":False,"ready":False,"retryable":True,"inventoryComplete":True,
                 "matchingCount":0,"signedCandidateCount":0,"titleNonce":"nonce-a","attempt":1}
        class PendingObserver:
            def __init__(self):self.calls=0
            def call(self,*_args):self.calls+=1;return {**pending,"attempt":self.calls}
        now=[0.0];observer=PendingObserver()
        result=MODULE.await_observer_title_probe(observer,"nonce-a",timeout=.5,poll=.25,
            sleep_fn=lambda delay:now.__setitem__(0,now[0]+delay),monotonic_fn=lambda:now[0])
        self.assertTrue(result["readinessTimedOut"]);self.assertEqual(observer.calls,3)
        class AmbiguousObserver:
            def __init__(self):self.calls=0
            def call(self,*_args):self.calls+=1;return {**pending,"signedCandidateCount":2}
        ambiguous=AmbiguousObserver();failed=MODULE.await_observer_title_probe(ambiguous,"nonce-a",timeout=1)
        self.assertFalse(failed["ok"]);self.assertFalse(failed["readinessTimedOut"])
        self.assertEqual(ambiguous.calls,1)

    def test_generated_index_is_frozen_before_candidate_digest_and_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for relative in MODULE.CANDIDATE_SURFACE_PATHS:
                path=root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text("fixture "+relative.as_posix())
            target=root/".appstore/testing/safari-e2e-assertions.md";target.write_text("unknown old bytes")
            text="# generated current index\n\nexact baseline\n"
            first=MODULE.freeze_candidate_surface(text,root)
            self.assertEqual(target.read_text(),text)
            self.assertEqual(first,MODULE.candidate_surface_identity(root)|{
                "generatedIndexSHA256":hashlib.sha256(text.encode()).hexdigest(),
                "generatedIndexBytes":len(text.encode())})
            second=MODULE.freeze_candidate_surface(text,root)
            self.assertEqual(second,first);self.assertEqual(target.read_text(),text)

    def test_window_containment_boundaries_and_target_presence(self):
        original = MODULE.coregraphics_windows
        try:
            MODULE.coregraphics_windows = lambda: [{"pid": 3, "windowId": 4, "alpha": 1, "width": 1360, "height": 2480, "x": -1408, "y": -900}]
            self.assertTrue(MODULE.verify_owned_windows(3, 4)["ok"])
            with self.assertRaises(RuntimeError):
                MODULE.verify_owned_windows(3, 99)
        finally:
            MODULE.coregraphics_windows = original

    def test_internal_window_identity_uses_pid_and_exact_geometry(self):
        original = MODULE.coregraphics_windows
        try:
            MODULE.coregraphics_windows = lambda: [
                {"pid": 9, "windowId": 31, "alpha": 1, "width": 1000, "height": 1000, "x": 0, "y": 0},
                {"pid": 7, "windowId": 32, "alpha": 1, "width": 1360, "height": 2480, "x": -1408, "y": -900},
                {"pid": 7, "windowId": 33, "alpha": 1, "width": 1360, "height": 2480, "x": -1408, "y": -900},
            ]
            with self.assertRaises(RuntimeError):
                MODULE.identify_window_id(7, {"width": 1360, "height": 2480})
            MODULE.coregraphics_windows = lambda: [
                {"pid": 9, "windowId": 31, "alpha": 1, "width": 1000, "height": 1000, "x": 0, "y": 0},
                {"pid": 7, "windowId": 32, "alpha": 1, "width": 1360, "height": 2480, "x": -1408, "y": -900},
            ]
            self.assertEqual(MODULE.identify_window_id(7, {"width": 1360, "height": 2480}), 32)
        finally:
            MODULE.coregraphics_windows = original

    def test_route_recheck_is_indexed_and_cleanup_scope_differs(self):
        feature = MODULE.Feature("IT-TEST", "hide_voice_search_button", "switch", "menu/x.js", "search", True)
        assertions = MODULE.expected_assertions([feature], ["search"])
        self.assertIn("ROUTE-SEARCH-KG271U", assertions)
        self.assertTrue(MODULE.cleanup_success("internal", True, True, True, False))
        self.assertFalse(MODULE.cleanup_success("internal", True, True, False, True))
        self.assertTrue(MODULE.cleanup_success("external", True, True, False, True))
        self.assertFalse(MODULE.cleanup_success("external", True, True, False, False))
        source=Path(MODULE.__file__).read_text()
        self.assertIn("feature_changed=_storage_diff(effect_store,after_store)",source)
        self.assertIn("pause=5 if not present else 2",source)

    def test_failed_session_delete_never_counts_window_close_as_session_closed(self):
        class ResidualSessionDriver:
            def __init__(self):
                self.window_close_succeeded=False
            def close_window(self):
                self.window_close_succeeded=True
            def close(self):
                raise RuntimeError("DELETE /session failed; session still live")
        driver=ResidualSessionDriver()
        cleanup=MODULE.close_webdriver_session(driver,True)
        self.assertTrue(cleanup["windowCloseRequested"])
        self.assertTrue(driver.window_close_succeeded)
        self.assertFalse(cleanup["sessionClosed"])
        self.assertEqual(cleanup["sessionCloseEvidence"]["status"],"failed")
        # Observer final may prove only the originally leased window absent;
        # a reachable external driver plus that evidence must not hide session residue.
        observer_final={"ok":True,"expired":True,"matchingCount":0}
        window_closed=bool(observer_final["ok"] and observer_final["expired"] and observer_final["matchingCount"]==0)
        self.assertFalse(MODULE.cleanup_success("external",cleanup["sessionClosed"],window_closed,False,True))

    def test_session_close_requires_typed_delete_session_response(self):
        self.assertFalse(MODULE.session_close_verified({"verified":True,"status":"deleted","httpStatus":200}))
        self.assertFalse(MODULE.session_close_verified({"verified":True,"status":"deleted","httpStatus":200,"value":[]}) )
        self.assertTrue(MODULE.session_close_verified({"verified":True,"status":"deleted","httpStatus":200,"value":None}))

    def test_close_window_empty_handles_prove_implicit_session_delete(self):
        # A deliberately unusable DELETE /session response proves no request
        # may be made after the exact last-window result.
        server=_ResponseServer(window_body=b'{"value":[]}',session_body=b'{"unexpected":true}')
        try:
            driver=MODULE.WebDriver("127.0.0.1",server.port);driver.session_id="fake"
            cleanup=MODULE.close_webdriver_session(driver,True)
            self.assertTrue(cleanup["sessionClosed"]);self.assertTrue(cleanup["windowCloseVerified"])
            self.assertTrue(cleanup["implicitDeleteByLastWindow"])
            self.assertEqual(cleanup["sessionCloseEvidence"]["status"],"implicit-delete-by-last-window")
            self.assertEqual(server.window_delete_count,1);self.assertEqual(server.session_delete_count,0)
            self.assertEqual(driver.session_id,"")
            self.assertTrue(MODULE.cleanup_success("external",True,True,False,True,True))
        finally:server.close()

    def test_close_window_nonempty_handles_requires_exact_delete_session(self):
        server=_ResponseServer(window_body=b'{"value":["remaining-window"]}',session_body=b'{"value":null}')
        try:
            driver=MODULE.WebDriver("127.0.0.1",server.port);driver.session_id="fake"
            cleanup=MODULE.close_webdriver_session(driver,True)
            self.assertTrue(cleanup["sessionClosed"]);self.assertTrue(cleanup["windowCloseVerified"])
            self.assertFalse(cleanup["implicitDeleteByLastWindow"])
            self.assertEqual(server.window_delete_count,1);self.assertEqual(server.session_delete_count,1)
            self.assertEqual(cleanup["windowCloseEvidence"]["remainingHandles"],["remaining-window"])
        finally:server.close()

    def test_close_window_malformed_or_ambiguous_never_cleanup_passes(self):
        invalid=(b"{}",b'{"value":null}',b'{"value":{}}',b'{"value":[""]}',
                 b'{"value":["a","a"]}',b'{"value":[],"extra":1}',
                 b'{"value":{"first":1,"first":2}}',b'{"value":[]}trailing',b"[]",b"")
        for body in invalid:
            with self.subTest(body=body):
                server=_ResponseServer(window_body=body,session_body=b'{"value":null}')
                try:
                    driver=MODULE.WebDriver("127.0.0.1",server.port);driver.session_id="fake"
                    cleanup=MODULE.close_webdriver_session(driver,True)
                    self.assertFalse(cleanup["windowCloseVerified"])
                    self.assertFalse(cleanup["implicitDeleteByLastWindow"])
                    self.assertTrue(cleanup["sessionClosed"],cleanup)
                    self.assertFalse(MODULE.cleanup_success("external",cleanup["sessionClosed"],True,False,True,cleanup["windowCloseVerified"]))
                finally:server.close()

    def test_close_window_malformed_response_keeps_session_id_when_delete_also_fails(self):
        server=_ResponseServer(window_body=b'{"value":null}',session_body=b"{}")
        try:
            driver=MODULE.WebDriver("127.0.0.1",server.port);driver.session_id="fake"
            cleanup=MODULE.close_webdriver_session(driver,True)
            self.assertFalse(cleanup["windowCloseVerified"]);self.assertFalse(cleanup["sessionClosed"])
            self.assertEqual(driver.session_id,"fake")
            self.assertFalse(MODULE.cleanup_success("external",False,True,False,True,False))
        finally:server.close()

    def test_webdriver_close_requires_exact_present_null_value(self):
        invalid_bodies=(b"{}",b'{"other":null}',b'{"value":[]}',b'{"value":{}}',
                        b'{"value":false}',b'{"value":0}',b'{"value":"null"}',
                        b'{"value":null,"extra":1}',b"",b"not-json",b"[]")
        invalid_bodies+=(b'{"value":{"error":"session not deleted"},"value":null}',
                         b'{"value":null,"value":{"error":"session not deleted"}}',
                         b'{"value":null,"value":null}',
                         b'{"value":{"nested":1,"nested":2}}',
                         b'{"value":null}trailing',b'{"value":NaN}',b'{"value":"\xff"}')
        for body in invalid_bodies:
            with self.subTest(body=body):
                server=_ResponseServer(session_body=body)
                try:
                    driver=MODULE.WebDriver("127.0.0.1",server.port);driver.session_id="fake"
                    with self.assertRaises(RuntimeError):driver.close()
                    self.assertEqual(driver.session_id,"fake")
                finally:server.close()
        for options in ({"status":500},{"disconnect_session":True}):
            with self.subTest(options=options):
                server=_ResponseServer(session_body=b'{"value":null}',**options)
                try:
                    driver=MODULE.WebDriver("127.0.0.1",server.port);driver.session_id="fake"
                    with self.assertRaises(RuntimeError):driver.close()
                    self.assertEqual(driver.session_id,"fake")
                finally:server.close()
        server=_ResponseServer(session_body=b'{"value":null}')
        try:
            driver=MODULE.WebDriver("127.0.0.1",server.port);driver.session_id="fake"
            evidence=driver.close()
            self.assertTrue(evidence["verified"]);self.assertEqual(evidence["value"],None)
            self.assertEqual(driver.session_id,"")
        finally:server.close()

    def test_http_session_residue_keeps_cleanup_nonpass(self):
        server=_ResponseServer(session_body=b"{}",window_body=b'{"value":null}',session_window_count=2)
        try:
            driver=MODULE.WebDriver("127.0.0.1",server.port);driver.session_id="fake"
            cleanup=MODULE.close_webdriver_session(driver,True)
            self.assertTrue(cleanup["windowCloseRequested"])
            self.assertFalse(cleanup["sessionClosed"])
            self.assertEqual(driver.session_id,"fake")
            self.assertEqual(server.residual_session_windows,1)
            observer_final={"ok":True,"expired":True,"matchingCount":0}
            self.assertFalse(MODULE.cleanup_success("external",cleanup["sessionClosed"],
                                                    observer_final["ok"] and observer_final["expired"] and observer_final["matchingCount"]==0,
                                                    False,True))
        finally:server.close()

    def test_webdriver_value_only_calls_preserve_valid_nested_response(self):
        server=_ResponseServer(session_body=b'{"value":{"nested":{"x":1}}}')
        try:
            driver=MODULE.WebDriver("127.0.0.1",server.port)
            self.assertEqual(driver.request("DELETE","/session/fake"),{"nested":{"x":1}})
            envelope=driver.request("DELETE","/session/fake",include_status=True)
            self.assertIsInstance(envelope,MODULE.WebDriverResponse)
            self.assertEqual(envelope.status,200);self.assertEqual(envelope.body,{"value":{"nested":{"x":1}}})
        finally:server.close()
        server=_ResponseServer(session_body=b'{"value":{"itLifecycle":true,"ok":false,"error":{"message":"product exception"}}}')
        try:
            driver=MODULE.WebDriver("127.0.0.1",server.port)
            self.assertEqual(driver.request("DELETE","/session/fake")["error"]["message"],"product exception")
        finally:server.close()

    def test_signed_default_does_not_load_webextension(self):
        driver = FakeDriver()
        signed = MODULE.create_session(driver, "signed", Path("/tmp/ignored"))
        self.assertEqual(driver.created, 1)
        self.assertEqual(driver.loaded, 0)
        self.assertEqual(signed["extensionLoad"], "not-requested")
        unpacked = MODULE.create_session(driver, "unpacked", Path("/tmp/unpacked"))
        self.assertEqual(driver.loaded, 1)
        self.assertEqual(unpacked["extensionLoad"], "webdriver-webextension")

    def test_restoration_requires_exact_persisted_state(self):
        before = MODULE.StorageState(False, None)
        ok, evidence = MODULE.evaluate_restore(before, {"present": False, "value": None}, {"present": False, "value": None})
        self.assertTrue(ok)
        self.assertEqual(evidence["expected"]["present"], False)
        bad, _ = MODULE.evaluate_restore(before, {"present": True, "value": None}, {"present": False, "value": None})
        self.assertFalse(bad)

    def test_normal_restoration_requires_typed_send_route_bridge_and_state_proof(self):
        feature=MODULE.Feature("IT-RESTORE-PROOF","hide_voice_search_button","switch","menu/proof.js","search",True)
        before=MODULE.StorageState(False,None);expected_payload={"key":feature.key,"present":False}
        valid_cleanup={"sent":True,"operation":"delete","requested":expected_payload,"queueDepth":0}
        valid_page={"url":MODULE.ROUTES["search"],"host":"www.youtube.com","protocol":"https:","ready":"complete","youtubeElements":1}
        valid_bridge={"improvedTube":True,"storage":True,"messages":True,"provider":True,"providerId":"it-messages-from-extension"}
        class RestoreDriver:
            def __init__(self,cleanup=valid_cleanup,page=valid_page,bridge=valid_bridge,state=before):
                self.cleanup=cleanup;self.page=page;self.bridge=bridge;self.state=state;self.refreshes=0;self.calls=[]
            def script(self,source,args=None):
                self.calls.append(source)
                if source==MODULE.SEND_STORAGE_JS:return self.cleanup
                if source==MODULE.STORAGE_STATE_JS:return {"present":self.state.present,"value":self.state.value if self.state.present else None,"storageLoaded":True}
                if source==MODULE.REAL_PAGE_JS:return self.page
                if source==MODULE.BRIDGE_JS:return self.bridge
                if source==MODULE.INSTRUMENT_JS:return True
                raise AssertionError("unexpected script")
            def refresh(self):self.refreshes+=1
        def invoke(**kwargs):
            old_sleep=MODULE.time.sleep;MODULE.time.sleep=lambda _seconds:None
            try:
                window=kwargs.pop("window",{"ok":True})
                rows=[];driver=RestoreDriver(**kwargs)
                restored=MODULE.restore_contract_state(driver,feature,MODULE.CONTRACTS[feature.key],"search",rows,before,True,"proof",0.0,lambda _phase:window)
                row=next((item for item in rows if item.assertion_id==feature.feature_id+"-RESTORATION"),None)
                return restored,row,driver
            finally:MODULE.time.sleep=old_sleep
        cases=(
            ("sent-false",{"cleanup":{"sent":False,"operation":"delete","requested":expected_payload,"queueDepth":0}}),
            ("malformed-send",{"cleanup":{}}),
            ("wrong-reload-route",{"page":{**valid_page,"url":"https://evil.invalid/"}}),
            ("missing-post-refresh-bridge",{"bridge":{"improvedTube":False}}),
            ("state-mismatch",{"state":MODULE.StorageState(True,"drift")}),
            ("malformed-containment",{"window":{"ok":1}}),
            ("malformed-queue",{"cleanup":{**valid_cleanup,"queueDepth":"0"}}),
            ("wrong-operation",{"cleanup":{**valid_cleanup,"operation":"set"}}),
            ("wrong-request",{"cleanup":{**valid_cleanup,"requested":{"key":feature.key,"present":True,"value":False}}}),
        )
        for name,kwargs in cases:
            with self.subTest(name=name):
                restored,row,_driver=invoke(**kwargs)
                self.assertFalse(restored);self.assertIsNotNone(row);self.assertNotEqual(row.status,MODULE.PASS)
                self.assertNotEqual(MODULE.feature_failure_state([row],feature),"pass")
        restored,row,driver=invoke()
        self.assertTrue(restored);self.assertIsNotNone(row);self.assertEqual(row.status,MODULE.PASS)
        self.assertTrue(row.evidence["cleanupVerified"]);self.assertTrue(MODULE.real_youtube_page_ok("search",row.evidence["reload"]))
        self.assertTrue(MODULE.bridge_ok(row.evidence["bridge"]));self.assertGreaterEqual(driver.refreshes,1)

    def test_falsy_final_restoration_requires_same_proof_and_emits_row(self):
        feature=MODULE.Feature("IT-FALSY-PROOF","hide_voice_search_button","switch","menu/proof.js","search",True)
        valid_page={"url":MODULE.ROUTES["search"],"host":"www.youtube.com","protocol":"https:","ready":"complete","youtubeElements":1}
        valid_bridge={"improvedTube":True,"storage":True,"messages":True,"provider":True,"providerId":"it-messages-from-extension"}
        class FalsyRestoreDriver:
            def __init__(self,final=None,page=valid_page,bridge_after=valid_bridge):
                self.state=MODULE.StorageState(False,None);self.final=final;self.page=page;self.bridge_after=bridge_after;self.send_count=0;self.refreshes=0
            def script(self,source,args=None):
                if source==MODULE.STORAGE_STATE_JS:return {"present":self.state.present,"value":self.state.value if self.state.present else None,"storageLoaded":True}
                if source==MODULE.BRIDGE_JS:return valid_bridge if self.refreshes==0 else self.bridge_after
                if source==MODULE.INSTRUMENT_JS:return True
                if source==MODULE.REAL_PAGE_JS:return self.page
                if source==MODULE.SEND_STORAGE_JS:
                    self.send_count+=1;payload=dict(args[0])
                    if self.send_count==11 and self.final is not None:return self.final
                    if payload["present"]:self.state=MODULE.StorageState(True,payload.get("value"))
                    else:self.state=MODULE.StorageState(False,None)
                    return {"sent":True,"operation":"set" if payload["present"] else "delete","requested":payload,"queueDepth":0}
                raise AssertionError("unexpected script")
            def refresh(self):self.refreshes+=1
        final_payload={"key":feature.key,"present":False}
        cases=(
            ("sent-false",{"final":{"sent":False,"operation":"delete","requested":final_payload,"queueDepth":0}}),
            ("missing-bridge",{"bridge_after":{"improvedTube":False}}),
            ("wrong-route",{"page":{**valid_page,"url":"https://evil.invalid/"}}),
        )
        old_sleep=MODULE.time.sleep;MODULE.time.sleep=lambda _seconds:None
        try:
            for name,kwargs in cases:
                with self.subTest(name=name):
                    rows=[];driver=FalsyRestoreDriver(**kwargs);self.assertFalse(MODULE.run_falsy_probe(driver,feature,"search",rows,lambda _phase:{"ok":True}))
                    row=next(item for item in rows if item.assertion_id==feature.feature_id+"-RESTORATION")
                    self.assertNotEqual(row.status,MODULE.PASS);self.assertEqual(len([item for item in rows if item.assertion_id==feature.feature_id+"-RESTORATION"]),1)
            rows=[];driver=FalsyRestoreDriver();self.assertTrue(MODULE.run_falsy_probe(driver,feature,"search",rows,lambda _phase:{"ok":True}))
            restoration=next(item for item in rows if item.assertion_id==feature.feature_id+"-RESTORATION")
            self.assertEqual(restoration.status,MODULE.PASS);self.assertEqual(driver.send_count,11);self.assertTrue(restoration.evidence["cleanupVerified"])
        finally:MODULE.time.sleep=old_sleep

    def test_failed_falsy_finalizer_is_fatal_and_blocks_continuation(self):
        first=MODULE.Feature("IT-FIRST","hide_voice_search_button","switch","menu/first.js","search",True)
        second=MODULE.Feature("IT-SECOND","add_scroll_to_top","switch","menu/second.js","search",True)
        rows=[];calls=[];original_contract=MODULE.run_contract;original_falsy=MODULE.run_falsy_probe
        def fake_contract(_driver,feature,_contract,route,results,_window_check):
            calls.append("contract:"+feature.key)
            for suffix,assertion in (("-TRANSPORT","exact bridge transport"),("-EFFECT","semantic feature effect"),("-RESTORATION","exact persisted restoration")):
                MODULE.record(results,feature.feature_id+suffix,feature.feature_id,assertion,MODULE.PASS,"live-semantic",route,"feature",{})
            return True
        def fake_falsy(_driver,feature,route,results,_window_check):
            calls.append("falsy:"+feature.key)
            MODULE.record(results,feature.feature_id+"-FALSY-TRANSPORT",feature.feature_id,"falsy transport regression (false, 0, empty, null, and absence)",MODULE.PASS,"transport",route,"falsy",{})
            MODULE.record(results,feature.feature_id+"-RESTORATION",feature.feature_id,"exact persisted restoration",MODULE.ISOLATION_FAILURE,"harness",route,"falsy-restoration",{"cleanupVerified":False})
            return False
        try:
            MODULE.run_contract=fake_contract;MODULE.run_falsy_probe=fake_falsy
            outcome=MODULE.run_feature_contracts(object(),[first,second],"search",rows,lambda _phase:{"ok":True},
                                                 continue_after_product_failure=True,exercise_falsy=True)
        finally:MODULE.run_contract=original_contract;MODULE.run_falsy_probe=original_falsy
        self.assertEqual(outcome,"fatal");self.assertEqual(calls,["contract:hide_voice_search_button","falsy:hide_voice_search_button"])
        self.assertTrue(all(item.status==MODULE.NOT_RUN for item in rows if item.feature_id==second.feature_id))

    def test_feature_result_classification(self):
        css = MODULE.CONTRACTS["hide_voice_search_button"]
        status, _ = MODULE.classify_observation(css, {"present": True, "visible": True}, {"present": True, "visible": False}, True)
        self.assertEqual(status, MODULE.PASS)
        status, _ = MODULE.classify_observation(css, {"present": True, "visible": False}, {"present": True, "visible": False}, True)
        self.assertEqual(status, MODULE.PRODUCT_FAILURE)
        shortcut = MODULE.CONTRACTS["shortcut_activate_captions"]
        status, _ = MODULE.classify_observation(shortcut, {"present": True, "pressed": "false"}, {"present": True, "pressed": "true"}, True)
        self.assertEqual(status, MODULE.PASS)
        watched = MODULE.CONTRACTS["track_watched_videos"]
        status, reason = MODULE.classify_observation(watched, {"watchedPresent": False}, {"watchedPresent": False}, True)
        self.assertEqual(status, MODULE.PRODUCT_FAILURE)
        self.assertIn("queue overlap", reason)

    def test_source_only_has_explicit_not_run_statuses(self):
        feature = MODULE.Feature("IT-TEST", "uncontracted", "switch", "menu/x.js", "watch", True)
        results = []
        MODULE.source_only_results(results, feature)
        self.assertEqual({item.status for item in results}, {MODULE.PASS, MODULE.UNVERIFIED, MODULE.NOT_RUN})
        self.assertEqual(len(results), 6)
        self.assertTrue(all(item.evidence_class == "source-only" for item in results[2:]))

    def test_full_live_preflight_requires_all_342_controls(self):
        features = MODULE.discover_features(MODULE.ROOT)
        preflight = MODULE.preflight_full_live(features)
        self.assertFalse(preflight.ok)
        self.assertEqual(preflight.counts, {"discovered": 342, "contracted": 5, "notApplicable": 0, "uncontracted": 337})
        self.assertEqual(len(preflight.errors), 337)
        self.assertTrue(all("complete contract or reviewed NOT_APPLICABLE" in error for error in preflight.errors))

    def test_full_live_preflight_accepts_explicit_reviewed_not_applicable(self):
        features = MODULE.discover_features(MODULE.ROOT)
        seeds = set(MODULE.CONTRACTS)
        contracts = {
            feature.key: MODULE.contract_from_feature_contract(MODULE.CONTRACTS[feature.key], feature)
            if feature.key in seeds else {
                "menuSource": feature.source,
                "applicability": "not_applicable",
                "reason": "reviewed fixture is intentionally unavailable",
            }
            for feature in features
        }
        preflight = MODULE.preflight_full_live(features, contracts)
        self.assertTrue(preflight.ok, preflight.errors)
        self.assertEqual(preflight.counts, {"discovered": 342, "contracted": 5, "notApplicable": 337, "uncontracted": 0})

    def test_full_live_terminal_rows_have_no_source_only_evidence(self):
        feature = MODULE.Feature("IT-FULL", "uncontracted", "switch", "menu/x.js", "watch", True)
        rows = []
        MODULE.source_only_results(rows, feature, full_live=True)
        self.assertEqual({row.assertion_id for row in rows}, set(MODULE.feature_assertions(feature, True)))
        self.assertNotIn("source-only", {row.evidence_class for row in rows})
        self.assertEqual(next(row for row in rows if row.assertion_id.endswith("-CONTRACT")).status, MODULE.UNVERIFIED)
        self.assertEqual({row.status for row in rows if not row.assertion_id.endswith("-DISCOVERED")}, {MODULE.UNVERIFIED, MODULE.NOT_RUN})

    def test_semantic_oracle_rejects_generic_storage_echo(self):
        result = MODULE.dispatch_oracle(
            {"kind": "visibility", "relation": "changed_to", "target": "value", "expected": True},
            {"value": False}, {"value": True},
        )
        self.assertFalse(result)
        self.assertIn("storage echo", result.reason)

    def test_contract_files_are_strictly_disjoint_by_menu_source(self):
        contract = {
            "schemaVersion": 1,
            "menuSource": "menu/skeleton-parts/one.js",
            "contracts": {"one": {"storageKey":"one","applicability": "not_applicable", "reason": "reviewed"}},
        }
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "one.json"
            second = Path(directory) / "two.json"
            first.write_text(json.dumps(contract))
            second.write_text(json.dumps({**contract, "contracts": {"two": {"storageKey":"two","applicability": "not_applicable", "reason": "reviewed"}}}))
            with self.assertRaises(ValueError):
                MODULE.load_contract_files([first, second])

    def test_full_catalog_has_one_authority_for_all_discovered_controls(self):
        features = MODULE.discover_features(MODULE.ROOT)
        catalog, diagnostics = MODULE.load_full_live_contract_catalog(
            [MODULE.ROOT / ".appstore/testing/full-live-contracts"], features
        )
        self.assertEqual(len(catalog), 342)
        self.assertEqual(diagnostics["fileCount"], 12)
        self.assertEqual(diagnostics["fileEntryCount"], 342)
        self.assertEqual(diagnostics["fileKeyCount"], 342)
        self.assertEqual(diagnostics["authoritativeEntryCount"], 342)
        self.assertEqual(diagnostics["missing"], [])
        self.assertEqual(diagnostics["extra"], [])
        self.assertEqual(diagnostics["duplicateKeys"], [])
        self.assertEqual(diagnostics["seedOverlapCount"], 5)
        self.assertEqual(
            [item["key"] for item in diagnostics["seedOverlaps"]],
            sorted(MODULE.CONTRACTS),
        )
        for key in MODULE.CONTRACTS:
            self.assertEqual(catalog[key].contract_source,"curated")
        preflight = MODULE.preflight_full_live(features, catalog)
        self.assertTrue(preflight.ok, preflight.errors)
        self.assertEqual(
            preflight.counts,
            {"discovered": 342, "contracted": 323, "notApplicable": 19, "uncontracted": 0},
        )

    def test_catalog_account_lifecycle_uses_stable_account_id_shape(self):
        features=MODULE.discover_features(MODULE.ROOT)
        catalog,_=MODULE.load_full_live_contract_catalog([MODULE.ROOT/".appstore/testing/full-live-contracts"],features)
        checked=[];explicit_account_ids=[]
        for contract in catalog.values():
            fixture=MODULE.ROUTE_FIXTURES.get(contract.fixture_id)
            if contract.is_not_applicable or not (contract.risk in {"account","destructive"} or getattr(fixture,"auth",None)=="dedicated_test_account"):continue
            scripts=[]
            for step in (contract.setup,contract.post_activation,contract.before_oracle,contract.after_oracle,contract.cleanup,contract.after_restoration):
                if isinstance(step,dict) and isinstance(step.get("script"),str):scripts.append(step["script"])
            activation=contract.activation if isinstance(contract.activation,dict) else {}
            if isinstance(activation.get("script"),str):scripts.append(activation["script"])
            body="\n".join(scripts);checked.append(contract.key)
            self.assertNotRegex(body,r"\bidentity\b",contract.key)
            if "accountId" in body:explicit_account_ids.append(contract.key)
        self.assertGreaterEqual(len(checked),10)
        self.assertGreaterEqual(len(explicit_account_ids),8)

    def test_quality_restoration_uses_the_restored_page_storage_mirror(self):
        features=MODULE.discover_features(MODULE.ROOT)
        catalog,_=MODULE.load_full_live_contract_catalog([MODULE.ROOT/".appstore/testing/full-live-contracts"],features)
        for key in ("player_quality_playlist","player_quality","player_quality_without_focus"):
            script=catalog[key].after_restoration["script"]
            self.assertIn("ctx.storageBaseline?."+key,script,key)
            self.assertIn("effect:'page-storage-mirror'",script,key)
            self.assertNotIn("getPlaybackQuality",script,key)

    def test_youtube_contracts_do_not_use_trusted_types_html_sinks(self):
        features=MODULE.discover_features(MODULE.ROOT)
        catalog,_=MODULE.load_full_live_contract_catalog([MODULE.ROOT/".appstore/testing/full-live-contracts"],features)
        for contract in catalog.values():
            for step in (contract.setup,contract.post_activation,contract.before_oracle,contract.after_oracle,contract.cleanup,contract.after_restoration):
                script=step.get("script","") if isinstance(step,dict) else ""
                self.assertNotIn("insertAdjacentHTML",script,contract.key)
                self.assertNotRegex(script,r"\.innerHTML\s*=",contract.key)

    def test_full_catalog_rejects_non_seed_duplicate_key_without_dropping_one(self):
        first = {
            "schemaVersion": 1,
            "menuSource": "menu/skeleton-parts/one.js",
            "contracts": {"duplicate_key": {"storageKey":"duplicate_key","applicability": "not_applicable", "reason": "reviewed"}},
        }
        second = {
            "schemaVersion": 1,
            "menuSource": "menu/skeleton-parts/two.js",
            "contracts": {"duplicate_key": {"storageKey":"duplicate_key","applicability": "not_applicable", "reason": "reviewed"}},
        }
        with tempfile.TemporaryDirectory() as directory:
            first_path = Path(directory) / "one.json"
            second_path = Path(directory) / "two.json"
            first_path.write_text(json.dumps(first))
            second_path.write_text(json.dumps(second))
            with self.assertRaisesRegex(ValueError, "duplicate contract key across files"):
                MODULE.load_full_live_contract_catalog([first_path, second_path])

    def test_fixture_registry_prefers_public_route_and_requires_readiness_proof(self):
        self.assertEqual(MODULE.fixture_for("watch").fixture_id, "watch.base")
        self.assertEqual(MODULE.ROUTE_FIXTURES["playlist.public"].exact_url,"https://www.youtube.com/playlist?list=PLk0bA6F9VgRV1iQ-vMtRjzZAjiml5PjVm")
        self.assertEqual(MODULE.ROUTE_FIXTURES["playlist.watch"].required_selectors,("#player video","ytd-playlist-panel-renderer"))
        fixture = MODULE.fixture_for("watch")
        valid = MODULE.validate_fixture(
            fixture,
            {
                "url": fixture.exact_url,
                "host": "www.youtube.com",
                "protocol": "https:",
                "readyState": "complete",
                "selectors": list(fixture.required_selectors),
            },
        )
        self.assertTrue(valid["ok"], valid)
        incomplete = MODULE.validate_fixture(
            fixture,
            {"url": fixture.exact_url, "host": "www.youtube.com", "readyState": "complete"},
        )
        self.assertFalse(incomplete["ok"])
        self.assertIn("required selector proof is unavailable", incomplete["errors"])

    def test_semantic_presence_and_numeric_oracles_are_not_storage_echoes(self):
        presence = MODULE.dispatch_oracle(
            {"kind": "presence", "relation": "changed_to", "target": "present", "expected": True},
            {"present": False},
            {"present": True},
        )
        self.assertTrue(presence, presence.reason)
        numeric = MODULE.dispatch_oracle(
            {"kind": "numeric_media", "relation": "within_tolerance", "target": "value", "expected": 1.25, "tolerance": 0.01},
            {"present": True, "value": 1.0},
            {"present": True, "value": 1.25},
        )
        self.assertTrue(numeric, numeric.reason)

    def test_strict_contract_loader_rejects_unknown_entry_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "strict.json"
            path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "menuSource": "menu/skeleton-parts/strict.js",
                        "contracts": {
                            "strict": {"applicability": "not_applicable", "reason": "reviewed", "unexpected": True}
                        },
                    }
                )
            )
            with self.assertRaises(ValueError):
                MODULE.load_contract_file(path)

    def test_complete_catalog_can_repeat_the_five_seed_entries(self):
        features = MODULE.discover_features(MODULE.ROOT)
        contracts = {
            feature.key: MODULE.contract_from_feature_contract(MODULE.CONTRACTS[feature.key], feature)
            if feature.key in MODULE.CONTRACTS
            else {"applicability": "NOT_APPLICABLE", "reason": "reviewed"}
            for feature in features
        }
        plans = MODULE.build_full_live_plan(features, contracts)
        self.assertEqual(len(plans), 342)
        self.assertEqual(sum(plan.status == "not_applicable" for plan in plans), 337)

    def test_full_index_has_candidate_hints_without_source_only_class(self):
        feature = MODULE.Feature(
            "IT-FULL-INDEX",
            "index_feature",
            "switch",
            "menu/index.js",
            "watch",
            True,
            metadata_digest="0123456789abcdef",
            source_hints=("ImprovedTube.indexFeature",),
        )
        text = MODULE.render_index([feature], MODULE.ROOT, full_live=True)
        self.assertIn("ImprovedTube.indexFeature", text)
        self.assertNotIn("SOURCE_ONLY", text)

    def test_async_lifecycle_awaits_top_level_await_and_appends_context(self):
        driver=FakeFullLiveDriver();context={"setup":{"ok":True},"before":None,"postActivation":None,"activation":None,"accountFixture":None,"observedAccount":None}
        result=MODULE._lifecycle(driver,{"script":"await Promise.resolve(); return {ok:true,awaited:true};","args":[7]},context)
        self.assertEqual(result,{"ok":True,"awaited":True})
        self.assertEqual(driver.events[-1][0],"lifecycle")

    def test_strict_loader_parses_top_level_await_and_validates_source_range(self):
        entry={"storageKey":"strict_async","fixtureId":"watch.base","route":"watch","surface":"youtube-page","applicability":"applicable",
               "setup":{"script":"await Promise.resolve(); return {ok:true};"},"activation":{"kind":"storage","key":"strict_async","value":True},
               "beforeOracle":{"script":"return {present:false};"},"afterOracle":{"script":"return {present:true};"},
               "oracle":{"kind":"presence","relation":"changed_to","target":"present","expected":True},"prerequisites":["fixture"],
               "dependencyKeys":[],"dependencyValues":{},"sideEffectKeys":[],"restoreScope":["strict_async"],
               "sourceRefs":[{"path":"scripts/appstore/safari_e2e.py","startLine":1,"endLine":1}],
               "settle":{"timeoutMs":100,"pollMs":10},"risk":"safe","contractVersion":1,"contractSource":"curated"}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"strict.json";path.write_text(json.dumps({"schemaVersion":1,"menuSource":"menu/skeleton-parts/strict.js","contracts":{"strict_async":entry}}))
            self.assertIn("strict_async",MODULE.load_contract_file(path))
            entry["sourceRefs"][0]["endLine"]=10**9;path.write_text(json.dumps({"schemaVersion":1,"menuSource":"menu/skeleton-parts/strict.js","contracts":{"strict_async":entry}}))
            with self.assertRaisesRegex(ValueError,"exceeds file length"):MODULE.load_contract_file(path)

    def test_dependency_values_must_exactly_match_declared_keys(self):
        feature=MODULE.Feature("IT-DEP","dep","switch","menu/x.js","watch",True,storage_key="dep")
        raw={"storageKey":"dep","fixtureId":"watch.base","route":"watch","surface":"youtube-page","applicability":"applicable",
             "setup":{"script":"return {ok:true};"},"activation":{"kind":"storage","key":"dep","value":True},
             "beforeOracle":{"script":"return {present:false};"},"afterOracle":{"script":"return {present:true};"},
             "oracle":{"kind":"presence","relation":"changed_to","target":"present","expected":True},"prerequisites":["fixture"],
             "dependencyKeys":["companion"],"dependencyValues":{},"sideEffectKeys":[],"restoreScope":["dep","companion"],
             "settle":{"timeoutMs":100,"pollMs":10},"risk":"safe"}
        errors=MODULE.validate_plan([feature],"full-live",{"dep":raw})
        self.assertTrue(any("dependencyValues" in error for error in errors),errors)

    def test_account_fixture_file_is_exact_and_target_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"account.json";value={"accountId":"delegated-disposable-account","targets":[{"fixtureId":"watch.account","videoId":"dQw4w9WgXcQ","channelId":"UCuAXFkgsw1L7xaCfnd5JJOw"}]};path.write_text(json.dumps(value))
            self.assertEqual(MODULE.load_account_fixture(path),value)
            value["marker"]="unsafe";path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError,"exact"):MODULE.load_account_fixture(path)

    def test_observed_account_must_equal_stable_account_id_video_and_channel(self):
        driver=FakeFullLiveDriver();contract=SimpleNamespace(fixture_id="watch.account",key="account")
        target={"accountId":"delegated-disposable-account","fixtureId":"watch.account","videoId":"dQw4w9WgXcQ","channelId":"UCuAXFkgsw1L7xaCfnd5JJOw"}
        self.assertEqual(MODULE._observe_account_current(driver,contract,target),target)
        driver.account["channelId"]="wrong"
        with self.assertRaisesRegex(RuntimeError,"does not equal"):MODULE._observe_account_current(driver,contract,target)

    def test_redirect_activation_navigates_source_and_proves_exact_post_fixture(self):
        class RedirectDriver(FakeFullLiveDriver):
            def navigate(self,url):
                super().navigate(url)
                if url==MODULE.ROUTE_FIXTURES["shorts.public"].exact_url:
                    self.url=MODULE.ROUTE_FIXTURES["watch.redirected-short"].exact_url
        driver=RedirectDriver()
        proof=MODULE._prove_youtube_redirect(driver,MODULE.ROUTE_FIXTURES["shorts.public"],MODULE.ROUTE_FIXTURES["watch.redirected-short"],lambda _: {"ok":True},"redirect")
        self.assertEqual(driver.events[-1],("navigate",MODULE.ROUTE_FIXTURES["shorts.public"].exact_url))
        self.assertEqual(proof["sourceFixtureId"],"shorts.public")
        self.assertEqual(proof["expectedFixtureId"],"watch.redirected-short")
        self.assertTrue(proof["fixture"]["ok"])
        self.assertTrue(proof["persistedStorage"])

    def test_post_activation_unavailable_restores_and_continues(self):
        features=[];plans={}
        for index in range(3):
            key="post_gate_"+str(index);feature=MODULE.Feature("IT-POST-"+str(index),key,"switch","menu/x.js","search",True,storage_key=key);features.append(feature)
            raw={"menuSource":feature.source,"featureId":feature.feature_id,"storageKey":key,"fixtureId":"search.improvedtube","route":"search","surface":"youtube-page",
                 "applicability":"applicable","setup":{"script":"return {ok:true};"},"activation":{"kind":"storage","key":key,"value":True},
                 "beforeOracle":{"script":"return {visible:true};"},"afterOracle":{"script":"return {visible:false};"},
                 "oracle":{"kind":"visibility","relation":"changed_to","target":"visible","expected":False},"prerequisites":["fixture"],
                 "dependencyKeys":[],"dependencyValues":{},"sideEffectKeys":[],"restoreScope":[key],"settle":{"timeoutMs":100,"pollMs":10},"risk":"safe"}
            if index==0:
                raw["postActivation"]={"script":"throw new Error('activation unavailable');"}
                raw["cleanup"]={"script":"return {ok:false};"}
            if index==1:raw["activation"]["script"]="throw new Error('activation unavailable');"
            contract=MODULE.normalize_contract(key,raw,feature.source);plans[key]=MODULE.FeaturePlan(feature.feature_id,key,key,feature.component,feature.source,feature.route,contract,"contracted")
        identity={"extensionPlist":{"bundleId":"com.tiendoxuan.improvedtube.Extension"},"extensionSignature":{"TeamIdentifier":"76JE9YNX29"},
                  "extensionManifest":{"name":"Improve YouTube! for YouTube & Videos","version":"4","manifest_version":3,"options_page":"menu/index.html"}}
        driver=FakeFullLiveDriver();rows=[]
        with tempfile.TemporaryDirectory() as directory:
            outcome=MODULE.run_full_live_contracts(driver,features,plans,identity,rows,Path(directory),SimpleNamespace(allow_permission=False,allow_account=False,allow_destructive=False,account_fixture_data=None),lambda _: {"ok":True})
        self.assertFalse(outcome["terminal"])
        self.assertEqual(next(row.status for row in rows if row.assertion_id=="IT-POST-0-EFFECT"),MODULE.UNVERIFIED)
        self.assertEqual(next(row.status for row in rows if row.assertion_id=="IT-POST-0-RESTORATION"),MODULE.PASS)
        self.assertEqual(next(row.status for row in rows if row.assertion_id=="IT-POST-1-EFFECT"),MODULE.UNVERIFIED)
        self.assertEqual(next(row.status for row in rows if row.assertion_id=="IT-POST-1-RESTORATION"),MODULE.PASS)
        self.assertEqual(next(row.status for row in rows if row.assertion_id=="IT-POST-2-EFFECT"),MODULE.PASS)

    def test_dependency_values_are_written_before_setup_and_primary_after_before(self):
        feature=MODULE.Feature("IT-ORDER","dependency_order","switch","menu/x.js","search",True,storage_key="dependency_order")
        raw={"storageKey":"dependency_order","fixtureId":"search.improvedtube","route":"search","surface":"youtube-page","applicability":"applicable","preActivationValue":False,
             "setup":{"script":"return {ok:true};"},"activation":{"kind":"storage","key":"dependency_order","value":True},
             "beforeOracle":{"script":"return {visible:true};"},"afterOracle":{"script":"return {visible:false};"},
             "oracle":{"kind":"visibility","relation":"changed_to","target":"visible","expected":False},"prerequisites":["fixture"],
             "dependencyKeys":["companion"],"dependencyValues":{"companion":"ready"},"sideEffectKeys":[],"restoreScope":["dependency_order","companion"],
             "settle":{"timeoutMs":100,"pollMs":10},"risk":"safe"}
        contract=MODULE.normalize_contract(feature.key,raw,feature.source);plan=MODULE.FeaturePlan(feature.feature_id,feature.key,feature.storage_key,feature.component,feature.source,feature.route,contract,"contracted")
        identity={"extensionPlist":{"bundleId":"com.tiendoxuan.improvedtube.Extension"},"extensionSignature":{"TeamIdentifier":"76JE9YNX29"},
                  "extensionManifest":{"name":"Improve YouTube! for YouTube & Videos","version":"4","manifest_version":3,"options_page":"menu/index.html"}}
        driver=FakeFullLiveDriver();driver.values={"companion":False};rows=[]
        with tempfile.TemporaryDirectory() as directory:
            MODULE.run_full_live_contracts(driver,[feature],{feature.key:plan},identity,rows,Path(directory),SimpleNamespace(allow_permission=False,allow_account=False,allow_destructive=False,account_fixture_data=None),lambda _: {"ok":True})
        neutral=next(i for i,event in enumerate(driver.events) if event[:4]==("storage","dependency_order",True,False))
        dep=next(i for i,event in enumerate(driver.events) if event[:3]==("storage","companion",True))
        setup=next(i for i,event in enumerate(driver.events) if event[:2]==("lifecycle","return {ok:true};"))
        before=next(i for i,event in enumerate(driver.events) if event[:2]==("lifecycle","return {visible:true};"))
        primary=next(i for i,event in enumerate(driver.events) if event[:4]==("storage","dependency_order",True,True))
        self.assertLess(neutral,dep);self.assertLess(dep,setup);self.assertLess(setup,before);self.assertLess(before,primary)
        setup_context=driver.events[setup][3]
        self.assertEqual(setup_context["storageBaseline"]["dependency_order"],{"present":False,"value":None})
        self.assertEqual(setup_context["storageBaseline"]["companion"],{"present":True,"value":False})
        self.assertEqual(driver.values,{"companion":False})

    def test_sentinel_before_requires_explicit_restoration_observer(self):
        feature=MODULE.Feature("IT-SENTINEL","sentinel","switch","menu/x.js","watch",True,storage_key="sentinel")
        raw={"storageKey":"sentinel","fixtureId":"watch.base","route":"watch","surface":"youtube-page","applicability":"applicable",
             "setup":{"script":"return {ok:true};"},"activation":{"kind":"storage","key":"sentinel","value":True},
             "beforeOracle":{"script":"window.__itSentinel=true; return {present:true};"},"afterOracle":{"script":"return {present:false};"},
             "oracle":{"kind":"presence","relation":"changed_to","target":"present","expected":False},"prerequisites":["fixture"],
             "dependencyKeys":[],"dependencyValues":{},"sideEffectKeys":[],"restoreScope":["sentinel"],"settle":{"timeoutMs":100,"pollMs":10},"risk":"safe"}
        self.assertTrue(any("sentinel-backed" in error for error in MODULE.validate_plan([feature],"full-live",{"sentinel":raw})))

    def test_phased_trusted_actions_await_each_observer(self):
        driver=FakeFullLiveDriver();contract=SimpleNamespace(settle={"timeoutMs":100,"pollMs":10})
        phase={"prepare":{"script":"return {ok:true};"},"actions":[{"type":"keyDown","value":"\ue007"},{"type":"keyUp","value":"\ue007"}],"observe":{"script":"return {ok:true};"}}
        activation={"phases":[phase,phase]};evidence=MODULE._run_phased_activation(driver,activation,contract,lambda: {})
        self.assertEqual(len(evidence),2);self.assertEqual(len(driver.actions),4)
        self.assertTrue(all(item["observe"]["ok"] for item in evidence))

    def test_multi_window_path_uses_two_real_players_and_closes_only_owned_tab(self):
        class MultiDriver(FakeFullLiveDriver):
            def __init__(self):
                super().__init__();self.handles=["main"];self.current="main";self.urls={"main":self.url};self.video={"main":{"paused":True,"currentTime":0}};self.trigger=False
            def navigate(self,url):self.url=url;self.urls[self.current]=url;self.events.append(("navigate",url))
            def current_window_handle(self):return self.current
            def window_handles(self):return list(self.handles)
            def new_window(self,kind="tab"):
                self.handles.append("owned-second");self.current="owned-second";self.url="about:blank";self.urls[self.current]=self.url;self.video[self.current]={"paused":True,"currentTime":0};return {"handle":self.current,"type":kind}
            def switch_to_window(self,handle):self.current=handle;self.url=self.urls[handle]
            def close_window(self):
                self.handles.remove(self.current);self.urls.pop(self.current);self.video.pop(self.current);self.current=self.handles[0];self.url=self.urls[self.current]
                return {"verified":True,"remainingHandles":list(self.handles)}
            def script_async(self,source,args=None):
                if "itLifecycle:true" in source:
                    body=(args or [""])[0]
                    if body in {MODULE._VIDEO_PLAY_STEP["script"],MODULE._VIDEO_TRIGGER_STEP["script"]}:
                        self.video[self.current]["paused"]=False;self.video[self.current]["currentTime"]+=1
                        if self.trigger and self.current=="main":self.video["owned-second"]["paused"]=True
                        value={"ok":True,"playTransition":body==MODULE._VIDEO_TRIGGER_STEP["script"],**self.video[self.current]}
                        return {"itLifecycle":True,"ok":True,"value":value}
                    if body==MODULE._VIDEO_STATE_STEP["script"]:
                        return {"itLifecycle":True,"ok":True,"value":{"ok":True,"present":True,**self.video[self.current]}}
                return super().script_async(source,args)
        driver=MultiDriver();context={};state=MODULE._prepare_multi_window(driver,MODULE.ROUTE_FIXTURES["watch.player"],MODULE.ROUTE_FIXTURES["watch.player"],lambda _: {"ok":True},context)
        self.assertTrue(state["bothPlaying"]);driver.trigger=True;effect=MODULE._trigger_multi_window(driver,state,context)
        self.assertTrue(effect["otherPaused"]);cleanup=MODULE._close_multi_window(driver,state)
        self.assertTrue(cleanup["verified"]);self.assertEqual(driver.window_handles(),["main"])

    def test_prompt_cleanup_neutralizes_unload_before_options_navigation(self):
        class PromptDriver(FakeFullLiveDriver):
            def script(self,source,args=None):
                if source=="location.href=arguments[0];return {requested:true};":self.url=args[0];return {"requested":True}
                return super().script(source,args)
        feature=MODULE.Feature("IT-PROMPT","prompt_cleanup","button","menu/x.js","watch",True,storage_key="prompt_cleanup")
        raw={"storageKey":"prompt_cleanup","fixtureId":"watch.base","route":"watch","surface":"youtube-page","applicability":"applicable",
             "setup":{"script":"return {ok:true};"},"activation":{"kind":"storage-prompt","key":"prompt_cleanup","value":True,"navigationUrl":"https://www.youtube.com/watch?v=dQw4w9WgXcQ","promptAction":"dismiss"},
             "beforeOracle":{"script":"return {visible:true};"},"afterOracle":{"script":"return {visible:false};"},
             "cleanup":{"script":"return {ok:true,verified:true,navigationNeutralized:true};"},
             "oracle":{"kind":"visibility","relation":"changed_to","target":"visible","expected":False},"prerequisites":["prompt"],
             "dependencyKeys":[],"dependencyValues":{},"sideEffectKeys":[],"restoreScope":["prompt_cleanup"],"settle":{"timeoutMs":100,"pollMs":10},"risk":"permission"}
        contract=MODULE.normalize_contract(feature.key,raw,feature.source);plan=MODULE.FeaturePlan(feature.feature_id,feature.key,feature.storage_key,feature.component,feature.source,feature.route,contract,"contracted")
        identity={"extensionPlist":{"bundleId":"com.tiendoxuan.improvedtube.Extension"},"extensionSignature":{"TeamIdentifier":"76JE9YNX29"},"extensionManifest":{"name":"Improve YouTube! for YouTube & Videos","version":"4","manifest_version":3,"options_page":"menu/index.html"}}
        driver=PromptDriver();rows=[]
        with tempfile.TemporaryDirectory() as directory:
            result=MODULE.run_full_live_contracts(driver,[feature],{feature.key:plan},identity,rows,Path(directory),SimpleNamespace(allow_permission=True,allow_account=False,allow_destructive=False,account_fixture_data=None),lambda _: {"ok":True})
        cleanup_index=next(i for i,event in enumerate(driver.events) if event[:2]==("lifecycle","return {ok:true,verified:true,navigationNeutralized:true};"))
        next_navigation=next(i for i,event in enumerate(driver.events[cleanup_index+1:],cleanup_index+1) if event[0]=="navigate")
        self.assertLess(cleanup_index,next_navigation);self.assertFalse(result["terminal"])

    def test_account_target_is_freshly_bound_before_activation_and_cleanup(self):
        class AccountDriver(FakeFullLiveDriver):
            def __init__(self):super().__init__();self.account_reads=[]
            def script(self,source,args=None):
                if source==MODULE.ACCOUNT_CONTEXT_JS:self.account_reads.append(self.url)
                return super().script(source,args)
        feature=MODULE.Feature("IT-ACCOUNT","account_bound","button","menu/x.js","watch",True,storage_key="account_bound")
        raw={"storageKey":"account_bound","fixtureId":"watch.account","route":"watch","surface":"youtube-page","applicability":"applicable",
             "setup":{"script":"return {ok:true};"},"activation":{"kind":"storage","key":"account_bound","value":True},
             "beforeOracle":{"script":"return {visible:true};"},"afterOracle":{"script":"return {visible:false};"},
             "cleanup":{"script":"return {ok:true,verified:true};"},"afterRestoration":{"script":"return {ok:true};"},
             "oracle":{"kind":"visibility","relation":"changed_to","target":"visible","expected":False},"prerequisites":["account"],
             "dependencyKeys":[],"dependencyValues":{},"sideEffectKeys":[],"restoreScope":["account_bound"],"settle":{"timeoutMs":100,"pollMs":10},"risk":"account"}
        contract=MODULE.normalize_contract(feature.key,raw,feature.source);plan=MODULE.FeaturePlan(feature.feature_id,feature.key,feature.storage_key,feature.component,feature.source,feature.route,contract,"contracted")
        identity={"extensionPlist":{"bundleId":"com.tiendoxuan.improvedtube.Extension"},"extensionSignature":{"TeamIdentifier":"76JE9YNX29"},"extensionManifest":{"name":"Improve YouTube! for YouTube & Videos","version":"4","manifest_version":3,"options_page":"menu/index.html"}}
        fixture_data={"accountId":"delegated-disposable-account","targets":[{"fixtureId":"watch.account","videoId":"dQw4w9WgXcQ","channelId":"UCuAXFkgsw1L7xaCfnd5JJOw"}]}
        driver=AccountDriver();rows=[]
        with tempfile.TemporaryDirectory() as directory:
            result=MODULE.run_full_live_contracts(driver,[feature],{feature.key:plan},identity,rows,Path(directory),SimpleNamespace(allow_permission=False,allow_account=True,allow_destructive=False,account_fixture_data=fixture_data),lambda _: {"ok":True})
        exact="https://www.youtube.com/watch?v=dQw4w9WgXcQ"
        self.assertFalse(result["terminal"]);self.assertGreaterEqual(driver.account_reads.count(exact),5)
        cleanup_event=next(event for event in driver.events if event[:2]==("lifecycle","return {ok:true,verified:true};"))
        self.assertEqual(cleanup_event[2],exact)

    def test_fixture_card_account_binding_returns_to_and_stays_on_library(self):
        feature=MODULE.Feature("IT-LIBRARY","hide_watch_later","button","menu/x.js","watch",True,storage_key="hide_watch_later")
        raw={"storageKey":"hide_watch_later","fixtureId":"library.account","route":"watch","surface":"youtube-page","applicability":"applicable","accountBindingMode":"fixture-card",
             "setup":{"script":"return {ok:true};"},"activation":{"kind":"storage","key":"hide_watch_later","value":True},
             "beforeOracle":{"script":"return {visible:true};"},"afterOracle":{"script":"return {visible:false};"},
             "cleanup":{"script":"return {ok:true,verified:true};"},"afterRestoration":{"script":"return {ok:true};"},
             "oracle":{"kind":"visibility","relation":"changed_to","target":"visible","expected":False},"prerequisites":["library card"],
             "dependencyKeys":[],"dependencyValues":{},"sideEffectKeys":[],"restoreScope":["hide_watch_later"],"settle":{"timeoutMs":100,"pollMs":10},"risk":"account"}
        contract=MODULE.normalize_contract(feature.key,raw,feature.source);plan=MODULE.FeaturePlan(feature.feature_id,feature.key,feature.storage_key,feature.component,feature.source,feature.route,contract,"contracted")
        identity={"extensionPlist":{"bundleId":"com.tiendoxuan.improvedtube.Extension"},"extensionSignature":{"TeamIdentifier":"76JE9YNX29"},"extensionManifest":{"name":"Improve YouTube! for YouTube & Videos","version":"4","manifest_version":3,"options_page":"menu/index.html"}}
        fixture_data={"accountId":"delegated-disposable-account","targets":[{"fixtureId":"library.account","videoId":"dQw4w9WgXcQ","channelId":"UCuAXFkgsw1L7xaCfnd5JJOw"}]}
        driver=FakeFullLiveDriver();rows=[]
        with tempfile.TemporaryDirectory() as directory:
            result=MODULE.run_full_live_contracts(driver,[feature],{feature.key:plan},identity,rows,Path(directory),SimpleNamespace(allow_permission=False,allow_account=True,allow_destructive=False,account_fixture_data=fixture_data),lambda _: {"ok":True})
        library=MODULE.ROUTE_FIXTURES["library.account"].exact_url
        self.assertFalse(result["terminal"]);self.assertEqual(driver.url,library)
        cleanup=next(event for event in driver.events if event[:2]==("lifecycle","return {ok:true,verified:true};"))
        self.assertEqual(cleanup[2],library);self.assertEqual(cleanup[3]["accountBinding"]["mode"],"fixture-card")

    def test_cleanup_failure_still_restores_absent_storage_and_double_snapshots(self):
        feature=MODULE.Feature("IT-CLEANUP-ROLLBACK","cleanup_rollback","switch","menu/x.js","search",True,storage_key="cleanup_rollback")
        raw={"storageKey":"cleanup_rollback","fixtureId":"search.improvedtube","route":"search","surface":"youtube-page","applicability":"applicable",
             "setup":{"script":"return {ok:true};"},"activation":{"kind":"storage","key":"cleanup_rollback","value":True},
             "beforeOracle":{"script":"return {visible:true};"},"afterOracle":{"script":"return {visible:false};"},"cleanup":{"script":"return {ok:false};"},
             "oracle":{"kind":"visibility","relation":"changed_to","target":"visible","expected":False},"prerequisites":["fixture"],
             "dependencyKeys":[],"dependencyValues":{},"sideEffectKeys":[],"restoreScope":["cleanup_rollback"],"settle":{"timeoutMs":100,"pollMs":10},"risk":"safe"}
        contract=MODULE.normalize_contract(feature.key,raw,feature.source);plan=MODULE.FeaturePlan(feature.feature_id,feature.key,feature.storage_key,feature.component,feature.source,feature.route,contract,"contracted")
        identity={"extensionPlist":{"bundleId":"com.tiendoxuan.improvedtube.Extension"},"extensionSignature":{"TeamIdentifier":"76JE9YNX29"},"extensionManifest":{"name":"Improve YouTube! for YouTube & Videos","version":"4","manifest_version":3,"options_page":"menu/index.html"}}
        driver=FakeFullLiveDriver();rows=[]
        with tempfile.TemporaryDirectory() as directory:
            result=MODULE.run_full_live_contracts(driver,[feature],{feature.key:plan},identity,rows,Path(directory),SimpleNamespace(allow_permission=False,allow_account=False,allow_destructive=False,account_fixture_data=None),lambda _: {"ok":True})
        self.assertTrue(result["terminal"]);self.assertNotIn("cleanup_rollback",driver.values)
        restoration=next(row for row in rows if row.assertion_id=="IT-CLEANUP-ROLLBACK-RESTORATION")
        self.assertEqual(restoration.status,MODULE.ISOLATION_FAILURE);self.assertTrue(restoration.evidence["firstSnapshot"]);self.assertTrue(restoration.evidence["secondSnapshot"])

    def test_missing_expected_redirect_is_product_failure_not_unverified(self):
        feature=MODULE.Feature("IT-REDIRECT","redirect_shorts_to_watch","switch","menu/x.js","shorts",True,storage_key="redirect_shorts_to_watch")
        raw={"storageKey":"redirect_shorts_to_watch","fixtureId":"shorts.public","route":"shorts","surface":"youtube-page","applicability":"applicable",
             "setup":{"script":"return {ok:true};"},"postActivation":{"script":"return {ok:false,reason:'unavailable'};"},
             "activation":{"kind":"storage-redirect","key":"redirect_shorts_to_watch","value":True,"postFixtureId":"watch.redirected-short"},
             "beforeOracle":{"script":"return {visible:true};"},"afterOracle":{"script":"return {visible:false};"},
             "oracle":{"kind":"visibility","relation":"changed_to","target":"visible","expected":False},"prerequisites":["short"],
             "dependencyKeys":[],"dependencyValues":{},"sideEffectKeys":[],"restoreScope":["redirect_shorts_to_watch"],"settle":{"timeoutMs":100,"pollMs":10},"risk":"safe"}
        contract=MODULE.normalize_contract(feature.key,raw,feature.source);plan=MODULE.FeaturePlan(feature.feature_id,feature.key,feature.storage_key,feature.component,feature.source,feature.route,contract,"contracted")
        identity={"extensionPlist":{"bundleId":"com.tiendoxuan.improvedtube.Extension"},"extensionSignature":{"TeamIdentifier":"76JE9YNX29"},"extensionManifest":{"name":"Improve YouTube! for YouTube & Videos","version":"4","manifest_version":3,"options_page":"menu/index.html"}}
        missing={"sourceFixtureId":"shorts.public","expectedFixtureId":"watch.redirected-short","redirectObserved":False,"fixture":{"ok":False},"bridge":{"improvedTube":True},"containment":{"ok":True}}
        driver=FakeFullLiveDriver();rows=[]
        with tempfile.TemporaryDirectory() as directory,patch.object(MODULE,"_prove_youtube_redirect",return_value=missing):
            result=MODULE.run_full_live_contracts(driver,[feature],{feature.key:plan},identity,rows,Path(directory),SimpleNamespace(allow_permission=False,allow_account=False,allow_destructive=False,account_fixture_data=None),lambda _: {"ok":True})
        self.assertFalse(result["terminal"])
        self.assertEqual(next(row.status for row in rows if row.assertion_id=="IT-REDIRECT-TRANSPORT"),MODULE.PASS)
        self.assertEqual(next(row.status for row in rows if row.assertion_id=="IT-REDIRECT-EFFECT"),MODULE.PRODUCT_FAILURE)
        self.assertEqual(next(row.status for row in rows if row.assertion_id=="IT-REDIRECT-RESTORATION"),MODULE.PASS)

    def test_full_live_assertion_set_excludes_focused_falsy_transport(self):
        feature=MODULE.Feature("IT-NO-FALSY","no_falsy","switch","menu/x.js","watch",True)
        self.assertNotIn("IT-NO-FALSY-FALSY-TRANSPORT",MODULE.feature_assertions(feature,True))
        self.assertIn("IT-NO-FALSY-FALSY-TRANSPORT",MODULE.feature_assertions(feature,False))

    def test_signed_bundle_requires_exact_team_on_app_and_extension(self):
        with tempfile.TemporaryDirectory() as directory:
            app=Path(directory)/"ImprovedTube.app";extension=app/MODULE.EXTENSION_RELATIVE;resources=extension/"Contents/Resources"
            (app/"Contents").mkdir(parents=True);resources.mkdir(parents=True)
            app_info={"CFBundleIdentifier":MODULE.EXPECTED_APP_BUNDLE_ID,"CFBundleShortVersionString":"4","CFBundleVersion":"4"}
            ext_info={"CFBundleIdentifier":MODULE.EXPECTED_EXTENSION_BUNDLE_ID,"CFBundleShortVersionString":"4","CFBundleVersion":"4"}
            with (app/"Contents/Info.plist").open("wb") as handle:plistlib.dump(app_info,handle)
            with (extension/"Contents/Info.plist").open("wb") as handle:plistlib.dump(ext_info,handle)
            (resources/"manifest.json").write_text(json.dumps({"name":"ImprovedTube","version":"4","manifest_version":3,"options_page":"menu/index.html"}))
            def signed(command,timeout=30):
                if "--verify" in command:return (0,"","")
                is_extension=str(command[-1]).endswith(".appex");identifier=MODULE.EXPECTED_EXTENSION_BUNDLE_ID if is_extension else MODULE.EXPECTED_APP_BUNDLE_ID;team=MODULE.EXPECTED_TEAM_IDENTIFIER if is_extension else "WRONGTEAM"
                return (0,"",f"Identifier={identifier}\nTeamIdentifier={team}\nAuthority={MODULE.EXPECTED_TESTFLIGHT_AUTHORITY}\nCDHash=abc\n")
            with patch.object(MODULE,"command_output",side_effect=signed),patch.object(MODULE,"asset_tree_digest",return_value="digest"):
                evidence=MODULE.inspect_signed_bundle(app)
            self.assertFalse(evidence["valid"])
            self.assertIn("unexpected app signing TeamIdentifier",evidence["errors"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
