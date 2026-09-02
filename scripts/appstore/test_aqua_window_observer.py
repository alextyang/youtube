#!/usr/bin/env python3
import importlib.util
import copy
import json
import os
import plistlib
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("aqua_observer",HERE/"aqua_window_observer.py")
MOD=importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name]=MOD
SPEC.loader.exec_module(MOD)
LAUNCH_SPEC=importlib.util.spec_from_file_location("aqua_launcher",HERE/"launch_aqua_observer.py")
LAUNCH=importlib.util.module_from_spec(LAUNCH_SPEC)
sys.modules[LAUNCH_SPEC.name]=LAUNCH
LAUNCH_SPEC.loader.exec_module(LAUNCH)

def request(obs,sequence,operation,**extra):
    value={"runId":obs.run_id,"capability":obs.capability,"sequence":sequence,"operation":operation}
    value.update(extra)
    return value

class ObserverProtocolTests(unittest.TestCase):
    def test_connection_idle_timeout_outlasts_webdriver_request_bound(self):
        self.assertGreater(MOD.CONNECTION_IDLE_TIMEOUT_SECONDS,180)
        self.assertLessEqual(MOD.CONNECTION_IDLE_TIMEOUT_SECONDS,300)

    def setUp(self):
        self.live=[{"owner":"Safari Technology Preview","pid":77,"windowId":9,"alpha":1,"name":"nonce","x":-1408,"y":-900,"width":1360,"height":2480}]
        self.signature={"bundlePath":str(MOD.STP_APP),"executablePath":MOD.STP_EXECUTABLE,
                        "plistIdentifier":MOD.STP_BUNDLE_ID,"signedIdentifier":MOD.STP_BUNDLE_ID,
                        "displayExecutable":MOD.STP_EXECUTABLE,
                        "authorities":["Software Signing","Apple Code Signing Certification Authority","Apple Root CA"],
                        "teamIdentifier":"not set","designatedRequirement":MOD.STP_DESIGNATED_REQUIREMENT,
                        "bundleVerified":True,"executableVerified":True,"requirementVerified":True,
                        "strict":True,"deep":True,"allArchitectures":True,"valid":True}
        def process(pid):
            if pid!=77: raise MOD.ObserverError("unknown pid")
            return {"pid":77,"startTime":"start-a","uid":os.getuid(),"commandDigest":"digest",
                    "bundleId":MOD.STP_BUNDLE_ID,"executable":MOD.STP_EXECUTABLE,"signature":dict(self.signature)}
        self.process=process
        def ax_windows(pid,window_id,title):
            target=next((window for window in self.live if window.get("pid")==pid and window.get("windowId")==window_id),{})
            bounds={key:target.get(key) for key in ("x","y","width","height")}
            return [{"owner":"Safari Technology Preview","bundleId":MOD.STP_BUNDLE_ID,
                     "pid":pid,"title":title,"axWindowNumber":window_id,"bounds":bounds}]
        self.obs=MOD.AquaObserver(Path(tempfile.mkdtemp())/"observer.sock","run-a","cap-a",502,
            windows_fn=lambda:self.live,process_fn=process,peer_fn=lambda _sock:502,
            ax_windows_fn=ax_windows)
        self.obs.peer_uid_actual=502

    def new_observer(self, windows=None, process=None):
        windows_fn=(lambda:self.live) if windows is None else (lambda windows=windows:windows)
        process_fn=self.process if process is None else process
        def ax_windows(pid,window_id,title):
            records=windows_fn()
            target=next((window for window in records if window.get("pid")==pid and window.get("windowId")==window_id),{})
            bounds={key:target.get(key) for key in ("x","y","width","height")}
            return [{"owner":"Safari Technology Preview","bundleId":MOD.STP_BUNDLE_ID,
                     "pid":pid,"title":title,"axWindowNumber":window_id,"bounds":bounds}]
        obs=MOD.AquaObserver(Path(tempfile.mkdtemp())/"observer.sock","run-a","cap-a",502,
            windows_fn=windows_fn,process_fn=process_fn,peer_fn=lambda _sock:502,
            ax_windows_fn=ax_windows)
        obs.peer_uid_actual=502
        return obs

    def webdriver_binding(self,nonce,pid=77,handle="owned-main"):
        return {"webdriverBrowserPid":pid,"webdriverWindowHandle":handle,
                "webdriverWindowHandles":[handle],"webdriverDocumentTitle":nonce}

    def empty_ax_record(self,nonce="",pid=77,window_id=9,bounds=None):
        return {"owner":"Safari Technology Preview","bundleId":MOD.STP_BUNDLE_ID,"pid":pid,
                "title":nonce,"axWindowNumber":window_id,
                "bounds":bounds or {"x":-1320,"y":39,"width":1360,"height":2480}}

    def prime_late(self, obs, nonce_a="nonce-a", nonce_b="nonce-b", prefix="Personal — "):
        """Baseline, probe A, then expose the same window under decorated B."""
        self.live.clear()
        baseline=obs.handle(request(obs,1,"baseline",titleNonce=nonce_a,bindingMode="late"))
        self.assertTrue(baseline["ok"],baseline)
        self.live.append({"owner":"Safari Technology Preview","pid":77,"windowId":9,"alpha":1,
                          "name":prefix+nonce_a,"x":-1408,"y":-900,"width":1360,"height":2480})
        probe=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce=nonce_a))
        self.assertTrue(probe["ok"],probe)
        self.assertEqual(probe["bindingMode"],"late")
        self.assertEqual(probe["nativeTitle"],prefix+nonce_a)
        self.live[0]["name"]=prefix+nonce_b
        return nonce_a,nonce_b,prefix,probe

    def test_peer_uid_and_protocol_auth(self):
        class Sock: pass
        self.obs.authenticate_peer(Sock())
        self.assertEqual(self.obs.peer_uid_actual,502)
        self.assertTrue(self.obs.handle(request(self.obs,1,"baseline",pid=77,titleNonce="nonce"))["ok"])
        with self.assertRaises(MOD.ObserverError):
            self.obs.handle(request(self.obs,3,"claim",pid=77,windowId=9,titleNonce="nonce",requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))

    def test_claim_observe_final_and_expiry(self):
        baseline=self.obs.handle(request(self.obs,1,"baseline",pid=77,titleNonce="nonce"))
        self.assertEqual(baseline["candidateWindowId"],9)
        self.assertEqual(baseline["pid"],77)
        self.assertEqual(baseline["titleNonce"],"nonce")
        claim=self.obs.handle(request(self.obs,2,"claim",pid=77,windowId=9,titleNonce="nonce",requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        self.assertTrue(claim["ok"]);self.assertEqual(claim["pid"],77)
        observed=self.obs.handle(request(self.obs,3,"observe",phase="route"))
        self.assertTrue(observed["ok"]);self.assertEqual(observed["matchingCount"],1)
        self.live.clear()
        final=self.obs.handle(request(self.obs,4,"final"))
        self.assertTrue(final["ok"]);self.assertTrue(final["expired"]);self.assertEqual(final["matchingCount"],0)
        with self.assertRaises(MOD.ObserverError):
            self.obs.handle(request(self.obs,5,"observe",phase="after-final"))

    def test_late_baseline_requires_fresh_nonce_absence_then_claims_without_pid(self):
        obs=self.new_observer(process=lambda _pid:self.process(_pid))
        nonce_a,nonce_b,_prefix,_probe=self.prime_late(obs,"fresh-late-a","fresh-late-b")
        obs.placer=lambda pid,window_id,title,bounds:{"method":"test-placer","pid":pid,"windowId":window_id,"titleNonce":title,"requestedBounds":dict(bounds)}
        placement=obs.handle(request(obs,3,"place",bindingMode="late",titleNonce=nonce_b,
                                      requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        self.assertTrue(placement["ok"]);self.assertTrue(placement["placementEvidence"]["verified"])
        with self.assertRaises(MOD.ObserverError):
            obs.handle(request(obs,4,"claim",pid=77,windowId=9,titleNonce=nonce_b,
                               requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        claim=obs.handle(request(obs,5,"claim",titleNonce=nonce_b,
                                      requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        self.assertTrue(claim["ok"]);self.assertEqual(claim["bindingMode"],"late")
        self.assertEqual(claim["pid"],77);self.assertEqual(claim["windowId"],9)
        self.assertEqual(claim["identity"]["startTime"],"start-a")

    def test_late_baseline_rejects_preexisting_nonce_collision(self):
        baseline=self.obs.handle(request(self.obs,1,"baseline",titleNonce="nonce",bindingMode="late"))
        self.assertFalse(baseline["ok"]);self.assertFalse(baseline["baselineClear"])
        self.assertEqual(baseline["matchingCount"],1);self.assertIsNone(baseline["pid"])

    def test_late_baseline_rejects_preexisting_signed_stp_process_without_windows(self):
        obs=MOD.AquaObserver(Path(tempfile.mkdtemp())/"observer.sock","run-a","cap-a",502,
            windows_fn=lambda:[],process_fn=self.process,peer_fn=lambda _sock:502,
            stp_pids_fn=lambda:[77])
        obs.peer_uid_actual=502
        baseline=obs.handle(request(obs,1,"baseline",titleNonce="nonce",bindingMode="late"))
        self.assertFalse(baseline["ok"]);self.assertFalse(baseline["baselineClear"])
        self.assertEqual(baseline["matchingCount"],0)
        self.assertTrue(baseline["processInventoryComplete"])
        self.assertEqual(baseline["stpWindowInventory"],[])
        self.assertEqual(baseline["stpProcessInventory"],[self.process(77)])
        with self.assertRaises(MOD.ObserverError):
            obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="nonce",
                               **self.webdriver_binding("nonce")))

    def test_late_claim_rejects_zero_multiple_malformed_wrong_process_and_bounds(self):
        valid={"x":-1408,"y":-900,"width":1360,"height":2480}
        cases=[
            ([],self.process),
            (self.live+[dict(self.live[0],windowId=10)],self.process),
            ([dict(self.live[0],pid="77")],self.process),
            (self.live,lambda _pid:{"pid":77,"startTime":"start-a","uid":os.getuid(),"commandDigest":"digest","bundleId":"com.apple.Safari","executable":"/Applications/Safari.app/Contents/MacOS/Safari"}),
            ([dict(self.live[0],width=1359)],self.process),
        ]
        for windows,process in cases:
            with self.subTest(windows=windows):
                visible=[];obs=self.new_observer(windows=visible,process=process)
                obs.handle(request(obs,1,"baseline",titleNonce="nonce",bindingMode="late"))
                visible.extend(windows)
                with self.assertRaises(MOD.ObserverError):
                    obs.handle(request(obs,2,"claim",titleNonce="nonce",requestedBounds=valid))

    def test_successful_late_claim_binds_immutable_process_identity(self):
        obs=self.new_observer()
        _a,nonce,_prefix,_probe=self.prime_late(obs,"identity-a","identity-b")
        obs.placer=lambda pid,window_id,title,bounds:{"method":"test-placer","pid":pid,"windowId":window_id,"titleNonce":title,"requestedBounds":dict(bounds)}
        placement=obs.handle(request(obs,3,"place",bindingMode="late",titleNonce=nonce,
                                     requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        self.assertTrue(placement["ok"])
        claim=obs.handle(request(obs,4,"claim",titleNonce=nonce,
                                 requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        self.assertEqual(claim["bindingMode"],"late")
        bound=dict(claim["identity"]);self.assertEqual(obs.lease["identity"],bound)
        claim["identity"]["startTime"]="tampered-response"
        self.assertEqual(obs.lease["identity"]["startTime"],"start-a")
        self.live.clear()
        obs.process_fn=lambda _pid:{**bound,"startTime":"start-reused"}
        with self.assertRaises(MOD.ObserverError):obs.handle(request(obs,5,"final"))
        self.assertFalse(obs.finalized)

    def test_replay_pid_reuse_title_and_ambiguity_rejected(self):
        with self.assertRaises(MOD.ObserverError):
            self.obs.handle(request(self.obs,2,"baseline",pid=77,titleNonce="nonce"))
        ambiguous=self.live+[dict(self.live[0],windowId=10)]
        self.obs.windows_fn=lambda:ambiguous
        self.assertFalse(self.obs.handle(request(self.obs,1,"baseline",pid=77,titleNonce="nonce"))["ok"])
        self.obs.windows_fn=lambda:self.live
        self.obs.handle(request(self.obs,2,"baseline",pid=77,titleNonce="nonce"))
        self.obs.handle(request(self.obs,3,"claim",pid=77,windowId=9,titleNonce="nonce",requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        self.obs.process_fn=lambda pid:{"pid":77,"startTime":"start-b","uid":os.getuid(),"commandDigest":"digest",
                                        "bundleId":MOD.STP_BUNDLE_ID,"executable":MOD.STP_EXECUTABLE,"signature":dict(self.signature)}
        with self.assertRaises(MOD.ObserverError):
            self.obs.handle(request(self.obs,4,"observe",phase="pid-reuse"))

    def test_title_change_after_claim_uses_immutable_identity_and_bounds(self):
        self.obs.handle(request(self.obs,1,"baseline",pid=77,titleNonce="nonce"))
        self.obs.handle(request(self.obs,2,"claim",pid=77,windowId=9,titleNonce="nonce",requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        self.live[0]["name"]="normal-safari"
        self.assertTrue(self.obs.handle(request(self.obs,3,"observe",phase="title-change"))["ok"])
        with self.assertRaises(MOD.ObserverError):
            MOD.AquaObserver(Path(tempfile.mkdtemp())/"x","run","cap",1,process_fn=lambda _:{"pid":1,"startTime":"x","executable":"/Applications/Safari.app/Contents/MacOS/Safari","bundleId":"com.apple.Safari"},windows_fn=lambda:[])._baseline({"pid":1,"titleNonce":"x"})

    def test_observe_rejects_move_and_resize_from_immutable_lease_bounds(self):
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        for field,value in (("x",-2400),("y",-2500),("width",1300),("height",2400)):
            with self.subTest(field=field):
                self.live[:]=[{"owner":"Safari Technology Preview","pid":77,"windowId":9,"alpha":1,"name":"nonce",
                               "x":-1408,"y":-900,"width":1360,"height":2480}]
                obs=self.new_observer()
                obs.handle(request(obs,1,"claim",pid=77,windowId=9,titleNonce="nonce",requestedBounds=requested))
                self.live[0][field]=value
                observed=obs.handle(request(obs,2,"observe",phase="geometry-drift"))
                self.assertFalse(observed["ok"])
                self.assertNotEqual(observed["bounds"],observed["requestedBounds"])

    def test_claim_rejects_malformed_or_mismatched_bounds(self):
        valid={"x":-1408,"y":-900,"width":1360,"height":2480}
        malformed=[
            None,
            {},
            {"x":-1408,"y":-900,"width":1360},
            {**valid,"extra":1},
            {**valid,"x":-1408.0},
            {**valid,"y":float("nan")},
            {**valid,"width":True},
            {**valid,"width":0},
            {**valid,"height":-1},
        ]
        for bounds in malformed:
            with self.subTest(bounds=bounds):
                obs=self.new_observer()
                with self.assertRaises(MOD.ObserverError):
                    obs.handle(request(obs,1,"claim",pid=77,windowId=9,titleNonce="nonce",requestedBounds=bounds))
        malformed_targets=[
            dict(self.live[0],x=-1408.0),
            dict(self.live[0],y=float("inf")),
            dict(self.live[0],width=0),
            dict(self.live[0],height=-1),
            {key:value for key,value in self.live[0].items() if key!="x"},
        ]
        for target in malformed_targets:
            with self.subTest(target=target):
                obs=self.new_observer(windows=[target])
                with self.assertRaises(MOD.ObserverError):
                    obs.handle(request(obs,1,"claim",pid=77,windowId=9,titleNonce="nonce",requestedBounds=valid))
        mismatched=dict(valid,width=1359)
        obs=self.new_observer()
        with self.assertRaises(MOD.ObserverError):
            obs.handle(request(obs,1,"claim",pid=77,windowId=9,titleNonce="nonce",requestedBounds=mismatched))
        self.assertEqual(obs.phase,"created")

    def test_identity_requires_present_integer_active_uid(self):
        base={"pid":77,"startTime":"start-a","commandDigest":"digest","bundleId":MOD.STP_BUNDLE_ID,
              "executable":MOD.STP_EXECUTABLE,"signature":dict(self.signature)}
        variants=[
            base,
            {**base,"uid":None},
            {**base,"uid":str(os.getuid())},
            {**base,"uid":True},
            {**base,"uid":os.getuid()+1},
        ]
        for identity in variants:
            with self.subTest(uid=identity.get("uid","missing")):
                obs=self.new_observer(process=lambda _pid,identity=identity:identity)
                with self.assertRaises(MOD.ObserverError):
                    obs.handle(request(obs,1,"baseline",pid=77,titleNonce="nonce"))

    def test_final_rejects_pid_reuse_even_when_window_absent(self):
        obs=self.new_observer()
        obs.handle(request(obs,1,"claim",pid=77,windowId=9,titleNonce="nonce",requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        self.live.clear()
        reused={"pid":77,"startTime":"start-b","uid":os.getuid(),"commandDigest":"digest",
                "bundleId":MOD.STP_BUNDLE_ID,"executable":MOD.STP_EXECUTABLE,"signature":dict(self.signature)}
        obs.process_fn=lambda _pid:reused
        with self.assertRaises(MOD.ObserverError):
            obs.handle(request(obs,2,"final"))
        self.assertFalse(obs.finalized)

    def test_final_accepts_original_process_exit_with_explicit_evidence(self):
        obs=self.new_observer()
        obs.handle(request(obs,1,"claim",pid=77,windowId=9,titleNonce="nonce",requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        self.live.clear()
        def exited(_pid):
            raise MOD.ProcessExitedError("Safari PID is not running")
        obs.process_fn=exited
        final=obs.handle(request(obs,2,"final"))
        self.assertTrue(final["ok"])
        self.assertTrue(final["expired"])
        self.assertEqual(final["matchingCount"],0)
        self.assertEqual(final["processStatus"],"exited")
        self.assertFalse(final["processIdentityVerified"])
        self.assertEqual(final["processIdentityEvidence"]["expectedStartTime"],"start-a")
        with self.assertRaises(MOD.ObserverError):
            obs.handle(request(obs,3,"observe",phase="after-final"))

    def test_final_rejects_ambiguous_identity_lookup(self):
        obs=self.new_observer()
        obs.handle(request(obs,1,"claim",pid=77,windowId=9,titleNonce="nonce",requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        self.live.clear()
        def ambiguous(_pid):
            raise MOD.ObserverError("identity lookup failed")
        obs.process_fn=ambiguous
        with self.assertRaises(MOD.ObserverError):
            obs.handle(request(obs,2,"final"))
        self.assertFalse(obs.finalized)

    def test_final_does_not_treat_plain_exit_text_as_process_exit(self):
        obs=self.new_observer()
        obs.handle(request(obs,1,"claim",pid=77,windowId=9,titleNonce="nonce",requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        self.live.clear()
        def ambiguous(_pid):
            raise MOD.ObserverError("Safari PID is not running")
        obs.process_fn=ambiguous
        with self.assertRaises(MOD.ObserverError):
            obs.handle(request(obs,2,"final"))
        self.assertFalse(obs.finalized)

    def test_late_placement_corrects_webdriver_y_clamp_and_binds_immutable_target(self):
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        obs=self.new_observer();_a,nonce,prefix,_probe=self.prime_late(obs,"clamped-y-a","clamped-y-b")
        self.live[0]["y"]=30
        calls=[]
        def placer(pid,window_id,title,bounds):
            calls.append((pid,window_id,title,dict(bounds)))
            self.live[0].update(bounds)
            return {"method":"fake-active-aqua","pid":pid,"windowId":window_id,"titleNonce":title,"requestedBounds":dict(bounds)}
        obs.placer=placer
        placement=obs.handle(request(obs,3,"place",bindingMode="late",titleNonce=nonce,requestedBounds=requested))
        self.assertTrue(placement["ok"]);self.assertEqual(placement["placementEvidence"]["beforeBounds"]["y"],30)
        self.assertEqual(placement["placementEvidence"]["afterBounds"],requested);self.assertEqual(calls[0][1],9)
        claim=obs.handle(request(obs,4,"claim",titleNonce=nonce,requestedBounds=requested))
        self.assertTrue(claim["ok"]);self.assertEqual(claim["pid"],77);self.assertEqual(claim["windowId"],9)
        self.assertEqual(obs.provisional["processStartTime"],"start-a")

    def test_late_placement_rejects_zero_multiple_wrong_app_wrong_identity_and_bounds(self):
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        base=dict(self.live[0],name="Personal — place-b")
        bad_identity={"pid":77,"startTime":"start-a","uid":os.getuid(),"commandDigest":"digest",
                      "bundleId":"com.apple.Safari","executable":"/Applications/Safari.app/Contents/MacOS/Safari",
                      "signature":dict(self.signature)}
        cases=[
            ("zero",[],self.process),
            ("multiple",[base,dict(base,windowId=10)],self.process),
            ("wrong-app",[dict(base,owner="Safari")],self.process),
            ("wrong-identity",[base],lambda _pid:bad_identity),
            ("wrong-bounds",[dict(base,width=1359)],self.process),
        ]
        for label,windows,process in cases:
            with self.subTest(label=label):
                visible=[];obs=self.new_observer(windows=visible,process=process)
                obs.handle(request(obs,1,"baseline",titleNonce="place-a",bindingMode="late"))
                visible.append(dict(self.live[0],name="Personal — place-a"))
                obs.process_fn=self.process
                obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="place-a"))
                # The rejection cases below exercise post-probe placement;
                # use a clean identity fixture for the process-sensitive
                # variants and expose the requested B title only afterwards.
                visible.clear();visible.extend([dict(item,name="Personal — place-b") for item in windows])
                if label=="wrong-identity":
                    obs.process_fn=process
                obs.placer=lambda *_args:{"method":"fake-active-aqua"}
                with self.assertRaises(MOD.ObserverError):
                    obs.handle(request(obs,3,"place",bindingMode="late",titleNonce="place-b",requestedBounds=requested))
                self.assertIsNone(obs.provisional);self.assertEqual(obs.placement_count,1)

    def test_late_placement_rejects_permission_failure_swap_pid_reuse_and_replay(self):
        requested={"x":-1408,"y":-900,"width":1360,"height":2480};nonce="place-replay-b"
        obs=self.new_observer()
        self.prime_late(obs,"place-replay-a",nonce)
        obs.placer=lambda *_args:(_ for _ in ()).throw(PermissionError("AX denied"))
        with self.assertRaises(MOD.ObserverError):obs.handle(request(obs,3,"place",bindingMode="late",titleNonce=nonce,requestedBounds=requested))
        self.assertIsNone(obs.provisional);self.assertEqual(obs.placement_count,1)
        with self.assertRaises(MOD.ObserverError):obs.handle(request(obs,4,"place",bindingMode="late",titleNonce=nonce,requestedBounds=requested))

        # A fresh observer proves a successful placement cannot be replayed or
        # repeated, and placement is no longer legal after claim.
        obs=self.new_observer();self.prime_late(obs,"place-replay-a2",nonce)
        def successful(pid,window_id,title,bounds):
            self.live[0].update(bounds);return {"method":"fake-active-aqua"}
        obs.placer=successful;obs.handle(request(obs,3,"place",bindingMode="late",titleNonce=nonce,requestedBounds=requested))
        with self.assertRaises(MOD.ObserverError):obs.handle(request(obs,4,"place",bindingMode="late",titleNonce=nonce,requestedBounds=requested))
        obs.handle(request(obs,5,"claim",titleNonce=nonce,requestedBounds=requested))
        with self.assertRaises(MOD.ObserverError):obs.handle(request(obs,6,"place",bindingMode="late",titleNonce=nonce,requestedBounds=requested))

    def test_late_placement_rejects_provisional_window_swap_and_pid_start_reuse(self):
        requested={"x":-1408,"y":-900,"width":1360,"height":2480};nonce="place-swap-b"
        replacement=dict(self.live[0],pid=88,windowId=19,name="Personal — "+nonce)
        identities={77:self.process(77),88:{"pid":88,"startTime":"start-b","uid":os.getuid(),"commandDigest":"digest-b",
                                             "bundleId":MOD.STP_BUNDLE_ID,"executable":MOD.STP_EXECUTABLE,"signature":dict(self.signature)}}
        visible=[];obs=self.new_observer(windows=visible,process=lambda pid:identities[pid]);obs.handle(request(obs,1,"baseline",titleNonce="place-swap-a",bindingMode="late"));visible.append(dict(self.live[0],name="Personal — place-swap-a"));obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="place-swap-a"));visible[0]["name"]="Personal — "+nonce
        obs.placer=lambda *_args:(visible.clear(),visible.append(replacement),{"method":"fake-active-aqua"})[-1]
        with self.assertRaises(MOD.ObserverError):obs.handle(request(obs,3,"place",bindingMode="late",titleNonce=nonce,requestedBounds=requested))
        self.assertIsNone(obs.provisional)

        visible.clear();calls=[0]
        def reused(pid):
            calls[0]+=1
            identity=dict(identities[77]);
            if calls[0]>3:identity["startTime"]="start-reused"
            return identity
        obs=self.new_observer(windows=visible,process=reused);obs.handle(request(obs,1,"baseline",titleNonce="place-reuse-a",bindingMode="late"));visible.append(dict(self.live[0],name="Personal — place-reuse-a"));obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="place-reuse-a"));visible[0]["name"]="Personal — "+nonce;obs.placer=lambda *_args:{"method":"fake-active-aqua"}
        with self.assertRaises(MOD.ObserverError):obs.handle(request(obs,3,"place",bindingMode="late",titleNonce=nonce,requestedBounds=requested))

    def test_late_placement_binds_exact_ax_window_number_before_mutation(self):
        requested={"x":-1408,"y":-900,"width":1360,"height":2480};nonce="ax-two-windows-b"
        obs=self.new_observer();self.prime_late(obs,"ax-two-windows-a",nonce)
        def ax_record(number):
            return {"owner":"Safari Technology Preview","bundleId":MOD.STP_BUNDLE_ID,
                    "pid":77,"title": "Personal — "+nonce,"axWindowNumber":number,
                    "bounds": {key:self.live[0][key] for key in ("x","y","width","height")}}
        # The native AX surface can expose another same-process, same-title
        # window; the exact AXWindowNumber still selects the provisional CG one.
        obs.ax_windows_fn=lambda pid,window_id,title:[ax_record(10),ax_record(window_id)]
        calls=[]
        def placer(pid,window_id,title,bounds):
            calls.append((pid,window_id,title,dict(bounds)));self.live[0].update(bounds)
            return {"method":"fake-active-aqua"}
        obs.placer=placer
        placement=obs.handle(request(obs,3,"place",bindingMode="late",titleNonce=nonce,requestedBounds=requested))
        self.assertTrue(placement["ok"]);self.assertEqual(len(calls),1);self.assertEqual(calls[0][1],9)
        ax_evidence=placement["placementEvidence"]["axBefore"]
        self.assertEqual(ax_evidence["candidateCount"],2)
        self.assertEqual(ax_evidence["axWindowNumber"],9)
        self.assertEqual(ax_evidence["selected"]["axWindowNumber"],9)

    def test_late_placement_rejects_ax_mapping_before_any_mutation(self):
        requested={"x":-1408,"y":-900,"width":1360,"height":2480};nonce="ax-reject-b";native="Personal — "+nonce
        cases=[]
        def record(number=9,**extra):
            value={"owner":"Safari Technology Preview","bundleId":MOD.STP_BUNDLE_ID,
                   "pid":77,"title":native,"axWindowNumber":number,
                   "bounds":dict(requested)}
            value.update(extra);return value
        cases.extend([
            ("missing",lambda *_args:[{k:v for k,v in record().items() if k not in {"axWindowNumber","bounds"}}]),
            ("none",lambda *_args:[record(None),record(None)]),
            ("bool",lambda *_args:[record(True)]),
            ("string",lambda *_args:[record("9")]),
            ("mismatch",lambda *_args:[record(10)]),
            ("duplicate",lambda *_args:[record(9),record(9)]),
            ("malformed-record",lambda *_args:[None]),
            ("wrong-pid",lambda *_args:[record(pid=88)]),
            ("wrong-title",lambda *_args:[record(title="other")]),
            ("wrong-geometry",lambda *_args:[record(bounds=dict(requested,width=1359))]),
            ("inaccessible",lambda *_args:(_ for _ in ()).throw(PermissionError("AX denied"))),
        ])
        for label,ax_windows in cases:
            with self.subTest(label=label):
                visible=[];obs=self.new_observer(windows=visible)
                obs.handle(request(obs,1,"baseline",titleNonce="ax-reject-a",bindingMode="late"))
                visible.append(dict(self.live[0],name="Personal — ax-reject-a"));obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="ax-reject-a"));visible[0]["name"]=native;before=dict(visible[0]);calls=[]
                obs.ax_windows_fn=ax_windows
                obs.placer=lambda *_args:(calls.append(True),{"method":"must-not-run"})[-1]
                with self.assertRaises(MOD.ObserverError):
                    obs.handle(request(obs,3,"place",bindingMode="late",titleNonce=nonce,requestedBounds=requested))
                self.assertEqual(calls,[],label);self.assertEqual(visible[0],before,label)
                self.assertIsNone(obs.provisional);self.assertEqual(obs.placement_count,1)

    def test_production_placement_command_is_fixed_and_non_shell_injectable(self):
        bounds={"x":-1408,"y":-900,"width":1360,"height":2480};nonce="nonce-without-shell"
        candidate={"pid":77,"windowId":9,"axWindowNumber":9,"title":"Personal — "+nonce,"bounds":dict(bounds)}
        payload={"ok":True,"method":"application-services-ax","helperUid":os.getuid(),"pid":77,
                 "windowId":9,"axWindowNumber":9,"titleNonce":nonce,"nativeTitle":"Personal — "+nonce,
                 "mappingMethod":"ax-window-number","cgBefore":dict(bounds),"candidateCount":1,"matchedCount":1,
                 "candidates":[candidate],"before":dict(bounds),"requestedBounds":dict(bounds),"after":dict(bounds)}
        with tempfile.TemporaryDirectory() as directory:
            helper=Path(directory)/"helper";helper.write_text("native helper");os.chmod(helper,0o700)
            original=MOD._run_helper_fd;calls=[]
            try:
                def fake_run(fd,digest,device,inode,argv):
                    calls.append((fd,digest,device,inode,argv))
                    return SimpleNamespace(returncode=0,stdout=json.dumps(payload,separators=(",",":"))+"\n",stderr="")
                MOD._run_helper_fd=fake_run
                result=MOD.place_stp_window(77,9,nonce,bounds,helper_path=helper,expected_native_title="Personal — "+nonce)
                self.assertTrue(result["verified"]);self.assertEqual(result["method"],"application-services-ax")
                self.assertEqual(calls[0][4], ["improvedtube-aqua-ax-helper","77","9",nonce,"Personal — "+nonce,"-1408","-900","1360","2480","split"])
                self.assertNotIn("shell",calls[0][4]);self.assertNotIn("osascript",calls[0][4])
            finally:MOD._run_helper_fd=original

    def test_helper_fd_pins_execution_against_path_swap(self):
        bounds={"x":-1408,"y":-900,"width":1360,"height":2480};nonce="fd-path-swap"
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);helper=root/"helper";replacement=root/"replacement";marker=root/"forged-ran"
            helper.write_bytes(b"original helper bytes");replacement.write_bytes(b"forged replacement bytes")
            os.chmod(helper,0o700);os.chmod(replacement,0o700)
            fd,digest,device,inode=MOD._open_helper_path(helper)
            try:
                _info,raw=MOD._read_validated_helper_fd(fd,digest,device,inode)
                self.assertEqual(raw,b"original helper bytes")
                os.chflags(helper,0)
                os.replace(replacement,helper)
                with self.assertRaises(MOD.ObserverError):
                    MOD._read_validated_helper_fd(fd,digest,device,inode)
                self.assertEqual(raw,b"original helper bytes")
                self.assertFalse(marker.exists())
            finally:
                os.close(fd)
                try:os.chflags(helper,0)
                except OSError:pass
            self.assertFalse(marker.exists())

    def test_helper_fd_substitution_reuse_and_hash_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);first=root/"first";second=root/"second"
            first.write_text("first-helper");second.write_text("second-helper")
            os.chmod(first,0o700);os.chmod(second,0o700)
            fd,digest,device,inode=MOD._open_helper_path(first)
            other_fd,other_digest,other_device,other_inode=MOD._open_helper_path(second)
            calls=[];original_run=MOD._run_helper_fd
            try:
                MOD._run_helper_fd=lambda *args,**kwargs:(calls.append((args,kwargs)),None)[1]
                with self.assertRaises(MOD.ObserverError):
                    MOD.place_stp_window(77,9,"fd-substitution",{"x":-1408,"y":-900,"width":1360,"height":2480},helper_fd=fd,helper_digest=other_digest,helper_device=other_device,helper_inode=other_inode)
                self.assertEqual(calls,[])
                os.close(fd);fd=None
                with self.assertRaises(MOD.ObserverError):
                    MOD.place_stp_window(77,9,"fd-closed",{"x":-1408,"y":-900,"width":1360,"height":2480},helper_fd=other_fd,helper_digest=digest,helper_device=device,helper_inode=inode)
                self.assertEqual(calls,[])
            finally:
                MOD._run_helper_fd=original_run
                if fd is not None:
                    os.close(fd)
                os.close(other_fd)
                os.chflags(first,0);os.chflags(second,0)

    def test_same_inherited_helper_fd_executes_only_the_pinned_object(self):
        bounds={"x":-1408,"y":-900,"width":1360,"height":2480};nonce="same-fd"
        payload=self._native_payload(nonce,bounds)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);helper=root/"helper";helper.write_text("native-helper-bytes");os.chmod(helper,0o700)
            fd,digest,device,inode=MOD._open_helper_path(helper);calls=[];original_run=MOD._run_helper_fd
            try:
                def fake_run(fd,digest,device,inode,argv):
                    calls.append((fd,digest,device,inode,argv))
                    return SimpleNamespace(returncode=0,stdout=json.dumps(payload)+chr(10),stderr="")
                MOD._run_helper_fd=fake_run
                result=MOD.place_stp_window(77,9,nonce,bounds,helper_fd=fd,helper_digest=digest,helper_device=device,helper_inode=inode)
            finally:
                MOD._run_helper_fd=original_run;os.close(fd);os.chflags(helper,0)
            self.assertTrue(result["verified"]);self.assertEqual(calls[0][4][0],"improvedtube-aqua-ax-helper")
            self.assertEqual(calls[0][0],fd)

    @unittest.skipUnless(sys.platform == "darwin","requires macOS dyld")
    def test_same_fd_memory_bundle_executes_after_path_swap_attempt(self):
        bounds={"x":-1408,"y":-900,"width":1360,"height":2480};nonce="same-fd-bundle"
        payload=self._native_payload(nonce,bounds)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);helper=root/"helper.bundle";replacement=root/"replacement.bundle"
            source=root/"helper.c"
            c_payload=json.dumps(json.dumps(payload,separators=(",",":"))+chr(10))
            source.write_text("#include <stdio.h>\n"
                              "int improvedtube_ax_helper_main(int argc,char **argv){"
                              "(void)argc;(void)argv;fputs("+c_payload+",stdout);fflush(stdout);return 0;}\n")
            forged=json.dumps(json.dumps({**payload,"method":"forged-helper"},separators=(",",":"))+chr(10))
            replacement_source=root/"replacement.c"
            replacement_source.write_text("#include <stdio.h>\n"
                                          "int improvedtube_ax_helper_main(int argc,char **argv){"
                                          "(void)argc;(void)argv;fputs("+forged+",stdout);fflush(stdout);return 0;}\n")
            compile_original=subprocess.run(["/usr/bin/clang","-bundle","-o",str(helper),str(source)],
                                            capture_output=True,text=True)
            compile_replacement=subprocess.run(["/usr/bin/clang","-bundle","-o",str(replacement),str(replacement_source)],
                                               capture_output=True,text=True)
            self.assertEqual(compile_original.returncode,0,compile_original.stderr)
            self.assertEqual(compile_replacement.returncode,0,compile_replacement.stderr)
            os.chmod(helper,0o700);os.chmod(replacement,0o700)
            fd,digest,device,inode=MOD._open_helper_path(helper)
            try:
                try:
                    os.replace(replacement,helper)
                except PermissionError:
                    pass
                result=MOD._run_helper_fd(
                    fd,digest,device,inode,
                    ["improvedtube-aqua-ax-helper","77","9",nonce,
                     "-1408","-900","1360","2480"])
                parsed=MOD.parse_ax_helper_result(result,77,9,nonce,bounds)
                self.assertTrue(parsed["verified"])
                self.assertEqual(parsed["method"],"application-services-ax")
            finally:
                os.close(fd)
                for path in (helper,replacement):
                    try:os.chflags(path,0)
                    except OSError:pass

    def test_title_matching_requires_exact_nonce_everywhere(self):
        nonce="ExactTitle"
        decoys=("prefix-"+nonce,nonce+"-suffix",nonce.upper(),nonce+" ",nonce+"\u2603")
        for title in decoys:
            with self.subTest(title=title):
                windows=[dict(self.live[0],name=title)];obs=self.new_observer(windows=windows)
                baseline=obs.handle(request(obs,1,"baseline",pid=77,titleNonce=nonce))
                self.assertFalse(baseline["ok"]);self.assertEqual(baseline["matchingCount"],0)
        duplicate=self.new_observer(windows=[dict(self.live[0],name=nonce),dict(self.live[0],windowId=10,name=nonce)])
        baseline=duplicate.handle(request(duplicate,1,"baseline",titleNonce=nonce,bindingMode="late"))
        self.assertFalse(baseline["ok"]);self.assertEqual(baseline["matchingCount"],2)
        bounds={"x":-1408,"y":-900,"width":1360,"height":2480}
        for title in decoys:
            with self.subTest(helper_title=title):
                payload=self._native_payload(nonce,bounds)
                payload["candidates"][0]["title"]=title
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(payload)+"\n",stderr=""),77,9,nonce,bounds)
    def _native_payload(self, nonce="native-helper", bounds=None, native_title=None, **changes):
        bounds=bounds or {"x":-1408,"y":-900,"width":1360,"height":2480}
        native_title=nonce if native_title is None else native_title
        candidate={"pid":77,"windowId":9,"axWindowNumber":9,"title":native_title,"bounds":dict(bounds)}
        payload={"ok":True,"method":"application-services-ax","helperUid":os.getuid(),"pid":77,
                 "windowId":9,"axWindowNumber":9,"titleNonce":nonce,"nativeTitle":native_title,
                 "mappingMethod":"ax-window-number","cgBefore":dict(bounds),"candidateCount":1,"matchedCount":1,
                 "candidates":[candidate],"before":dict(bounds),"requestedBounds":dict(bounds),"after":dict(bounds)}
        payload.update(changes);return payload

    def test_native_helper_response_parser_is_strict_and_exact(self):
        bounds={"x":-1408,"y":-900,"width":1360,"height":2480};nonce="native-parser"
        payload=self._native_payload(nonce,bounds)
        accepted=MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(payload)+"\n",stderr=""),77,9,nonce,bounds)
        self.assertTrue(accepted["verified"]);self.assertEqual(accepted["after"],bounds)
        malformed=[
            "[]\n",
            json.dumps(payload)+"\n\n",
            '{"ok":true,"ok":true}\n',
            "not-json\n",
            json.dumps({**payload,"helperUid":True})+"\n",
            json.dumps({**payload,"windowId":10})+"\n",
            json.dumps({**payload,"after":dict(bounds,width=1359)})+"\n",
        ]
        for raw in malformed:
            with self.subTest(raw=raw):
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=raw,stderr=""),77,9,nonce,bounds)
        with self.assertRaises(MOD.ObserverError):
            MOD.parse_ax_helper_result(SimpleNamespace(returncode=1,stdout=json.dumps(payload)+"\n",stderr=""),77,9,nonce,bounds)
        with self.assertRaises(MOD.ObserverError):
            MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(payload)+"\n",stderr="helper diagnostic"),77,9,nonce,bounds)

    def test_native_helper_injected_success_and_failure_do_not_mutate(self):
        bounds={"x":-1408,"y":-900,"width":1360,"height":2480};nonce_a="native-injected-a";nonce="native-injected-b";native_title="Personal — "+nonce
        with tempfile.TemporaryDirectory() as directory:
            helper=Path(directory)/"helper";helper.write_text("native helper");os.chmod(helper,0o700)
            self.live.clear()
            obs=MOD.AquaObserver(Path(directory)/"observer.sock","run-native","cap-native",502,
                windows_fn=lambda:self.live,process_fn=self.process,peer_fn=lambda _sock:502,ax_helper=helper)
            obs.peer_uid_actual=502;obs.handle(request(obs,1,"baseline",titleNonce=nonce_a,bindingMode="late"));self.live.append({"owner":"Safari Technology Preview","pid":77,"windowId":9,"alpha":1,"name":native_title.replace(nonce,nonce_a),"x":-1408,"y":-900,"width":1360,"height":2480});obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce=nonce_a));self.live[0]["name"]=native_title
            original=MOD._run_helper_fd;calls=[]
            try:
                def fake_run(fd,digest,device,inode,argv):
                    calls.append((fd,digest,device,inode,argv))
                    return SimpleNamespace(returncode=0,stdout=json.dumps(self._native_payload(nonce,bounds,native_title=native_title))+chr(10),stderr="")
                MOD._run_helper_fd=fake_run
                placement=obs.handle(request(obs,3,"place",bindingMode="late",titleNonce=nonce,requestedBounds=bounds))
                self.assertTrue(placement["ok"]);self.assertEqual(placement["placementEvidence"]["method"],"application-services-ax")
                self.assertEqual(calls[0][4][0],"improvedtube-aqua-ax-helper");self.assertIsInstance(calls[0][0],int)
            finally:MOD._run_helper_fd=original

            self.live.clear();obs=self.new_observer(windows=self.live)
            obs.ax_helper=helper;obs.ax_windows_fn=None;obs.placer=lambda pid,window_id,title,requested:MOD.place_stp_window(pid,window_id,title,requested,helper)
            obs.handle(request(obs,1,"baseline",titleNonce=nonce_a,bindingMode="late"));self.live.append({"owner":"Safari Technology Preview","pid":77,"windowId":9,"alpha":1,"name":native_title.replace(nonce,nonce_a),"x":-1408,"y":-900,"width":1360,"height":2480});obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce=nonce_a));self.live[0]["name"]=native_title
            before=dict(self.live[0]);original=MOD._run_helper_fd
            try:
                MOD._run_helper_fd=lambda *_args,**_kwargs:SimpleNamespace(returncode=1,stdout=json.dumps({"ok":False,"method":"application-services-ax","error":"AX denied"})+chr(10),stderr="")
                with self.assertRaises(MOD.ObserverError):obs.handle(request(obs,3,"place",bindingMode="late",titleNonce=nonce,requestedBounds=bounds))
            finally:MOD._run_helper_fd=original
            self.assertEqual(self.live[0],before);self.assertIsNone(obs.provisional);self.assertEqual(obs.placement_count,1)

    def test_native_helper_source_has_exact_scope_and_compiles(self):
        source=LAUNCH.AX_HELPER_SOURCE
        self.assertNotIn("title.contains(nonce)",source)
        observer_source=Path(MOD.__file__).read_text()
        self.assertNotIn("nonce in name",observer_source)
        self.assertNotIn("nonce not in candidate",observer_source)
        self.assertIn("NSCreateObjectFileImageFromMemory",observer_source)
        self.assertIn("_read_validated_helper_fd",observer_source)
        self.assertNotIn("subprocess.run([str(path)",observer_source)
        launcher_source=Path(LAUNCH.__file__).read_text()
        self.assertIn('"-emit-library"',launcher_source)
        self.assertIn('"-bundle"',launcher_source)
        self.assertIn('"helper.bundle"',launcher_source)
        for marker in ("NSRunningApplication(processIdentifier: pid_t(pid))","expectedBundle","expectedExecutable",
                       "AXUIElementCreateApplication(pid_t(pid))","kAXWindowsAttribute","kAXTitleAttribute",
                       "AXWindowNumber","kAXPositionAttribute","kAXSizeAttribute","AXUIElementSetAttributeValue",
                       "notSettableWithEvidence","resizeNotSettableWithEvidence","resize-only",
                       "move-only","cgevent-titlebar","inspect-empty-cg-title",
                       "webdriver-pid-single-window-empty-cg-title","CGEvent","CGWindowListCopyWindowInfo",
                       "CGPreflightPostEventAccess","withCursorRestored","defer","setPosition","setSize",
                       "AXUIElementCopyElementAtPosition","AXUIElementCreateSystemWide",
                       "kAXRoleAttribute","kAXSubroleAttribute","AXActionNames",
                       "kAXWindowAttribute","kAXTopLevelUIElementAttribute","kAXTopLevelUIElement",
                       "top-level-AXWindow","top-level-parent-chain","exactTargetAXWindow",
                       "targetContainsTopLevel","top-level-target-descendant","kAXChildrenAttribute",
                       "maxDepth","maxNodes","childrenStatus","childrenValue","childPid",
                       "systemWideNativeWindowBinding","system-wide-native-window-id",
                       "nativeWindowBinding","nativeWindowIDMethod","nativeWindowIDStatus",
                       "targetNativeWindowID","topLevelNativeWindowID","hitWindowStatus",
                       "topLevelWindowStatus",
                       "topLevelParentStatus","targetChildrenStatus","system-wide-native-window-id-v1",
                       "topLevelPid","relatedWindowStatus","relationParentPid",
                       "relationParentStatus","relationSeen","kAXEnabledAttribute","eligibleRecords",
                       "AXWindowAncestorProof","kAXParentAttribute","parent-chain",
                       "self-AXWindow","ancestorMethod",
                       "allowedSourceRolePairs","CFEqual","targetAxWindowNumber",
                       "AXHitTestReceiverUnavailable","receiverOutcomes","sourceMethod",
                       "descendant-frame","AX descendant depth boundary has unresolved children",
                       "leftMouseDownPosted","cleanupUpAttempted","cleanupUpSucceeded",
                       "errorCode","mappingEvidence","topmostProof","cursorBefore","cursorRestored",
                       "trustedAXExportingImagePath","trustedAXResolverMethod","trustedAXProvenanceMethod",
                       "trustedAXWindowIDResolver","dlopen","RTLD_FIRST","Dl_info","dladdr",
                       "dli_fname","dli_fbase","realpath","_AXUIElementGetWindow","exactNativeWindowID",
                       "nativeWindowIDProvenanceMethod","nativeWindowIDProvenanceImage",
                       "nativeWindowIDProvenanceExpectedImage","nativeWindowIDProvenanceVerified",
                       "nativeWindowIDProvenanceBasePresent","nativeWindowIDProvenanceHandlePresent",
                       "CGWindowID","standardMouseButtonValues","buttonState"):
            self.assertIn(marker,source)
        self.assertNotIn("trustedAXFrameworkPath",source)
        self.assertNotIn("dlsym(RTLD_DEFAULT",source)
        self.assertNotIn("_AXUIElementGetWindow@ApplicationServices",source)
        self.assertIn("Versions/A/Frameworks/HIServices.framework/Versions/A/HIServices",source)
        self.assertIn("let flags = RTLD_NOW | RTLD_LOCAL | RTLD_FIRST",source)
        self.assertIn("dladdr(symbol, &imageInfo)",source)
        self.assertIn("canonicalSystemImagePath",source)
        self.assertIn("_verify_direct_resize_target",observer_source)
        self.assertIn('helper_operation="resize-only"',observer_source)
        self.assertIn("run_cgevent_backend",observer_source)
        self.assertIn("_run_cgevent_move",observer_source)
        run_source=source[source.index("func run(_ arguments") :]
        self.assertLess(run_source.index('if effectiveOperation == "cgevent-titlebar"'),run_source.index("try setPosition(target.element"))
        set_call=run_source.index("try setGeometry(target.element, requested)")
        self.assertLess(run_source.index("AXUIElementCreateApplication(pid_t(pid))"),set_call)
        self.assertLess(run_source.index("title != nativeTitle"),set_call)
        self.assertLess(run_source.index("number == windowId"),set_call)
        with tempfile.TemporaryDirectory() as directory:
            swift=Path(directory)/"helper.swift";binary=Path(directory)/"helper.bundle";swift.write_text(source)
            result=subprocess.run(["/usr/bin/swiftc","-emit-library","-Xlinker","-bundle","-framework","ApplicationServices","-framework","AppKit","-framework","CoreGraphics","-O","-o",str(binary),str(swift)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stderr,"")

    def test_native_ax_receiver_and_exact_target_descendant_fallback_are_bounded(self):
        source=LAUNCH.AX_HELPER_SOURCE
        self.assertIn("func axElementAt(_ receiver: AXUIElement, _ point: CGPoint)",source)
        self.assertIn("AXUIElementCopyElementAtPosition(receiver, Float(point.x), Float(point.y), &element)",source)
        self.assertIn("AXUIElementCreateSystemWide()",source)
        self.assertIn("AXUIElementCreateApplication(pid_t(pid))",source)
        self.assertIn("let receivers: [AXUIElement]",source)
        self.assertIn("func optionalAXChildren(_ element: AXUIElement)",source)
        self.assertIn("kAXChildrenAttribute",source)
        self.assertIn("func collectAXDescendants",source)
        self.assertIn("func descendantFrameSource",source)
        self.assertIn("try collectAXDescendants(target, 0, &seen, &nodes)",source)
        self.assertIn("CFEqual(ancestor, target)",source)
        self.assertIn("pointInside(point, node.bounds)",source)
        self.assertIn("node.actions.isEmpty",source)
        self.assertIn("allowedSourceRolePairs.contains(pair)",source)
        cgevent=source[source.index("func cgeventTitlebarMove"):]
        self.assertIn("draggableAXSource(pid, windowId, target, before)",cgevent)
        self.assertNotIn("AXUIElementCopyElementAtPosition(systemWide",source)
        fallback=source.index("return try descendantFrameSource")
        no_source=source.index("if let first = accepted.first",source.index("func draggableAXSource"))
        self.assertGreater(fallback,no_source)
        draggable=source[source.index("func draggableAXSource"):source.index("func cursorPoint")]
        self.assertIn("catch let unavailable as AXHitTestReceiverUnavailable",draggable)
        self.assertNotIn("catch {\n                rejected.append",draggable)
        self.assertIn("receiverOutcomes.count == candidatePoints.count * receivers.count",draggable)
        self.assertIn("receiverOutcomes.allSatisfy",draggable)
        self.assertIn("return try descendantFrameSource(pid, target, before, candidatePoints, receiverOutcomes)",draggable)
        fallback_source=source[source.index("func descendantFrameSource"):source.index("func draggableAXSource")]
        # Both native selectors are first-safe in deterministic point order;
        # no later AXWindow preference may outrank an earlier inert source.
        self.assertNotIn("accepted.first(where",source)
        self.assertIn("candidatePoints.prefix(1).enumerated()",fallback_source)
        self.assertIn("if depth == 3",source[source.index("func collectAXDescendants"):source.index("func descendantFrameSource")])
        self.assertIn("AX descendant depth boundary has unresolved children",source)
        self.assertIn("copyAXString(ancestor, kAXRoleAttribute",fallback_source)
        self.assertIn("copyAXString(ancestor, kAXSubroleAttribute",fallback_source)
        self.assertIn('"ancestorRole": source.ancestorRole',fallback_source)
        self.assertIn('"ancestorSubrole": source.ancestorSubrole',fallback_source)
        self.assertNotIn('"ancestorRole": "AXWindow"',fallback_source)
        self.assertNotIn('"ancestorSubrole": "AXStandardWindow"',fallback_source)
        traversal=source[source.index("func collectAXDescendants"):source.index("func descendantFrameSource")]
        self.assertIn("if depth == 3",traversal)
        self.assertIn("guard children.isEmpty",traversal)
        self.assertLess(traversal.index("if depth == 3"),traversal.index("for child in children"))
        self.assertNotIn("guard depth <= 3 else { return }",traversal)
        self.assertIn("seen.count <= 128",traversal)

    def test_descendant_depth_boundary_rejects_deeper_interactive_child(self):
        """A node beyond the hard traversal boundary must not authorize a drag."""
        source=LAUNCH.AX_HELPER_SOURCE
        traversal=source[source.index("func collectAXDescendants"):source.index("func descendantFrameSource")]
        self.assertIn("if depth == 3",traversal)
        self.assertIn("guard children.isEmpty else",traversal)
        self.assertIn("AX descendant depth boundary has unresolved children",traversal)
        fallback=source[source.index("func descendantFrameSource"):source.index("func draggableAXSource")]
        self.assertIn("node.actions.isEmpty",fallback)
        self.assertIn("blocked = true",fallback)
        self.assertIn("ancestorRole",fallback)
        self.assertIn("ancestorSubrole",fallback)

    def test_ax_ancestry_and_source_methods_require_canonical_proof_modes(self):
        observer_source=Path(MOD.__file__).read_text()
        self.assertIn("allow_injected: bool = False",observer_source)
        self.assertIn("_parse_ax_hit_evidence(ax_hit,before,pid,window_id,allow_injected=True)",observer_source)
        self.assertIn("CGEvent AX injected proof is not an explicit test context",observer_source)
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — ancestry-canonical"
        payload=self._cgevent_success_payload("ancestry-canonical",title,before,requested)
        self_window=json.loads(json.dumps(payload));self_window["axHitTest"].update(
            role="AXWindow",subrole="AXStandardWindow",ancestorMethod="self-AXWindow")
        self_window["preMouseDownAXHitTest"] = json.loads(json.dumps(self_window["axHitTest"]))
        self.assertTrue(MOD.parse_ax_helper_result(SimpleNamespace(
            returncode=0,stdout=json.dumps(self_window)+"\n",stderr=""),
            77,9,"ancestry-canonical",requested,expected_native_title=title,
            expected_before_bounds=before)["verified"])
        parent_window=json.loads(json.dumps(payload));parent_window["axHitTest"].update(
            ancestorMethod="parent-chain")
        parent_window["preMouseDownAXHitTest"] = json.loads(json.dumps(parent_window["axHitTest"]))
        self.assertTrue(MOD.parse_ax_helper_result(SimpleNamespace(
            returncode=0,stdout=json.dumps(parent_window)+"\n",stderr=""),
            77,9,"ancestry-canonical",requested,expected_native_title=title,
            expected_before_bounds=before)["verified"])
        target_ax_object=object();target={"owner":"Safari Technology Preview","pid":77,
            "windowId":9,"title":title,"layer":0,"alpha":1,"bounds":dict(before)}
        for label,mutation in (
            ("native-injected-ancestor",lambda p:p["axHitTest"].update(ancestorMethod="injected")),
            ("native-injected-source",lambda p:p["axHitTest"].update(sourceMethod="injected",ancestorMethod="kAXWindowAttribute")),
            ("self-with-group",lambda p:p["axHitTest"].update(ancestorMethod="self-AXWindow")),
            ("parent-with-window",lambda p:p["axHitTest"].update(ancestorMethod="parent-chain",
                                                                     role="AXWindow",subrole="AXStandardWindow")),
            ("parent-with-cross-pair",lambda p:p["axHitTest"].update(ancestorMethod="parent-chain",
                                                                         role="AXGroup",subrole="AXStandardWindow")),
            ("injected-only-ancestor",lambda p:p["axHitTest"].update(ancestorMethod="injected")),
        ):
            with self.subTest(label=label):
                bad=json.loads(json.dumps(payload));mutation(bad);calls=[]
                def hit(_points,bad=bad["axHitTest"]):
                    result=dict(bad);result["_ancestorObject"]=target_ax_object;return result
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(bad)+"\n",stderr=""),
                        77,9,"ancestry-canonical",requested,expected_native_title=title,
                        expected_before_bounds=before)
                with self.assertRaises(MOD.ObserverError):
                    MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,native_title=title,
                        records=[target],cursor_before={"x":10,"y":20},can_post=lambda:True,
                        warp=lambda point:calls.append(("warp",point)),
                        post=lambda kind,point:calls.append((kind,point)),
                        restore=lambda point:calls.append(("restore",point)),
                        cursor_after=lambda:{"x":10,"y":20},observed_bounds=lambda:dict(requested),
                        ax_hit_test=hit,target_ax_object=target_ax_object)
                self.assertEqual(calls,[])
        # The injected seam is explicit and must use injected for both fields;
        # production parse_ax_helper_result has no opt-in to this context.
        injected=json.loads(json.dumps(payload));injected["axHitTest"].update(
            sourceMethod="injected",ancestorMethod="injected",
            receiverOutcomes=[{"candidateIndex":i,"receiver":"injected","result":"hit","status":0}
                              for i in range(3)])
        injected_result=dict(injected["axHitTest"]);injected_result["_ancestorObject"]=target_ax_object
        with self.assertRaises(MOD.ObserverError):
            MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,
                stdout=json.dumps(injected)+"\n",stderr=""),77,9,"ancestry-canonical",requested,
                expected_native_title=title,expected_before_bounds=before)
        calls=[]
        accepted=MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,native_title=title,
            records=[target],cursor_before={"x":10,"y":20},can_post=lambda:True,
            warp=lambda point:calls.append(("warp",point)),
            post=lambda kind,point:calls.append((kind,point)),
            restore=lambda point:calls.append(("restore",point)),
            cursor_after=lambda:{"x":10,"y":20},observed_bounds=lambda:dict(requested),
            ax_hit_test=lambda _points:injected_result,target_ax_object=target_ax_object)
        self.assertTrue(accepted["eventSequence"]);self.assertTrue(calls)

    def test_ax_window_ancestry_method_is_exact_and_fail_closed(self):
        source=LAUNCH.AX_HELPER_SOURCE
        ancestry=source[source.index("func exactTargetAXWindow"):source.index("func axElementAt")]
        self.assertIn("AXWindowAncestorProof",ancestry)
        self.assertIn("AXUIElementCopyAttributeValue(element, kAXWindowAttribute",ancestry)
        self.assertIn("CFGetTypeID(value) == AXUIElementGetTypeID()",ancestry)
        self.assertIn("kAXParentAttribute",ancestry)
        self.assertIn("for _ in 0..<8",ancestry)
        self.assertIn("guard status == .noValue else",ancestry)
        self.assertIn("kAXTopLevelUIElementAttribute",ancestry)
        self.assertIn('"kAXTopLevelUIElement", "top-level element"',ancestry)
        self.assertIn("CFEqual(topLevel, target)",ancestry)
        self.assertIn("Int(topLevelPid) == expectedPid",ancestry)
        self.assertIn('role == "AXWindow"',ancestry)
        self.assertIn('subrole == "AXStandardWindow"',ancestry)
        self.assertIn("if topLevelStatus == .attributeUnsupported",ancestry)
        self.assertIn("guard topLevelStatus == .noValue else",ancestry)
        self.assertLess(ancestry.index("if topLevelStatus == .success"),
                        ancestry.index("if topLevelStatus == .attributeUnsupported"))
        self.assertLess(ancestry.index("if topLevelStatus == .attributeUnsupported"),
                        ancestry.index("let role = try copyAXString",
                                      ancestry.index("func axWindowAncestor")))
        self.assertLess(ancestry.index("kAXWindowAttribute"),ancestry.index("kAXParentAttribute"))
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — ancestry-method"
        payload=self._cgevent_success_payload("ancestry-method",title,before,requested)
        accepted=MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,
            stdout=json.dumps(payload)+"\n",stderr=""),77,9,"ancestry-method",requested,
            expected_native_title=title,expected_before_bounds=before)
        self.assertEqual(accepted["axHitTest"]["ancestorMethod"],"kAXWindowAttribute")
        top_level=json.loads(json.dumps(payload))
        top_level["axHitTest"]["ancestorMethod"]="kAXTopLevelUIElement"
        top_level["preMouseDownAXHitTest"] = json.loads(json.dumps(top_level["axHitTest"]))
        top_level_accepted=MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,
            stdout=json.dumps(top_level)+"\n",stderr=""),77,9,"ancestry-method",requested,
            expected_native_title=title,expected_before_bounds=before)
        self.assertEqual(top_level_accepted["axHitTest"]["ancestorMethod"],
                         "kAXTopLevelUIElement")
        target_ax_object=object();target={"owner":"Safari Technology Preview","pid":77,
            "windowId":9,"title":title,"layer":0,"alpha":1,"bounds":dict(before)}
        for label,mutation in (
            ("missing",lambda p:p["axHitTest"].pop("ancestorMethod")),
            ("none",lambda p:p["axHitTest"].update(ancestorMethod=None)),
            ("unsupported",lambda p:p["axHitTest"].update(ancestorMethod="kAXUnknownAttribute")),
            ("noValue",lambda p:p["axHitTest"].update(ancestorMethod="noValue")),
            ("wrong-pid",lambda p:p["axHitTest"].update(ancestorPid=88)),
            ("wrong-role",lambda p:p["axHitTest"].update(ancestorRole="AXGroup")),
            ("wrong-subrole",lambda p:p["axHitTest"].update(ancestorSubrole="AXDialog")),
            ("malformed-role",lambda p:p["axHitTest"].update(ancestorRole=True)),
        ):
            with self.subTest(label=label):
                bad=json.loads(json.dumps(payload));mutation(bad);calls=[]
                def hit(_points,bad=bad["axHitTest"]):
                    result=dict(bad);result["_ancestorObject"]=target_ax_object;return result
                with self.assertRaises(MOD.ObserverError):
                    MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,native_title=title,
                        records=[target],cursor_before={"x":10,"y":20},can_post=lambda:True,
                        warp=lambda point:calls.append(("warp",point)),
                        post=lambda kind,point:calls.append((kind,point)),
                        restore=lambda point:calls.append(("restore",point)),
                        cursor_after=lambda:{"x":10,"y":20},observed_bounds=lambda:dict(requested),
                        ax_hit_test=hit,target_ax_object=target_ax_object)
                self.assertEqual(calls,[])

        # A top-level success is terminal evidence: malformed identity or
        # role fields cannot fall through to parent/descendant compatibility.
        for label,mutation in (
            ("top-level-wrong-pid",lambda p:p["axHitTest"].update(
                ancestorMethod="kAXTopLevelUIElement",ancestorPid=88)),
            ("top-level-wrong-role",lambda p:p["axHitTest"].update(
                ancestorMethod="kAXTopLevelUIElement",ancestorRole="AXGroup")),
            ("top-level-wrong-subrole",lambda p:p["axHitTest"].update(
                ancestorMethod="kAXTopLevelUIElement",ancestorSubrole="AXDialog")),
            ("top-level-malformed-method",lambda p:p["axHitTest"].update(
                ancestorMethod=None)),
        ):
            with self.subTest(label=label):
                bad=json.loads(json.dumps(top_level));mutation(bad);calls=[]
                def hit(_points,bad=bad["axHitTest"]):
                    result=dict(bad);result["_ancestorObject"]=target_ax_object;return result
                with self.assertRaises(MOD.ObserverError):
                    MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,
                        native_title=title,records=[target],cursor_before={"x":10,"y":20},
                        can_post=lambda:True,warp=lambda point:calls.append(("warp",point)),
                        post=lambda kind,point:calls.append((kind,point)),
                        restore=lambda point:calls.append(("restore",point)),
                        cursor_after=lambda:{"x":10,"y":20},
                        observed_bounds=lambda:dict(requested),ax_hit_test=hit,
                        target_ax_object=target_ax_object)
                self.assertEqual(calls,[])

    def test_ax_top_level_nested_relations_are_exact_and_terminal(self):
        """A non-equal top-level AX object may resolve only exact relations."""
        source=LAUNCH.AX_HELPER_SOURCE
        ancestry=source[source.index("func exactTargetAXWindow"):source.index("func axElementAt")]
        self.assertIn("if CFEqual(topLevel, target)",ancestry)
        self.assertIn("relatedWindowStatus",ancestry)
        self.assertIn('"top-level-AXWindow"',ancestry)
        self.assertIn('"top-level-parent-chain"',ancestry)
        self.assertIn("if relatedWindowStatus == .attributeUnsupported",ancestry)
        self.assertIn("guard relatedWindowStatus == .noValue else",ancestry)
        self.assertIn("CFEqual(relationParent, target)",ancestry)
        self.assertIn("Int(relationParentPid) == expectedPid",ancestry)
        self.assertIn("relationSeen.contains(where: { CFEqual($0, relationParent) })",ancestry)
        self.assertIn("AX top-level parent relation is cyclic",ancestry)
        self.assertIn("AX top-level parent relation exceeded bounded depth",ancestry)
        self.assertLess(ancestry.index("relatedWindowStatus"),
                        ancestry.index("relationParentStatus"))
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — ancestry-relations"
        payload=self._cgevent_success_payload("ancestry-relations",title,before,requested)
        for method in ("top-level-AXWindow","top-level-parent-chain"):
            with self.subTest(method=method):
                valid=json.loads(json.dumps(payload))
                valid["axHitTest"]["ancestorMethod"]=method
                valid["preMouseDownAXHitTest"] = json.loads(json.dumps(valid["axHitTest"]))
                parsed=MOD.parse_ax_helper_result(SimpleNamespace(
                    returncode=0,stdout=json.dumps(valid)+"\n",stderr=""),
                    77,9,"ancestry-relations",requested,
                    expected_native_title=title,expected_before_bounds=before)
                self.assertEqual(parsed["axHitTest"]["ancestorMethod"],method)
        target_ax_object=object();target={"owner":"Safari Technology Preview","pid":77,
            "windowId":9,"title":title,"layer":0,"alpha":1,"bounds":dict(before)}
        for label,mutation in (
            ("wrong-pid",lambda p:p["axHitTest"].update(
                ancestorMethod="top-level-AXWindow",ancestorPid=78)),
            ("wrong-role",lambda p:p["axHitTest"].update(
                ancestorMethod="top-level-parent-chain",ancestorRole="AXGroup")),
            ("wrong-subrole",lambda p:p["axHitTest"].update(
                ancestorMethod="top-level-parent-chain",ancestorSubrole="AXDialog")),
            ("relation-no-value",lambda p:p["axHitTest"].update(
                ancestorMethod="top-level-AXWindow-noValue")),
            ("relation-unsupported",lambda p:p["axHitTest"].update(
                ancestorMethod="top-level-AXWindow-attributeUnsupported")),
            ("relation-malformed",lambda p:p["axHitTest"].update(
                ancestorMethod=None)),
            ("target-unmatched",lambda p:p["axHitTest"].update(
                ancestorMethod="top-level-parent-chain",targetWindowMatched=False)),
        ):
            with self.subTest(label=label):
                bad=json.loads(json.dumps(payload));mutation(bad);calls=[]
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_ax_helper_result(SimpleNamespace(
                        returncode=0,stdout=json.dumps(bad)+"\n",stderr=""),
                        77,9,"ancestry-relations",requested,
                        expected_native_title=title,expected_before_bounds=before)
                def hit(_points,bad=bad["axHitTest"]):
                    result=dict(bad);result["_ancestorObject"]=target_ax_object;return result
                with self.assertRaises(MOD.ObserverError):
                    MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,
                        native_title=title,records=[target],cursor_before={"x":10,"y":20},
                        can_post=lambda:True,warp=lambda point:calls.append(("warp",point)),
                        post=lambda kind,point:calls.append((kind,point)),
                        restore=lambda point:calls.append(("restore",point)),
                        cursor_after=lambda:{"x":10,"y":20},
                        observed_bounds=lambda:dict(requested),ax_hit_test=hit,
                        target_ax_object=target_ax_object)
                self.assertEqual(calls,[])
        # A relation transcript must remain bound to the carried AX object;
        # an object substitution fails before any input callback.
        valid=json.loads(json.dumps(payload))
        valid["axHitTest"]["ancestorMethod"]="top-level-AXWindow"
        calls=[]
        def wrong_object(_points):
            result=dict(valid["axHitTest"]);result["_ancestorObject"]=object();return result
        with self.assertRaises(MOD.ObserverError):
            MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,
                native_title=title,records=[target],cursor_before={"x":10,"y":20},
                can_post=lambda:True,warp=lambda point:calls.append(("warp",point)),
                post=lambda kind,point:calls.append((kind,point)),
                restore=lambda point:calls.append(("restore",point)),
                cursor_after=lambda:{"x":10,"y":20},
                observed_bounds=lambda:dict(requested),ax_hit_test=wrong_object,
                target_ax_object=target_ax_object)
        self.assertEqual(calls,[])

    def test_ax_top_level_target_children_membership_is_bounded_and_exact(self):
        """The final compatibility proof is target-rooted AX identity membership."""
        source=LAUNCH.AX_HELPER_SOURCE
        ancestry=source[source.index("func exactTargetAXWindow"):source.index("func axElementAt")]
        self.assertIn("func targetContainsTopLevel",ancestry)
        self.assertIn("kAXChildrenAttribute",ancestry)
        self.assertIn("let maxDepth = 8",ancestry)
        self.assertIn("let maxNodes = 128",ancestry)
        self.assertIn("AX target children proof children are unavailable",ancestry)
        self.assertIn("AX target children proof graph is cyclic or duplicated",ancestry)
        self.assertIn("AX target children proof exceeded bounded depth",ancestry)
        self.assertIn("AX target children proof exceeded node cap",ancestry)
        self.assertIn("CFEqual(child, topLevel)",ancestry)
        self.assertIn("Int(childPid) == expectedPid",ancestry)
        self.assertIn('"top-level-target-descendant"',ancestry)
        self.assertLess(ancestry.index("relatedWindowStatus"),
                        ancestry.index("var relationUnavailable"))
        self.assertLess(ancestry.index("var relationUnavailable"),
                        ancestry.index("return try targetContainsTopLevel"))
        # The parser accepts the one canonical native method, but cannot be
        # tricked into accepting a self-asserted cycle/depth/cap/path label.
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — ancestry-children"
        payload=self._cgevent_success_payload("ancestry-children",title,before,requested)
        payload["axHitTest"]["ancestorMethod"]="top-level-target-descendant"
        payload["preMouseDownAXHitTest"] = json.loads(json.dumps(payload["axHitTest"]))
        parsed=MOD.parse_ax_helper_result(SimpleNamespace(
            returncode=0,stdout=json.dumps(payload)+"\n",stderr=""),
            77,9,"ancestry-children",requested,
            expected_native_title=title,expected_before_bounds=before)
        self.assertEqual(parsed["axHitTest"]["ancestorMethod"],
                         "top-level-target-descendant")
        target_ax_object=object();target={"owner":"Safari Technology Preview","pid":77,
            "windowId":9,"title":title,"layer":0,"alpha":1,"bounds":dict(before)}
        for label,mutation in (
            ("missing",lambda p:p.pop("ancestorMethod")),
            ("cycle",lambda p:p.update(ancestorMethod="top-level-target-descendant-cycle")),
            ("depth",lambda p:p.update(ancestorMethod="top-level-target-descendant-depth")),
            ("cap",lambda p:p.update(ancestorMethod="top-level-target-descendant-cap")),
            ("wrong-pid",lambda p:p.update(ancestorPid=78)),
            ("wrong-target",lambda p:p.update(targetWindowMatched=False)),
            ("wrong-role",lambda p:p.update(ancestorRole="AXGroup")),
            ("wrong-subrole",lambda p:p.update(ancestorSubrole="AXDialog")),
        ):
            with self.subTest(label=label):
                bad=json.loads(json.dumps(payload));mutation(bad["axHitTest"]);calls=[]
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_ax_helper_result(SimpleNamespace(
                        returncode=0,stdout=json.dumps(bad)+"\n",stderr=""),
                        77,9,"ancestry-children",requested,
                        expected_native_title=title,expected_before_bounds=before)
                def hit(_points,bad=bad["axHitTest"]):
                    result=dict(bad);result["_ancestorObject"]=target_ax_object;return result
                with self.assertRaises(MOD.ObserverError):
                    MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,
                        native_title=title,records=[target],cursor_before={"x":10,"y":20},
                        can_post=lambda:True,warp=lambda point:calls.append(("warp",point)),
                        post=lambda kind,point:calls.append((kind,point)),
                        restore=lambda point:calls.append(("restore",point)),
                        cursor_after=lambda:{"x":10,"y":20},
                        observed_bounds=lambda:dict(requested),ax_hit_test=hit,
                        target_ax_object=target_ax_object)
                self.assertEqual(calls,[])

    def test_coordinate_fallback_requires_complete_system_wide_unavailability_and_topmost(self):
        """Only production candidate zero may use the final coordinate attestation."""
        source=LAUNCH.AX_HELPER_SOURCE
        fallback_source=source[source.index("func systemWideNativeWindowBinding"):source.index("func axWindowAncestor")]
        for marker in ("kAXWindowAttribute", "kAXTopLevelUIElementAttribute", "kAXParentAttribute",
                       "kAXChildrenAttribute", "AXUIElementGetPid", "CFEqual(topLevel, target)",
                       "AXWindow", "AXStandardWindow", "unavailableStatus", "targetChildrenStatus"):
            self.assertIn(marker,fallback_source)
        self.assertNotIn("AXUIElementCreateApplication",fallback_source)
        self.assertNotIn('"injected"',fallback_source)
        self.assertLess(source.index("try axWindowAncestor(element, pid, target)"),
                        source.index("try systemWideNativeWindowBinding(element, pid, windowId, target)"))
        self.assertIn('"system-wide-native-window-id-v1"',fallback_source)
        self.assertIn('"nativeWindowBinding": fallback',source)
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        nonce="coordinate-fallback";title="Personal — "+nonce
        payload=self._cgevent_success_payload(nonce,title,before,requested)
        hit=payload["axHitTest"]
        hit["ancestorMethod"]="system-wide-native-window-id"
        hit["receiverOutcomes"]=[{"candidateIndex":0,"receiver":"system-wide",
                                  "result":"hit","status":0}]
        hit["nativeWindowBinding"]={
            "version":"system-wide-native-window-id-v1","candidateIndex":0,
            "receiver":"system-wide","hitPid":77,"hitRole":"AXGroup",
            "hitSubrole":"AXTitleBar","hitActions":[],"hitEnabled":True,
            "hitMatchedTarget":False,
            "nativeWindowIDMethod":"_AXUIElementGetWindow@HIServices",
            "nativeWindowIDStatus":0,"nativeWindowID":9,
            "targetNativeWindowIDStatus":0,"targetNativeWindowID":9,
            "topLevelNativeWindowIDStatus":0,"topLevelNativeWindowID":9,
            "nativeWindowIDProvenanceMethod":"dladdr-exact-sealed-system-image",
            "nativeWindowIDProvenanceImage":"/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/HIServices.framework/Versions/A/HIServices",
            "nativeWindowIDProvenanceExpectedImage":"/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/HIServices.framework/Versions/A/HIServices",
            "nativeWindowIDProvenanceVerified":True,
            "nativeWindowIDProvenanceBasePresent":True,
            "nativeWindowIDProvenanceHandlePresent":True,
            "hitWindowStatus":-25205,"topLevelStatus":0,"topLevelType":"AXUIElement",
            "topLevelPid":77,"topLevelRole":"AXGroup","topLevelSubrole":"AXTitleBar",
            "topLevelActions":[],"topLevelEnabled":True,"topLevelMatchedTarget":False,
            "topLevelWindowStatus":-25212,"topLevelParentStatus":-25205,
            "targetChildrenStatus":-25212,"targetType":"AXUIElement",
            "targetPid":77,"targetRole":"AXWindow","targetSubrole":"AXStandardWindow",
            "targetMatched":True}
        payload["preMouseDownAXHitTest"] = json.loads(json.dumps(payload["axHitTest"]))
        accepted=MOD.parse_ax_helper_result(SimpleNamespace(
            returncode=0,stdout=json.dumps(payload)+"\n",stderr=""),
            77,9,nonce,requested,expected_native_title=title,
            expected_before_bounds=before)
        self.assertTrue(accepted["verified"])
        self.assertEqual(accepted["axHitTest"]["ancestorMethod"],
                         "system-wide-native-window-id")
        self.assertEqual(accepted["axHitTest"]["receiverOutcomes"],
                         [{"candidateIndex":0,"receiver":"system-wide",
                           "result":"hit","status":0}])
        self.assertEqual(accepted["axHitTest"]["nativeWindowBinding"]["targetChildrenStatus"],-25212)

        target_ax_object=object()
        target={"owner":"Safari Technology Preview","pid":77,"windowId":9,
                "title":title,"layer":0,"alpha":1,"bounds":dict(before)}
        def assert_rejected(label,mutate):
            with self.subTest(label=label):
                bad=json.loads(json.dumps(payload));mutate(bad)
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_ax_helper_result(SimpleNamespace(
                        returncode=0,stdout=json.dumps(bad)+"\n",stderr=""),
                        77,9,nonce,requested,expected_native_title=title,
                        expected_before_bounds=before)
                calls=[]
                def hit(_points,bad=bad["axHitTest"]):
                    result=dict(bad);result["_ancestorObject"]=target_ax_object;return result
                with self.assertRaises(MOD.ObserverError):
                    MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,
                        native_title=title,records=[target],cursor_before={"x":10,"y":20},
                        can_post=lambda:True,warp=lambda point:calls.append(("warp",point)),
                        post=lambda kind,point:calls.append((kind,point)),
                        restore=lambda point:calls.append(("restore",point)),
                        cursor_after=lambda:{"x":10,"y":20},
                        observed_bounds=lambda:dict(requested),ax_hit_test=hit,
                        target_ax_object=target_ax_object)
                self.assertEqual(calls,[])

        assert_rejected("app receiver",lambda p:(p["axHitTest"].update(sourceMethod="application"),
            p["axHitTest"].update(receiverOutcomes=[
                {"candidateIndex":0,"receiver":"system-wide","result":"unavailable","status":-25200},
                {"candidateIndex":0,"receiver":"application","result":"hit","status":0}])) )
        assert_rejected("injected",lambda p:p["axHitTest"].update(sourceMethod="injected"))
        assert_rejected("nonzero candidate",lambda p:(p["axHitTest"].update(candidateIndex=1,
            chosenPoint=dict(p["axHitTest"]["candidatePoints"][1])),
            p["axHitTest"]["nativeWindowBinding"].update(candidateIndex=1)))
        assert_rejected("wrong hit pid",lambda p:p["axHitTest"].update(pid=88))
        assert_rejected("wrong top-level pid",lambda p:p["axHitTest"]["nativeWindowBinding"].update(topLevelPid=88))
        assert_rejected("boolean top-level status",lambda p:p["axHitTest"]["nativeWindowBinding"].update(topLevelStatus=False))
        assert_rejected("boolean candidate",lambda p:p["axHitTest"]["nativeWindowBinding"].update(candidateIndex=False))
        assert_rejected("partial hit relation",lambda p:p["axHitTest"]["nativeWindowBinding"].update(hitWindowStatus=-25200))
        assert_rejected("partial top-level window",lambda p:p["axHitTest"]["nativeWindowBinding"].update(topLevelWindowStatus=0))
        assert_rejected("missing target children",lambda p:p["axHitTest"]["nativeWindowBinding"].pop("targetChildrenStatus"))
        assert_rejected("wrong target role",lambda p:p["axHitTest"]["nativeWindowBinding"].update(targetRole="AXGroup"))
        assert_rejected("target unmatched",lambda p:p["axHitTest"].update(targetWindowMatched=False))
        assert_rejected("wrong native hit window ID",lambda p:p["axHitTest"]["nativeWindowBinding"].update(nativeWindowID=10))
        assert_rejected("wrong native target window ID",lambda p:p["axHitTest"]["nativeWindowBinding"].update(targetNativeWindowID=10))
        assert_rejected("wrong native top-level window ID",lambda p:p["axHitTest"]["nativeWindowBinding"].update(topLevelNativeWindowID=10))
        assert_rejected("SPI unavailable",lambda p:p["axHitTest"]["nativeWindowBinding"].update(nativeWindowIDStatus=-25205))
        assert_rejected("SPI interposed",lambda p:p["axHitTest"]["nativeWindowBinding"].update(nativeWindowIDMethod="_AXUIElementGetWindow@RTLD_DEFAULT"))
        assert_rejected("wrong resolver image",lambda p:p["axHitTest"]["nativeWindowBinding"].update(
            nativeWindowIDProvenanceImage="/tmp/HIServices"))
        assert_rejected("dladdr null image",lambda p:p["axHitTest"]["nativeWindowBinding"].pop(
            "nativeWindowIDProvenanceImage"))
        assert_rejected("resolver path alias",lambda p:p["axHitTest"]["nativeWindowBinding"].update(
            nativeWindowIDProvenanceImage="/System/Library/Frameworks/ApplicationServices.framework/Versions/Current/Frameworks/HIServices.framework/Versions/A/HIServices"))
        assert_rejected("wrong expected resolver image",lambda p:p["axHitTest"]["nativeWindowBinding"].update(
            nativeWindowIDProvenanceExpectedImage="/tmp/HIServices"))
        assert_rejected("resolver provenance method",lambda p:p["axHitTest"]["nativeWindowBinding"].update(
            nativeWindowIDProvenanceMethod="dladdr-unverified"))
        assert_rejected("resolver image unverified",lambda p:p["axHitTest"]["nativeWindowBinding"].update(
            nativeWindowIDProvenanceVerified=False))
        assert_rejected("resolver base missing",lambda p:p["axHitTest"]["nativeWindowBinding"].update(
            nativeWindowIDProvenanceBasePresent=False))
        assert_rejected("resolver handle missing",lambda p:p["axHitTest"]["nativeWindowBinding"].update(
            nativeWindowIDProvenanceHandlePresent=False))
        assert_rejected("SPI status malformed",lambda p:p["axHitTest"]["nativeWindowBinding"].update(targetNativeWindowIDStatus=True))
        assert_rejected("post native hit drift",lambda p:p["preMouseDownAXHitTest"]["nativeWindowBinding"].update(nativeWindowID=10))
        assert_rejected("occluder",lambda p:p["topmostProof"].update(overlayAbove=1))
        assert_rejected("record misses source",lambda p:p["topmostProof"]["eligibleRecords"][0].update(
            bounds={"x":0,"y":0,"width":10,"height":10}))
        assert_rejected("source outside target",lambda p:p["topmostProof"].update(sourcePoint={"x":0,"y":0}))
        assert_rejected("target mapping",lambda p:p["axHitTest"].update(targetAxWindowNumber=10))

        # Coordinate proof cannot self-assert a same-PID standard window or
        # hide a window-role top-level object.  The native helper supplies the
        # exact object relation bit and actual top-level role pair.
        assert_rejected("wrong hit AXWindow object",lambda p:(
            p["axHitTest"].update(role="AXWindow",subrole="AXStandardWindow"),
            p["axHitTest"]["nativeWindowBinding"].update(
                hitRole="AXWindow",hitSubrole="AXStandardWindow",hitMatchedTarget=False)))
        assert_rejected("wrong top-level AXWindow object",lambda p:(
            p["axHitTest"]["nativeWindowBinding"].update(
                topLevelRole="AXWindow",topLevelSubrole="AXStandardWindow")))
        assert_rejected("top-level role missing",lambda p:p["axHitTest"]["nativeWindowBinding"].pop("topLevelRole"))

    def test_ax_receiver_outcomes_gate_descendant_fallback(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — receiver-outcomes"
        payload=self._cgevent_success_payload("receiver-outcomes",title,before,requested)
        parsed=MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(payload)+"\n",stderr=""),
                                          77,9,"receiver-outcomes",requested,
                                          expected_native_title=title,expected_before_bounds=before)
        self.assertTrue(parsed["verified"])
        fallback=json.loads(json.dumps(payload));hit=fallback["axHitTest"]
        hit["sourceMethod"]="descendant-frame"
        hit["receiverOutcomes"]=[{"candidateIndex":index,"receiver":receiver,
                                  "result":"unavailable","status":-25200}
                                 for index in range(3) for receiver in ("system-wide","application")]
        fallback["preMouseDownAXHitTest"] = json.loads(json.dumps(fallback["axHitTest"]))
        parsed=MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(fallback)+"\n",stderr=""),
                                          77,9,"receiver-outcomes",requested,
                                          expected_native_title=title,expected_before_bounds=before)
        self.assertTrue(parsed["verified"])
        for label,mutate in (
            ("duplicate",lambda p:p["axHitTest"]["receiverOutcomes"].append(dict(p["axHitTest"]["receiverOutcomes"][0]))),
            ("successful-fallback",lambda p:p["axHitTest"]["receiverOutcomes"].__setitem__(0,{"candidateIndex":0,"receiver":"system-wide","result":"hit","status":0})),
            ("missing-receiver",lambda p:p["axHitTest"]["receiverOutcomes"].pop()),
            ("bad-status",lambda p:p["axHitTest"]["receiverOutcomes"][0].update(status=0)),
        ):
            with self.subTest(label=label):
                bad=json.loads(json.dumps(fallback));mutate(bad)
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(bad)+"\n",stderr=""),
                                                77,9,"receiver-outcomes",requested,
                                                expected_native_title=title,expected_before_bounds=before)

    def test_ax_receiver_success_must_bind_to_declared_chosen_candidate(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — receiver-binding"
        payload=self._cgevent_success_payload("receiver-binding",title,before,requested)
        candidates=payload["axHitTest"]["candidatePoints"]
        target_ax_object=object()
        valid_application=json.loads(json.dumps(payload))
        valid_application["axHitTest"]["sourceMethod"]="application"
        valid_application["axHitTest"]["receiverOutcomes"]=[
            {"candidateIndex":0,"receiver":"system-wide","result":"unavailable","status":-25200},
            {"candidateIndex":0,"receiver":"application","result":"hit","status":0},
            {"candidateIndex":1,"receiver":"system-wide","result":"hit","status":0},
            {"candidateIndex":2,"receiver":"system-wide","result":"hit","status":0},
        ]
        valid_application["preMouseDownAXHitTest"] = json.loads(json.dumps(valid_application["axHitTest"]))
        accepted=MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,
            stdout=json.dumps(valid_application)+"\n",stderr=""),
            77,9,"receiver-binding",requested,expected_native_title=title,
            expected_before_bounds=before)
        self.assertTrue(accepted["verified"])
        # Candidate 0 is declared/chosen, but the application hit is only at
        # candidate 1 and the system-wide hit only at candidate 2.  The old
        # parser accepted this contradictory transcript by searching globally.
        bypass=json.loads(json.dumps(payload))
        hit=bypass["axHitTest"]
        hit["sourceMethod"]="application"
        hit["candidateIndex"]=0
        hit["chosenPoint"]=dict(candidates[0])
        hit["receiverOutcomes"]=[
            {"candidateIndex":0,"receiver":"system-wide","result":"unavailable","status":-25200},
            {"candidateIndex":0,"receiver":"application","result":"unavailable","status":-25200},
            {"candidateIndex":1,"receiver":"system-wide","result":"unavailable","status":-25200},
            {"candidateIndex":1,"receiver":"application","result":"hit","status":0},
            {"candidateIndex":2,"receiver":"system-wide","result":"hit","status":0},
        ]
        with self.assertRaises(MOD.ObserverError):
            MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(bypass)+"\n",stderr=""),
                77,9,"receiver-binding",requested,expected_native_title=title,
                expected_before_bounds=before)
        calls=[]
        target={"owner":"Safari Technology Preview","pid":77,"windowId":9,"title":title,
                "layer":0,"alpha":1,"bounds":dict(before)}
        def mismatched_hit(points):
            result=dict(hit)
            result["candidatePoints"]=points
            result["chosenPoint"]=dict(points[0])
            result["_ancestorObject"]=target_ax_object
            return result
        with self.assertRaises(MOD.ObserverError):
            MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,native_title=title,
                records=[target],cursor_before={"x":10,"y":20},can_post=lambda:True,
                warp=lambda point:calls.append(("warp",point)),
                post=lambda kind,point:calls.append((kind,point)),
                restore=lambda point:calls.append(("restore",point)),
                cursor_after=lambda:{"x":10,"y":20},observed_bounds=lambda:dict(requested),
                ax_hit_test=mismatched_hit,target_ax_object=target_ax_object)
        self.assertEqual(calls,[])

    def test_receiver_parser_requires_chosen_index_binding_in_source(self):
        source=Path(MOD.__file__).read_text()
        self.assertIn("source_method: str, chosen_index: int",source)
        self.assertIn("chosen_group=grouped[chosen_index]",source)
        self.assertIn("system-wide receiver does not match chosen point",source)
        self.assertIn("application receiver does not match chosen point",source)

    def test_ax_receiver_transcript_requires_first_canonical_candidate(self):
        """Only the first selectable point may be bound to native AX evidence."""
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — canonical-first"
        base=self._cgevent_success_payload("canonical-first",title,before,requested)
        points=base["axHitTest"]["candidatePoints"]

        def transcript(source_method, chosen_index, *, earlier_hit=None,
                       malformed_later=False):
            hit=json.loads(json.dumps(base["axHitTest"]))
            hit["sourceMethod"]=source_method
            hit["candidateIndex"]=chosen_index
            hit["chosenPoint"]=dict(points[chosen_index])
            outcomes=[]
            for index in range(len(points)):
                if malformed_later and index == len(points)-1:
                    outcomes.append({"candidateIndex":index,"receiver":"application",
                                     "result":"hit","status":0})
                    continue
                if earlier_hit == index:
                    if source_method == "application":
                        outcomes.extend((
                            {"candidateIndex":index,"receiver":"system-wide",
                             "result":"unavailable","status":-25200},
                            {"candidateIndex":index,"receiver":"application",
                             "result":"hit","status":0},
                        ))
                    else:
                        outcomes.append({"candidateIndex":index,"receiver":"system-wide",
                                         "result":"hit","status":0})
                elif index == chosen_index:
                    if source_method == "application":
                        outcomes.extend((
                            {"candidateIndex":index,"receiver":"system-wide",
                             "result":"unavailable","status":-25200},
                            {"candidateIndex":index,"receiver":"application",
                             "result":"hit","status":0},
                        ))
                    else:
                        outcomes.append({"candidateIndex":index,"receiver":"system-wide",
                                         "result":"hit","status":0})
                else:
                    outcomes.extend((
                        {"candidateIndex":index,"receiver":"system-wide",
                         "result":"unavailable","status":-25200},
                        {"candidateIndex":index,"receiver":"application",
                         "result":"unavailable","status":-25200},
                    ))
            hit["receiverOutcomes"]=outcomes
            return hit

        # A later point is valid only after every preceding receiver has
        # returned a typed API-unavailable result.
        for source_method in ("system-wide","application"):
            with self.subTest(source_method=source_method):
                valid=transcript(source_method,2)
                parsed=MOD._parse_ax_hit_evidence(valid,before,77,9)
                self.assertEqual(parsed["candidateIndex"],2)

                for earlier_hit in (0,1):
                    with self.subTest(earlier_hit=earlier_hit):
                        bad=transcript(source_method,2,earlier_hit=earlier_hit)
                        with self.assertRaises(MOD.ObserverError):
                            MOD._parse_ax_hit_evidence(bad,before,77,9)

        # Receiver order/coverage after the chosen point is also canonical;
        # an application-only later result is not an untried native group.
        bad_later=transcript("system-wide",1,malformed_later=True)
        with self.assertRaises(MOD.ObserverError):
            MOD._parse_ax_hit_evidence(bad_later,before,77,9)

        # The same impossible later selection must fail through the complete
        # production result parser before any placement callback is reached.
        impossible=json.loads(json.dumps(base))
        impossible["axHitTest"]=transcript("system-wide",2,earlier_hit=0)
        with self.assertRaises(MOD.ObserverError):
            MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,
                stdout=json.dumps(impossible)+"\n",stderr=""),77,9,
                "canonical-first",requested,expected_native_title=title,
                expected_before_bounds=before)

    def test_native_selection_is_first_safe_without_later_role_preference(self):
        """A later AXWindow cannot silently outrank an earlier safe source."""
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — first-safe"
        base=self._cgevent_success_payload("first-safe",title,before,requested)
        # Both role permutations are valid when the chosen candidate is the
        # first successful receiver point.  The native helper now returns this
        # first point, so a later AXWindow/Group cannot be hidden behind an
        # implicit preference.
        for pair in (("AXGroup","AXTitleBar"),("AXWindow","AXStandardWindow")):
            with self.subTest(pair=pair):
                payload=json.loads(json.dumps(base))
                hit=payload["axHitTest"]
                hit.update({"candidateIndex":0,"chosenPoint":dict(hit["candidatePoints"][0]),
                            "role":pair[0],"subrole":pair[1],
                            "receiverOutcomes":[{"candidateIndex":index,
                                                  "receiver":"system-wide",
                                                  "result":"hit","status":0}
                                                 for index in range(3)]})
                payload["preMouseDownAXHitTest"] = json.loads(json.dumps(hit))
                parsed=MOD._parse_ax_hit_evidence(hit,before,77,9)
                self.assertEqual(parsed["candidateIndex"],0)
                self.assertTrue(MOD.parse_ax_helper_result(SimpleNamespace(
                    returncode=0,stdout=json.dumps(payload)+"\n",stderr=""),77,9,
                    "first-safe",requested,expected_native_title=title,
                    expected_before_bounds=before)["verified"])

    def test_descendant_selection_has_no_unverifiable_nonzero_choice(self):
        """Without per-candidate descendant evidence, only native point zero is bound."""
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — descendant-first"
        base=self._cgevent_success_payload("descendant-first",title,before,requested)
        target_ax_object=object()
        target={"owner":"Safari Technology Preview","pid":77,"windowId":9,
                "title":title,"layer":0,"alpha":1,"bounds":dict(before)}
        for index in (1,2):
            with self.subTest(candidate=index):
                payload=json.loads(json.dumps(base))
                hit=payload["axHitTest"]
                hit.update({"sourceMethod":"descendant-frame","candidateIndex":index,
                            "chosenPoint":dict(hit["candidatePoints"][index]),
                            "receiverOutcomes":[{"candidateIndex":candidate,
                                                  "receiver":receiver,
                                                  "result":"unavailable","status":-25200}
                                                 for candidate in range(3)
                                                 for receiver in ("system-wide","application")]})
                with self.assertRaises(MOD.ObserverError):
                    MOD._parse_ax_hit_evidence(hit,before,77,9)
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_ax_helper_result(SimpleNamespace(
                        returncode=0,stdout=json.dumps(payload)+"\n",stderr=""),77,9,
                        "descendant-first",requested,expected_native_title=title,
                        expected_before_bounds=before)
                calls=[];bad=dict(hit);bad["_ancestorObject"]=target_ax_object
                with self.assertRaises(MOD.ObserverError):
                    MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,
                        native_title=title,records=[target],cursor_before={"x":10,"y":20},
                        can_post=lambda:True,warp=lambda p:calls.append(("warp",p)),
                        post=lambda k,p:calls.append((k,p)),restore=lambda p:calls.append(("restore",p)),
                        cursor_after=lambda:{"x":10,"y":20},observed_bounds=lambda:dict(requested),
                        ax_hit_test=lambda _points,bad=bad:bad,target_ax_object=target_ax_object)
                self.assertEqual(calls,[])

    def test_descendant_frame_cannot_claim_self_window_ancestry(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — descendant-self"
        payload=self._cgevent_success_payload("descendant-self",title,before,requested)
        hit=payload["axHitTest"]
        hit.update({"sourceMethod":"descendant-frame","role":"AXWindow",
                    "subrole":"AXStandardWindow","ancestorMethod":"self-AXWindow",
                    "receiverOutcomes":[{"candidateIndex":index,"receiver":receiver,
                                         "result":"unavailable","status":-25200}
                                        for index in range(3)
                                        for receiver in ("system-wide","application")]})
        with self.assertRaises(MOD.ObserverError):
            MOD._parse_ax_hit_evidence(hit,before,77,9)
        with self.assertRaises(MOD.ObserverError):
            MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,
                stdout=json.dumps(payload)+"\n",stderr=""),77,9,
                "descendant-self",requested,expected_native_title=title,
                expected_before_bounds=before)

        target_ax_object=object();target={"owner":"Safari Technology Preview","pid":77,
            "windowId":9,"title":title,"layer":0,"alpha":1,"bounds":dict(before)}
        calls=[]
        bad_result=dict(hit);bad_result["_ancestorObject"]=target_ax_object
        with self.assertRaises(MOD.ObserverError):
            MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,
                native_title=title,records=[target],cursor_before={"x":10,"y":20},
                can_post=lambda:True,warp=lambda p:calls.append(("warp",p)),
                post=lambda k,p:calls.append((k,p)),restore=lambda p:calls.append(("restore",p)),
                cursor_after=lambda:{"x":10,"y":20},observed_bounds=lambda:dict(requested),
                ax_hit_test=lambda _points:bad_result,target_ax_object=target_ax_object)
        self.assertEqual(calls,[])

    def test_injected_context_is_exclusive_and_first_candidate_bound(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — injected-exclusive"
        base=self._cgevent_success_payload("injected-exclusive",title,before,requested)
        points=base["axHitTest"]["candidatePoints"]
        target_ax_object=object()

        def injected(index, *, native=False):
            hit=json.loads(json.dumps(base["axHitTest"]))
            hit["candidateIndex"]=index;hit["chosenPoint"]=dict(points[index])
            if native:
                hit["sourceMethod"]="system-wide"
                hit["ancestorMethod"]="kAXWindowAttribute"
                hit["receiverOutcomes"]=[{"candidateIndex":i,"receiver":"system-wide",
                                           "result":"hit","status":0}
                                          for i in range(len(points))]
            else:
                hit["sourceMethod"]="injected";hit["ancestorMethod"]="injected"
                hit["receiverOutcomes"]=[{"candidateIndex":i,"receiver":"injected",
                                           "result":"hit","status":0}
                                          for i in range(len(points))]
            hit["_ancestorObject"]=target_ax_object
            return hit

        with self.assertRaises(MOD.ObserverError):
            MOD._parse_ax_hit_evidence(injected(0,native=True),before,77,9,
                                       allow_injected=True)
        with self.assertRaises(MOD.ObserverError):
            MOD._parse_ax_hit_evidence(injected(1),before,77,9,
                                       allow_injected=True)

        target={"owner":"Safari Technology Preview","pid":77,"windowId":9,
                "title":title,"layer":0,"alpha":1,"bounds":dict(before)}
        calls=[]
        with self.assertRaises(MOD.ObserverError):
            MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,
                native_title=title,records=[target],cursor_before={"x":10,"y":20},
                can_post=lambda:True,warp=lambda p:calls.append(("warp",p)),
                post=lambda k,p:calls.append((k,p)),restore=lambda p:calls.append(("restore",p)),
                cursor_after=lambda:{"x":10,"y":20},observed_bounds=lambda:dict(requested),
                ax_hit_test=lambda _points:injected(0,native=True),
                target_ax_object=target_ax_object)
        self.assertEqual(calls,[])

    def test_direct_stp_script_is_fixed_to_bundle_and_uses_typed_argv(self):
        source=MOD.DIRECT_STP_APPLESCRIPT
        self.assertIn('tell application id "com.apple.SafariTechnologyPreview"',source)
        self.assertIn("on run argv",source)
        self.assertIn("boundsMatch",source)
        self.assertNotIn("System Events",source)
        self.assertNotIn("do shell script",source)
        self.assertNotIn("& expectedTitle",source)
        self.assertNotIn("& nativeTitle",source)
        if Path("/usr/bin/osacompile").exists():
            with tempfile.TemporaryDirectory() as directory:
                script=Path(directory)/"direct.applescript";compiled=Path(directory)/"direct.scpt"
                script.write_text(source)
                result=subprocess.run(["/usr/bin/osacompile","-o",str(compiled),str(script)],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stderr,"")

    def test_launcher_owns_native_helper_lifecycle_and_passes_private_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);helper_dir=root/"helper-run";helper_dir.mkdir(mode=0o700);source=helper_dir/"helper.swift";binary=helper_dir/"helper.bundle";source.write_text("source");binary.write_text("binary");os.chmod(source,0o600);os.chmod(binary,0o700)
            original_compile=LAUNCH.compile_ax_helper;original_call=LAUNCH.subprocess.call;captured=[]
            try:
                LAUNCH.compile_ax_helper=lambda:(helper_dir,binary)
                LAUNCH.subprocess.call=lambda command,**kwargs:(captured.append((command,kwargs)),0)[1]
                rc=LAUNCH.main(["--socket","/tmp/worker18.sock","--run-id","worker18","--peer-uid","503",
                                "--capability-file",str(root/"cap"),"--ready-file",str(root/"ready")])
            finally:
                LAUNCH.compile_ax_helper=original_compile;LAUNCH.subprocess.call=original_call
            command,kwargs=captured[0];fd=int(command[command.index('--ax-helper-fd')+1])
            self.assertEqual(rc,0);self.assertFalse(helper_dir.exists());self.assertIn('--ax-helper-digest',command);self.assertIn('--ax-helper-device',command);self.assertIn('--ax-helper-inode',command);self.assertNotIn(str(binary),command);self.assertEqual(kwargs['pass_fds'],(fd,))
            self.assertIn('env',kwargs)
            self.assertFalse(any(key.startswith('DYLD_') for key in kwargs['env']))
            self.assertEqual(kwargs['env'].get('PATH'),os.environ.get('PATH'))

    def test_launcher_dyld_override_environment_is_removed_before_observer_exec(self):
        original=os.environ.get("DYLD_FRAMEWORK_PATH")
        try:
            os.environ["DYLD_FRAMEWORK_PATH"]="/tmp/forged-framework"
            sanitized=LAUNCH._sanitized_loader_environment()
        finally:
            if original is None:
                os.environ.pop("DYLD_FRAMEWORK_PATH",None)
            else:
                os.environ["DYLD_FRAMEWORK_PATH"]=original
        self.assertNotIn("DYLD_FRAMEWORK_PATH",sanitized)
        self.assertEqual(sanitized.get("PATH"),os.environ.get("PATH"))

    def _process_identity_with(self, executable, bundle):
        original_run=MOD.subprocess.run;original_path=MOD.process_executable_path;original_bundle=MOD.process_bundle_identifier;original_signature=MOD.process_bundle_signature
        def fake_run(command,**_kwargs):
            if "uid=" in command:return SimpleNamespace(returncode=0,stdout=str(os.getuid())+"\n",stderr="")
            return SimpleNamespace(returncode=0,stdout="Sat Aug 30 10:11:12 2026 /Applications/Safari Technology Preview.app/Contents/MacOS/Safari Technology Preview --spoof\n",stderr="")
        def fake_signature(_path):
            return {"bundlePath":str(MOD.STP_APP),"executablePath":MOD.STP_EXECUTABLE,
                    "plistIdentifier":bundle,"signedIdentifier":bundle,"displayExecutable":MOD.STP_EXECUTABLE,
                    "authorities":["Software Signing","Apple Code Signing Certification Authority","Apple Root CA"],
                    "teamIdentifier":"not set","designatedRequirement":MOD.STP_DESIGNATED_REQUIREMENT,
                    "bundleVerified":True,"executableVerified":True,"requirementVerified":True,
                    "strict":True,"deep":True,
                    "allArchitectures":True,"valid":True}
        MOD.subprocess.run=fake_run;MOD.process_executable_path=lambda _pid:executable;MOD.process_bundle_identifier=lambda _path:bundle;MOD.process_bundle_signature=fake_signature
        try:return MOD.process_identity(77)
        finally:MOD.subprocess.run=original_run;MOD.process_executable_path=original_path;MOD.process_bundle_identifier=original_bundle;MOD.process_bundle_signature=original_signature

    def test_process_identity_uses_exact_observed_path_not_argument_substring(self):
        with self.assertRaises(MOD.ObserverError):
            self._process_identity_with("/Applications/Safari.app/Contents/MacOS/Safari",MOD.STP_BUNDLE_ID)
        with self.assertRaises(MOD.ObserverError):
            self._process_identity_with("/Applications/Other.app/Contents/MacOS/Safari Technology Preview",MOD.STP_BUNDLE_ID)

    def test_process_identity_rejects_wrong_bundle_and_lookup_failure(self):
        with self.assertRaises(MOD.ObserverError):
            self._process_identity_with(MOD.STP_EXECUTABLE,"com.apple.Safari")
        original=MOD.process_executable_path
        try:
            MOD.process_executable_path=lambda _pid:(_ for _ in ()).throw(MOD.ObserverError("ambiguous process lookup"))
            with self.assertRaises(MOD.ObserverError):MOD.process_identity(77)
        finally:MOD.process_executable_path=original

    def test_process_identity_accepts_valid_exact_stp_identity(self):
        identity=self._process_identity_with(MOD.STP_EXECUTABLE,MOD.STP_BUNDLE_ID)
        self.assertEqual(identity["executable"],MOD.STP_EXECUTABLE)
        self.assertEqual(identity["bundleId"],MOD.STP_BUNDLE_ID)
        self.assertEqual(identity["pid"],77)
        self.assertTrue(identity["signature"]["valid"])
        self.assertEqual(identity["signature"]["designatedRequirement"],MOD.STP_DESIGNATED_REQUIREMENT)

    def _bundle_signature_with(self, *, verify_rc=0, authorities=None, team="not set", requirement=None):
        with tempfile.TemporaryDirectory() as directory:
            bundle=Path(directory)/"Safari Technology Preview.app"
            executable=bundle/"Contents"/"MacOS"/"Safari Technology Preview"
            executable.parent.mkdir(parents=True)
            with (bundle/"Contents"/"Info.plist").open("wb") as handle:
                plistlib.dump({"CFBundleIdentifier":MOD.STP_BUNDLE_ID},handle)
            authorities=authorities or ["Software Signing","Apple Code Signing Certification Authority","Apple Root CA"]
            display="\n".join(["Executable="+str(executable),"Identifier="+MOD.STP_BUNDLE_ID,
                               *["Authority="+value for value in authorities],"TeamIdentifier="+team])+"\n"
            requirement=requirement or MOD.STP_DESIGNATED_REQUIREMENT
            original=MOD.subprocess.run
            def fake_run(command,**_kwargs):
                if "--display" in command:return SimpleNamespace(returncode=0,stdout="",stderr=display)
                if "--verify" in command:return SimpleNamespace(returncode=verify_rc,stdout="",stderr="")
                if "-r-" in command:return SimpleNamespace(returncode=0,stdout="",stderr="designated => "+requirement+"\n")
                raise AssertionError(command)
            MOD.subprocess.run=fake_run
            try:return MOD.process_bundle_signature(str(executable))
            finally:MOD.subprocess.run=original

    def test_process_bundle_signature_rejects_display_only_and_ad_hoc(self):
        with self.assertRaises(MOD.ObserverError):
            self._bundle_signature_with(verify_rc=1)
        with self.assertRaises(MOD.ObserverError):
            self._bundle_signature_with(authorities=["adhoc"])

    def test_process_bundle_signature_rejects_wrong_authority_team_and_requirement(self):
        with self.assertRaises(MOD.ObserverError):
            self._bundle_signature_with(authorities=["Software Signing","Developer ID Application"])
        with self.assertRaises(MOD.ObserverError):
            self._bundle_signature_with(team="BAD-TEAM")
        with self.assertRaises(MOD.ObserverError):
            self._bundle_signature_with(requirement='identifier "com.apple.Safari" and anchor apple')

    def test_process_bundle_signature_accepts_pinned_apple_requirement(self):
        signature=self._bundle_signature_with()
        self.assertTrue(signature["valid"])
        self.assertTrue(signature["bundleVerified"])
        self.assertTrue(signature["executableVerified"])
        self.assertTrue(signature["requirementVerified"])
        self.assertEqual(signature["designatedRequirement"],MOD.STP_DESIGNATED_REQUIREMENT)
        self.assertEqual(signature["teamIdentifier"],"not set")

    def test_process_identity_does_not_convert_successful_empty_results_to_exit(self):
        original_run=MOD.subprocess.run
        try:
            for stderr in ("transient identity provider failure",""):
                with self.subTest(stderr=stderr):
                    MOD.subprocess.run=lambda _command,stderr=stderr,**_kwargs:SimpleNamespace(returncode=0,stdout="",stderr=stderr)
                    with self.assertRaises(MOD.ObserverError) as raised:
                        MOD.process_identity(77)
                    self.assertNotIsInstance(raised.exception,MOD.ProcessExitedError)
        finally:MOD.subprocess.run=original_run

    def test_final_keeps_empty_identity_result_unfinalized(self):
        original_run=MOD.subprocess.run
        try:
            for stderr in ("transient identity provider failure",""):
                with self.subTest(stderr=stderr):
                    self.live[:]=[{"owner":"Safari Technology Preview","pid":77,"windowId":9,"alpha":1,"name":"nonce","x":-1408,"y":-900,"width":1360,"height":2480}]
                    obs=self.new_observer()
                    obs.handle(request(obs,1,"claim",pid=77,windowId=9,titleNonce="nonce",requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
                    self.live.clear()
                    MOD.subprocess.run=lambda _command,stderr=stderr,**_kwargs:SimpleNamespace(returncode=0,stdout="",stderr=stderr)
                    obs.process_fn=MOD.process_identity
                    with self.assertRaises(MOD.ObserverError):obs.handle(request(obs,2,"final"))
                    self.assertFalse(obs.finalized);self.assertEqual(obs.phase,"claimed")
        finally:MOD.subprocess.run=original_run

    def test_socket_placement_is_root_sticky_tmp_only(self):
        with self.assertRaises(MOD.ObserverError):
            MOD.validate_socket_placement(Path(tempfile.mkdtemp())/"observer.sock")
        MOD.validate_socket_placement(Path("/tmp/observer-worker05-test.sock"))

    def test_observer_responses_are_capability_authenticated(self):
        left,right=socket.socketpair()
        try:
            item=self.obs._canonical("auth",True)
            self.obs._send(left,item)
            response=__import__("json").loads(right.recv(65536).split(b"\n",1)[0].decode())
            supplied=response.pop("responseMac")
            expected=__import__("hmac").new(self.obs.capability.encode(),__import__("json").dumps(response,separators=(",",":"),sort_keys=True).encode(),__import__("hashlib").sha256).hexdigest()
            self.assertEqual(supplied,expected)
        finally:
            left.close();right.close()

    def test_malformed_or_disconnected_peer_is_rejected(self):
        with self.assertRaises(MOD.ObserverError):
            self.obs.handle(None)
        with self.assertRaises(MOD.ObserverError):
            self.obs.handle({"operation":[]})
        with self.assertRaises(MOD.ObserverError):
            bad=request(self.obs,1,"baseline",titleNonce="nonce",pid=77);bad["capability"]="wrong-cap"
            self.obs.handle(bad)
        with self.assertRaises(MOD.ObserverError):
            bad=request(self.obs,1,"baseline",titleNonce="nonce",pid=77);bad["capability"]=123
            self.obs.handle(bad)
        left,right=socket.socketpair()
        try:
            right.close()
            with self.assertRaises(MOD.ObserverError):
                self.obs._receive(left)
        finally:
            left.close()

    def test_socket_receive_parses_newline_delimited_json(self):
        left,right=socket.socketpair()
        try:
            right.sendall(b'{"operation":"baseline","titleNonce":"nonce"}\n')
            self.assertEqual(self.obs._receive(left),{"operation":"baseline","titleNonce":"nonce"})
        finally:
            left.close();right.close()

    def test_binding_mode_rejects_pid_mode_mismatch(self):
        with self.assertRaises(MOD.ObserverError):
            self.obs.handle(request(self.obs,1,"baseline",pid=77,titleNonce="nonce",bindingMode="late"))
        obs=self.new_observer(windows=[])
        with self.assertRaises(MOD.ObserverError):
            obs.handle(request(obs,1,"baseline",titleNonce="nonce",bindingMode="prebound-diagnostic"))

    def test_dynamic_native_title_prefix_is_terminal_and_unique(self):
        for prefix in ("Personal — ", "Other Profile — ", "Localized · "):
            native=prefix+"probe-a"
            self.assertEqual(MOD.derive_native_title_prefix(native,"probe-a"),prefix)
        bad=("probe-aPersonal — ", "Personal — probe-aprobe-a", "Personal — probe-a-suffix")
        for native in bad:
            with self.subTest(native=native):
                with self.assertRaises(MOD.ObserverError):MOD.derive_native_title_prefix(native,"probe-a")

    def test_late_baseline_inventory_requires_zero_visible_signed_stp_windows(self):
        clean=self.new_observer(windows=[])
        response=clean.handle(request(clean,1,"baseline",titleNonce="inventory-a",bindingMode="late"))
        self.assertTrue(response["ok"]);self.assertEqual(response["matchingCount"],0)
        self.assertEqual(response["stpWindowInventory"],[]);self.assertTrue(response["inventoryComplete"])
        visible=[dict(self.live[0],name="unrelated"),dict(self.live[0],windowId=10,name="another")]
        crowded=self.new_observer(windows=visible)
        response=crowded.handle(request(crowded,1,"baseline",titleNonce="inventory-a",bindingMode="late"))
        self.assertFalse(response["ok"]);self.assertEqual(response["matchingCount"],2)
        self.assertFalse(crowded.baseline_clear)

    def test_named_target_selection_retains_unnamed_coregraphics_auxiliaries(self):
        visible=[];obs=self.new_observer(windows=visible)
        baseline=obs.handle(request(obs,1,"baseline",titleNonce="aux-a",bindingMode="late"))
        self.assertTrue(baseline["ok"],baseline)
        named=dict(self.live[0],name="Personal — aux-a")
        auxiliaries=[dict(self.live[0],windowId=100+index,name="") for index in range(5)]
        visible.extend([named]+auxiliaries)
        probe=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="aux-a"))
        self.assertTrue(probe["ok"],probe)
        self.assertEqual(probe["windowId"],9)
        self.assertEqual(len(probe["stpWindowInventory"]),6)
        self.assertEqual(sum(item["targetEligible"] is True for item in probe["stpWindowInventory"]),1)
        self.assertEqual(sum(item["name"] == "" for item in probe["stpWindowInventory"]),5)

    def test_direct_stp_fallback_requires_exact_typed_ax_not_settable_mapping(self):
        bounds={"x":-1408,"y":-900,"width":1360,"height":2480};nonce="typed-fallback";title="Personal — "+nonce
        candidate={"pid":77,"windowId":9,"axWindowNumber":9,"title":title,"bounds":dict(bounds)}
        payload={"ok":False,"method":"application-services-ax","errorCode":"not-settable",
                 "error":"AX attribute is not settable: AXSize status=0","attribute":"AXSize","status":0,
                 "helperUid":os.getuid(),"pid":77,"windowId":9,"axWindowNumber":9,"titleNonce":nonce,
                 "nativeTitle":title,"mappingMethod":"ax-window-number","cgBefore":dict(bounds),
                 "candidateCount":1,"matchedCount":1,"candidates":[candidate],"before":dict(bounds)}
        with self.assertRaises(MOD.AXNotSettableError) as caught:
            MOD.parse_ax_helper_result(SimpleNamespace(returncode=1,stdout=json.dumps(payload)+"\n",stderr=""),
                                        77,9,nonce,bounds,expected_native_title=title,expected_before_bounds=bounds)
        self.assertTrue(caught.exception.mapping["verified"])
        self.assertEqual(caught.exception.mapping["mappingMethod"],"ax-window-number")

        for bad in (
            {**payload,"status":-25205},
            {**payload,"attribute":"AXPosition","error":"AX attribute is not settable: AXSize status=0"},
            {**payload,"errorCode":"permission"},
            {key:value for key,value in payload.items() if key!="candidates"},
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(MOD.ObserverError) as error:
                    MOD.parse_ax_helper_result(SimpleNamespace(returncode=1,stdout=json.dumps(bad)+"\n",stderr=""),
                                                77,9,nonce,bounds,expected_native_title=title,expected_before_bounds=bounds)
                self.assertNotIsInstance(error.exception,MOD.AXNotSettableError)

    def _direct_success_result(self, before, after, app_status="UNAVAILABLE", app_id=0):
        fields=[MOD.DIRECT_STP_PROTOCOL,"OK",app_status,str(app_id),"1",
                str(before["x"]),str(before["y"]),str(before["width"]),str(before["height"]),
                str(after["x"]),str(after["y"]),str(after["width"]),str(after["height"])]
        return SimpleNamespace(returncode=0,stdout="\t".join(fields)+"\n",stderr="")

    def _split_success_payload(self, nonce, title, before, requested, *, size_settable,
                               resize_method, operation="split", after=None,
                               intermediate=None):
        if after is None:
            after=dict(requested)
        if intermediate is None:
            intermediate=dict(before)
        candidate={"pid":77,"windowId":9,"axWindowNumber":9,"title":title,"bounds":dict(before)}
        return {"ok":True,"method":"application-services-ax","operation":operation,
                "helperUid":os.getuid(),"pid":77,"windowId":9,"axWindowNumber":9,
                "titleNonce":nonce,"nativeTitle":title,"mappingMethod":"ax-window-number",
                "cgBefore":dict(before),"candidateCount":1,"matchedCount":1,"candidates":[candidate],
                "before":dict(before),"requestedBounds":dict(requested),"after":dict(after),
                "positionSettable":True,"sizeSettable":size_settable,
                "resizeMethod":resize_method,"moveMethod":"AX",
                "beforePosition":{"x":before["x"],"y":before["y"]},
                "beforeSize":{"width":before["width"],"height":before["height"]},
                "intermediateBounds":dict(intermediate)}

    def _ax_position_ignored_payload(self, nonce, title, before, requested, *,
                                     operation="split", after=None):
        if after is None:
            after={"x":-1320,"y":39,"width":requested["width"],"height":requested["height"]}
        candidate={"pid":77,"windowId":9,"axWindowNumber":9,"title":title,"bounds":dict(before)}
        return {"ok":False,"method":"application-services-ax","errorCode":"position-ignored",
                "error":"AX position write readback is not exact","attribute":"AXPosition","status":0,
                "helperUid":os.getuid(),"pid":77,"windowId":9,"axWindowNumber":9,
                "titleNonce":nonce,"nativeTitle":title,"mappingMethod":"ax-window-number",
                "cgBefore":dict(before),"candidateCount":1,"matchedCount":1,"candidates":[candidate],
                "before":dict(before),"requestedBounds":dict(requested),"after":dict(after),
                "operation":operation,"positionSettable":True,"sizeSettable":True,
                "resizeMethod":"webDriver-existing" if operation=="split" else "pre-resized",
                "moveMethod":"AX","beforePosition":{"x":before["x"],"y":before["y"]},
                "beforeSize":{"width":before["width"],"height":before["height"]},
                "intermediateBounds":dict(before)}

    def _cgevent_success_payload(self, nonce, title, before, requested):
        payload=self._split_success_payload(nonce,title,before,requested,size_settable=True,
                                            resize_method="pre-resized",operation="cgevent-titlebar",
                                            after=requested,intermediate=before)
        delta={"x":requested["x"]-before["x"],"y":requested["y"]-before["y"]}
        source={"x":before["x"]+220,"y":before["y"]+18}
        destination={"x":source["x"]+delta["x"],"y":source["y"]+delta["y"]}
        payload["moveMethod"]="cgevent-titlebar"
        candidates=[{"x":before["x"]+220,"y":before["y"]+18},
                    {"x":before["x"]+before["width"]//2,"y":before["y"]+18},
                    {"x":before["x"]+before["width"]-220,"y":before["y"]+18}]
        payload.update({"sourcePoint":source,"destinationPoint":destination,"delta":delta,
                        "axHitTest":{"candidatePoints":candidates,"candidateIndex":0,
                        "chosenPoint":source,"role":"AXGroup","subrole":"AXTitleBar",
                        "actions":[],"enabled":True,"pid":77,"ancestorPid":77,
                        "ancestorRole":"AXWindow","ancestorSubrole":"AXStandardWindow","ancestorMethod":"kAXWindowAttribute",
                        "targetWindowMatched":True,"targetAxWindowNumber":9,
                        "mappingMethod":"ax-window-number","sourceMethod":"system-wide",
                        "receiverOutcomes":[{"candidateIndex":index,"receiver":"system-wide",
                                             "result":"hit","status":0}
                                            for index in range(len(candidates))]},
                        "safePoint":True,"topmostProof":{"targetPid":77,"targetWindowId":9,
                        "targetTitle":title,"sourcePoint":source,"targetBounds":dict(before),
                        "targetIndex":0,"eligibleCount":2,"overlayAbove":0,
                        "eligibleRecords":[{"index":0,"cgIndex":0,"layer":0,"alpha":1,
                        "owner":"Safari Technology Preview","pid":77,"windowId":9,
                        "title":title,"bounds":dict(before)},
                        {"index":1,"cgIndex":1,"layer":0,"alpha":1,
                        "owner":"Cua Driver","pid":65488,"windowId":18105,
                        "title":"","bounds":{"x":-1784,"y":0,"width":3840,"height":1620}}]},
                        "cursorBefore":{"x":90,"y":120},"cursorAfter":{"x":90,"y":120},
                        "cursorRestored":True,"eventSequence":["leftMouseDown"]+["leftMouseDragged"]*24+["leftMouseUp"],
                        "eventCount":26,"dragSteps":24,"postBounds":dict(requested),
                        "buttonStateBeforeWarp":{str(index):False for index in range(32)},
                        "buttonStateBeforeMouseDown":{str(index):False for index in range(32)},
                        "preMouseDownBounds":dict(before),
                        "preMouseDownTopmostProof":None,
                        "preMouseDownAXHitTest":None,
                        "inputReattested":True,
                        "cleanupUpAttempted":False,"cleanupUpSucceeded":False,
                        "cleanupUpPoint":None,"leftMouseUpConfirmed":True})
        payload["preMouseDownTopmostProof"] = json.loads(json.dumps(payload["topmostProof"]))
        payload["preMouseDownAXHitTest"] = json.loads(json.dumps(payload["axHitTest"]))
        return payload

    def test_direct_stp_fallback_exact_bounds_negative_coordinates_and_injection_safe_command(self):
        before={"x":366,"y":39,"width":800,"height":652}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        nonce="direct-script-b";title="Personal — "+nonce
        mapping={"verified":True,"pid":77,"windowId":9,"axWindowNumber":9,"title":title,
                 "mappingMethod":"ax-window-number","before":dict(before),"cgBefore":dict(before),"nativeTitle":title,
                 "candidateCount":1,
                 "matchedCount":1,"candidates":[{"pid":77,"windowId":9,"axWindowNumber":9,
                 "title":title,"bounds":dict(before)}]}
        captured=[]
        def runner(command):
            captured.append(command)
            return self._direct_success_result(before,requested)
        result=MOD.direct_stp_window(77,9,nonce,requested,native_title=title,
                                      expected_before_bounds=before,ax_mapping=mapping,runner=runner)
        self.assertTrue(result["verified"]);self.assertEqual(result["mappingMethod"],"title-geometry")
        self.assertEqual(captured[0][0],"/usr/bin/osascript");self.assertEqual(captured[0][1],"-e")
        self.assertEqual(captured[0][3],"--");self.assertEqual(captured[0][4:7],["77","9",title])
        self.assertIn('tell application id "com.apple.SafariTechnologyPreview"',captured[0][2])
        self.assertNotIn(title,captured[0][2]);self.assertNotIn("System Events",captured[0][2])
        self.assertNotIn("do shell script",captured[0][2])

        result=MOD.direct_stp_window(77,9,nonce,requested,native_title=title,
                                      expected_before_bounds=before,ax_mapping=mapping,
                                      runner=lambda _command:self._direct_success_result(before,requested,"EXACT",9))
        self.assertEqual(result["mappingMethod"],"app-window-id");self.assertEqual(result["appWindowId"],9)
        resize_after={"x":before["x"],"y":before["y"],"width":requested["width"],"height":requested["height"]}
        result=MOD.direct_stp_window(77,9,nonce,requested,native_title=title,
                                      expected_before_bounds=before,ax_mapping=mapping,
                                      resize_only=True,
                                      runner=lambda command:(captured.append(command),self._direct_success_result(before,resize_after))[1])
        self.assertEqual(result["operation"],"resize-only");self.assertFalse(result["positionMutated"])
        self.assertEqual(captured[-1][-1],"resize-only")

    def test_direct_stp_fallback_rejects_zero_multiple_wrong_title_or_bounds_protocol(self):
        before={"x":366,"y":39,"width":800,"height":652};requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        failures=["candidate-count","candidate-count","app-window-id-mismatch","bounds-readback"]
        for reason in failures:
            with self.subTest(reason=reason):
                result=SimpleNamespace(returncode=0,stdout=f"{MOD.DIRECT_STP_PROTOCOL}\tERROR\t{reason}\t0\n",stderr="")
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_direct_stp_result(result,77,9,"Personal — direct-b",
                                                before,requested)
        malformed=[
            self._direct_success_result(before,requested).stdout.replace("\n","\n\n"),
            self._direct_success_result(before,dict(requested,width=1359)).stdout,
            self._direct_success_result(before,requested,app_status="EXACT",app_id=10).stdout,
            self._direct_success_result(before,requested).stdout.replace("\t1\t366", "\t2\t366"),
        ]
        for raw in malformed:
            with self.subTest(raw=raw):
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_direct_stp_result(SimpleNamespace(returncode=0,stdout=raw,stderr=""),77,9,
                                                "Personal — direct-b",before,requested)

    def test_split_placement_reuses_exact_webdriver_size_without_ax_size_write(self):
        before={"x":-1320,"y":30,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        nonce="split-existing";title="Personal — "+nonce
        payload=self._split_success_payload(nonce,title,before,requested,size_settable=False,
                                            resize_method="webDriver-existing")
        original_validate=MOD._validate_helper_fd;original_run=MOD._run_helper_fd
        fake_fd=os.open(os.devnull,os.O_RDONLY);calls=[];direct=[]
        try:
            MOD._validate_helper_fd=lambda *_args:None
            def run_helper(*args):
                calls.append(args[-1])
                return SimpleNamespace(returncode=0,stdout=json.dumps(payload)+"\n",stderr="")
            MOD._run_helper_fd=run_helper
            def must_not_run(*_args,**_kwargs):
                direct.append(True);raise AssertionError("direct fallback must not run for an existing size")
            result=MOD.place_stp_window(77,9,nonce,requested,helper_fd=fake_fd,helper_digest="a"*64,
                                        helper_device=0,helper_inode=1,expected_native_title=title,
                                        expected_before_bounds=before,direct_placer=must_not_run)
        finally:
            MOD._validate_helper_fd=original_validate;MOD._run_helper_fd=original_run;os.close(fake_fd)
        self.assertTrue(result["verified"]);self.assertEqual(result["operation"],"split")
        self.assertEqual(result["resizeMethod"],"webDriver-existing");self.assertEqual(result["moveMethod"],"AX")
        self.assertEqual(result["beforeBounds"] if "beforeBounds" in result else result["before"]["y"],30)
        self.assertEqual(calls[0][-1],"split");self.assertEqual(direct,[])

    def test_split_placement_uses_ax_size_then_ax_position_when_size_differs(self):
        before={"x":366,"y":39,"width":800,"height":652}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        intermediate={"x":366,"y":39,"width":1360,"height":2480}
        nonce="split-ax";title="Personal — "+nonce
        payload=self._split_success_payload(nonce,title,before,requested,size_settable=True,
                                            resize_method="AX",operation="resize-only",
                                            after=intermediate,intermediate=intermediate)
        move_payload=self._split_success_payload(nonce,title,intermediate,requested,size_settable=True,
                                                 resize_method="pre-resized",operation="move-only",
                                                 after=requested,intermediate=intermediate)
        original_validate=MOD._validate_helper_fd;original_run=MOD._run_helper_fd
        fake_fd=os.open(os.devnull,os.O_RDONLY);calls=[]
        try:
            MOD._validate_helper_fd=lambda *_args:None
            helper_results=[payload,move_payload]
            MOD._run_helper_fd=lambda *args:(calls.append(args[-1]),SimpleNamespace(returncode=0,stdout=json.dumps(helper_results.pop(0))+"\n",stderr=""))[1]
            result=MOD.place_stp_window(77,9,nonce,requested,helper_fd=fake_fd,helper_digest="a"*64,
                                        helper_device=0,helper_inode=1,expected_native_title=title,
                                        expected_before_bounds=before,
                                        windows_fn=lambda:[{"owner":"Safari Technology Preview","pid":77,"windowId":9,
                                                            "alpha":1,"name":title,**intermediate}],
                                        process_fn=lambda _pid:self.process(77),expected_identity=self.process(77))
        finally:
            MOD._validate_helper_fd=original_validate;MOD._run_helper_fd=original_run;os.close(fake_fd)
        self.assertTrue(result["verified"]);self.assertEqual(result["resizeMethod"],"AX")
        self.assertEqual(result["moveMethod"],"AX");self.assertEqual(result["intermediateBounds"],intermediate)
        self.assertEqual(result["resizeRebind"]["bounds"],intermediate)
        self.assertEqual(result["resizeRebind"]["identity"]["startTime"],"start-a")
        self.assertEqual(calls,[['improvedtube-aqua-ax-helper','77','9',nonce,title,'-1408','-900','1360','2480','resize-only'],
                                ['improvedtube-aqua-ax-helper','77','9',nonce,title,'-1408','-900','1360','2480','move-only']])

    def test_parse_cgevent_evidence_requires_exact_topmost_cursor_and_events(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        nonce="cgevent-parser";title="Personal — "+nonce
        payload=self._cgevent_success_payload(nonce,title,before,requested)
        result=MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(payload)+"\n",stderr=""),
                                          77,9,nonce,requested,expected_native_title=title,
                                          expected_before_bounds=before)
        self.assertTrue(result["verified"]);self.assertEqual(result["operation"],"cgevent-titlebar")
        self.assertEqual(result["moveMethod"],"cgevent-titlebar");self.assertEqual(result["eventCount"],26)
        for label,mutate in (
            ("overlay-above",lambda p:p["topmostProof"].update(overlayAbove=1)),
            ("wrong-id",lambda p:p["topmostProof"].update(targetWindowId=10)),
            ("wrong-title",lambda p:p["topmostProof"].update(targetTitle="decoy")),
            ("wrong-source",lambda p:p.update(sourcePoint={"x":before["x"]+221,"y":before["y"]+18})),
            ("wrong-delta",lambda p:p.update(delta={"x":-1,"y":-1})),
            ("cursor-not-restored",lambda p:p.update(cursorAfter={"x":91,"y":120})),
            ("numeric-boolean",lambda p:p.update(eventCount=True)),
            ("nested-numeric-string",lambda p:p["topmostProof"].update(targetPid="77")),
            ("cursor-float",lambda p:p.update(cursorBefore={"x":90.0,"y":120})),
            ("event-order",lambda p:p.update(eventSequence=["leftMouseDown"]+["leftMouseUp"]*24+["leftMouseUp"])),
            ("post-drift",lambda p:p.update(postBounds=dict(requested,width=1359))),
        ):
            with self.subTest(label=label):
                bad=json.loads(json.dumps(payload));mutate(bad)
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(bad)+"\n",stderr=""),
                                                77,9,nonce,requested,expected_native_title=title,
                                                expected_before_bounds=before)

    def test_injected_cgevent_backend_proves_order_topmost_delta_and_restore(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        nonce="cgevent-backend";title="Personal — "+nonce
        target={"owner":"Safari Technology Preview","pid":77,"windowId":9,"title":title,
                "layer":0,"alpha":1,"bounds":dict(before)}
        behind={"owner":"Cua Driver","pid":65488,"windowId":18105,"title":"",
                "layer":0,"alpha":1,"bounds":{"x":-1784,"y":0,"width":3840,"height":1620}}
        events=[];warps=[];restores=[]
        output=MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,native_title=title,
            records=[target,behind],cursor_before={"x":90,"y":120},can_post=lambda:True,
            warp=lambda point:warps.append(point),post=lambda kind,point:events.append((kind,point)),
            restore=lambda point:restores.append(point),cursor_after=lambda:{"x":90,"y":120},
            observed_bounds=lambda:dict(requested))
        self.assertEqual(events[0][0],"leftMouseDown");self.assertEqual(events[-1][0],"leftMouseUp")
        self.assertEqual([kind for kind,_ in events[1:-1]], ["leftMouseDragged"]*24)
        self.assertEqual(output["delta"],{"x":-88,"y":-939});self.assertEqual(output["sourcePoint"],{"x":-1100,"y":57})
        self.assertEqual(output["destinationPoint"],{"x":-1188,"y":-882});self.assertEqual(restores,[{"x":90,"y":120}])
        self.assertEqual(warps,[{"x":-1100,"y":57}])
        self.assertEqual(output["topmostProof"]["eligibleRecords"][0]["windowId"],9)
        self.assertEqual(output["axHitTest"]["role"],"AXGroup")

        for label,records,can_post,post,observed in (
            ("overlay",[dict(behind,bounds=dict(target["bounds"])),target],lambda:True,lambda *_:None,lambda:requested),
            ("higher-layer-overlay",[dict(behind,layer=1,bounds=dict(target["bounds"])),target],lambda:True,lambda *_:None,lambda:requested),
            ("permission",[target],lambda:False,lambda *_:None,lambda:requested),
            ("post-drift",[target],lambda:True,lambda *_:None,lambda:dict(requested,width=1359)),
            ("post-error",[target],lambda:True,lambda *_:(_ for _ in ()).throw(RuntimeError("TCC")),lambda:requested),
        ):
            with self.subTest(label=label):
                branch_restores=[]
                with self.assertRaises(Exception):
                    MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,native_title=title,
                        records=records,cursor_before={"x":90,"y":120},can_post=can_post,
                        warp=lambda _point:None,post=post,restore=lambda point:branch_restores.append(point),
                        cursor_after=lambda:{"x":90,"y":120},observed_bounds=observed)
                expected_restores=[] if label in {"overlay","higher-layer-overlay"} else [{"x":90,"y":120}]
                self.assertEqual(branch_restores,expected_restores,label)

    def test_cgevent_quiesces_all_standard_buttons_before_warp_and_mouse_down(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — button-quiescence"
        target={"owner":"Safari Technology Preview","pid":77,"windowId":9,
                "title":title,"layer":0,"alpha":1,"bounds":dict(before)}
        quiet={str(index):False for index in range(32)}
        pressed_states=[]
        for label,button in (("left-pressed",0),("right-pressed",1),
                             ("center-pressed",2),("button3-pressed",3),
                             ("button31-pressed",31)):
            state=dict(quiet);state[str(button)]=True
            pressed_states.append((label,state))
        pressed_states.extend((
            ("unknown-button",{str(index):False for index in range(31)}),
            ("malformed-button",{**quiet,"31":"up"})))
        for label,state in pressed_states:
            with self.subTest(label=label):
                calls=[]
                with self.assertRaises(MOD.ObserverError):
                    MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,
                        native_title=title,records=[target],cursor_before={"x":10,"y":20},
                        can_post=lambda:True,warp=lambda point:calls.append(("warp",point)),
                        post=lambda kind,point:calls.append((kind,point)),
                        restore=lambda point:calls.append(("restore",point)),
                        cursor_after=lambda:{"x":10,"y":20},
                        observed_bounds=lambda:dict(requested),button_state=lambda state=state:state)
                self.assertEqual(calls,[],label)

        # A button can become pressed after the cursor moved.  The second
        # state gate must reject before mouseDown, while restoration remains
        # the only cleanup callback.
        pressed_after_warp=dict(quiet);pressed_after_warp["31"]=True
        states=iter((quiet,pressed_after_warp))
        calls=[]
        with self.assertRaises(MOD.ObserverError):
            MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,
                native_title=title,records=[target],cursor_before={"x":10,"y":20},
                can_post=lambda:True,warp=lambda point:calls.append(("warp",point)),
                post=lambda kind,point:calls.append((kind,point)),
                restore=lambda point:calls.append(("restore",point)),
                cursor_after=lambda:{"x":10,"y":20},
                observed_bounds=lambda:dict(requested),button_state=lambda:next(states))
        self.assertEqual([kind for kind,_ in calls],["warp","restore"])

    def test_cgevent_reattests_target_topmost_and_ax_before_mouse_down(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — reattest"
        target={"owner":"Safari Technology Preview","pid":77,"windowId":9,
                "title":title,"layer":0,"alpha":1,"bounds":dict(before)}
        occluder={"owner":"Other App","pid":88,"windowId":10,"title":"overlay",
                  "layer":3,"alpha":1,"bounds":dict(before)}
        quiet={str(index):False for index in range(32)}
        cases=(
            ("occluder-after-warp",lambda:[occluder,target],lambda:dict(before)),
            ("window-id-after-warp",lambda:[dict(target,windowId=10)],lambda:dict(before)),
            ("title-after-warp",lambda:[dict(target,title="decoy")],lambda:dict(before)),
            ("bounds-after-warp",lambda:[dict(target,bounds=dict(before,width=1359))],lambda:dict(before)),
            ("geometry-recheck",lambda:[target],lambda:dict(before,x=-1319)),
        )
        for label,record_fn,bounds_fn in cases:
            with self.subTest(label=label):
                calls=[]
                with self.assertRaises(MOD.ObserverError):
                    MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,
                        native_title=title,records=[target],cursor_before={"x":10,"y":20},
                        can_post=lambda:True,warp=lambda point:calls.append(("warp",point)),
                        post=lambda kind,point:calls.append((kind,point)),
                        restore=lambda point:calls.append(("restore",point)),
                        cursor_after=lambda:{"x":10,"y":20},
                        observed_bounds=lambda:dict(requested),button_state=lambda:quiet,
                        records_after_warp=record_fn,bounds_after_warp=bounds_fn)
                self.assertEqual([kind for kind,_ in calls],["warp","restore"],label)

    def test_cgevent_parser_requires_preinput_attestation_and_coordinate_identity(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — parser-reattest"
        payload=self._cgevent_success_payload("parser-reattest",title,before,requested)
        for label,mutation in (
            ("missing-button-before-warp",lambda p:p.pop("buttonStateBeforeWarp")),
            ("pressed-before-down",lambda p:p["buttonStateBeforeMouseDown"].update({"31":True})),
            ("pre-bounds-drift",lambda p:p.update(preMouseDownBounds=dict(before,x=-1319))),
            ("pre-topmost-drift",lambda p:p["preMouseDownTopmostProof"].update(targetWindowId=10)),
            ("pre-ax-drift",lambda p:p["preMouseDownAXHitTest"].update(chosenPoint={"x":before["x"]+221,"y":before["y"]+18})),
            ("reattest-flag",lambda p:p.update(inputReattested=False)),
        ):
            with self.subTest(label=label):
                bad=json.loads(json.dumps(payload));mutation(bad)
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(bad)+"\n",stderr=""),
                        77,9,"parser-reattest",requested,expected_native_title=title,
                        expected_before_bounds=before)
        fallback=json.loads(json.dumps(payload));hit=fallback["axHitTest"]
        hit.update(ancestorMethod="system-wide-native-window-id")
        hit["receiverOutcomes"]=[{"candidateIndex":0,"receiver":"system-wide","result":"hit","status":0}]
        hit["nativeWindowBinding"]={
            "version":"system-wide-native-window-id-v1","candidateIndex":0,
            "receiver":"system-wide","hitPid":77,"hitRole":"AXGroup",
            "hitSubrole":"AXTitleBar","hitActions":[],"hitEnabled":True,
            "hitMatchedTarget":False,
            "nativeWindowIDMethod":"_AXUIElementGetWindow@HIServices",
            "nativeWindowIDStatus":0,"nativeWindowID":9,
            "targetNativeWindowIDStatus":0,"targetNativeWindowID":9,
            "topLevelNativeWindowIDStatus":0,"topLevelNativeWindowID":9,
            "nativeWindowIDProvenanceMethod":"dladdr-exact-sealed-system-image",
            "nativeWindowIDProvenanceImage":"/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/HIServices.framework/Versions/A/HIServices",
            "nativeWindowIDProvenanceExpectedImage":"/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/HIServices.framework/Versions/A/HIServices",
            "nativeWindowIDProvenanceVerified":True,
            "nativeWindowIDProvenanceBasePresent":True,
            "nativeWindowIDProvenanceHandlePresent":True,
            "hitWindowStatus":-25205,"topLevelStatus":0,
            "topLevelType":"AXUIElement","topLevelPid":77,"topLevelRole":"AXGroup",
            "topLevelSubrole":"AXTitleBar","topLevelActions":[],"topLevelEnabled":True,
            "topLevelMatchedTarget":False,"topLevelWindowStatus":-25212,
            "topLevelParentStatus":-25205,"targetChildrenStatus":-25212,
            "targetType":"AXUIElement","targetPid":77,"targetRole":"AXWindow",
            "targetSubrole":"AXStandardWindow","targetMatched":True}
        fallback["preMouseDownAXHitTest"]=json.loads(json.dumps(hit))
        accepted=MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(fallback)+"\n",stderr=""),
            77,9,"parser-reattest",requested,expected_native_title=title,expected_before_bounds=before)
        self.assertEqual(accepted["axHitTest"]["nativeWindowBinding"]["topLevelRole"],"AXGroup")
        # A hover transition from inert title-bar chrome to the exact target
        # window is canonicalized by the trusted native window ID; each
        # transcript still undergoes its own strict role/identity checks.
        hover=json.loads(json.dumps(fallback))
        hover_hit=hover["preMouseDownAXHitTest"]
        hover_hit.update(role="AXWindow",subrole="AXStandardWindow")
        hover_hit["nativeWindowBinding"].update(
            hitRole="AXWindow",hitSubrole="AXStandardWindow",hitMatchedTarget=True)
        hover_accepted=MOD.parse_ax_helper_result(SimpleNamespace(
            returncode=0,stdout=json.dumps(hover)+"\n",stderr=""),
            77,9,"parser-reattest",requested,expected_native_title=title,
            expected_before_bounds=before)
        self.assertTrue(hover_accepted["verified"])
        for label,mutation in (
            ("window-hit-not-target",lambda p:(p["axHitTest"].update(role="AXWindow",subrole="AXStandardWindow"),
                p["axHitTest"]["nativeWindowBinding"].update(hitRole="AXWindow",hitSubrole="AXStandardWindow",hitMatchedTarget=False))),
            ("window-top-level",lambda p:p["axHitTest"]["nativeWindowBinding"].update(
                topLevelRole="AXWindow",topLevelSubrole="AXStandardWindow")),
        ):
            with self.subTest(label=label):
                bad=json.loads(json.dumps(fallback));mutation(bad)
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(bad)+"\n",stderr=""),
                        77,9,"parser-reattest",requested,expected_native_title=title,
                        expected_before_bounds=before)

    def test_cgevent_full_z_order_rejects_unknown_frontmost_and_preserves_layers(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — full-z-order"
        target={"owner":"Safari Technology Preview","pid":77,"windowId":9,"title":title,
                "layer":1,"alpha":1,"bounds":dict(before)}
        events=[];warps=[];restores=[]
        output=MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,native_title=title,
            records=[target],cursor_before={"x":10,"y":20},can_post=lambda:True,
            warp=lambda point:warps.append(point),post=lambda kind,point:events.append((kind,point)),
            restore=lambda point:restores.append(point),cursor_after=lambda:{"x":10,"y":20},
            observed_bounds=lambda:dict(requested))
        self.assertEqual(output["topmostProof"]["eligibleRecords"][0]["layer"],1)
        self.assertEqual(warps,[{"x":-1100,"y":57}]);self.assertEqual(len(events),26)

        unknown={"layer":2,"alpha":1,"bounds":dict(before)}
        events=[];warps=[];restores=[]
        with self.assertRaises(MOD.ObserverError):
            MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,native_title=title,
                records=[unknown,target],cursor_before={"x":10,"y":20},can_post=lambda:True,
                warp=lambda point:warps.append(point),post=lambda kind,point:events.append((kind,point)),
                restore=lambda point:restores.append(point),cursor_after=lambda:{"x":10,"y":20},
                observed_bounds=lambda:dict(requested))
        self.assertEqual(warps,[]);self.assertEqual(events,[]);self.assertEqual(restores,[])

    def test_cgevent_ax_hit_test_requires_bounded_allowlisted_noninteractive_source(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — ax-hit"
        target={"owner":"Safari Technology Preview","pid":77,"windowId":9,"title":title,
                "layer":0,"alpha":1,"bounds":dict(before)}
        captured=[];events=[];warps=[];target_ax_object=object()
        def valid_hit(points):
            captured.append(points)
            return {"candidatePoints":points,"candidateIndex":0,"chosenPoint":points[0],
                    "role":"AXWindow","subrole":"AXStandardWindow","actions":[],"enabled":True,
                    "pid":77,"ancestorPid":77,"ancestorRole":"AXWindow",
                    "ancestorSubrole":"AXStandardWindow","ancestorMethod":"injected","targetWindowMatched":True,
                    "targetAxWindowNumber":9,"mappingMethod":"ax-window-number",
                    "sourceMethod":"injected","receiverOutcomes":[
                        {"candidateIndex":index,"receiver":"injected","result":"hit","status":0}
                        for index in range(len(points))],
                    "_ancestorObject":target_ax_object}
        result=MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,native_title=title,
            records=[target],cursor_before={"x":10,"y":20},can_post=lambda:True,
            warp=lambda point:warps.append(point),post=lambda kind,point:events.append((kind,point)),
            restore=lambda _point:None,cursor_after=lambda:{"x":10,"y":20},
            observed_bounds=lambda:dict(requested),ax_hit_test=valid_hit,
            target_ax_object=target_ax_object)
        self.assertEqual(len(captured),1);self.assertEqual(result["sourcePoint"],captured[0][0])
        self.assertEqual(warps,[captured[0][0]])
        for label,mutation in (
            ("button",{"role":"AXButton","subrole":"AXButton"}),
            ("tab",{"role":"AXGroup","subrole":"AXTab"}),
            ("window-titlebar-cross-pair",{"role":"AXWindow","subrole":"AXTitleBar"}),
            ("group-window-cross-pair",{"role":"AXGroup","subrole":"AXStandardWindow"}),
            ("press-action",{"actions":["AXPress"]}),
            ("unknown-ancestor",{"ancestorRole":"AXUnknown"}),
            ("wrong-pid",{"pid":88}),
            ("disabled",{"enabled":False}),
            ("spoofed-point",{"chosenPoint":{"x":before["x"]+221,"y":before["y"]+18}}),
        ):
            with self.subTest(label=label):
                calls=[];mutated=dict(valid_hit(captured[0]) if captured else {
                    "candidatePoints":MOD._cgevent_candidate_points(before),"candidateIndex":0,
                    "chosenPoint":MOD._cgevent_candidate_points(before)[0],"role":"AXGroup",
                    "subrole":"AXTitleBar","actions":[],"enabled":True,"pid":77,
                    "ancestorPid":77,"ancestorRole":"AXWindow","ancestorSubrole":"AXStandardWindow",
                    "ancestorMethod":"injected","targetWindowMatched":True,"targetAxWindowNumber":9,
                    "mappingMethod":"ax-window-number","sourceMethod":"injected",
                    "receiverOutcomes":[{"candidateIndex":index,"receiver":"injected",
                                         "result":"hit","status":0}
                                        for index in range(len(MOD._cgevent_candidate_points(before)))],
                    "_ancestorObject":target_ax_object})
                mutated.update(mutation)
                with self.assertRaises(MOD.ObserverError):
                    MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,native_title=title,
                        records=[target],cursor_before={"x":10,"y":20},can_post=lambda:True,
                        warp=lambda point:calls.append(("warp",point)),post=lambda kind,point:calls.append((kind,point)),
                        restore=lambda point:calls.append(("restore",point)),cursor_after=lambda:{"x":10,"y":20},
                        observed_bounds=lambda:dict(requested),ax_hit_test=lambda _points,mutated=mutated:mutated,
                        target_ax_object=target_ax_object)
                self.assertEqual([item[0] for item in calls],[],label)

    def test_cgevent_ax_hit_test_rejects_same_title_geometry_different_ax_object(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — ax-object"
        target={"owner":"Safari Technology Preview","pid":77,"windowId":9,"title":title,
                "layer":0,"alpha":1,"bounds":dict(before)}
        target_ax_object=object();different_ax_object=object();calls=[]
        def re_resolved_different(points):
            return {"candidatePoints":points,"candidateIndex":0,"chosenPoint":points[0],
                    "role":"AXGroup","subrole":"AXTitleBar","actions":[],"enabled":True,
                    "pid":77,"ancestorPid":77,"ancestorRole":"AXWindow",
                    "ancestorSubrole":"AXStandardWindow","ancestorMethod":"injected","targetWindowMatched":True,
                    "targetAxWindowNumber":9,"mappingMethod":"ax-window-number",
                    "_ancestorObject":different_ax_object}
        with self.assertRaises(MOD.ObserverError):
            MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,native_title=title,
                records=[target],cursor_before={"x":10,"y":20},can_post=lambda:True,
                warp=lambda point:calls.append(("warp",point)),post=lambda kind,point:calls.append((kind,point)),
                restore=lambda point:calls.append(("restore",point)),cursor_after=lambda:{"x":10,"y":20},
                observed_bounds=lambda:dict(requested),ax_hit_test=re_resolved_different,
                target_ax_object=target_ax_object)
        self.assertEqual(calls,[])

    def test_cgevent_post_failures_compensate_left_up_before_restore(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — cleanup"
        target={"owner":"Safari Technology Preview","pid":77,"windowId":9,"title":title,
                "layer":0,"alpha":1,"bounds":dict(before)}
        # Fail each stage after the down has been posted.  The compensating
        # up is best-effort and must precede cursor restoration.
        for failure_call in range(2,27):
            with self.subTest(failure_call=failure_call):
                calls=[];timeline=[];post_calls=[0]
                def post(kind,point):
                    post_calls[0]+=1
                    if post_calls[0] == failure_call:
                        raise RuntimeError("injected post failure")
                    calls.append((kind,dict(point)));timeline.append((kind,dict(point)))
                with self.assertRaises(Exception):
                    MOD.run_cgevent_backend(before,requested,pid=77,window_id=9,native_title=title,
                        records=[target],cursor_before={"x":10,"y":20},can_post=lambda:True,
                        warp=lambda point:(calls.append(("warp",dict(point))),timeline.append(("warp",dict(point)))),post=post,
                        restore=lambda point:(timeline.append(("restore",dict(point)))),cursor_after=lambda:{"x":10,"y":20},
                        observed_bounds=lambda:dict(requested))
                kinds=[kind for kind,_point in calls]
                self.assertIn("leftMouseDown",kinds)
                self.assertEqual(kinds[-1],"leftMouseUp")
                timeline_kinds=[kind for kind,_point in timeline]
                self.assertEqual(timeline_kinds[-1],"restore")
                self.assertEqual(timeline_kinds.count("restore"),1)
                self.assertLess(max(index for index,(kind,_point) in enumerate(timeline) if kind == "leftMouseUp"),
                                next(index for index,(kind,_point) in enumerate(timeline) if kind == "restore"))

    def test_parse_cgevent_evidence_rejects_ax_controls_and_topmost_overlay(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        title="Personal — parse-ax"
        payload=self._cgevent_success_payload("parse-ax",title,before,requested)
        for label,mutation in (
            ("button",lambda p:p["axHitTest"].update(role="AXButton",subrole="AXButton")),
            ("action",lambda p:p["axHitTest"].update(actions=["AXPress"])),
            ("ancestor",lambda p:p["axHitTest"].update(targetWindowMatched=False)),
            ("ancestor-role-missing",lambda p:p["axHitTest"].pop("ancestorRole")),
            ("ancestor-subrole-nonstandard",lambda p:p["axHitTest"].update(ancestorSubrole="AXDialog")),
            ("ancestor-role-malformed",lambda p:p["axHitTest"].update(ancestorRole=True)),
            ("positive-overlay",lambda p:p["topmostProof"]["eligibleRecords"].insert(0,{
                "index":0,"cgIndex":4,"layer":5,"alpha":1,"owner":"Panel","pid":88,
                "windowId":44,"title":"panel","bounds":dict(before)})),
        ):
            with self.subTest(label=label):
                bad=json.loads(json.dumps(payload));mutation(bad)
                with self.assertRaises(MOD.ObserverError):
                    MOD.parse_ax_helper_result(SimpleNamespace(returncode=0,stdout=json.dumps(bad)+"\n",stderr=""),
                        77,9,"parse-ax",requested,expected_native_title=title,expected_before_bounds=before)

    def test_ax_position_clamp_runs_one_cgevent_fallback_and_exact_post_rebind(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        nonce="cgevent-clamp";title="Personal — "+nonce
        ax_failure=self._ax_position_ignored_payload(nonce,title,before,requested)
        cgevent=self._cgevent_success_payload(nonce,title,before,requested)
        original_validate=MOD._validate_helper_fd;original_run=MOD._run_helper_fd
        fake_fd=os.open(os.devnull,os.O_RDONLY);calls=[];helper_results=[
            SimpleNamespace(returncode=1,stdout=json.dumps(ax_failure)+"\n",stderr=""),
            SimpleNamespace(returncode=0,stdout=json.dumps(cgevent)+"\n",stderr=""),]
        try:
            MOD._validate_helper_fd=lambda *_args:None
            MOD._run_helper_fd=lambda *args:(calls.append(args[-1]),helper_results.pop(0))[1]
            result=MOD.place_stp_window(77,9,nonce,requested,helper_fd=fake_fd,helper_digest="a"*64,
                helper_device=0,helper_inode=1,expected_native_title=title,expected_before_bounds=before,
                direct_placer=lambda *_args:(_ for _ in ()).throw(AssertionError("direct fallback is not allowed")),
                windows_fn=lambda:[{"owner":"Safari Technology Preview","pid":77,"windowId":9,
                                    "alpha":1,"name":title,**requested}],
                process_fn=lambda _pid:self.process(77),expected_identity=self.process(77))
        finally:
            MOD._validate_helper_fd=original_validate;MOD._run_helper_fd=original_run;os.close(fake_fd)
        self.assertTrue(result["verified"]);self.assertEqual(result["moveMethod"],"cgevent-titlebar")
        self.assertEqual(result["cgeventMove"]["operation"],"cgevent-titlebar")
        self.assertEqual(result["cgeventPost"]["bounds"],requested)
        self.assertEqual(calls,[['improvedtube-aqua-ax-helper','77','9',nonce,title,'-1408','-900','1360','2480','split'],
                                ['improvedtube-aqua-ax-helper','77','9',nonce,title,'-1408','-900','1360','2480','cgevent-titlebar']])

    def test_ax_permission_or_identity_failure_never_runs_cgevent_fallback(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        nonce="cgevent-no-fallback";title="Personal — "+nonce
        generic={"ok":False,"method":"application-services-ax","error":"AX position write failed"}
        original_validate=MOD._validate_helper_fd;original_run=MOD._run_helper_fd
        fake_fd=os.open(os.devnull,os.O_RDONLY);calls=[]
        try:
            MOD._validate_helper_fd=lambda *_args:None
            MOD._run_helper_fd=lambda *args:(calls.append(args[-1]),SimpleNamespace(returncode=1,stdout=json.dumps(generic)+"\n",stderr=""))[1]
            with self.assertRaises(MOD.ObserverError):
                MOD.place_stp_window(77,9,nonce,requested,helper_fd=fake_fd,helper_digest="a"*64,
                    helper_device=0,helper_inode=1,expected_native_title=title,expected_before_bounds=before,
                    windows_fn=lambda:[{"owner":"Safari Technology Preview","pid":77,"windowId":9,
                                        "alpha":1,"name":title,**before}],process_fn=lambda _pid:self.process(77),
                    expected_identity=self.process(77))
        finally:
            MOD._validate_helper_fd=original_validate;MOD._run_helper_fd=original_run;os.close(fake_fd)
        self.assertEqual(calls,[['improvedtube-aqua-ax-helper','77','9',nonce,title,'-1408','-900','1360','2480','split']])

    def test_direct_resize_path_uses_cgevent_only_after_typed_ax_move_miss(self):
        before={"x":366,"y":39,"width":800,"height":652}
        intermediate={"x":366,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        nonce="cgevent-direct";title="Personal — "+nonce
        candidate={"pid":77,"windowId":9,"axWindowNumber":9,"title":title,"bounds":dict(before)}
        resize_failure={"ok":False,"method":"application-services-ax","errorCode":"resize-not-settable",
                        "error":"AX attribute is not settable: AXSize status=0","attribute":"AXSize","status":0,
                        "helperUid":os.getuid(),"pid":77,"windowId":9,"axWindowNumber":9,
                        "titleNonce":nonce,"nativeTitle":title,"mappingMethod":"ax-window-number",
                        "cgBefore":dict(before),"candidateCount":1,"matchedCount":1,"candidates":[candidate],
                        "before":dict(before),"operation":"resize-only","positionSettable":True,
                        "sizeSettable":False,"resizeMethod":"stp-direct","moveMethod":"AX",
                        "requestedBounds":dict(requested),"beforePosition":{"x":before["x"],"y":before["y"]},
                        "beforeSize":{"width":before["width"],"height":before["height"]}}
        move_miss=self._ax_position_ignored_payload(nonce,title,intermediate,requested,operation="move-only")
        cgevent=self._cgevent_success_payload(nonce,title,intermediate,requested)
        original_validate=MOD._validate_helper_fd;original_run=MOD._run_helper_fd
        fake_fd=os.open(os.devnull,os.O_RDONLY);calls=[];results=[
            SimpleNamespace(returncode=1,stdout=json.dumps(resize_failure)+"\n",stderr=""),
            SimpleNamespace(returncode=1,stdout=json.dumps(move_miss)+"\n",stderr=""),
            SimpleNamespace(returncode=0,stdout=json.dumps(cgevent)+"\n",stderr=""),]
        window_states=[[{"owner":"Safari Technology Preview","pid":77,"windowId":9,
                         "alpha":1,"name":title,**intermediate}],
                       [{"owner":"Safari Technology Preview","pid":77,"windowId":9,
                         "alpha":1,"name":title,**requested}]]
        try:
            MOD._validate_helper_fd=lambda *_args:None
            MOD._run_helper_fd=lambda *args:(calls.append(args[-1]),results.pop(0))[1]
            result=MOD.place_stp_window(77,9,nonce,requested,helper_fd=fake_fd,helper_digest="a"*64,
                helper_device=0,helper_inode=1,expected_native_title=title,expected_before_bounds=before,
                direct_placer=lambda *_args,**_kwargs:{"verified":True,"method":"safari-direct-apple-event",
                    "operation":"resize-only","positionMutated":False,"before":dict(before),"after":dict(intermediate)},
                windows_fn=lambda:window_states.pop(0),
                process_fn=lambda _pid:self.process(77),expected_identity=self.process(77))
        finally:
            MOD._validate_helper_fd=original_validate;MOD._run_helper_fd=original_run;os.close(fake_fd)
        self.assertTrue(result["verified"]);self.assertEqual(result["resizeMethod"],"stp-direct")
        self.assertEqual(result["moveMethod"],"cgevent-titlebar")
        self.assertEqual(calls,[['improvedtube-aqua-ax-helper','77','9',nonce,title,'-1408','-900','1360','2480','resize-only'],
                                ['improvedtube-aqua-ax-helper','77','9',nonce,title,'-1408','-900','1360','2480','move-only'],
                                ['improvedtube-aqua-ax-helper','77','9',nonce,title,'-1408','-900','1360','2480','cgevent-titlebar']])

    def test_cgevent_post_swap_reuse_or_bounds_failure_blocks_success(self):
        before={"x":-1320,"y":39,"width":1360,"height":2480}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        nonce="cgevent-post-check";title="Personal — "+nonce
        ax_failure=self._ax_position_ignored_payload(nonce,title,before,requested)
        cgevent=self._cgevent_success_payload(nonce,title,before,requested)
        identity=self.process(77)
        cases=[
            ("window-swap",[{"owner":"Safari Technology Preview","pid":77,"windowId":10,"alpha":1,"name":title,**requested}],lambda _pid:identity),
            ("title-swap",[{"owner":"Safari Technology Preview","pid":77,"windowId":9,"alpha":1,"name":"decoy",**requested}],lambda _pid:identity),
            ("bounds-swap",[{"owner":"Safari Technology Preview","pid":77,"windowId":9,"alpha":1,"name":title,**dict(requested,width=1359)}],lambda _pid:identity),
            ("pid-reuse",[{"owner":"Safari Technology Preview","pid":77,"windowId":9,"alpha":1,"name":title,**requested},],None),
        ]
        for label,records,process_fn in cases:
            with self.subTest(label=label):
                original_validate=MOD._validate_helper_fd;original_run=MOD._run_helper_fd
                fake_fd=os.open(os.devnull,os.O_RDONLY);calls=[]
                try:
                    MOD._validate_helper_fd=lambda *_args:None
                    results=[SimpleNamespace(returncode=1,stdout=json.dumps(ax_failure)+"\n",stderr=""),
                             SimpleNamespace(returncode=0,stdout=json.dumps(cgevent)+"\n",stderr="")]
                    MOD._run_helper_fd=lambda *args:(calls.append(args[-1]),results.pop(0))[1]
                    if process_fn is None:
                        process_calls=[0]
                        def process_reuse(_pid):
                            process_calls[0]+=1
                            return identity if process_calls[0] == 1 else {**identity,"startTime":"reused"}
                        process_fn=process_reuse
                    with self.assertRaises(MOD.ObserverError):
                        MOD.place_stp_window(77,9,nonce,requested,helper_fd=fake_fd,helper_digest="a"*64,
                            helper_device=0,helper_inode=1,expected_native_title=title,expected_before_bounds=before,
                            windows_fn=lambda records=records:records,process_fn=process_fn,expected_identity=identity)
                finally:
                    MOD._validate_helper_fd=original_validate;MOD._run_helper_fd=original_run;os.close(fake_fd)
                self.assertEqual(calls,[['improvedtube-aqua-ax-helper','77','9',nonce,title,'-1408','-900','1360','2480','split'],
                                        ['improvedtube-aqua-ax-helper','77','9',nonce,title,'-1408','-900','1360','2480','cgevent-titlebar']],label)

    def test_ax_resize_rebind_requires_same_cg_window_and_process_before_move(self):
        before={"x":366,"y":39,"width":800,"height":652}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        intermediate={"x":366,"y":39,"width":1360,"height":2480}
        nonce="split-rebind";title="Personal — "+nonce
        resize_payload=self._split_success_payload(nonce,title,before,requested,size_settable=True,
                                                    resize_method="AX",operation="resize-only",
                                                    after=intermediate,intermediate=intermediate)
        identity=self.process(77)
        valid_record={"owner":"Safari Technology Preview","pid":77,"windowId":9,"alpha":1,
                      "name":title,**intermediate}
        cases=[
            ("window-swap",[dict(valid_record,windowId=10)],lambda _pid:identity),
            ("title-swap",[dict(valid_record,name="Personal — decoy")],lambda _pid:identity),
            ("pid-swap",[dict(valid_record,pid=88)],lambda _pid:identity),
            ("geometry-swap",[dict(valid_record,width=1359)],lambda _pid:identity),
            ("duplicate",[dict(valid_record),dict(valid_record)],lambda _pid:identity),
            ("process-reuse",[dict(valid_record)],lambda _pid:{**identity,"startTime":"reused-start"}),
        ]
        for label,records,process_fn in cases:
            with self.subTest(label=label):
                original_validate=MOD._validate_helper_fd;original_run=MOD._run_helper_fd
                fake_fd=os.open(os.devnull,os.O_RDONLY);calls=[]
                try:
                    MOD._validate_helper_fd=lambda *_args:None
                    MOD._run_helper_fd=lambda *args:(calls.append(args[-1]),SimpleNamespace(returncode=0,stdout=json.dumps(resize_payload)+"\n",stderr=""))[1]
                    with self.assertRaises(MOD.ObserverError):
                        MOD.place_stp_window(77,9,nonce,requested,helper_fd=fake_fd,helper_digest="a"*64,
                                             helper_device=0,helper_inode=1,expected_native_title=title,
                                             expected_before_bounds=before,windows_fn=lambda records=records:records,
                                             process_fn=process_fn,expected_identity=identity)
                finally:
                    MOD._validate_helper_fd=original_validate;MOD._run_helper_fd=original_run;os.close(fake_fd)
                self.assertEqual(len(calls),1,label)
                self.assertEqual(calls[0][-1],"resize-only",label)
        original_validate=MOD._validate_helper_fd;original_run=MOD._run_helper_fd
        fake_fd=os.open(os.devnull,os.O_RDONLY);calls=[]
        try:
            MOD._validate_helper_fd=lambda *_args:None
            MOD._run_helper_fd=lambda *args:(calls.append(args[-1]),SimpleNamespace(returncode=0,stdout=json.dumps(resize_payload)+"\n",stderr=""))[1]
            with self.assertRaises(MOD.ObserverError):
                MOD.place_stp_window(77,9,nonce,requested,helper_fd=fake_fd,helper_digest="a"*64,
                                     helper_device=0,helper_inode=1,expected_native_title=title,
                                     expected_before_bounds=before,windows_fn=lambda:[valid_record],
                                     process_fn=lambda _pid:identity)
        finally:
            MOD._validate_helper_fd=original_validate;MOD._run_helper_fd=original_run;os.close(fake_fd)
        self.assertEqual(len(calls),1)

    def test_split_placement_rejects_nonsettable_or_clamped_ax_position(self):
        before={"x":366,"y":39,"width":800,"height":652}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        nonce="split-position";title="Personal — "+nonce
        payload=self._split_success_payload(nonce,title,before,requested,size_settable=True,
                                            resize_method="AX",intermediate={"x":366,"y":39,"width":1360,"height":2480})
        payload["positionSettable"]=False
        original_validate=MOD._validate_helper_fd;original_run=MOD._run_helper_fd
        fake_fd=os.open(os.devnull,os.O_RDONLY);direct=[]
        try:
            MOD._validate_helper_fd=lambda *_args:None
            MOD._run_helper_fd=lambda *_args:SimpleNamespace(returncode=0,stdout=json.dumps(payload)+"\n",stderr="")
            def must_not_run(*_args,**_kwargs):direct.append(True);raise AssertionError("position failure reached fallback")
            with self.assertRaises(MOD.ObserverError):
                MOD.place_stp_window(77,9,nonce,requested,helper_fd=fake_fd,helper_digest="a"*64,
                                     helper_device=0,helper_inode=1,expected_native_title=title,
                                     expected_before_bounds=before,direct_placer=must_not_run)
        finally:
            MOD._validate_helper_fd=original_validate;MOD._run_helper_fd=original_run;os.close(fake_fd)
        self.assertEqual(direct,[])

        mapping={"verified":True,"pid":77,"windowId":9,"axWindowNumber":9,"title":title,
                 "mappingMethod":"ax-window-number","before":dict(before),"cgBefore":dict(before),
                 "nativeTitle":title,"candidateCount":1,"matchedCount":1,
                 "candidates":[{"pid":77,"windowId":9,"axWindowNumber":9,"title":title,"bounds":dict(before)}]}
        clamped={"x":-1320,"y":39,"width":1360,"height":2480}
        with self.assertRaises(MOD.ObserverError):
            MOD.direct_stp_window(77,9,nonce,requested,native_title=title,expected_before_bounds=before,
                                  ax_mapping=mapping,resize_only=True,
                                  runner=lambda _args:self._direct_success_result(before,clamped))

    def test_split_direct_resize_postcheck_rejects_size_drift_before_ax_move(self):
        before={"x":366,"y":39,"width":800,"height":652}
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        nonce="split-drift";title="Personal — "+nonce
        candidate={"pid":77,"windowId":9,"axWindowNumber":9,"title":title,"bounds":dict(before)}
        failure={"ok":False,"method":"application-services-ax","errorCode":"resize-not-settable",
                 "error":"AX attribute is not settable: AXSize status=0","attribute":"AXSize","status":0,
                 "helperUid":os.getuid(),"pid":77,"windowId":9,"axWindowNumber":9,"titleNonce":nonce,
                 "nativeTitle":title,"mappingMethod":"ax-window-number","cgBefore":dict(before),
                 "candidateCount":1,"matchedCount":1,"candidates":[candidate],"before":dict(before),
                 "operation":"resize-only","positionSettable":True,"sizeSettable":False,
                 "resizeMethod":"stp-direct","moveMethod":"AX","requestedBounds":dict(requested),
                 "beforePosition":{"x":before["x"],"y":before["y"]},
                 "beforeSize":{"width":before["width"],"height":before["height"]}}
        intermediate={"x":before["x"],"y":before["y"],"width":requested["width"],"height":requested["height"]}
        original_validate=MOD._validate_helper_fd;original_run=MOD._run_helper_fd
        fake_fd=os.open(os.devnull,os.O_RDONLY);calls=[]
        try:
            MOD._validate_helper_fd=lambda *_args:None
            MOD._run_helper_fd=lambda *args:(calls.append(args[-1]),SimpleNamespace(returncode=1,stdout=json.dumps(failure)+"\n",stderr=""))[1]
            def fallback(*_args,**_kwargs):
                return {"verified":True,"method":"safari-direct-apple-event","operation":"resize-only",
                        "positionMutated":False,"before":dict(before),"after":dict(intermediate)}
            drift={"owner":"Safari Technology Preview","pid":77,"windowId":9,"alpha":1,
                   "name":title,"x":before["x"],"y":before["y"],"width":1359,"height":requested["height"]}
            with self.assertRaises(MOD.ObserverError):
                MOD.place_stp_window(77,9,nonce,requested,helper_fd=fake_fd,helper_digest="a"*64,
                                     helper_device=0,helper_inode=1,expected_native_title=title,
                                     expected_before_bounds=before,direct_placer=fallback,
                                     windows_fn=lambda:[drift],process_fn=lambda _pid:self.process(77),
                                     expected_identity=self.process(77))
        finally:
            MOD._validate_helper_fd=original_validate;MOD._run_helper_fd=original_run;os.close(fake_fd)
        self.assertEqual(calls,[['improvedtube-aqua-ax-helper','77','9',nonce,title,'-1408','-900','1360','2480','resize-only']])

    def test_place_uses_direct_fallback_only_for_typed_ax_not_settable(self):
        before={"x":366,"y":39,"width":800,"height":652};requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        nonce="place-typed-fallback";title="Personal — "+nonce
        candidate={"pid":77,"windowId":9,"axWindowNumber":9,"title":title,"bounds":dict(before)}
        ax_failure={"ok":False,"method":"application-services-ax","errorCode":"resize-not-settable",
                    "error":"AX attribute is not settable: AXSize status=0","attribute":"AXSize","status":0,
                    "helperUid":os.getuid(),"pid":77,"windowId":9,"axWindowNumber":9,"titleNonce":nonce,
                    "nativeTitle":title,"mappingMethod":"ax-window-number","cgBefore":dict(before),
                    "candidateCount":1,"matchedCount":1,"candidates":[candidate],"before":dict(before),
                    "operation":"resize-only","positionSettable":True,"sizeSettable":False,
                    "resizeMethod":"stp-direct","moveMethod":"AX","requestedBounds":dict(requested),
                    "beforePosition":{"x":before["x"],"y":before["y"]},
                    "beforeSize":{"width":before["width"],"height":before["height"]}}
        intermediate={"x":before["x"],"y":before["y"],"width":requested["width"],"height":requested["height"]}
        move_candidate={"pid":77,"windowId":9,"axWindowNumber":9,"title":title,"bounds":dict(intermediate)}
        move_payload={"ok":True,"method":"application-services-ax","operation":"move-only",
                 "helperUid":os.getuid(),"pid":77,"windowId":9,"axWindowNumber":9,"titleNonce":nonce,
                 "nativeTitle":title,"mappingMethod":"ax-window-number","cgBefore":dict(intermediate),
                 "candidateCount":1,"matchedCount":1,"candidates":[move_candidate],"before":dict(intermediate),
                 "requestedBounds":dict(requested),"after":dict(requested),"positionSettable":True,
                 "sizeSettable":False,"resizeMethod":"pre-resized","moveMethod":"AX",
                 "beforePosition":{"x":before["x"],"y":before["y"]},
                 "beforeSize":{"width":requested["width"],"height":requested["height"]},
                 "intermediateBounds":dict(intermediate)}
        original_validate=MOD._validate_helper_fd;original_run=MOD._run_helper_fd;calls=[]
        fake_fd=os.open(os.devnull,os.O_RDONLY)
        fallback_calls=[]
        try:
            MOD._validate_helper_fd=lambda *_args:None
            helper_results=[SimpleNamespace(returncode=1,stdout=json.dumps(ax_failure)+"\n",stderr=""),
                            SimpleNamespace(returncode=0,stdout=json.dumps(move_payload)+"\n",stderr="")]
            def run_helper(*_args):
                calls.append(_args[-1]);return helper_results.pop(0)
            MOD._run_helper_fd=run_helper
            def fallback(pid,window_id,nonce,requested_bounds,**kwargs):
                fallback_calls.append((pid,window_id,nonce,dict(requested_bounds),kwargs))
                self.assertTrue(kwargs["resize_only"])
                return {"verified":True,"method":"safari-direct-apple-event","operation":"resize-only",
                        "positionMutated":False,"before":dict(before),"after":dict(intermediate)}
            result=MOD.place_stp_window(77,9,nonce,requested,helper_fd=fake_fd,helper_digest="a"*64,
                                        helper_device=0,helper_inode=1,expected_native_title=title,
                                        expected_before_bounds=before,direct_placer=fallback,
                                        windows_fn=lambda:[{"owner":"Safari Technology Preview","pid":77,"windowId":9,
                                                            "alpha":1,"name":title,**intermediate}],
                                        process_fn=lambda _pid:self.process(77),expected_identity=self.process(77))
        finally:
            MOD._validate_helper_fd=original_validate;MOD._run_helper_fd=original_run;os.close(fake_fd)
        self.assertTrue(result["verified"]);self.assertEqual(result["method"],"split-placement")
        self.assertEqual(result["resizeMethod"],"stp-direct");self.assertEqual(result["moveMethod"],"AX")
        self.assertEqual(len(fallback_calls),1);self.assertEqual(fallback_calls[0][0:3],(77,9,nonce))
        self.assertEqual(fallback_calls[0][4]["ax_mapping"]["mappingMethod"],"ax-window-number")
        self.assertEqual(len(calls),2);self.assertEqual(calls[0][-1],"resize-only");self.assertEqual(calls[1][-1],"move-only")
        generic={**ax_failure,"errorCode":"permission"}
        original_validate=MOD._validate_helper_fd;original_run=MOD._run_helper_fd;fake_fd=os.open(os.devnull,os.O_RDONLY)
        try:
            MOD._validate_helper_fd=lambda *_args:None
            MOD._run_helper_fd=lambda *_args:SimpleNamespace(returncode=1,stdout=json.dumps(generic)+"\n",stderr="")
            with self.assertRaises(MOD.ObserverError):
                MOD.place_stp_window(77,9,nonce,requested,helper_fd=fake_fd,helper_digest="a"*64,
                                     helper_device=0,helper_inode=1,expected_native_title=title,
                                     expected_before_bounds=before,direct_placer=fallback)
        finally:
            MOD._validate_helper_fd=original_validate;MOD._run_helper_fd=original_run;os.close(fake_fd)
        self.assertEqual(len(fallback_calls),1)

    def test_title_probe_binds_exact_native_title_then_requires_independent_b(self):
        obs=self.new_observer();a,b,prefix,probe=self.prime_late(obs,"probe-a","probe-b","Other Profile — ")
        self.assertEqual(probe["derivedPrefix"],prefix)
        obs.placer=lambda pid,window_id,title,bounds:(self.live[0].update(bounds),{"method":"test"})[-1]
        placement=obs.handle(request(obs,3,"place",bindingMode="late",titleNonce=b,
                                     requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        self.assertTrue(placement["ok"]);self.assertEqual(placement["nativeTitle"],prefix+b)
        self.assertEqual(placement["provisional"]["nativeTitle"],prefix+b)

    def test_title_probe_waits_for_visible_window_and_exact_title_transition(self):
        visible=[];obs=self.new_observer(windows=visible)
        baseline=obs.handle(request(obs,1,"baseline",titleNonce="ready-a",bindingMode="late"))
        self.assertTrue(baseline["ok"]);self.assertEqual(baseline["stpWindowInventory"],[])
        pending=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="ready-a"))
        self.assertFalse(pending["ok"]);self.assertTrue(pending["retryable"])
        self.assertEqual(pending["signedCandidateCount"],0);self.assertEqual(pending["attempt"],1)
        visible.append(dict(self.live[0],name="ImprovedTube bootstrap"))
        transitioning=obs.handle(request(obs,3,"title-probe",bindingMode="late",titleNonce="ready-a"))
        self.assertFalse(transitioning["ok"]);self.assertTrue(transitioning["retryable"])
        self.assertEqual(transitioning["pendingPid"],77);self.assertEqual(transitioning["pendingWindowId"],9)
        self.assertEqual(transitioning["stpWindowInventory"][0]["name"],"ImprovedTube bootstrap")
        visible[0]["name"]="Personal — ready-a"
        ready=obs.handle(request(obs,4,"title-probe",bindingMode="late",titleNonce="ready-a"))
        self.assertTrue(ready["ok"]);self.assertTrue(ready["ready"]);self.assertFalse(ready["retryable"])
        self.assertEqual(ready["attempt"],3);self.assertEqual(ready["titleProbe"]["attempts"],3)
        visible[0]["name"]="Personal — ready-b"
        obs.placer=lambda pid,window_id,title,bounds:(visible[0].update(bounds),{"method":"test"})[-1]
        placed=obs.handle(request(obs,5,"place",bindingMode="late",titleNonce="ready-b",
                                  requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))
        self.assertTrue(placed["ok"])

    def test_empty_cg_title_binds_exact_webdriver_pid_handle_and_ax_window(self):
        visible=[];obs=self.new_observer(windows=visible)
        obs.handle(request(obs,1,"baseline",titleNonce="empty-a",bindingMode="late"))
        visible.append(dict(self.live[0],name="",layer=0,x=-1320,y=39))
        probe=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="empty-a",
                                 **self.webdriver_binding("empty-a")))
        self.assertTrue(probe["ok"]);self.assertEqual(probe["bindingMode"],MOD.EMPTY_CG_BINDING_MODE)
        self.assertEqual(probe["pid"],77);self.assertEqual(probe["windowId"],9)
        binding=probe["emptyCGTitleBinding"]
        self.assertTrue(binding["verified"]);self.assertEqual(binding["webdriver"]["windowHandles"],["owned-main"])
        self.assertEqual(binding["axMapping"]["mappingMethod"],"ax-window-number-empty-cg-title")
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        obs.placer=lambda pid,window_id,title,bounds:(visible[0].update(bounds),{"method":"test-empty-title-AX"})[-1]
        placed=obs.handle(request(obs,3,"place",bindingMode=MOD.EMPTY_CG_BINDING_MODE,
            titleNonce="empty-b",requestedBounds=requested,**self.webdriver_binding("empty-b")))
        self.assertTrue(placed["ok"]);self.assertEqual(placed["nativeTitle"],"")
        self.assertEqual(placed["placementEvidence"]["bindingMode"],MOD.EMPTY_CG_BINDING_MODE)
        claim=obs.handle(request(obs,4,"claim",bindingMode=MOD.EMPTY_CG_BINDING_MODE,
            titleNonce="empty-b",requestedBounds=requested,**self.webdriver_binding("empty-b")))
        self.assertTrue(claim["ok"]);self.assertEqual(claim["bindingMode"],MOD.EMPTY_CG_BINDING_MODE)
        self.assertTrue(obs.handle(request(obs,5,"observe",phase="bound"))["ok"])

    def test_empty_cg_title_selects_ax_mapped_main_with_auxiliary_first_through_claim(self):
        auxiliary={**self.live[0],"windowId":10,"name":"","x":-15,"y":2372,"width":280,"height":168}
        main={**self.live[0],"windowId":9,"name":"","x":-1320,"y":39,"width":1360,"height":2480}
        visible=[];obs=self.new_observer(windows=visible)
        obs.handle(request(obs,1,"baseline",titleNonce="run130-a",bindingMode="late"))
        visible.extend([auxiliary,main])
        def ax_windows(pid,_window_id,nonce):
            return [self.empty_ax_record(nonce=nonce,pid=pid,window_id=9,
                    bounds={key:main[key] for key in ("x","y","width","height")})]
        obs.ax_windows_fn=ax_windows
        probe=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="run130-a",
                                 **self.webdriver_binding("run130-a")))
        self.assertTrue(probe["ok"]);self.assertEqual(probe["windowId"],9)
        outcomes=probe["emptyCGCandidateSelection"]["candidateOutcomes"]
        self.assertEqual([(item["windowId"],item["mappingStatus"]) for item in outcomes],[(9,"mapped"),(10,"unmapped")])
        requested={"x":-1408,"y":-900,"width":1360,"height":2480};aux_before=copy.deepcopy(auxiliary)
        def placer(pid,window_id,_nonce,bounds):
            self.assertEqual((pid,window_id),(77,9));main.update(bounds);return {"method":"test-empty-title-AX"}
        obs.placer=placer
        placed=obs.handle(request(obs,3,"place",bindingMode=MOD.EMPTY_CG_BINDING_MODE,titleNonce="run130-b",
                                  requestedBounds=requested,**self.webdriver_binding("run130-b")))
        self.assertTrue(placed["ok"]);self.assertEqual(auxiliary,aux_before)
        for key in ("emptyCGCandidateSelectionBefore","emptyCGCandidateSelectionAfter"):
            evidence=placed["placementEvidence"][key]
            self.assertEqual(evidence["selected"]["candidate"]["windowId"],9)
            self.assertEqual({item["windowId"]:item["mappingStatus"] for item in evidence["candidateOutcomes"]},
                             {9:"mapped",10:"unmapped"})
        claim=obs.handle(request(obs,4,"claim",bindingMode=MOD.EMPTY_CG_BINDING_MODE,titleNonce="run130-b",
                                 requestedBounds=requested,**self.webdriver_binding("run130-b")))
        self.assertTrue(claim["ok"]);self.assertEqual(claim["windowId"],9)
        self.assertEqual(claim["emptyCGCandidateSelection"]["mappedCount"],1)
        self.assertTrue(obs.handle(request(obs,5,"observe",phase="bound"))["ok"])

    def test_empty_cg_title_zero_mapped_is_bounded_pending_without_mutation(self):
        visible=[];obs=self.new_observer(windows=visible);mutations=[]
        obs.handle(request(obs,1,"baseline",titleNonce="zero-a",bindingMode="late"))
        visible.extend([{**self.live[0],"windowId":9,"name":""},{**self.live[0],"windowId":10,"name":""}])
        obs.ax_windows_fn=lambda pid,_window_id,nonce:[self.empty_ax_record(nonce=nonce,pid=pid,window_id=99)]
        obs.placer=lambda *_args:mutations.append(True) or {"method":"unexpected"}
        pending=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="zero-a",
                                   **self.webdriver_binding("zero-a")))
        self.assertFalse(pending["ok"]);self.assertTrue(pending["retryable"])
        self.assertEqual(pending["emptyCGCandidateSelection"]["mappedCount"],0)
        self.assertEqual([item["mappingStatus"] for item in pending["emptyCGCandidateSelection"]["candidateOutcomes"]],
                         ["unmapped","unmapped"])
        obs.title_probe_count=64
        with self.assertRaises(MOD.ObserverError):
            obs.handle(request(obs,3,"title-probe",bindingMode="late",titleNonce="zero-a",
                               **self.webdriver_binding("zero-a")))
        self.assertIsNone(obs.title_probe);self.assertIsNone(obs.provisional);self.assertEqual(mutations,[])

    def test_empty_cg_title_rejects_cross_pid_named_and_hard_helper_error_before_mutation(self):
        for label,records,process in (
            ("cross-pid",[{**self.live[0],"name":""},{**self.live[0],"pid":88,"windowId":10,"name":""}],
             lambda pid:{**self.process(77),"pid":pid,"startTime":"start-a" if pid==77 else "start-b"}),
        ):
            with self.subTest(label=label):
                visible=[];obs=self.new_observer(windows=visible,process=process);calls=[]
                obs.handle(request(obs,1,"baseline",titleNonce=label+"-a",bindingMode="late"));visible.extend(records)
                obs.ax_windows_fn=lambda *_args:calls.append(True) or []
                rejected=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce=label+"-a",
                                            **self.webdriver_binding(label+"-a")))
                self.assertFalse(rejected["ok"]);self.assertFalse(rejected["retryable"]);self.assertEqual(calls,[])
                self.assertEqual(len(rejected["emptyCGCandidateSelection"]["inventoryBefore"]),2)
        visible=[];obs=self.new_observer(windows=visible);calls=[]
        obs.handle(request(obs,1,"baseline",titleNonce="named-a",bindingMode="late"));visible.append({**self.live[0],"name":""})
        obs.ax_windows_fn=lambda pid,_window_id,nonce:[self.empty_ax_record(nonce=nonce,pid=pid,window_id=99)]
        first=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="named-a",**self.webdriver_binding("named-a")))
        self.assertTrue(first["retryable"]);visible.append({**self.live[0],"windowId":10,"name":"Other"})
        obs.ax_windows_fn=lambda *_args:calls.append(True) or []
        named=obs.handle(request(obs,3,"title-probe",bindingMode="late",titleNonce="named-a",**self.webdriver_binding("named-a")))
        self.assertFalse(named["ok"]);self.assertFalse(named["retryable"]);self.assertEqual(calls,[])
        visible=[];obs=self.new_observer(windows=visible);obs.handle(request(obs,1,"baseline",titleNonce="hard-a",bindingMode="late"))
        visible.extend([{**self.live[0],"windowId":9,"name":""},{**self.live[0],"windowId":10,"name":""}])
        def hard(pid,window_id,nonce):
            if window_id==10:raise MOD.ObserverError("Accessibility trust is unavailable")
            target=visible[0]
            return [self.empty_ax_record(nonce=nonce,pid=pid,window_id=9,
                    bounds={key:target[key] for key in ("x","y","width","height")})]
        obs.ax_windows_fn=hard
        rejected=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="hard-a",
                                    **self.webdriver_binding("hard-a")))
        self.assertFalse(rejected["ok"]);self.assertFalse(rejected["retryable"])
        self.assertEqual({item["mappingStatus"] for item in rejected["emptyCGCandidateSelection"]["candidateOutcomes"]},
                         {"mapped","error"})

    def test_empty_cg_title_inventory_race_is_pending(self):
        visible=[];obs=self.new_observer(windows=visible);obs.handle(request(obs,1,"baseline",titleNonce="race-a",bindingMode="late"))
        main={**self.live[0],"windowId":9,"name":""};aux={**self.live[0],"windowId":10,"name":""};visible.extend([main,aux])
        def racing(pid,window_id,nonce):
            if window_id==10:aux["x"]-=1
            return [self.empty_ax_record(nonce=nonce,pid=pid,window_id=9,
                    bounds={key:main[key] for key in ("x","y","width","height")})]
        obs.ax_windows_fn=racing
        pending=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="race-a",
                                   **self.webdriver_binding("race-a")))
        self.assertFalse(pending["ok"]);self.assertTrue(pending["retryable"])
        self.assertFalse(pending["emptyCGCandidateSelection"]["stableInventory"])

    def test_empty_cg_title_same_ax_number_geometry_drift_is_terminal_with_other_mapping(self):
        visible=[];obs=self.new_observer(windows=visible);mutations=[]
        obs.handle(request(obs,1,"baseline",titleNonce="geometry-a",bindingMode="late"))
        main={**self.live[0],"windowId":9,"name":"","x":-1320,"y":39}
        auxiliary={**self.live[0],"windowId":10,"name":"","x":-15,"y":2372,"width":280,"height":168}
        visible.extend([main,auxiliary])
        def contradictory(pid,window_id,nonce):
            target=main
            return [self.empty_ax_record(nonce=nonce,pid=pid,window_id=window_id,
                    bounds={key:target[key] for key in ("x","y","width","height")})]
        obs.ax_windows_fn=contradictory;obs.placer=lambda *_args:mutations.append(True) or {"method":"unexpected"}
        rejected=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="geometry-a",
                                    **self.webdriver_binding("geometry-a")))
        selection=rejected["emptyCGCandidateSelection"]
        self.assertFalse(rejected["ok"]);self.assertFalse(rejected["retryable"])
        self.assertEqual({item["mappingStatus"] for item in selection["candidateOutcomes"]},{"mapped","error"})
        self.assertIsNone(obs.title_probe);self.assertIsNone(obs.provisional)
        self.assertEqual(obs.placement_count,0);self.assertEqual(mutations,[])

    def test_empty_cg_title_hard_helper_error_precedes_inventory_race(self):
        visible=[];obs=self.new_observer(windows=visible);mutations=[]
        obs.handle(request(obs,1,"baseline",titleNonce="hard-race-a",bindingMode="late"))
        main={**self.live[0],"windowId":9,"name":""};aux={**self.live[0],"windowId":10,"name":""};visible.extend([main,aux])
        def hard_race(pid,window_id,nonce):
            if window_id==10:
                aux["x"]-=1
                raise MOD.ObserverError("Accessibility trust is unavailable")
            return [self.empty_ax_record(nonce=nonce,pid=pid,window_id=9,
                    bounds={key:main[key] for key in ("x","y","width","height")})]
        obs.ax_windows_fn=hard_race;obs.placer=lambda *_args:mutations.append(True) or {"method":"unexpected"}
        rejected=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="hard-race-a",
                                    **self.webdriver_binding("hard-race-a")))
        selection=rejected["emptyCGCandidateSelection"]
        self.assertFalse(rejected["ok"]);self.assertFalse(rejected["retryable"])
        self.assertEqual(selection["decision"],"rejected");self.assertFalse(selection["stableInventory"])
        self.assertNotEqual(selection["inventoryBefore"],selection["inventoryAfter"])
        self.assertEqual({item["mappingStatus"] for item in selection["candidateOutcomes"]},{"mapped","error"})
        self.assertEqual(mutations,[])

    def test_empty_cg_title_rejects_new_mapped_auxiliary_at_placement(self):
        visible=[];obs=self.new_observer(windows=visible);obs.handle(request(obs,1,"baseline",titleNonce="drift-a",bindingMode="late"))
        main={**self.live[0],"windowId":9,"name":""};aux={**self.live[0],"windowId":10,"name":""};visible.extend([main,aux])
        obs.ax_windows_fn=lambda pid,_window_id,nonce:[self.empty_ax_record(nonce=nonce,pid=pid,window_id=9,
            bounds={key:main[key] for key in ("x","y","width","height")})]
        probe=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="drift-a",
                                 **self.webdriver_binding("drift-a")))
        self.assertTrue(probe["ok"]);mutations=[]
        def both_map(pid,window_id,nonce):
            target=main if window_id==9 else aux
            return [self.empty_ax_record(nonce=nonce,pid=pid,window_id=window_id,
                    bounds={key:target[key] for key in ("x","y","width","height")})]
        obs.ax_windows_fn=both_map;obs.placer=lambda *_args:mutations.append(True) or {"method":"unexpected"}
        rejected=obs.handle(request(obs,3,"place",bindingMode=MOD.EMPTY_CG_BINDING_MODE,titleNonce="drift-b",
                                    requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480},
                                    **self.webdriver_binding("drift-b")))
        self.assertFalse(rejected["ok"]);self.assertEqual(rejected["emptyCGCandidateSelection"]["mappedCount"],2)
        self.assertEqual(mutations,[]);self.assertIsNone(obs.provisional)

    def test_empty_cg_title_rejects_preexisting_and_two_mapped_unnamed_windows(self):
        preexisting=[dict(self.live[0],name="",layer=0)];obs=self.new_observer(windows=preexisting)
        obs.handle(request(obs,1,"baseline",titleNonce="pre-a",bindingMode="late"))
        with self.assertRaises(MOD.ObserverError):
            obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="pre-a",**self.webdriver_binding("pre-a")))
        for label,windows in {
            "multiple":[dict(self.live[0],name="",layer=0),dict(self.live[0],name="",layer=0,windowId=10)],
            "invisible":[dict(self.live[0],name="",layer=0,alpha=0)],
            "off-layer":[dict(self.live[0],name="",layer=1)],
            "normal-safari":[dict(self.live[0],owner="Safari",name="",layer=0)],
        }.items():
            with self.subTest(label=label):
                visible=[];candidate=self.new_observer(windows=visible)
                candidate.handle(request(candidate,1,"baseline",titleNonce=label+"-a",bindingMode="late"))
                visible.extend(windows)
                if label=="multiple":
                    pending=candidate.handle(request(candidate,2,"title-probe",bindingMode="late",titleNonce=label+"-a",**self.webdriver_binding(label+"-a")))
                    self.assertFalse(pending["ok"]);self.assertFalse(pending["ready"]);self.assertFalse(pending["retryable"])
                    self.assertEqual(pending["signedCandidateCount"],0);self.assertEqual(pending["attempt"],1)
                    self.assertEqual(len(pending["stpWindowInventory"]),2);self.assertIsNone(candidate.title_probe)
                    self.assertEqual(pending["emptyCGCandidateSelection"]["mappedCount"],2)
                else:
                    pending=candidate.handle(request(candidate,2,"title-probe",bindingMode="late",titleNonce=label+"-a",**self.webdriver_binding(label+"-a")) )
                    self.assertFalse(pending["ok"]);self.assertEqual(pending["signedCandidateCount"],0)

    def test_empty_cg_title_rejects_webdriver_pid_handle_title_and_ax_mapping_drift(self):
        invalid_webdriver=(
            {**self.webdriver_binding("strict-a"),"webdriverBrowserPid":88},
            {**self.webdriver_binding("strict-a"),"webdriverWindowHandles":["owned-main","other"]},
            {**self.webdriver_binding("strict-a"),"webdriverWindowHandle":"other"},
            {**self.webdriver_binding("strict-a"),"webdriverDocumentTitle":"wrong"},
        )
        for index,evidence in enumerate(invalid_webdriver):
            visible=[];obs=self.new_observer(windows=visible);obs.handle(request(obs,1,"baseline",titleNonce="strict-a",bindingMode="late"));visible.append(dict(self.live[0],name="",layer=0))
            if index==0:
                rejected=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="strict-a",**evidence))
                self.assertFalse(rejected["ok"]);self.assertFalse(rejected["retryable"])
            else:
                with self.assertRaises(MOD.ObserverError):obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="strict-a",**evidence))
        bad_ax=([],[self.empty_ax_record(window_id=10)],[self.empty_ax_record(nonce="mismatch")],
                [self.empty_ax_record(bounds={"x":0,"y":0,"width":1,"height":1})])
        for index,records in enumerate(bad_ax):
            visible=[];obs=self.new_observer(windows=visible);obs.ax_windows_fn=lambda *_args,records=records:records
            obs.handle(request(obs,1,"baseline",titleNonce="ax-a",bindingMode="late"));visible.append(dict(self.live[0],name="",layer=0,x=-1320,y=39))
            response=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="ax-a",**self.webdriver_binding("ax-a")))
            self.assertFalse(response["ok"])
            self.assertEqual(response["retryable"],index==1)

    def test_empty_cg_title_rejects_webdriver_handle_drift_across_phases(self):
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}

        visible=[];probe_to_place=self.new_observer(windows=visible)
        probe_to_place.handle(request(probe_to_place,1,"baseline",titleNonce="place-a",bindingMode="late"))
        visible.append(dict(self.live[0],name="",layer=0,x=-1320,y=39))
        probe_to_place.handle(request(probe_to_place,2,"title-probe",bindingMode="late",titleNonce="place-a",
                                      **self.webdriver_binding("place-a")))
        drifted_place={**self.webdriver_binding("place-b"),"webdriverWindowHandle":"other","webdriverWindowHandles":["other"]}
        with self.assertRaises(MOD.ObserverError):
            probe_to_place.handle(request(probe_to_place,3,"place",bindingMode=MOD.EMPTY_CG_BINDING_MODE,
                                          titleNonce="place-b",requestedBounds=requested,**drifted_place))

        visible=[];place_to_claim=self.new_observer(windows=visible)
        place_to_claim.handle(request(place_to_claim,1,"baseline",titleNonce="claim-a",bindingMode="late"))
        visible.append(dict(self.live[0],name="",layer=0,x=-1320,y=39))
        place_to_claim.handle(request(place_to_claim,2,"title-probe",bindingMode="late",titleNonce="claim-a",
                                      **self.webdriver_binding("claim-a")))
        place_to_claim.placer=lambda pid,window_id,title,bounds:(visible[0].update(bounds),{"method":"test-empty-title-AX"})[-1]
        place_to_claim.handle(request(place_to_claim,3,"place",bindingMode=MOD.EMPTY_CG_BINDING_MODE,
                                      titleNonce="claim-b",requestedBounds=requested,**self.webdriver_binding("claim-b")))
        drifted_claim={**self.webdriver_binding("claim-b"),"webdriverWindowHandle":"other","webdriverWindowHandles":["other"]}
        with self.assertRaises(MOD.ObserverError):
            place_to_claim.handle(request(place_to_claim,4,"claim",bindingMode=MOD.EMPTY_CG_BINDING_MODE,
                                          titleNonce="claim-b",requestedBounds=requested,**drifted_claim))

    def test_empty_cg_title_rejects_nonempty_mismatch_swap_and_containment_failure(self):
        visible=[];obs=self.new_observer(windows=visible);obs.handle(request(obs,1,"baseline",titleNonce="notitle-a",bindingMode="late"))
        visible.append(dict(self.live[0],name="ImprovedTube bootstrap",layer=0))
        pending=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="notitle-a",**self.webdriver_binding("notitle-a")))
        self.assertFalse(pending["ok"]);self.assertNotEqual(pending.get("bindingMode"),MOD.EMPTY_CG_BINDING_MODE)
        visible=[];bound=self.new_observer(windows=visible);bound.handle(request(bound,1,"baseline",titleNonce="swap-a",bindingMode="late"));visible.append(dict(self.live[0],name="",layer=0))
        self.assertTrue(bound.handle(request(bound,2,"title-probe",bindingMode="late",titleNonce="swap-a",**self.webdriver_binding("swap-a")))["ok"])
        visible[0].update({"pid":88,"windowId":19});bound.process_fn=lambda pid:self.process(77) if pid==77 else {**self.process(77),"pid":88,"startTime":"start-b"}
        swapped=bound.handle(request(bound,3,"place",bindingMode=MOD.EMPTY_CG_BINDING_MODE,titleNonce="swap-b",requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480},**self.webdriver_binding("swap-b")))
        self.assertFalse(swapped["ok"])
        visible=[];outside=self.new_observer(windows=visible);outside.handle(request(outside,1,"baseline",titleNonce="outside-a",bindingMode="late"));visible.append(dict(self.live[0],name="",layer=0))
        outside.handle(request(outside,2,"title-probe",bindingMode="late",titleNonce="outside-a",**self.webdriver_binding("outside-a")))
        with self.assertRaises(MOD.ObserverError):outside.handle(request(outside,3,"place",bindingMode=MOD.EMPTY_CG_BINDING_MODE,titleNonce="outside-b",requestedBounds={"x":0,"y":0,"width":1360,"height":2480},**self.webdriver_binding("outside-b")))

    def test_empty_cg_title_native_helper_mapping_parser_is_exact(self):
        bounds={"x":-1320,"y":39,"width":1360,"height":2480}
        candidate={"pid":77,"windowId":9,"axWindowNumber":9,"title":"","bounds":dict(bounds)}
        payload={"ok":True,"method":"application-services-ax","operation":"inspect-empty-cg-title",
            "bindingMode":MOD.EMPTY_CG_BINDING_MODE,"mappingStatus":"mapped","helperUid":os.getuid(),"pid":77,"windowId":9,
            "axWindowNumber":9,"titleNonce":"empty-a","nativeTitle":"",
            "mappingMethod":"ax-window-number-empty-cg-title","cgBefore":dict(bounds),
            "candidateCount":1,"matchedCount":1,"candidates":[candidate],"before":dict(bounds),
            "titleEvidence":"webdriver-document-title","mutationAttempted":False}
        result=lambda value:SimpleNamespace(returncode=0,stdout=json.dumps(value)+"\n",stderr="")
        evidence=MOD.parse_empty_title_ax_helper_result(result(payload),77,9,"empty-a",bounds,"inspect-empty-cg-title")
        self.assertTrue(evidence["verified"]);self.assertEqual(evidence["axWindowNumber"],9)
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        placement={**payload,"operation":"split","mutationAttempted":True,"requestedBounds":requested,
            "after":requested,"positionSettable":True,"sizeSettable":True,
            "resizeMethod":"webDriver-existing","moveMethod":"AX",
            "beforePosition":{"x":bounds["x"],"y":bounds["y"]},
            "beforeSize":{"width":bounds["width"],"height":bounds["height"]},
            "intermediateBounds":dict(bounds)}
        self.assertTrue(MOD.parse_empty_title_ax_helper_result(result(placement),77,9,"empty-a",bounds,"split",requested)["verified"])
        unmapped={"ok":True,"method":"application-services-ax","operation":"inspect-empty-cg-title",
            "bindingMode":MOD.EMPTY_CG_BINDING_MODE,"mappingStatus":"unmapped","helperUid":os.getuid(),
            "pid":77,"windowId":9,"titleNonce":"empty-a","nativeTitle":"","cgBefore":dict(bounds),
            "candidateCount":1,"matchedCount":0,
            "candidates":[{"pid":77,"axWindowNumber":10,"title":"","bounds":dict(bounds)}],
            "mutationAttempted":False}
        parsed_unmapped=MOD.parse_empty_title_ax_helper_result(result(unmapped),77,9,"empty-a",bounds,"inspect-empty-cg-title")
        self.assertTrue(parsed_unmapped["verified"]);self.assertEqual(parsed_unmapped["mappingStatus"],"unmapped")
        forged=copy.deepcopy(unmapped)
        forged["candidates"][0].update({"axWindowNumber":9,"bounds":{"x":0,"y":0,"width":1,"height":1}})
        with self.assertRaises(MOD.ObserverError):
            MOD.parse_empty_title_ax_helper_result(result(forged),77,9,"empty-a",bounds,"inspect-empty-cg-title")
        mutations=(
            lambda p:p.update(axWindowNumber=10),
            lambda p:p["candidates"][0].update(axWindowNumber=10),
            lambda p:p["candidates"][0].update(title="mismatch"),
            lambda p:p.update(candidateCount=2),
            lambda p:p.update(mutationAttempted=True),
            lambda p:p.update(bindingMode="late"),
            lambda p:p.update(cgBefore={"x":0,"y":0,"width":1,"height":1}),
        )
        for mutate in mutations:
            bad=copy.deepcopy(payload);mutate(bad)
            with self.assertRaises(MOD.ObserverError):
                MOD.parse_empty_title_ax_helper_result(result(bad),77,9,"empty-a",bounds,"inspect-empty-cg-title")

    def test_empty_cg_title_native_helper_failure_is_strict_sanitized_and_bounded(self):
        bounds={"x":-1320,"y":39,"width":1360,"height":2480}
        result=lambda value,returncode=1:SimpleNamespace(returncode=returncode,stdout=json.dumps(value)+"\n",stderr="")
        valid={"ok":False,"method":"application-services-ax","error":"Accessibility trust is unavailable"}
        with self.assertRaisesRegex(MOD.ObserverError,
                r"^empty-title AX helper failure: Accessibility trust is unavailable$"):
            MOD.parse_empty_title_ax_helper_result(result(valid),77,9,"failure-a",bounds,"inspect-empty-cg-title")
        status={**valid,"error":"AX window number unavailable: AXWindowNumber status=-25205"}
        with self.assertRaisesRegex(MOD.ObserverError,
                r"^empty-title AX helper failure: AX window number unavailable: AXWindowNumber status=-25205$"):
            MOD.parse_empty_title_ax_helper_result(result(status),77,9,"failure-a",bounds,"inspect-empty-cg-title")
        for raw in ("AX attribute unavailable: AXWindows status=-25200",
                    "AX window number unavailable: _AXWindowNumber status=0"):
            with self.subTest(raw=raw),self.assertRaises(MOD.ObserverError) as caught:
                MOD.parse_empty_title_ax_helper_result(result({**valid,"error":raw}),77,9,"failure-a",bounds,
                                                       "inspect-empty-cg-title")
            self.assertEqual(str(caught.exception),"empty-title AX helper failure: "+raw)
        malformed=(
            ({**valid,"extra":"value"},1),
            ({"ok":False,"method":"application-services-ax"},1),
            ({**valid,"ok":True},1),
            ({**valid,"method":"other"},1),
            ({**valid,"error":1},1),
            ({**valid,"error":""},1),
            ({**valid,"error":" leading"},1),
            ({**valid,"error":"line\nbreak"},1),
            ({**valid,"error":"x"*513},1),
            ({**valid,"error":"failure at /tmp/private-helper"},1),
            ({**valid,"error":"capability secret-value"},1),
            (valid,0),
            (valid,2),
        )
        for payload,returncode in malformed:
            with self.subTest(payload=payload,returncode=returncode):
                with self.assertRaises(MOD.ObserverError) as caught:
                    MOD.parse_empty_title_ax_helper_result(result(payload,returncode),77,9,"failure-a",bounds,
                                                           "inspect-empty-cg-title")
                self.assertEqual(str(caught.exception),"empty-title AX helper rejected exact mapping")
                self.assertNotIn("/tmp/private-helper",str(caught.exception))
                self.assertNotIn("secret-value",str(caught.exception))

    def test_empty_cg_title_native_helper_failure_rejects_secrets_entropy_and_unicode_everywhere(self):
        bounds={"x":-1408,"y":-900,"width":1360,"height":2480}
        unsafe=("password=hunter2","passwd hunter2","Bearer abcdefghijklmnopqrstuvwxyz0123456789",
                "authorization: Basic dXNlcjpwYXNz","api_key=0123456789abcdef0123456789abcdef",
                "cookie=session-value","session_id=0123456789abcdef","private_key=abcdef",
                "access_key=abcdef","0123456789abcdef"*8,
                "safe\u0085unsafe","safe\u202eunsafe","safe\u200bunsafe","\ud800")
        for raw in unsafe:
            with self.subTest(raw=ascii(raw)):
                payload={"ok":False,"method":"application-services-ax","error":raw}
                result=SimpleNamespace(returncode=1,stdout=json.dumps(payload)+"\n",stderr="")
                with self.assertRaises(MOD.ObserverError) as caught:
                    MOD.parse_empty_title_ax_helper_result(result,77,9,"unsafe-a",bounds,"inspect-empty-cg-title")
                self.assertEqual(str(caught.exception),"empty-title AX helper rejected exact mapping")

                visible=[];obs=self.new_observer(windows=visible)
                obs.handle(request(obs,1,"baseline",titleNonce="unsafe-a",bindingMode="late"))
                visible.append({**self.live[0],"windowId":9,"name":""})
                def helper_failure(pid,window_id,nonce,_bounds,result=result):
                    return MOD.parse_empty_title_ax_helper_result(result,pid,window_id,nonce,bounds,
                                                                  "inspect-empty-cg-title")
                obs._empty_title_ax_evidence=helper_failure
                rejected=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="unsafe-a",
                                            **self.webdriver_binding("unsafe-a")))
                outcome=rejected["emptyCGCandidateSelection"]["candidateOutcomes"][0]
                self.assertEqual(outcome["helperFailure"]["message"],
                                 "empty-title AX helper rejected exact mapping")
                serialized=json.dumps(rejected,sort_keys=True)
                self.assertNotIn(raw,serialized)

    def test_empty_cg_title_native_helper_failure_rejects_noncanonical_and_unknown_ax_status_everywhere(self):
        bounds={"x":-1408,"y":-900,"width":1360,"height":2480}
        unsafe=("AX window number unavailable: AXWindowNumber status=-0",
                "AX attribute unavailable: AXWindows status=00",
                "AX window number unavailable: AXWindowNumber status=0001",
                "AX window number unavailable: AXWindowNumber status=-025205",
                "AX attribute unavailable: AXWindows status=+1",
                "AX attribute unavailable: AXWindows status=1",
                "AX attribute unavailable: AXWindows status=-25215",
                "AX attribute unavailable: AXWindows status=9999999999")
        for raw in unsafe:
            with self.subTest(raw=raw):
                result=SimpleNamespace(returncode=1,stdout=json.dumps({"ok":False,
                    "method":"application-services-ax","error":raw})+"\n",stderr="")
                with self.assertRaises(MOD.ObserverError) as caught:
                    MOD.parse_empty_title_ax_helper_result(result,77,9,"status-a",bounds,"inspect-empty-cg-title")
                self.assertEqual(str(caught.exception),"empty-title AX helper rejected exact mapping")

                visible=[];obs=self.new_observer(windows=visible)
                obs.handle(request(obs,1,"baseline",titleNonce="status-a",bindingMode="late"))
                visible.append({**self.live[0],"windowId":9,"name":""})
                def helper_failure(pid,window_id,nonce,_bounds,result=result):
                    return MOD.parse_empty_title_ax_helper_result(result,pid,window_id,nonce,bounds,
                                                                  "inspect-empty-cg-title")
                obs._empty_title_ax_evidence=helper_failure
                rejected=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="status-a",
                                            **self.webdriver_binding("status-a")))
                outcome=rejected["emptyCGCandidateSelection"]["candidateOutcomes"][0]
                self.assertEqual(outcome["helperFailure"]["message"],
                                 "empty-title AX helper rejected exact mapping")
                self.assertNotIn(raw,json.dumps(rejected,sort_keys=True))

    def test_empty_cg_title_valid_native_helper_failure_survives_candidate_outcomes_without_leakage(self):
        visible=[];obs=self.new_observer(windows=visible)
        obs.handle(request(obs,1,"baseline",titleNonce="failure-a",bindingMode="late"))
        visible.extend([{**self.live[0],"windowId":9,"name":""},{**self.live[0],"windowId":10,"name":""}])
        bounds={"x":-1408,"y":-900,"width":1360,"height":2480}
        def helper_failure(pid,window_id,nonce,_bounds):
            result=SimpleNamespace(returncode=1,stdout=json.dumps({"ok":False,"method":"application-services-ax",
                "error":"AX windows attribute is missing or malformed"})+"\n",stderr="")
            return MOD.parse_empty_title_ax_helper_result(result,pid,window_id,nonce,bounds,"inspect-empty-cg-title")
        obs._empty_title_ax_evidence=helper_failure
        rejected=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="failure-a",
                                    **self.webdriver_binding("failure-a")))
        selection=rejected["emptyCGCandidateSelection"]
        self.assertFalse(rejected["ok"]);self.assertFalse(rejected["retryable"])
        self.assertEqual([item["helperFailure"]["message"] for item in selection["candidateOutcomes"]],
                         ["empty-title AX helper failure: AX windows attribute is missing or malformed"]*2)
        serialized=json.dumps(selection,sort_keys=True).casefold()
        self.assertNotIn("capability",serialized);self.assertNotIn("/tmp/",serialized)

    def test_empty_cg_title_production_path_uses_pinned_read_only_ax_helper(self):
        visible=[]
        obs=MOD.AquaObserver(Path(tempfile.mkdtemp())/"observer.sock","run-a","cap-a",502,
            windows_fn=lambda:visible,process_fn=self.process,peer_fn=lambda _sock:502,
            ax_windows_fn=None,ax_helper_fd=44,ax_helper_digest="a"*64,ax_helper_device=1,ax_helper_inode=2)
        obs.peer_uid_actual=502;obs.handle(request(obs,1,"baseline",titleNonce="helper-a",bindingMode="late"))
        bounds={"x":-1320,"y":39,"width":1360,"height":2480}
        visible.append(dict(self.live[0],name="",layer=0,**bounds));calls=[]
        payload={"ok":True,"method":"application-services-ax","operation":"inspect-empty-cg-title",
            "bindingMode":MOD.EMPTY_CG_BINDING_MODE,"mappingStatus":"mapped","helperUid":os.getuid(),"pid":77,"windowId":9,
            "axWindowNumber":9,"titleNonce":"helper-a","nativeTitle":"",
            "mappingMethod":"ax-window-number-empty-cg-title","cgBefore":dict(bounds),
            "candidateCount":1,"matchedCount":1,
            "candidates":[{"pid":77,"windowId":9,"axWindowNumber":9,"title":"","bounds":dict(bounds)}],
            "before":dict(bounds),"titleEvidence":"webdriver-document-title","mutationAttempted":False}
        original_validate=MOD._validate_helper_fd;original_run=MOD._run_helper_fd
        try:
            MOD._validate_helper_fd=lambda *_args:None
            def run_helper(*args):
                argv=args[-1];calls.append(argv)
                if argv[-2]=="inspect-empty-cg-title":
                    current={"x":int(argv[5]),"y":int(argv[6]),"width":int(argv[7]),"height":int(argv[8])}
                    value={**payload,"titleNonce":argv[3],"cgBefore":current,"before":current,
                           "candidates":[{**payload["candidates"][0],"bounds":current}]}
                else:
                    requested={"x":-1408,"y":-900,"width":1360,"height":2480}
                    value={**payload,"operation":"split","titleNonce":"helper-b","mutationAttempted":True,
                        "requestedBounds":requested,"after":requested,"positionSettable":True,"sizeSettable":True,
                        "resizeMethod":"webDriver-existing","moveMethod":"AX",
                        "beforePosition":{"x":bounds["x"],"y":bounds["y"]},
                        "beforeSize":{"width":bounds["width"],"height":bounds["height"]},
                        "intermediateBounds":dict(bounds)}
                    visible[0].update(requested)
                return SimpleNamespace(returncode=0,stdout=json.dumps(value)+"\n",stderr="")
            MOD._run_helper_fd=run_helper
            probe=obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="helper-a",**self.webdriver_binding("helper-a")))
            placed=obs.handle(request(obs,3,"place",bindingMode=MOD.EMPTY_CG_BINDING_MODE,titleNonce="helper-b",
                requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480},**self.webdriver_binding("helper-b")))
        finally:MOD._validate_helper_fd=original_validate;MOD._run_helper_fd=original_run
        self.assertTrue(probe["ok"]);self.assertTrue(placed["ok"]);self.assertEqual(len(calls),4)
        self.assertEqual(calls[0][0:5],["improvedtube-aqua-ax-helper","77","9","helper-a",""])
        self.assertEqual(calls[0][-2:],["inspect-empty-cg-title",MOD.EMPTY_CG_BINDING_MODE])
        self.assertEqual(calls[1][-2:],["inspect-empty-cg-title",MOD.EMPTY_CG_BINDING_MODE])
        self.assertEqual(calls[2][-2:],["split",MOD.EMPTY_CG_BINDING_MODE])
        self.assertEqual(calls[3][-2:],["inspect-empty-cg-title",MOD.EMPTY_CG_BINDING_MODE])

    def test_title_probe_pending_never_accepts_ambiguity_or_identity_swap(self):
        visible=[];obs=self.new_observer(windows=visible)
        obs.handle(request(obs,1,"baseline",titleNonce="strict-a",bindingMode="late"))
        visible.append(dict(self.live[0],name="ImprovedTube bootstrap"))
        self.assertFalse(obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="strict-a"))["ok"])
        visible[0].update({"pid":88,"windowId":19,"name":"Personal — strict-a"})
        obs.process_fn=lambda pid:self.process(77) if pid==77 else {**self.process(77),"pid":88,"startTime":"start-b"}
        with self.assertRaises(MOD.ObserverError):
            obs.handle(request(obs,3,"title-probe",bindingMode="late",titleNonce="strict-a"))
        invisible=[];other=self.new_observer(windows=invisible)
        other.handle(request(other,1,"baseline",titleNonce="invisible-a",bindingMode="late"))
        invisible.append(dict(self.live[0],alpha=0,name="Personal — invisible-a"))
        pending=other.handle(request(other,2,"title-probe",bindingMode="late",titleNonce="invisible-a"))
        self.assertFalse(pending["ok"]);self.assertEqual(pending["signedCandidateCount"],0)

    def test_title_probe_rejects_nonce_position_multiplicity_and_cg_swap(self):
        for native in ("probe-aPersonal — ", "Personal — probe-aprobe-a", "Personal — probe-a-suffix"):
            with self.subTest(native=native):
                visible=[];obs=self.new_observer(windows=visible);obs.handle(request(obs,1,"baseline",titleNonce="probe-a",bindingMode="late"))
                visible.append(dict(self.live[0],name=native))
                with self.assertRaises(MOD.ObserverError):obs.handle(request(obs,2,"title-probe",bindingMode="late",titleNonce="probe-a"))
        obs=self.new_observer();self.prime_late(obs,"swap-a","swap-b")
        self.live[0].update({"pid":88,"windowId":19})
        obs.process_fn=lambda pid:self.process(77) if pid==77 else {**self.process(77),"pid":88,"startTime":"start-b"}
        with self.assertRaises(MOD.ObserverError):
            obs.handle(request(obs,3,"place",bindingMode="late",titleNonce="swap-b",
                               requestedBounds={"x":-1408,"y":-900,"width":1360,"height":2480}))

    def test_ax_title_geometry_fallback_and_ambiguity_fail_before_mutation(self):
        requested={"x":-1408,"y":-900,"width":1360,"height":2480}
        obs=self.new_observer();_a,b,prefix,_probe=self.prime_late(obs,"ax-fallback-a","ax-fallback-b")
        native=prefix+b
        obs.ax_windows_fn=lambda *_args:[{"owner":"Safari Technology Preview","bundleId":MOD.STP_BUNDLE_ID,
            "pid":77,"title":native,"axWindowNumber":None,"bounds":dict(requested)}]
        calls=[]
        def placer(_pid,_wid,_title,bounds):calls.append(True);self.live[0].update(bounds);return {"method":"fallback"}
        obs.placer=placer
        response=obs.handle(request(obs,3,"place",bindingMode="late",titleNonce=b,requestedBounds=requested))
        self.assertTrue(response["ok"]);self.assertEqual(response["placementEvidence"]["axBefore"]["mappingMethod"],"title-geometry")
        self.assertEqual(len(calls),1)
        for records in (
            [{"owner":"Safari Technology Preview","bundleId":MOD.STP_BUNDLE_ID,"pid":77,"title":native,"axWindowNumber":None,"bounds":dict(requested)},
             {"owner":"Safari Technology Preview","bundleId":MOD.STP_BUNDLE_ID,"pid":77,"title":native,"axWindowNumber":None,"bounds":dict(requested)}],
            [{"owner":"Safari Technology Preview","bundleId":MOD.STP_BUNDLE_ID,"pid":77,"title":native,"axWindowNumber":10,"bounds":dict(requested)}],
        ):
            bad=self.new_observer();self.prime_late(bad,"ax-bad-a","ax-bad-b");calls=[];bad.ax_windows_fn=lambda *_args,records=records:records;bad.placer=lambda *_args:(calls.append(True),{"method":"must-not"})[-1]
            with self.assertRaises(MOD.ObserverError):bad.handle(request(bad,3,"place",bindingMode="late",titleNonce="ax-bad-b",requestedBounds=requested))
            self.assertEqual(calls,[])

if __name__=="__main__":
    unittest.main(verbosity=2)
