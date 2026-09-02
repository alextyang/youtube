#!/usr/bin/env python3
"""Fail-closed Safari E2E release gate for signed ImprovedTube builds.
Static discovery is source evidence only; live PASS requires an explicit semantic
contract and exact persisted restoration.
"""
from __future__ import annotations
import argparse, base64, ctypes, datetime as dt, hashlib, hmac, http.client, json, os, plistlib
import re, secrets, socket, subprocess, sys, time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterable
try:
    from full_live_framework import (MISSING, ContractSpec, DirectStorageAdapter, FeaturePlan, FullLivePreflight, OracleKind,
        OracleSpec, ROUTE_FIXTURES, StorageAdapter, StorageSnapshot, atomic_json_dump, build_feature_plan,
        contract_file_schema, contract_from_feature_contract, dispatch_oracle, extract_menu_metadata,
        fixture_for, load_contract_file, load_contract_files, normalize_contract, preflight_full_live as framework_preflight,
        oracle_matches, validate_fixture, validate_plan as framework_validate_plan)
except ImportError:
    from scripts.appstore.full_live_framework import (MISSING, ContractSpec, DirectStorageAdapter, FeaturePlan, FullLivePreflight, OracleKind,
        OracleSpec, ROUTE_FIXTURES, StorageAdapter, StorageSnapshot, atomic_json_dump, build_feature_plan,
        contract_file_schema, contract_from_feature_contract, dispatch_oracle, extract_menu_metadata,
        fixture_for, load_contract_file, load_contract_files, normalize_contract, preflight_full_live as framework_preflight,
        oracle_matches, validate_fixture, validate_plan as framework_validate_plan)

ROOT=Path(__file__).resolve().parents[2]
APP_PATH=Path("/Applications/ImprovedTube.app")
EXTENSION_RELATIVE=Path("Contents/PlugIns/ImprovedTube Extension.appex")
INSTALLED=APP_PATH/EXTENSION_RELATIVE/"Contents/Resources"
RESULTS_ROOT=ROOT/".appstore/testing/e2e-results"
INDEX_PATH=ROOT/".appstore/testing/safari-e2e-assertions.md"
EXPECTED_APP_BUNDLE_ID="com.tiendoxuan.improvedtube"
EXPECTED_EXTENSION_BUNDLE_ID="com.tiendoxuan.improvedtube.Extension"
EXPECTED_TESTFLIGHT_AUTHORITY="TestFlight Beta Distribution"
EXPECTED_TEAM_IDENTIFIER="76JE9YNX29"
KG271U_BOUNDS={"x":-1440,"y":-940,"right":0,"bottom":1620}
ROUTES={"watch":"https://www.youtube.com/watch?v=dQw4w9WgXcQ","channel":"https://www.youtube.com/@YouTube",
"playlist":"https://www.youtube.com/playlist?list=PLk0bA6F9VgRV1iQ-vMtRjzZAjiml5PjVm",
"search":"https://www.youtube.com/results?search_query=ImprovedTube","shorts":"https://www.youtube.com/shorts/aqz-KE-bpKQ"}
PASS,FAIL="PASS","FAIL";UNVERIFIED,NOT_RUN="UNVERIFIED","NOT_RUN"
PRODUCT_FAILURE,HARNESS_FAILURE="PRODUCT_FAILURE","HARNESS_FAILURE"
ISOLATION_FAILURE,ENVIRONMENT_FAILURE="ISOLATION_FAILURE","ENVIRONMENT_FAILURE"
NOT_APPLICABLE="NOT_APPLICABLE"
EVIDENCE_CLASSES={"identity","discovery","transport","live-semantic","source-only","product","isolation","harness","environment","console","coverage"}
OBSERVER_CAPABILITY_ENV="IMPROVEDTUBE_AQUA_OBSERVER_CAPABILITY"
OBSERVER_BRIDGE_PROTOCOL="improvedtube-aqua-bridge-v1"
CANDIDATE_SURFACE_PATHS=(
    Path(".gitignore"),
    Path("package.json"),
    Path(".appstore/testing/safari-e2e-assertions.md"),
    Path("scripts/appstore/aqua_window_observer.py"),
    Path("scripts/appstore/full_live_framework.py"),
    Path("scripts/appstore/launch_aqua_observer.py"),
    Path("scripts/appstore/safari_e2e.py"),
    Path("scripts/appstore/test_aqua_window_observer.py"),
    Path("scripts/appstore/test_safari_e2e.py"),
)

@dataclass(frozen=True)
class Feature:
    feature_id:str; key:str; component:str; source:str; route:str; probe:Any
    storage_key:str|None=None; menu_id:str|None=None; labels:tuple[str,...]=(); tags:tuple[str,...]=()
    default:Any=None; options:tuple[Any,...]=(); min:Any=None; max:Any=None; step:Any=None
    metadata_digest:str=""; source_hints:tuple[str,...]=(); classification:str="actual_feature"; metadata:Any=None

@dataclass(frozen=True)
class FeatureContract:
    """Data-driven route, lifecycle and semantic observation contract."""
    key:str; route:str; setup_js:str; activation_js:str; before_observe_js:str
    after_observe_js:str; cleanup_js:str; prerequisites:tuple[str,...]
    observation_kind:str; activation_value:Any; evidence_class:str="live-semantic"
    known_regression:str|None=None

@dataclass
class Result:
    assertion_id:str; feature_id:str; assertion:str; status:str
    evidence_class:str; route:str; phase:str; evidence:Any; duration_ms:int

@dataclass(frozen=True)
class StorageState:
    present:bool; value:Any=None

@dataclass(frozen=True)
class WebDriverResponse:
    """Decoded response envelope preserving the W3C object and value."""
    status:int
    body:dict[str,Any]
    value:Any

def strict_json_loads(raw:bytes)->Any:
    """Decode JSON without silently collapsing duplicate or non-finite data."""
    if type(raw) is not bytes:raise ValueError("WebDriver response must be bytes")
    def object_without_duplicates(pairs:list[tuple[str,Any]])->dict[str,Any]:
        value={}
        for key,item in pairs:
            if key in value:raise ValueError("duplicate JSON object member")
            value[key]=item
        return value
    def reject_constant(value:str)->Any:raise ValueError("non-finite JSON constant "+value)
    return json.loads(raw.decode("utf-8"),object_pairs_hook=object_without_duplicates,parse_constant=reject_constant)

FALSY_PROBE_STATES=(StorageState(True,False),StorageState(True,0),StorageState(True,""),StorageState(True,None),StorageState(False,None))

def camelize(key:str)->str:
    p=key.split("_");return p[0]+"".join(x[:1].upper()+x[1:] for x in p[1:])

def route_for(key:str)->str:
    low=key.lower()
    if "short" in low and "shortcut" not in low:return "shorts"
    if "playlist" in low:return "playlist"
    if "channel" in low or "subscriber" in low:return "channel"
    if "search" in low:return "search"
    return "watch"

def balanced_object(text:str,start:int)->str:
    depth=0;quote="";escaped=False
    for pos in range(start,len(text)):
        ch=text[pos]
        if quote:
            if escaped:escaped=False
            elif ch=="\\\\":escaped=True
            elif ch==quote:quote=""
            continue
        if ch in ("'",'"',chr(96)):quote=ch
        elif ch=="{":depth+=1
        elif ch=="}":
            depth-=1
            if depth==0:return text[start:pos+1]
    return text[start:]

def scalar(pattern:str,body:str)->Any:
    m=re.search(pattern,body)
    if not m:return None
    raw=m.group(1)
    if raw in ("true","false"):return raw=="true"
    if raw=="null":return None
    if re.fullmatch(r"-?\d+(?:\.\d+)?",raw):return float(raw) if "." in raw else int(raw)
    return raw.strip("'\\\"")

def probe_for(component:str,body:str)->Any:
    cur=scalar(r"\bvalue\s*:\s*(true|false|null|-?\d+(?:\.\d+)?|'[^']*'|\"[^\"]*\")",body)
    if component=="switch":return not cur if isinstance(cur,bool) else True
    if component=="slider":
        lo=scalar(r"\bmin\s*:\s*(-?\d+(?:\.\d+)?)",body);hi=scalar(r"\bmax\s*:\s*(-?\d+(?:\.\d+)?)",body)
        lo=0 if lo is None else lo;hi=100 if hi is None else hi;return lo+(hi-lo)/2
    if component=="color-picker":return [12,34,56]
    if component=="text-field":return "ImprovedTube E2E"
    if component=="shortcut":return {"keys":{"65":{"key":"a","code":"KeyA"}}}
    choices=re.findall(r"\bvalue\s*:\s*('([^']*)'|\"([^\"]*)\"|-?\d+(?:\.\d+)?)",body)
    for whole,single,double in choices:
        value=single or double or whole
        if value!=str(cur):
            try:return int(value)
            except ValueError:return value.strip("'\\\"")
    return "default"

def discover_features(root:Path)->list[Feature]:
    directory=root/"menu/skeleton-parts"
    if not directory.is_dir():raise RuntimeError("missing menu/skeleton-parts in "+str(root))
    pat=re.compile(r"(?P<key>[A-Za-z_$][\w$-]*)\s*:\s*\{\s*component\s*:\s*['\"](?P<component>switch|select|slider|radio|shortcut|color-picker|text-field)['\"]")
    found={}
    for path in sorted(directory.glob("*.js")):
        text=path.read_text(errors="replace")
        for m in pat.finditer(text):
            body=balanced_object(text,text.find("{",m.start()))
            key=scalar(r"\bstorage\s*:\s*('[^']*'|\"[^\"]*\")",body) or m.group("key")
            if not isinstance(key,str) or not key or key in found:continue
            rel=path.relative_to(root).as_posix();component=m.group("component")
            fid="IT-"+hashlib.sha1((key+"|"+rel).encode()).hexdigest()[:8].upper()
            metadata=extract_menu_metadata(body,key,component,rel,m.group("key"))
            found[key]=Feature(fid,key,component,rel,route_for(key),probe_for(component,body),
                               metadata["storageKey"],metadata["menuId"],tuple(metadata["labels"]),tuple(metadata["tags"]),
                               metadata["default"],tuple(metadata["options"]),metadata["min"],metadata["max"],metadata["step"],
                               metadata["metadataDigest"],tuple(metadata["sourceHints"]),"actual_feature",metadata)
    return sorted(found.values(),key=lambda f:(f.route,f.key))

BRIDGE_JS="""const p=document.querySelector('#it-messages-from-extension');
const attr=k=>p?.getAttribute(k)||null;
return {improvedTube:typeof window.ImprovedTube==='object',
storage:!!(window.ImprovedTube&&ImprovedTube.storage&&typeof ImprovedTube.storage==='object'),
messages:!!(window.ImprovedTube&&ImprovedTube.messages&&typeof ImprovedTube.messages.send==='function'),
provider:!!p,providerId:p?.id||null,
providerBundleId:attr('data-it-provider-bundle-id'),providerCDHash:attr('data-it-provider-cdhash'),
providerAssetSHA256:attr('data-it-provider-asset-sha256'),providerProtocol:attr('data-it-provider-protocol'),
providerContentDigest:attr('data-it-provider-content-digest')};"""
STORAGE_STATE_JS="""const key=arguments[0],s=window.ImprovedTube&&ImprovedTube.storage;
const provider=document.querySelector('#it-messages-from-extension');let storageLoaded=false;
try{storageLoaded=JSON.parse(provider?.textContent||'null')?.action==='storage-loaded';}catch{}
const own=!!s&&Object.prototype.hasOwnProperty.call(s,key),present=own&&typeof s[key]!=='undefined';return {present,value:present?s[key]:null,mirrorOwn:own,storageLoaded};"""
PAGE_STORAGE_SNAPSHOT_JS="""const keys=arguments[0],provider=document.querySelector('#it-messages-from-extension');
if(!provider)return {ok:false,storageLoaded:false};const read=()=>{try{return JSON.parse(provider.textContent||'null')}catch{return null}};
if(!globalThis.__itE2EPersistedStorage){const initial=read(),mirror=window.ImprovedTube?.storage,source=initial?.action==='storage-loaded'&&initial.storage&&typeof initial.storage==='object'?initial.storage:mirror&&typeof mirror==='object'?mirror:null;if(!source)return {ok:false,storageLoaded:false,mirrorFallback:false};
globalThis.__itE2EPersistedStorage=JSON.parse(JSON.stringify(source));globalThis.__itE2EMirrorFallback=source===mirror;document.addEventListener('it-message-from-extension',()=>{const update=read();
if(update?.action==='storage-loaded'&&update.storage&&typeof update.storage==='object')globalThis.__itE2EPersistedStorage=JSON.parse(JSON.stringify(update.storage));
else if(update?.action==='storage-changed'&&typeof update.key==='string'){if(Object.prototype.hasOwnProperty.call(update,'value'))globalThis.__itE2EPersistedStorage[update.key]=update.value;else delete globalThis.__itE2EPersistedStorage[update.key];}});}
const s=globalThis.__itE2EPersistedStorage,selected=keys===null?Object.keys(s):keys,value={};for(const key of selected)if(Object.prototype.hasOwnProperty.call(s,key))value[key]=s[key];return {ok:true,storageLoaded:true,mirrorFallback:globalThis.__itE2EMirrorFallback===true,value};"""
SEND_STORAGE_JS="""const q=arguments[0];if(!window.ImprovedTube||!ImprovedTube.messages)return {sent:false,reason:'ImprovedTube bridge absent'};
if(typeof q.present!=='boolean')return {sent:false,reason:'explicit present boolean required'};
const payload=q.present?{action:'set',key:q.key,value:q.value}:{action:'set',key:q.key,value:false};
ImprovedTube.messages.send(payload);return {sent:true,operation:q.present?'set':'delete',requested:q,queueDepth:ImprovedTube.messages.queue?.length??null};"""
INSTRUMENT_JS="""if(!window.__itE2E){window.__itE2E={phase:'route-load',errors:[]};
addEventListener('error',function(e){window.__itE2E.errors.push({route:location.href,phase:window.__itE2E.phase,message:String(e.message||e.error||'window error'),source:e.filename||null,line:e.lineno||null,column:e.colno||null})});
addEventListener('unhandledrejection',function(e){window.__itE2E.errors.push({route:location.href,phase:window.__itE2E.phase,message:String(e.reason||'unhandled rejection'),source:null,line:null,column:null})});}return true;"""
SET_PHASE_JS="if(window.__itE2E)window.__itE2E.phase=arguments[0];return true;"
SET_TITLE_NONCE_JS="const n=String(arguments[0]);document.title=n;return {title:document.title};"
ERRORS_JS="return (window.__itE2E&&window.__itE2E.errors||[]).slice();"
ACCOUNT_CONTEXT_JS="""const r=window.ytInitialPlayerResponse||window.ytplayer?.config?.args?.player_response||null;
let response=r;try{if(typeof response==='string')response=JSON.parse(response);}catch{}
const details=response?.videoDetails||window.ytInitialPlayerResponse?.videoDetails||{};
const delegated=String(window.ytcfg?.get?.('DELEGATED_SESSION_ID')||'').trim(),datasync=String(window.ytcfg?.get?.('DATASYNC_ID')||'').trim();
const accountId=delegated||(datasync.includes('||')?datasync.split('||')[0]:datasync);
return {loggedIn:window.ytcfg?.get?.('LOGGED_IN')===true,accountId,
videoId:new URL(location.href).searchParams.get('v')||details.videoId||null,channelId:details.channelId||null};"""
ARTIFACT_STATE_JS="return {fullscreen:!!document.fullscreenElement,pictureInPicture:!!document.pictureInPictureElement};"
VIEWPORT_JS="return {innerWidth:window.innerWidth,innerHeight:window.innerHeight};"
SIDE_EFFECT_SNAPSHOT_JS="""const q=arguments[0]||{},capture=(store,keys)=>Object.fromEntries((keys||[]).map(k=>[k,{present:store.getItem(k)!==null,value:store.getItem(k)}]));
const cookies={};for(const name of q.cookieNames||[]){const part=document.cookie.split(';').map(x=>x.trim()).find(x=>x.startsWith(encodeURIComponent(name)+'='));cookies[name]=part?{present:true,value:part.slice(part.indexOf('=')+1)}:{present:false,value:null};}
return {localStorage:capture(localStorage,q.localStorageKeys),sessionStorage:capture(sessionStorage,q.sessionStorageKeys),cookies};"""
SIDE_EFFECT_RESTORE_JS="""const q=arguments[0]||{},restore=(store,states)=>{for(const [key,state] of Object.entries(states||{})){if(state.present)store.setItem(key,state.value);else store.removeItem(key);}};
restore(localStorage,q.localStorage);restore(sessionStorage,q.sessionStorage);
for(const [name,state] of Object.entries(q.cookies||{})){const encoded=encodeURIComponent(name);document.cookie=encoded+'=; Max-Age=0; path=/; domain=.youtube.com; SameSite=Lax';document.cookie=encoded+'=; Max-Age=0; path=/; SameSite=Lax';if(state.present)document.cookie=encoded+'='+state.value+'; path=/; domain=.youtube.com; SameSite=Lax';}
return {ok:true,current:(()=>{const cookies={};for(const name of Object.keys(q.cookies||{})){const part=document.cookie.split(';').map(x=>x.trim()).find(x=>x.startsWith(encodeURIComponent(name)+'='));cookies[name]=part?{present:true,value:part.slice(part.indexOf('=')+1)}:{present:false,value:null};}return {localStorage:Object.fromEntries(Object.keys(q.localStorage||{}).map(k=>[k,{present:localStorage.getItem(k)!==null,value:localStorage.getItem(k)}])),sessionStorage:Object.fromEntries(Object.keys(q.sessionStorage||{}).map(k=>[k,{present:sessionStorage.getItem(k)!==null,value:sessionStorage.getItem(k)}])),cookies};})()};"""
ASYNC_LIFECYCLE_JS="""const done=arguments[arguments.length-1],argv=arguments[1],allowUndefined=arguments[2]===true;
(async()=>{try{const fn=async function(){/*__IT_LIFECYCLE_BODY__*/};const value=await fn.apply(window,argv);
const encoded=JSON.stringify(value);if(encoded===undefined){if(allowUndefined){done({itLifecycle:true,ok:true,value:null});return;}throw new Error('lifecycle returned undefined');}done({itLifecycle:true,ok:true,value:JSON.parse(encoded)});
}catch(error){done({itLifecycle:true,ok:false,error:{name:String(error?.name||'Error'),message:String(error?.message||error),stack:String(error?.stack||'')}});}})();"""
REAL_PAGE_JS="""const u=new URL(location.href),s=['ytd-app','#content','ytd-watch-flexy','ytd-browse','ytd-search','ytd-reel-video-renderer'];
return {url:location.href,host:u.hostname,protocol:u.protocol,ready:document.readyState,youtubeElements:s.filter(x=>document.querySelector(x)).length,title:document.title};"""
CSS_SETUP_JS="const e=document.querySelector('#voice-search-button');return {ok:!!e,selector:'#voice-search-button'};"
CSS_OBSERVE_JS="""const e=document.querySelector('#voice-search-button');if(!e)return {present:false};
const c=getComputedStyle(e),r=e.getBoundingClientRect();return {present:true,visible:c.display!=='none'&&c.visibility!=='hidden'&&Number(c.opacity)!==0,display:c.display,visibility:c.visibility,opacity:c.opacity,rect:{x:r.x,y:r.y,width:r.width,height:r.height}};"""
DOM_SETUP_JS="return {ok:!!document.body,scrollY:window.scrollY};"
DOM_ACTIVATE_JS="""const q=arguments[0];if(!window.ImprovedTube||!ImprovedTube.messages)return {sent:false};
ImprovedTube.messages.send({action:'set',key:q.key,value:q.value});window.scrollTo(0,Math.max(window.innerHeight+10,1000));window.dispatchEvent(new Event('scroll'));return {sent:true};"""
DOM_OBSERVE_JS="return {present:!!document.querySelector('#it-scroll-to-top'),scrollY:window.scrollY};"
SLIDER_SETUP_JS="const v=document.querySelector('video'),s=window.ImprovedTube&&ImprovedTube.storage;return {ok:!!v&&s&&s.player_forced_playback_speed===true,playbackRate:v?v.playbackRate:null,forced:s?s.player_forced_playback_speed:null};"
PLAYBACK_COMPANION_KEY="player_forced_playback_speed"
SLIDER_OBSERVE_JS="const v=document.querySelector('video');return {present:!!v,value:v?v.playbackRate:null};"
SHORTCUT_SETUP_JS="const b=document.querySelector('.ytp-subtitles-button');return {ok:!!b,pressed:b?b.getAttribute('aria-pressed'):null};"
SHORTCUT_OBSERVE_JS="const b=document.querySelector('.ytp-subtitles-button');return {present:!!b,pressed:b?b.getAttribute('aria-pressed'):null};"
WATCHED_SETUP_JS="""const v=document.querySelector('video'),id=new URL(location.href).searchParams.get('v');return {ok:!!v&&!!id,videoId:id};"""
WATCHED_ACTIVATE_JS="""const q=arguments[0];if(!window.ImprovedTube||!ImprovedTube.messages)return {sent:false};
ImprovedTube.messages.send({action:'set',key:q.key,value:q.value});ImprovedTube.messages.send({action:'set',key:q.key,value:q.value});return {sent:true,queueDepth:ImprovedTube.messages.queue?.length??null};"""
WATCHED_OBSERVE_JS="""const id=new URL(location.href).searchParams.get('v'),s=window.ImprovedTube&&ImprovedTube.storage;
const w=s&&s.watched&&id?s.watched[id]:undefined;return {videoId:id,watchedPresent:!!w,watched:w||null,queueDepth:window.ImprovedTube?.messages?.queue?.length??null};"""
OPTIONS_URL_REQUEST_JS="""const done=arguments[arguments.length-1];
if(!window.ImprovedTube?.messages?.send){done({ok:false,error:'ImprovedTube message bridge unavailable'});return;}
document.querySelector('.it-button__iframe[data-it-e2e-options-frame]')?.remove();
let settled=false;const finish=value=>{if(!settled){settled=true;done(value);}};
const frame=document.createElement('iframe');frame.className='it-button__iframe';frame.dataset.itE2eOptionsFrame='true';frame.hidden=true;
const current=()=>frame.src||frame.getAttribute('src')||'',recognized=url=>(url.startsWith('safari-web-extension:')&&new URL(url).pathname==='/menu/index.html')||url==='webkit-masked-url://hidden/';
frame.addEventListener('load',()=>{const url=current();if(recognized(url))finish({ok:true,url,frame,loaded:true});});document.documentElement.prepend(frame);
const deadline=Date.now()+5000;ImprovedTube.messages.send({requestOptionsUrl:true});
(function poll(){const url=current();if(Date.now()>=deadline){finish({ok:false,error:recognized(url)?'signed options iframe load timed out':'signed options URL handshake timed out',url,loaded:false});return;}
if(!settled)setTimeout(poll,50);})();"""
EXTENSION_CONTEXT_JS="""const api=globalThis.chrome,manifest=api?.runtime?.getManifest?.();
return {url:location.href,protocol:location.protocol,path:location.pathname,readyState:document.readyState,runtimeId:api?.runtime?.id||null,
manifestName:manifest?.name||null,manifestVersion:manifest?.version||null,manifestVersionNumber:manifest?.manifest_version||null,
optionsPage:manifest?.options_page||manifest?.options_ui?.page||null,storage:!!api?.storage?.local};"""
FIXTURE_EVIDENCE_JS="""const selectors=arguments[0]||[];
return {url:location.href,host:location.host,protocol:location.protocol,readyState:document.readyState,
selectors:selectors.filter(selector=>document.querySelector(selector))};"""
DIRECT_STORAGE_GET_JS="""const keys=arguments[0],callback=arguments[arguments.length-1];let settled=false;
const done=value=>{if(!settled){settled=true;clearTimeout(timer);callback(value);}};const timer=setTimeout(()=>done({ok:false,error:'direct storage get timed out'}),5000);
chrome.storage.local.get(keys,value=>{const error=chrome.runtime.lastError;done(error?{ok:false,error:error.message}:{ok:true,value});});"""
DIRECT_STORAGE_MUTATE_JS="""const request=arguments[0],callback=arguments[arguments.length-1];let settled=false;
const done=value=>{if(!settled){settled=true;clearTimeout(timer);callback(value);}};const timer=setTimeout(()=>done({ok:false,error:'direct storage mutation timed out'}),5000);
const finish=()=>{const error=chrome.runtime.lastError;if(error){done({ok:false,error:error.message});return;}
chrome.storage.local.get([request.key],value=>{const readError=chrome.runtime.lastError;
done(readError?{ok:false,error:readError.message}:{ok:true,present:Object.prototype.hasOwnProperty.call(value,request.key),value:value[request.key]});});};
if(request.present)chrome.storage.local.set({[request.key]:request.value},finish);else chrome.storage.local.remove([request.key],finish);"""

CONTRACTS={
"hide_voice_search_button":FeatureContract("hide_voice_search_button","search",CSS_SETUP_JS,SEND_STORAGE_JS,CSS_OBSERVE_JS,CSS_OBSERVE_JS,SEND_STORAGE_JS,("#voice search button exists",),"css_visibility",True),
"add_scroll_to_top":FeatureContract("add_scroll_to_top","watch",DOM_SETUP_JS,DOM_ACTIVATE_JS,DOM_OBSERVE_JS,DOM_OBSERVE_JS,SEND_STORAGE_JS,("document.body exists",),"dom_presence",True),
"player_playback_speed":FeatureContract("player_playback_speed","watch",SLIDER_SETUP_JS,SEND_STORAGE_JS,SLIDER_OBSERVE_JS,SLIDER_OBSERVE_JS,SEND_STORAGE_JS,("video exists","forced playback speed enabled"),"slider_value",1.25),
"shortcut_activate_captions":FeatureContract("shortcut_activate_captions","watch",SHORTCUT_SETUP_JS,SEND_STORAGE_JS,SHORTCUT_OBSERVE_JS,SHORTCUT_OBSERVE_JS,SEND_STORAGE_JS,("subtitles button exists","signed key event reliable"),"shortcut_toggle",{"keys":{67:{"key":"c","code":"KeyC"}}}),
"track_watched_videos":FeatureContract("track_watched_videos","watch",WATCHED_SETUP_JS,WATCHED_ACTIVATE_JS,WATCHED_OBSERVE_JS,WATCHED_OBSERVE_JS,SEND_STORAGE_JS,("watch video and id exist",),"watched_side_effect",True,known_regression="queue overlap can prevent track_watched_videos from recording the watch"),
}

def all_contracts(extra:dict[str,Any]|None=None)->dict[str,Any]:
    contracts=dict(CONTRACTS)
    for key,value in (extra or {}).items():
        if key in contracts:raise ValueError("duplicate contract key: "+key)
        contracts[key]=value
    return contracts

def _full_contracts(extra:dict[str,Any]|None=None)->dict[str,Any]:
    """Resolve seed contracts plus file entries without ambiguous overrides.

    A directory normally contains only the 337 remaining controls.  A
    generated complete catalog may also repeat the five retained seeds; when
    it covers the whole discovered seed set, that catalog is authoritative.
    Partial seed overrides remain an error so a file cannot silently replace a
    curated contract.
    """
    if not extra:return dict(CONTRACTS)
    overlap=set(extra)&set(CONTRACTS)
    if overlap and not set(extra).issuperset(CONTRACTS):
        raise ValueError("duplicate contract key: "+sorted(overlap)[0])
    return dict(extra) if set(extra).issuperset(CONTRACTS) else all_contracts(extra)

def load_full_live_contract_catalog(paths:Iterable[str|Path],features:Iterable[Feature]|None=None)->tuple[dict[str,ContractSpec],dict[str,Any]]:
    """Load the complete catalog while making curated seed precedence explicit.

    ``load_contract_files`` remains the strict generic loader: every JSON
    file must have a unique menuSource and every key may occur only once.  A
    full catalog intentionally repeats the five legacy focused keys, so this
    integration layer records those overlaps and uses the strict executable
    file contracts for full-live. No non-seed duplicate is resolved implicitly.
    """
    files=[]
    for item in paths:
        path=Path(item)
        files.extend(sorted(path.glob("*.json")) if path.is_dir() else [path])
    files=sorted(files)
    feature_list=list(features or ())
    feature_map={feature.key:feature for feature in feature_list}
    owners:dict[str,list[dict[str,Any]]]={}
    sources:dict[str,Path]={}
    entries:dict[str,ContractSpec]={}
    file_rows=[]
    file_entry_count=0
    for path in files:
        file_contracts=load_contract_file(path)
        source=next(iter(file_contracts.values())).menu_source
        if source in sources:
            raise ValueError("contract files must be disjoint by menuSource: "+source)
        sources[source]=path
        file_bytes=path.read_bytes()
        file_rows.append({"path":str(path),"name":path.name,"menuSource":source,
                          "entries":len(file_contracts),
                          "sha256":hashlib.sha256(file_bytes).hexdigest()})
        file_entry_count+=len(file_contracts)
        for key,contract in file_contracts.items():
            owner={"path":str(path),"name":path.name,"menuSource":source}
            owners.setdefault(key,[]).append(owner)
            if key in entries and key not in CONTRACTS:
                raise ValueError("duplicate contract key across files: "+key)
            entries.setdefault(key,contract)

    duplicate_keys=sorted(key for key,items in owners.items() if len(items)>1)
    seed_overlaps=[]
    authoritative=dict(entries)
    for key in sorted(set(owners)&set(CONTRACTS)):
        seed_overlaps.append({"key":key,"fileEntries":owners[key],"authority":"file-contract",
                              "reason":"strict executable full-live contract supersedes legacy focused seed"})
    for key in sorted(set(CONTRACTS)-set(authoritative)):
        authoritative[key]=contract_from_feature_contract(CONTRACTS[key],feature_map.get(key))

    discovered={feature.key for feature in feature_list}
    missing=sorted(discovered-set(authoritative)) if feature_list else []
    extra=sorted(set(authoritative)-discovered) if feature_list else []
    counts={"actualApplicable":sum(contract.applicability=="applicable" for contract in authoritative.values()),
            "reviewedNotApplicable":sum(contract.applicability=="not_applicable" for contract in authoritative.values())}
    digest_payload={"files":[{key:row[key] for key in ("name","menuSource","entries","sha256")} for row in file_rows],
                    "contracts":{key:authoritative[key].to_dict() for key in sorted(authoritative)}}
    catalog_digest=hashlib.sha256(json.dumps(digest_payload,sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()
    diagnostics={"files":file_rows,"fileCount":len(files),"sourceCount":len(sources),
                 "fileEntryCount":file_entry_count,"fileKeyCount":len(entries),
                 "authoritativeEntryCount":len(authoritative),"seedOverlapCount":len(seed_overlaps),
                 "seedOverlaps":seed_overlaps,"duplicateKeyCount":len(duplicate_keys),
                 "duplicateKeys":duplicate_keys,"missing":missing,"extra":extra,
                 **counts,"catalogDigest":catalog_digest}
    return authoritative,diagnostics

def build_full_live_plan(features:list[Feature],extra:dict[str,Any]|None=None)->list[FeaturePlan]:
    return build_feature_plan(features,_full_contracts(extra))

def validate_plan(features:list[Feature],mode:str="focused",contracts:dict[str,Any]|None=None)->list[str]:
    return framework_validate_plan(features,dict(CONTRACTS) if contracts is None else contracts,mode)

def preflight_full_live(features:list[Feature],contracts:dict[str,Any]|None=None)->FullLivePreflight:
    return framework_preflight(features,dict(CONTRACTS) if contracts is None else contracts)

def validate_contracts(features:Iterable[Feature]|None=None)->list[str]:
    errors=[]
    for key,c in CONTRACTS.items():
        if c.route not in ROUTES:errors.append(key+": unknown route")
        if not all((c.setup_js,c.activation_js,c.before_observe_js,c.after_observe_js,c.cleanup_js)):errors.append(key+": lifecycle step missing")
        if not c.prerequisites:errors.append(key+": prerequisites missing")
        if c.evidence_class not in EVIDENCE_CLASSES:errors.append(key+": invalid evidence class")
    if features is not None:
        keys={f.key for f in features};errors += [key+": not discovered" for key in CONTRACTS if key not in keys]
    return errors

def render_index(features:list[Feature],source_root:Path,full_live:bool=False,plans:list[FeaturePlan]|None=None)->str:
    counts={}
    for f in features:counts[f.route]=counts.get(f.route,0)+1
    plan_map={item.key:item for item in (plans or build_full_live_plan(features))}
    contract_count=sum(item.status=="contracted" for item in plan_map.values()) if full_live else sum(f.key in CONTRACTS for f in features)
    header="| Feature | Storage key | Control | Route | Source | Classification | Fixture | Oracle | Risk | Metadata digest | Candidate hints |" if full_live else "| Feature | Storage key | Control | Route | Source | Classification | Fixture | Oracle | Risk | Metadata digest |"
    divider="|---|---|---|---|---|---|---|---|---|---|---|" if full_live else "|---|---|---|---|---|---|---|---|---|---|"
    lines=["# ImprovedTube Safari E2E assertion index","","Generated from "+str(source_root)+".",
    "","Static discovery is source evidence only. A live PASS requires an explicit semantic contract with route, prerequisites, activation, before/after observation, cleanup, and persisted restoration.","",
    f"Controls: **{len(features)}**. Live semantic contracts: **{contract_count}**. Routes: "+", ".join(k+"="+str(v) for k,v in sorted(counts.items()))+".","",
    ("Full-live preflight refuses every uncontracted control; only complete contracts or reviewed NOT_APPLICABLE entries can run." if full_live else "Focused mode retains the legacy source inventory."),"",
    header,divider]
    for f in features:
        c=CONTRACTS.get(f.key);plan=plan_map.get(f.key)
        if full_live:
            classification="CONTRACTED" if plan and plan.status=="contracted" else "NOT_APPLICABLE" if plan and plan.status=="not_applicable" else "UNCONTRACTED (PREFLIGHT BLOCK)"
            fixture=plan.contract.fixture_id if plan and plan.contract else ""
            oracle=plan.contract.oracle.kind.value if plan and plan.contract and plan.contract.oracle else ""
            risk=plan.contract.risk if plan and plan.contract else ""
        else:
            classification="LIVE_SEMANTIC" if c else "SOURCE_ONLY (UNVERIFIED)";fixture="";oracle=c.observation_kind if c else "none";risk=""
        digest=f.metadata_digest[:16] if f.metadata_digest else ""
        hints="; ".join(f.source_hints) if full_live else ""
        lines.append(f"| {f.feature_id} | {f.storage_key or f.key} | {f.component} | {f.route} | {f.source} | {classification} | {fixture} | {oracle} | {risk} | {digest} |" + (f" {hints} |" if full_live else ""))
    lines += ["","## Evidence classes and gate","",
    "- IDENTITY: signed identifiers, TestFlight authority, version/build, Team ID, and CDHashes.",
    "- DISCOVERY: menu source inventory; not proof that a feature works.",
    "- TRANSPORT: exact present/value semantics. false, 0, empty string, null, and absence remain distinct.",
    "- FALSY-TRANSPORT: --exercise-falsy deliberately reports upstream false-as-remove behavior as PRODUCT_FAILURE and restores the exact prior state.",
    "- SIGNED_BRIDGE: live route proof requires ImprovedTube, storage, messages, and the actual #it-messages-from-extension provider.",
    "- KG271U: CoreGraphics scopes the verifier-owned visible layer-0 STP automation window to PID and window identity at session start and every navigation; unrelated helpers are disclosed but not claimed.",
    "- LIFECYCLE: internal mode owns and terminates its driver/STP children; external mode connects to a pre-existing active-Aqua driver, resolves its target window by PID plus exact requested geometry when needed, closes only its session/target window, and never kills the external driver or unrelated windows.",
    "- LIVE_SEMANTIC: only a named contract observer can produce this class.",
    ("- UNCONTRACTED: no complete contract; full-live preflight blocks before browser startup." if full_live else "- SOURCE_ONLY: no contract; transport/effect/restoration are NOT_RUN and the release gate fails."),
    "- PRODUCT_FAILURE: signed behavior contradicted a contract, including falsy-set and track/queue regressions.",
    "- ISOLATION_FAILURE: exact or persisted restoration failed; later features stop.",
    "- HARNESS/ENVIRONMENT: driver, browser, display, website, or cleanup failures.",
    "Global coverage means every indexed assertion row has a status. Screenshots are artifacts only and never feature proof.",
    "Operator path: run launch_aqua_observer.py as the active Aqua user on a one-run /tmp Unix socket; pass only the protected capability through IMPROVEDTUBE_AQUA_OBSERVER_CAPABILITY when invoking --driver-mode external.",""]
    return "\n".join(lines)

def deep_equal(a:Any,b:Any)->bool:
    return json.dumps(a,sort_keys=True,separators=(",",":"),ensure_ascii=False)==json.dumps(b,sort_keys=True,separators=(",",":"),ensure_ascii=False)
def state_from_wire(v:Any)->StorageState:
    if not isinstance(v,dict) or not isinstance(v.get("present"),bool):raise ValueError("storage state requires explicit present boolean")
    return StorageState(v["present"],v.get("value"))
def state_matches(a:StorageState,e:StorageState)->bool:return a.present==e.present and (not e.present or deep_equal(a.value,e.value))
def storage_payload(key:str,state:StorageState)->dict[str,Any]:
    payload={"key":key,"present":state.present}
    if state.present:payload["value"]=state.value
    return payload
def classify_transport(requested:StorageState,actual:StorageState,sent:bool,bridge:bool)->str:
    if not bridge or not sent:return HARNESS_FAILURE
    return PASS if state_matches(actual,requested) else PRODUCT_FAILURE
def classify_observation(c:FeatureContract,before:Any,after:Any,activation:Any)->tuple[str,str]:
    if not isinstance(before,dict) or not isinstance(after,dict):return HARNESS_FAILURE,"invalid observation"
    if c.observation_kind=="css_visibility":
        if not before.get("present") or not after.get("present"):return UNVERIFIED,"voice control unavailable"
        return (PASS,"computed visible -> hidden") if before.get("visible") is True and after.get("visible") is False else (PRODUCT_FAILURE,"visibility did not change")
    if c.observation_kind=="dom_presence":return (PASS,"semantic DOM control appeared") if before.get("present") is False and after.get("present") is True else (PRODUCT_FAILURE,"semantic DOM control did not appear")
    if c.observation_kind=="slider_value":
        if not before.get("present") or not after.get("present"):return UNVERIFIED,"video unavailable"
        try:ok=abs(float(after.get("value"))-float(activation))<.01 and abs(float(before.get("value"))-float(activation))>=.01
        except (TypeError,ValueError):ok=False
        return (PASS,"playbackRate reached requested value") if ok else (PRODUCT_FAILURE,"playbackRate did not change")
    if c.observation_kind=="shortcut_toggle":
        if not before.get("present") or not after.get("present"):return UNVERIFIED,"subtitles button unavailable"
        return (PASS,"aria-pressed toggled") if before.get("pressed")!=after.get("pressed") else (UNVERIFIED,"signed shortcut was not reliable")
    if c.observation_kind=="watched_side_effect":return (PASS,"watched record written") if after.get("watchedPresent") is True else (PRODUCT_FAILURE,c.known_regression or "watched record missing")
    return HARNESS_FAILURE,"unknown observation kind"

def candidate_surface_identity(root:Path=ROOT)->dict[str,Any]:
    paths=[root/relative for relative in CANDIDATE_SURFACE_PATHS]
    if any(not p.is_file() for p in paths):
        missing=[str(p.relative_to(root)) for p in paths if not p.is_file()]
        raise RuntimeError("candidate surface path missing: "+", ".join(missing))
    paths=sorted(paths,key=lambda p:p.relative_to(root).as_posix());d=hashlib.sha256();inventory=[]
    for p in paths:
        rel=p.relative_to(root).as_posix();data=p.read_bytes();d.update(rel.encode()+bytes((92,48))+len(data).to_bytes(8,"big")+data);inventory.append(rel)
    return {"sha256":d.hexdigest(),"paths":inventory}

def freeze_candidate_surface(index_text:str,root:Path=ROOT)->dict[str,Any]:
    """Materialize the generated index before hashing the immutable candidate surface."""
    target=root/Path(".appstore/testing/safari-e2e-assertions.md")
    target.parent.mkdir(parents=True,exist_ok=True);target.write_text(index_text)
    if target.read_text()!=index_text:raise RuntimeError("generated assertion index readback mismatch")
    candidate=candidate_surface_identity(root)
    candidate["generatedIndexSHA256"]=hashlib.sha256(index_text.encode()).hexdigest()
    candidate["generatedIndexBytes"]=len(index_text.encode())
    return candidate

def command_output(command:list[str],timeout:int=30)->tuple[int,str,str]:
    p=subprocess.run(command,capture_output=True,text=True,timeout=timeout);return p.returncode,p.stdout,p.stderr
def parse_codesign(text:str)->dict[str,Any]:
    r={"authorities":[]}
    for line in text.splitlines():
        if "=" not in line:continue
        k,v=line.split("=",1)
        if k=="Authority":r["authorities"].append(v)
        elif k in {"Identifier","TeamIdentifier","CDHash","CandidateCDHash","CandidateCDHashFull","Version"}:r[k]=v
    return r
def plist_info(path:Path)->dict[str,Any]:
    with path.open("rb") as h:v=plistlib.load(h)
    if not isinstance(v,dict):raise ValueError(str(path)+" is not a plist dictionary")
    return v
def asset_tree_digest(root:Path)->str:
    if not root.is_dir():raise ValueError("asset root is not a directory: "+str(root))
    paths=sorted(root.rglob("*"),key=lambda p:p.relative_to(root).as_posix())
    digest=hashlib.sha256()
    for path in paths:
        if path.is_symlink():raise ValueError("asset tree contains symlink: "+str(path.relative_to(root)))
        if not path.is_file():continue
        rel=path.relative_to(root).as_posix();data=path.read_bytes()
        digest.update(rel.encode()+bytes((92,48))+len(data).to_bytes(8,"big")+data)
    return digest.hexdigest()
def inspect_signed_bundle(app_path:Path=APP_PATH)->dict[str,Any]:
    ext=app_path/EXTENSION_RELATIVE;e={"appPath":str(app_path),"extensionPath":str(ext),"valid":False,"errors":[]}
    if not app_path.is_dir() or not ext.is_dir():e["errors"].append("expected installed app or embedded extension unavailable");return e
    try:
        ap,ep=plist_info(app_path/"Contents/Info.plist"),plist_info(ext/"Contents/Info.plist")
        manifest=json.loads((ext/"Contents/Resources/manifest.json").read_text())
        if not isinstance(manifest,dict):raise ValueError("signed extension manifest is not an object")
        e["appPlist"]={"bundleId":ap.get("CFBundleIdentifier"),"version":ap.get("CFBundleShortVersionString"),"build":ap.get("CFBundleVersion")}
        e["extensionPlist"]={"bundleId":ep.get("CFBundleIdentifier"),"version":ep.get("CFBundleShortVersionString"),"build":ep.get("CFBundleVersion")}
        e["extensionManifest"]={key:manifest.get(key) for key in ("name","version","manifest_version","options_page")}
        av=command_output(["/usr/bin/codesign","--verify","--deep","--strict","--verbose=2",str(app_path)])
        ev=command_output(["/usr/bin/codesign","--verify","--deep","--strict","--verbose=2",str(ext)])
        a=parse_codesign(command_output(["/usr/bin/codesign","-dv","--verbose=4",str(app_path)])[2]);x=parse_codesign(command_output(["/usr/bin/codesign","-dv","--verbose=4",str(ext)])[2])
        e["appSignature"],e["extensionSignature"]=a,x;errors=e["errors"]
        e["extensionAssetSHA256"]=asset_tree_digest(ext)
        if av[0]!=0 or ev[0]!=0:errors.append("codesign strict verification failed")
        if ap.get("CFBundleIdentifier")!=EXPECTED_APP_BUNDLE_ID:errors.append("unexpected app bundle identifier")
        if ep.get("CFBundleIdentifier")!=EXPECTED_EXTENSION_BUNDLE_ID:errors.append("unexpected extension bundle identifier")
        if a.get("Identifier")!=EXPECTED_APP_BUNDLE_ID or x.get("Identifier")!=EXPECTED_EXTENSION_BUNDLE_ID:errors.append("unexpected signed identifier")
        for name,s in (("app",a),("extension",x)):
            if EXPECTED_TESTFLIGHT_AUTHORITY not in s.get("authorities",[]):errors.append(name+" is not TestFlight-signed")
            if not s.get("CDHash"):errors.append(name+" CDHash is missing")
        if (ap.get("CFBundleShortVersionString"),ap.get("CFBundleVersion"))!=(ep.get("CFBundleShortVersionString"),ep.get("CFBundleVersion")):errors.append("version/build mismatch")
        if manifest.get("options_page")!="menu/index.html" or manifest.get("manifest_version") not in {2,3} or not manifest.get("name") or not manifest.get("version"):errors.append("unexpected signed extension manifest identity")
        teams={a.get("TeamIdentifier"),x.get("TeamIdentifier")}-{None};e["teamIdentifier"]=sorted(teams);e["testflight"]=EXPECTED_TESTFLIGHT_AUTHORITY in x.get("authorities",[])
        if a.get("TeamIdentifier")!=EXPECTED_TEAM_IDENTIFIER:errors.append("unexpected app signing TeamIdentifier")
        if x.get("TeamIdentifier")!=EXPECTED_TEAM_IDENTIFIER:errors.append("unexpected extension signing TeamIdentifier")
        e["valid"]=not errors
    except (OSError,ValueError,subprocess.SubprocessError,plistlib.InvalidFileException) as exc:e["errors"].append(str(exc))
    return e
validate_signed_bundle=inspect_signed_bundle

class WebDriver:
    def __init__(self,host:str,port:int):self.host,self.port,self.session_id=host,port,"";self.capabilities={};self.browser_pid=None;self.in_frame=False
    def request(self,method:str,path:str,payload:Any=None,timeout:int=180,include_status:bool=False)->Any:
        c=http.client.HTTPConnection(self.host,self.port,timeout=timeout)
        try:
            body=None if payload is None else json.dumps(payload);c.request(method,path,body=body,headers={"Content-Type":"application/json"});response=c.getresponse();raw=response.read()
        except (OSError,http.client.HTTPException) as exc:raise RuntimeError(method+" "+path+" transport failed: "+str(exc)) from exc
        finally:c.close()
        try:data=strict_json_loads(raw)
        except (UnicodeDecodeError,json.JSONDecodeError,ValueError) as exc:raise RuntimeError(method+" "+path+" returned malformed JSON") from exc
        if not isinstance(data,dict):raise RuntimeError(method+" "+path+" returned malformed response")
        value=data.get("value")
        if response.status>=400:raise RuntimeError(method+" "+path+" failed: "+json.dumps(value or data))
        return WebDriverResponse(response.status,data,value) if include_status else value
    def create(self)->None:
        value=self.request("POST","/session",{"capabilities":{"alwaysMatch":{"browserName":"Safari Technology Preview","pageLoadStrategy":"none","safari:automaticInspection":True}}})
        if not isinstance(value,dict):raise RuntimeError("Safari returned no session details")
        self.session_id=value.get("sessionId") or value.get("session_id") or ""
        if not self.session_id:raise RuntimeError("Safari returned no session id")
        self.capabilities=value.get("capabilities") if isinstance(value.get("capabilities"),dict) else {}
        self.browser_pid=self.capabilities.get("safari:processID")
    def set_timeouts(self,script_ms:int,page_load_ms:int)->None:
        self.command("POST","/timeouts",{"script":script_ms,"pageLoad":page_load_ms})
    def command(self,method:str,suffix:str,payload:Any=None,timeout:int=180)->Any:
        if not self.session_id:raise RuntimeError("WebDriver session is not active")
        return self.request(method,"/session/"+self.session_id+suffix,payload,timeout)
    def script(self,source:str,args:list[Any]|None=None)->Any:return self.command("POST","/execute/sync",{"script":source,"args":args or []},timeout=40)
    def script_async(self,source:str,args:list[Any]|None=None)->Any:return self.command("POST","/execute/async",{"script":source,"args":args or []},timeout=40)
    def _navigate_fresh(self,suffix:str,payload:Any=None)->None:
        marker=secrets.token_urlsafe(16)
        self.script("globalThis.__itE2ENavigationMarker=arguments[0];return true;",[marker])
        self.command("POST",suffix,payload,timeout=75);self.in_frame=False
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            try:
                if self.script("return globalThis.__itE2ENavigationMarker||null;")!=marker:return
            except RuntimeError:pass
            time.sleep(.1)
        raise RuntimeError("navigation did not commit a fresh document")
    def navigate(self,url:str)->None:
        if self.in_frame:self.switch_to_frame()
        self._navigate_fresh("/url",{"url":url})
    def refresh(self)->None:
        if self.in_frame:self.switch_to_frame()
        self._navigate_fresh("/refresh")
    def get_window_rect(self)->dict[str,Any]:
        value=self.command("GET","/window/rect")
        if not isinstance(value,dict) or any(type(value.get(key)) not in {int,float} for key in ("x","y","width","height")):
            raise RuntimeError("invalid WebDriver window rect")
        return value
    def set_window_rect(self,x:int,y:int,w:int,h:int)->Any:return self.command("POST","/window/rect",{"x":x,"y":y,"width":w,"height":h},timeout=20)
    def window_handles(self)->list[str]:
        value=self.command("GET","/window/handles")
        if not isinstance(value,list) or any(not isinstance(item,str) or not item for item in value):raise RuntimeError("invalid window handles")
        return value
    def current_window_handle(self)->str:
        value=self.command("GET","/window")
        if not isinstance(value,str) or not value:raise RuntimeError("invalid current window handle")
        return value
    def new_window(self,kind:str="tab")->dict[str,str]:
        value=self.command("POST","/window/new",{"type":kind})
        if not isinstance(value,dict) or not isinstance(value.get("handle"),str) or not value["handle"] or value.get("type") not in {"tab","window"}:raise RuntimeError("invalid new-window response")
        return {"handle":value["handle"],"type":value["type"]}
    def switch_to_window(self,handle:str)->None:self.command("POST","/window",{"handle":handle});self.in_frame=False
    def switch_to_frame(self,frame:Any=None)->None:
        if frame is None and not self.in_frame:return
        self.command("POST","/frame",{"id":frame});self.in_frame=frame is not None
    def alert_text(self)->str:
        value=self.command("GET","/alert/text")
        if not isinstance(value,str):raise RuntimeError("invalid alert text")
        return value
    def accept_alert(self)->None:self.command("POST","/alert/accept")
    def dismiss_alert(self)->None:self.command("POST","/alert/dismiss")
    def load_extension(self,path:Path)->Any:return self.command("POST","/webextension",{"type":"path","path":str(path)})
    def screenshot(self)->bytes:return base64.b64decode(self.command("GET","/screenshot",timeout=40))
    def key(self,value:str)->None:
        self.command("POST","/actions",{"actions":[{"type":"key","id":"it-e2e-keyboard","actions":[{"type":"keyDown","value":value},{"type":"keyUp","value":value}]}]});self.command("DELETE","/actions")
    def key_actions(self,actions:list[dict[str,str]])->None:
        pressed=[]
        try:
            for action in actions:
                if action["type"]=="keyDown":pressed.append(action["value"])
                elif not pressed or action["value"] not in pressed:raise RuntimeError("unbalanced W3C keyUp action")
                else:pressed.remove(action["value"])
            if pressed:raise RuntimeError("unbalanced W3C keyDown action")
            self.command("POST","/actions",{"actions":[{"type":"key","id":"it-full-live-keyboard","actions":actions}]})
        finally:self.command("DELETE","/actions")
    def close(self)->dict[str,Any]:
        if not self.session_id:return {"verified":True,"status":"already-absent"}
        try:
            response=self.request("DELETE","/session/"+self.session_id,timeout=30,include_status=True)
        except Exception as exc:
            raise RuntimeError("DELETE /session transport failed") from exc
        if (not isinstance(response,WebDriverResponse) or type(response.status) is not int
                or response.status<200 or response.status>=300
                or type(response.body) is not dict or set(response.body)!={"value"}
                or response.value is not None):
            raise RuntimeError("DELETE /session returned an unverified response shape")
        self.session_id=""
        return {"verified":True,"status":"deleted","httpStatus":response.status,"value":None}
    def close_window(self)->dict[str,Any]:
        """Close the current window and verify the exact remaining-handle result."""
        response=self.request("DELETE","/session/"+self.session_id+"/window",timeout=30,include_status=True)
        if (not isinstance(response,WebDriverResponse) or type(response.status) is not int
                or response.status<200 or response.status>=300 or type(response.body) is not dict
                or set(response.body)!={"value"} or type(response.value) is not list
                or any(type(handle) is not str or not handle for handle in response.value)
                or len(set(response.value))!=len(response.value)):
            raise RuntimeError("DELETE /window returned an unverified response shape")
        remaining=list(response.value)
        last_window=len(remaining)==0
        if last_window:self.session_id=""
        return {"verified":True,"status":"deleted-window","httpStatus":response.status,
                "remainingHandles":remaining,"lastWindow":last_window}

class BrowserStorageAdapter(StorageAdapter):
    """Direct chrome.storage.local adapter bound to the signed options iframe."""
    authority="signed-options-page"
    def __init__(self,driver:WebDriver,identity:dict[str,Any]):
        self.driver=driver;self.identity=identity;self.options_url="";self.context:dict[str,Any]={}
    def _expected_context(self)->dict[str,Any]:
        plist=self.identity.get("extensionPlist") or {};signature=self.identity.get("extensionSignature") or {}
        manifest=self.identity.get("extensionManifest") or {};team=signature.get("TeamIdentifier")
        runtime_id=(str(plist.get("bundleId"))+" ("+str(team)+")") if plist.get("bundleId") and team else None
        return {"runtimeId":runtime_id,"manifestName":manifest.get("name"),"manifestVersion":manifest.get("version"),
                "manifestVersionNumber":manifest.get("manifest_version"),"optionsPage":"menu/index.html"}
    def bind_from_youtube(self)->dict[str,Any]:
        return self.enter_options()
    def _enter_options_once(self)->dict[str,Any]:
        self.driver.switch_to_frame()
        response=self.driver.script_async(OPTIONS_URL_REQUEST_JS)
        if (not isinstance(response,dict) or response.get("ok") is not True
                or response.get("loaded") is not True
                or not isinstance(response.get("url"),str) or not isinstance(response.get("frame"),dict)):
            raise RuntimeError("signed options iframe request failed: "+json.dumps(response,default=str))
        self.driver.switch_to_frame(response["frame"])
        context=bounded_script(self.driver,EXTENSION_CONTEXT_JS,lambda value:isinstance(value,dict) and value.get("storage") is True and value.get("readyState")=="complete",pause=3)
        expected=self._expected_context()
        observed={key:context.get(key) if isinstance(context,dict) else None for key in expected}
        if (not isinstance(context,dict) or context.get("protocol")!="safari-web-extension:"
                or context.get("path")!="/menu/index.html" or context.get("readyState")!="complete" or context.get("storage") is not True or observed!=expected):
            raise RuntimeError("signed extension context identity mismatch: "+json.dumps({"expected":expected,"observed":context},default=str))
        self.options_url=context["url"];self.context=context;return context
    def enter_options(self)->dict[str,Any]:
        try:return self._enter_options_once()
        except RuntimeError as exc:
            if not any(reason in str(exc) for reason in ("no such window","signed options URL handshake timed out","ImprovedTube message bridge unavailable")):raise
            time.sleep(1)
            return self._enter_options_once()
    def snapshot(self,keys:Iterable[str]|None=None)->dict[str,StorageSnapshot]:
        requested=None if keys is None else list(dict.fromkeys(keys))
        response=self.driver.script_async(DIRECT_STORAGE_GET_JS,[requested])
        if not isinstance(response,dict) or response.get("ok") is not True or not isinstance(response.get("value"),dict):
            raise RuntimeError("direct storage get failed: "+json.dumps(response,default=str))
        values=response["value"]
        selected=sorted(values) if requested is None else requested
        return {key:StorageSnapshot.capture(key,key in values,values.get(key)) for key in selected}
    def _mutate(self,key:str,present:bool,value:Any=None)->StorageSnapshot:
        request={"key":key,"present":present}
        if present:request["value"]=value
        response=self.driver.script_async(DIRECT_STORAGE_MUTATE_JS,[request])
        if not isinstance(response,dict) or response.get("ok") is not True or type(response.get("present")) is not bool:
            raise RuntimeError("direct storage mutation failed: "+json.dumps(response,default=str))
        state=StorageSnapshot.capture(key,response["present"],response.get("value"))
        expected=StorageSnapshot.capture(key,present,value)
        if state.present!=expected.present or (present and not deep_equal(state.value,expected.value)):
            raise RuntimeError("direct storage readback mismatch for "+key)
        return state
    def set(self,key:str,value:Any)->StorageSnapshot:return self._mutate(key,True,value)
    def remove(self,key:str)->StorageSnapshot:return self._mutate(key,False)

class PageBridgeStorageAdapter(StorageAdapter):
    """Storage adapter for the signed page bridge after direct authority proof."""
    authority="verified-page-bridge"
    def __init__(self,driver:WebDriver,direct:BrowserStorageAdapter|None=None):self.driver=driver;self.direct=direct
    def _direct_call(self,method:str,*args:Any)->Any:
        if self.direct is None:raise RuntimeError("page storage fallback requires direct signed authority")
        self.direct.enter_options()
        try:return getattr(self.direct,method)(*args)
        finally:self.driver.switch_to_frame()
    def snapshot(self,keys:Iterable[str]|None=None)->dict[str,StorageSnapshot]:
        requested=None if keys is None else list(dict.fromkeys(keys));response=self.driver.script(PAGE_STORAGE_SNAPSHOT_JS,[requested])
        if not isinstance(response,dict) or response.get("ok") is not True or not isinstance(response.get("value"),dict):
            return self._direct_call("snapshot",requested)
        values=response["value"];selected=sorted(values) if requested is None else requested
        return {key:StorageSnapshot.capture(key,key in values,values.get(key)) for key in selected}
    def _mutate(self,key:str,present:bool,value:Any=None)->StorageSnapshot:
        requested=StorageState(present,value)
        if present and (value is None or value is False or value==0 or value==""):
            state=self._direct_call("set",key,value)
            observed=bounded_script(self.driver,STORAGE_STATE_JS,lambda item:state_is(item,requested),pause=2,args=[key])
            if not state_is(observed,requested):raise RuntimeError("page storage readback mismatch")
            return state
        try:
            payload=storage_payload(key,requested);response=self.driver.script(SEND_STORAGE_JS,[payload])
            ok,reason=cleanup_response_verified(response,key,requested)
            if not ok:raise RuntimeError("page storage mutation failed: "+reason)
            observed=bounded_script(self.driver,STORAGE_STATE_JS,lambda item:state_is(item,requested),pause=5 if not present else 2,args=[key])
            state=state_from_wire(observed)
            if not state_matches(state,requested):raise RuntimeError("page storage readback mismatch")
            return StorageSnapshot.capture(key,state.present,state.value)
        except RuntimeError:
            return self._direct_call("set",key,value) if present else self._direct_call("remove",key)
    def set(self,key:str,value:Any)->StorageSnapshot:return self._mutate(key,True,value)
    def remove(self,key:str)->StorageSnapshot:return self._mutate(key,False)

def validate_observer_socket_path(socket_path:str|Path)->None:
    """Mirror the observer's placement rule before making a client connection."""
    path=Path(socket_path)
    if path.parent!=Path("/tmp") or not path.name or path.name in {".",".."}:
        raise RuntimeError("observer socket must be directly under /tmp")
    try:directory=os.stat(path.parent)
    except OSError as exc:raise RuntimeError("observer socket directory is unavailable") from exc
    mode=directory.st_mode
    if directory.st_uid!=0 or not (mode & 0o1000) or not (mode & 0o0002):
        raise RuntimeError("observer socket directory is not root-owned sticky /tmp")

def active_aqua_uid(console_path:str|Path="/dev/console")->int:
    """Resolve the active console user's UID, never the remote client UID."""
    if sys.platform!="darwin":raise RuntimeError("macOS active Aqua console identity is required")
    try:uid=os.stat(console_path).st_uid
    except OSError as exc:raise RuntimeError("active Aqua console identity is unavailable") from exc
    if type(uid) is not int or uid<1:raise RuntimeError("active Aqua console UID is invalid")
    return uid

def resolve_observer_server_uid(explicit:int|None=None)->tuple[int,dict[str,Any]]:
    console_uid=active_aqua_uid()
    if explicit is not None and (type(explicit) is not int or explicit<1):
        raise RuntimeError("observer server UID is invalid")
    if explicit is not None and explicit!=console_uid:
        raise RuntimeError("observer server UID does not match active Aqua console UID")
    expected=console_uid if explicit is None else explicit
    return expected,{"ok":True,"source":"/dev/console","consoleUid":console_uid,"clientUid":os.getuid(),"explicit":explicit is not None,"expectedUid":expected}

def observer_socket_peer_uid(sock:socket.socket)->int:
    """Obtain the connected server's effective UID; no portable fallback."""
    if sys.platform!="darwin":raise RuntimeError("macOS getpeereid is required")
    try:
        libc=ctypes.CDLL(None);fn=getattr(libc,"getpeereid")
        euid=ctypes.c_uint(0);egid=ctypes.c_uint(0)
        fn.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_uint),ctypes.POINTER(ctypes.c_uint)];fn.restype=ctypes.c_int
        if fn(sock.fileno(),ctypes.byref(euid),ctypes.byref(egid))!=0:raise RuntimeError("server credential lookup failed")
        return int(euid.value)
    except (AttributeError,OSError):raise RuntimeError("server credential lookup failed")

def observer_response_mac(response:dict[str,Any],capability:str)->str:
    unsigned=dict(response);unsigned.pop("responseMac",None)
    payload=json.dumps(unsigned,separators=(",",":"),sort_keys=True).encode()
    return hmac.new(capability.encode(),payload,hashlib.sha256).hexdigest()

class AquaObserverClient:
    """One leased Unix-socket observer client; capability never enters evidence."""
    def __init__(self,socket_path:str,run_id:str,capability:str,server_uid_expected:int|None=None,
                 peer_uid_fn:Callable[[socket.socket],int]|None=None):
        if not socket_path or not run_id or not capability:raise ValueError("observer socket, run id, and capability are required")
        expected=active_aqua_uid() if server_uid_expected is None else server_uid_expected
        if type(expected) is not int or expected<1:raise ValueError("active Aqua server UID is required")
        self.socket_path=socket_path;self.run_id=run_id;self.capability=capability;self.server_uid_expected=expected
        self.peer_uid_fn=peer_uid_fn or observer_socket_peer_uid;self.server_uid_actual:int|None=None
        self.sequence=1;self.response_sequence=0;self.sock:socket.socket|None=None
    def connect(self)->None:
        validate_observer_socket_path(self.socket_path)
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(60)
        try:
            sock.connect(self.socket_path);actual=self.peer_uid_fn(sock)
            if type(actual) is not int or actual!=self.server_uid_expected:raise RuntimeError("observer server UID mismatch")
        except Exception:
            sock.close();raise
        self.sock=sock;self.server_uid_actual=actual
    def call(self,operation:str,extra:dict[str,Any]|None=None)->dict[str,Any]:
        if operation not in {"baseline","title-probe","place","claim","observe","final"}:raise ValueError("unsupported observer operation")
        if self.sock is None:raise RuntimeError("observer is not connected")
        request={"runId":self.run_id,"capability":self.capability,"sequence":self.sequence,"operation":operation};request.update(extra or {})
        self.sequence+=1;self.sock.sendall((json.dumps(request,separators=(",",":"))+"\n").encode())
        data=b""
        while b"\n" not in data:
            chunk=self.sock.recv(8192)
            if not chunk:raise RuntimeError("observer disconnected")
            data+=chunk
            if len(data)>65536:raise RuntimeError("observer response too large")
        try:
            response=strict_json_loads(data.split(b"\n",1)[0])
        except (UnicodeDecodeError,json.JSONDecodeError,ValueError) as exc:
            raise RuntimeError("observer returned malformed JSON") from exc
        if not isinstance(response,dict):raise RuntimeError("observer returned malformed response")
        supplied=response.get("responseMac")
        if type(supplied) is not str or not hmac.compare_digest(supplied,observer_response_mac(response,self.capability)):
            raise RuntimeError("observer response authentication failed")
        if (response.get("runId")!=self.run_id or response.get("operation")!=operation
                or type(response.get("sequence")) is not int or response["sequence"]!=self.response_sequence+1):
            raise RuntimeError("observer response run or sequence mismatch")
        self.response_sequence=response["sequence"]
        return response
    def close(self)->None:
        if self.sock:
            self.sock.close();self.sock=None

def webdriver_title_binding_evidence(driver:WebDriver,browser_pid:int,title_nonce:str)->dict[str,Any]:
    if type(browser_pid) is not int or browser_pid<1:raise RuntimeError("WebDriver browser PID is unavailable")
    handles=driver.window_handles();current=driver.current_window_handle()
    if len(handles)!=1 or handles[0]!=current:raise RuntimeError("title binding requires exactly one owned WebDriver handle")
    document=driver.script(SET_TITLE_NONCE_JS,[title_nonce])
    if not isinstance(document,dict) or document.get("title")!=title_nonce:
        raise RuntimeError("WebDriver document title nonce readback was not exact")
    return {"webdriverBrowserPid":browser_pid,"webdriverWindowHandle":current,
            "webdriverWindowHandles":handles,"webdriverDocumentTitle":document["title"]}

def await_observer_title_probe(observer:AquaObserverClient,title_nonce:str,*,timeout:float=12.0,
                               poll:float=.25,sleep_fn:Callable[[float],None]=time.sleep,
                               monotonic_fn:Callable[[],float]=time.monotonic,
                               request_evidence_fn:Callable[[],dict[str,Any]]|None=None)->dict[str,Any]:
    """Wait only for the signed observer's exact native-title binding to become ready."""
    if timeout<=0 or poll<=0:raise ValueError("title probe timeout and poll must be positive")
    deadline=monotonic_fn()+timeout;attempts=[]
    while True:
        request={"bindingMode":"late","titleNonce":title_nonce}
        if request_evidence_fn is not None:
            evidence=request_evidence_fn()
            if type(evidence) is not dict:raise RuntimeError("WebDriver title binding evidence is malformed")
            request.update(evidence)
        response=observer.call("title-probe",request)
        attempts.append({k:v for k,v in response.items() if k!="responseMac"})
        if response.get("ok") is True:
            final=dict(response);final["readinessAttempts"]=attempts;final["readinessTimedOut"]=False
            return final
        pending=(response.get("ready") is False and response.get("retryable") is True
                 and response.get("inventoryComplete") is True
                 and type(response.get("matchingCount")) is int and response["matchingCount"]==0
                 and type(response.get("signedCandidateCount")) is int
                 and response["signedCandidateCount"] in {0,1}
                 and response.get("titleNonce")==title_nonce
                 and response.get("attempt")==len(attempts))
        if not pending:
            final=dict(response);final["readinessAttempts"]=attempts;final["readinessTimedOut"]=False
            return final
        remaining=deadline-monotonic_fn()
        if remaining<=0:
            final=dict(response);final["readinessAttempts"]=attempts;final["readinessTimedOut"]=True
            return final
        sleep_fn(min(poll,remaining))

def bounded_script(driver:WebDriver,script:str,predicate:Callable[[Any],bool],pause:float=2,args:list[Any]|None=None)->Any:
    first=driver.script(script,args)
    if predicate(first):return first
    time.sleep(pause);return driver.script(script,args)
def bridge_ok(v:Any)->bool:
    return (type(v) is dict and v.get("improvedTube") is True and v.get("storage") is True
            and v.get("messages") is True and v.get("provider") is True
            and type(v.get("providerId")) is str and v.get("providerId")=="it-messages-from-extension")
def classify_bridge(v:Any)->str:return PASS if bridge_ok(v) else ENVIRONMENT_FAILURE
def ensure_bridge(driver:WebDriver,attempts:int=8,pause:float=1)->Any:
    if attempts<1 or pause<0:raise ValueError("bridge attempts must be positive and pause nonnegative")
    b=None
    for attempt in range(attempts):
        b=driver.script(BRIDGE_JS)
        if bridge_ok(b):driver.script(INSTRUMENT_JS);return b
        if attempt+1<attempts:time.sleep(pause)
    return b

def real_youtube_page_ok(route:str,value:Any)->bool:
    """Require the exact route envelope used by route setup and restoration."""
    if route not in ROUTES or type(value) is not dict:return False
    return (type(value.get("url")) is str and value["url"]==ROUTES[route]
            and value.get("host")=="www.youtube.com" and value.get("protocol")=="https:"
            and value.get("ready")=="complete" and type(value.get("youtubeElements")) is int
            and value["youtubeElements"]>0)

def cleanup_response_verified(response:Any,key:str,expected:StorageState)->tuple[bool,str]:
    """Validate the typed SEND_STORAGE_JS response used for cleanup."""
    expected_payload=storage_payload(key,expected);expected_operation="set" if expected.present else "delete"
    if type(response) is not dict:return False,"cleanup response is not an object"
    if set(response)!={"sent","operation","requested","queueDepth"}:return False,"cleanup response shape is not exact"
    if response.get("sent") is not True:return False,"cleanup transport was not acknowledged"
    if response.get("operation")!=expected_operation:return False,"cleanup operation mismatched expected state"
    if type(response.get("requested")) is not dict or not deep_equal(response["requested"],expected_payload):
        return False,"cleanup requested payload mismatched expected state"
    queue=response.get("queueDepth")
    if queue is not None and (type(queue) is not int or queue<0):return False,"cleanup queue evidence is malformed"
    return True,"typed cleanup acknowledgement"

def signed_provider_expectation(identity:dict[str,Any])->dict[str,str]|None:
    if type(identity) is not dict or not identity.get("valid"):return None
    extension_plist=identity.get("extensionPlist");signature=identity.get("extensionSignature")
    if not isinstance(extension_plist,dict) or not isinstance(signature,dict):return None
    bundle_id=extension_plist.get("bundleId");cdhash=signature.get("CDHash");asset=identity.get("extensionAssetSHA256")
    if any(type(value) is not str or not value for value in (bundle_id,cdhash,asset)):return None
    core={"protocol":OBSERVER_BRIDGE_PROTOCOL,"bundleId":bundle_id,"cdhash":cdhash,"assetSha256":asset}
    content=json.dumps(core,separators=(",",":"),sort_keys=True).encode()
    return {**core,"contentDigest":hashlib.sha256(content).hexdigest()}

def signed_provider_provenance(identity:dict[str,Any],bridge:Any,sut:str)->dict[str,Any]:
    expected=signed_provider_expectation(identity)
    observed={"bundleId":bridge.get("providerBundleId") if isinstance(bridge,dict) else None,
              "cdhash":bridge.get("providerCDHash") if isinstance(bridge,dict) else None,
              "assetSha256":bridge.get("providerAssetSHA256") if isinstance(bridge,dict) else None,
              "protocol":bridge.get("providerProtocol") if isinstance(bridge,dict) else None,
              "contentDigest":bridge.get("providerContentDigest") if isinstance(bridge,dict) else None}
    base={"bound":False,"browserAuthoritative":False,"sut":sut,"expected":expected,"observed":observed,
          "binding":"declared-page-level","declaredMatch":False}
    if sut!="signed":base["reason"]="sut-is-not-signed";return base
    if expected is None:base["reason"]="signed-installed-provider-identity-unavailable";return base
    if not bridge_ok(bridge):base["reason"]="bridge-unavailable";return base
    if any(type(value) is not str or not value for value in observed.values()):base["reason"]="provider-proof-fields-missing";return base
    if observed!=expected:base["reason"]="provider-proof-mismatch";return base
    base["declaredMatch"]=True
    base["reason"]="page-controlled-provider-metadata-is-not-browser-authoritative"
    return base

def release_gate(sut:str,identity:dict[str,Any],missing:Iterable[str],results:Iterable[Any],provider:Any,
                 observer_mode:str="late",full_live:bool=False)->bool:
    allowed={PASS,NOT_APPLICABLE} if full_live else {PASS}
    return (sut=="signed" and not list(missing) and type(identity) is dict and identity.get("valid") is True
            and observer_mode=="late"
            and type(provider) is dict and provider.get("bound") is True and provider.get("browserAuthoritative") is True
            and all(getattr(result,"status",None) in allowed for result in results))
def state_is(v:Any,expected:StorageState)->bool:
    try:return state_matches(state_from_wire(v),expected)
    except (TypeError,ValueError):return False
def observation_ready(c:FeatureContract,v:Any,before:Any,activation:Any)->bool:
    if not isinstance(v,dict):return False
    if c.observation_kind=="css_visibility":return v.get("present") is True and v.get("visible") is False
    if c.observation_kind=="dom_presence":return v.get("present") is True
    if c.observation_kind=="slider_value":
        try:return v.get("present") is True and abs(float(v.get("value"))-float(activation))<.01
        except (TypeError,ValueError):return False
    if c.observation_kind=="watched_side_effect":return v.get("watchedPresent") is True
    return True
def record(results:list[Result],aid:str,fid:str,assertion:str,status:str,eclass:str,route:str,phase:str,evidence:Any,started:float|None=None)->None:
    if eclass not in EVIDENCE_CLASSES:raise ValueError("invalid evidence class "+eclass)
    item=Result(aid,fid,assertion,status,eclass,route,phase,evidence,int(((time.monotonic()-started) if started is not None else 0)*1000))
    for index,existing in enumerate(results):
        if existing.assertion_id==aid:
            results[index]=item
            print(status.ljust(18),aid,flush=True)
            return
    results.append(item)
    print(status.ljust(18),aid,flush=True)
def feature_assertions(f:Feature,full_live:bool=False)->tuple[str,...]:
    suffixes=("-DISCOVERED","-CONTRACT","-GATE","-TRANSPORT","-EFFECT","-STORAGE","-RESTORATION") if full_live else ("-DISCOVERED","-CONTRACT","-TRANSPORT","-EFFECT","-RESTORATION","-FALSY-TRANSPORT")
    return tuple(f.feature_id+s for s in suffixes)

def source_only_results(results:list[Result],f:Feature,full_live:bool=False,plan:FeaturePlan|None=None)->None:
    started=time.monotonic();live=f.key in CONTRACTS
    if full_live:
        plan=plan or next((item for item in build_full_live_plan([f]) if item.key==f.key),None)
        status=NOT_APPLICABLE if plan and plan.status=="not_applicable" else PASS if plan and plan.status=="contracted" else UNVERIFIED
        reason=(plan.reason if plan else None) or ("reviewed applicability exclusion" if status==NOT_APPLICABLE else "full-live preflight failed: feature has no complete contract")
        metadata=f.metadata or {"key":f.key,"component":f.component,"source":f.source}
        record(results,f.feature_id+"-DISCOVERED",f.feature_id,"normalized menu control discovered",PASS,"discovery",f.route,"planning",metadata,started)
        record(results,f.feature_id+"-CONTRACT",f.feature_id,"complete full-live contract or reviewed applicability",status,"coverage",f.route,"planning",{"status":plan.status if plan else "uncontracted","reason":reason},started)
        gate_status=NOT_APPLICABLE if status==NOT_APPLICABLE else NOT_RUN
        for suffix,assertion in (("-GATE","risk and surface gate"),("-TRANSPORT","exact direct storage transport"),("-EFFECT","semantic feature effect"),("-STORAGE","direct storage snapshot and diff"),("-RESTORATION","exact persisted restoration")):
            record(results,f.feature_id+suffix,f.feature_id,assertion,gate_status,"coverage",f.route,"planning",{"reason":reason},started)
        return
    record(results,f.feature_id+"-DISCOVERED",f.feature_id,"menu control discovered",PASS,"discovery",f.route,"classification",{"key":f.key,"component":f.component,"source":f.source},started)
    record(results,f.feature_id+"-CONTRACT",f.feature_id,"semantic contract available",PASS if live else UNVERIFIED,"live-semantic" if live else "source-only",f.route,"classification",{"contract":live,"classification":"LIVE_SEMANTIC" if live else "SOURCE_ONLY"},started)
    for s,a in (("-TRANSPORT","exact bridge transport"),("-EFFECT","semantic feature effect"),("-RESTORATION","exact persisted restoration")):
        record(results,f.feature_id+s,f.feature_id,a,NOT_RUN,"source-only" if not live else "live-semantic",f.route,"classification",
               {"reason":"no semantic contract; source is not live proof" if not live else "live contract pending session execution","source":f.source},started)
    record(results,f.feature_id+"-FALSY-TRANSPORT",f.feature_id,"falsy transport regression (opt-in)",NOT_RUN,"source-only" if not live else "live-semantic",f.route,"classification",{"reason":"--exercise-falsy not selected"},started)
def evaluate_restore(before:StorageState,immediate:Any,persisted:Any)->tuple[bool,dict[str,Any]]:
    i,p=state_from_wire(immediate),state_from_wire(persisted);return state_matches(i,before) and state_matches(p,before),{"expected":asdict(before),"immediate":asdict(i),"persisted":asdict(p)}

def restore_contract_state(driver:WebDriver,f:Feature,c:FeatureContract,route:str,results:list[Result],before_state:StorageState|None,
                           prior_state_exact:bool,phase:str,started:float,
                           window_check:Callable[[str],dict[str,Any]]|None=None,
                           companion_key:str|None=None,companion_before_state:StorageState|None=None,
                           companion_prior_state_exact:bool=True)->bool:
    """Attempt the contract cleanup even when an earlier phase failed.

    A cleanup request is made only for an exactly captured prior state.  If the
    original state was not captured, cleanup is skipped because an absent
    fallback could delete a user's persisted setting.  Containment is checked
    after refresh before persisted state is accepted.
    """
    restoration_started=time.monotonic();restore_state=before_state;state_error=None
    evidence={"priorStateExact":prior_state_exact,"cleanupAttempted":False}
    try:
        if not prior_state_exact:
            raise RuntimeError("exact primary prior state unavailable; cleanup skipped")
        if restore_state is None:raise RuntimeError("exact primary prior state unavailable; cleanup skipped")
        evidence["priorStateAvailable"]=True
        restore_items=[(f.key,restore_state,prior_state_exact,"primary")]
        if companion_key is not None:
            companion_available=companion_before_state is not None and companion_prior_state_exact
            companion_state=companion_before_state if companion_available else StorageState(False,None)
            evidence["companion"]={"key":companion_key,"priorStateExact":companion_prior_state_exact,
                                    "priorStateAvailable":companion_before_state is not None,"cleanupAttempted":False}
            if companion_available:
                restore_items.append((companion_key,companion_state,companion_prior_state_exact,"companion"))
        state_evidence={"primary":{"key":f.key,"expected":asdict(restore_state),"priorStateExact":prior_state_exact}}
        if companion_key is not None:
            state_evidence["companion"]={"key":companion_key,"expected":asdict(companion_state),
                                          "priorStateExact":companion_prior_state_exact}
        evidence["states"]=state_evidence
        restore_error=None
        for key,state,_exact,label in restore_items:
            try:
                sent=driver.script(c.cleanup_js,[storage_payload(key,state)])
                send_ok,send_reason=cleanup_response_verified(sent,key,state)
                state_evidence[label].update({"sent":sent,"cleanupVerified":send_ok,"cleanupReason":send_reason})
                if label=="primary":
                    evidence["cleanupAttempted"]=True;evidence["sent"]=sent;evidence["cleanupVerified"]=send_ok;evidence["cleanupReason"]=send_reason
                else:
                    evidence["companion"].update({"cleanupAttempted":True,"sent":sent,"cleanupVerified":send_ok,"cleanupReason":send_reason})
                if not send_ok and restore_error is None:restore_error=label+" cleanup: "+send_reason
            except Exception as exc:
                state_evidence[label].update({"cleanupAttempted":True,"cleanupVerified":False,"error":str(exc)})
                if label=="primary":evidence["cleanupAttempted"]=True
                else:evidence["companion"].update({"cleanupAttempted":True,"cleanupVerified":False,"error":str(exc)})
                if restore_error is None:restore_error=label+" cleanup raised: "+str(exc)
        if restore_error:raise RuntimeError(restore_error)
        immediate_by_label={}
        for key,state,_exact,label in restore_items:
            immediate_by_label[label]=bounded_script(driver,STORAGE_STATE_JS,lambda v,state=state:state_is(v,state),pause=2,args=[key])
            state_evidence[label]["immediate"]=immediate_by_label[label]
        immediate=immediate_by_label["primary"]
        expected_restore=restore_state
        driver.refresh()
        if window_check is None:raise RuntimeError("restoration containment recheck is unavailable")
        window_evidence=window_check("restoration-refresh")
        if type(window_evidence) is not dict or window_evidence.get("ok") is not True:
            raise RuntimeError("owned STP window left KG271U during restoration route")
        reloaded=bounded_script(driver,REAL_PAGE_JS,lambda v:real_youtube_page_ok(route,v),pause=3)
        if not real_youtube_page_ok(route,reloaded):raise RuntimeError("restoration reload was not the exact expected HTTPS YouTube route")
        reload_bridge=ensure_bridge(driver)
        if not bridge_ok(reload_bridge):raise RuntimeError("post-refresh bridge/provider proof failed")
        persisted_by_label={}
        for key,state,_exact,label in restore_items:
            persisted_wire=bounded_script(driver,STORAGE_STATE_JS,
                                          lambda v,state=state:type(v) is dict and v.get("storageLoaded") is True and state_is(v,state),
                                          pause=3,args=[key])
            if type(persisted_wire) is not dict or persisted_wire.get("storageLoaded") is not True or not state_is(persisted_wire,state):
                raise RuntimeError(label+" persisted state readback was not authoritative")
            persisted_by_label[label]=persisted_wire;state_evidence[label]["persisted"]=persisted_wire
        persisted=persisted_by_label["primary"]
        restored,evidence_state=evaluate_restore(expected_restore,immediate,persisted)
        restored=bool(prior_state_exact and restored)
        evidence.update(evidence_state);evidence.update({"reload":reloaded,"bridge":reload_bridge,"window":window_evidence})
        state_evidence["primary"].update(evidence_state)
        if companion_key is not None:
            if companion_available:
                companion_expected=companion_before_state
                companion_immediate=state_from_wire(immediate_by_label["companion"])
                companion_persisted=state_from_wire(persisted_by_label["companion"])
                companion_restored=state_matches(companion_immediate,companion_expected) and state_matches(companion_persisted,companion_expected)
                restored=bool(companion_restored and restored)
                state_evidence["companion"].update({"immediate":asdict(companion_immediate),"persisted":asdict(companion_persisted),
                                                     "restored":companion_restored})
                evidence["companion"].update({"expected":asdict(companion_expected),"immediate":asdict(companion_immediate),
                                               "persisted":asdict(companion_persisted),"restored":companion_restored})
            else:
                restored=False
                state_evidence["companion"]["restored"]=False
        if state_error:evidence["priorStateError"]=state_error
        if not prior_state_exact:evidence["reason"]="original prior state was not captured exactly"
        if companion_key is not None and not companion_prior_state_exact and companion_available is False:evidence["companion"]["reason"]="original companion state was not captured exactly; cleanup skipped"
        record(results,f.feature_id+"-RESTORATION",f.feature_id,"exact persisted restoration",PASS if restored else ISOLATION_FAILURE,
               "live-semantic" if restored else "isolation",route,"restoration",evidence,restoration_started)
        return restored
    except Exception as exc:
        # A transport/refresh/containment error is a harness-side inability to
        # prove restoration.  Keep ISOLATION_FAILURE as the public status, but
        # mark the evidence as harness so continuation cannot cross it.
        evidence.update({"error":str(exc),"priorStateError":state_error} if state_error else {"error":str(exc)})
        record(results,f.feature_id+"-RESTORATION",f.feature_id,"exact persisted restoration",ISOLATION_FAILURE,
               "harness",route,"restoration",evidence,restoration_started)
        return False

def run_contract(driver:WebDriver,f:Feature,c:FeatureContract,route:str,results:list[Result],window_check:Callable[[str],dict[str,Any]]|None=None)->bool:
    phase="feature:"+f.key;started=time.monotonic();before_state=None;prior_state_exact=False;bridge=None;sent=None
    companion_before_state=None;companion_prior_state_exact=False;companion_setup=None;companion_setup_status=None
    try:
        driver.script(SET_PHASE_JS,[phase]);bridge=ensure_bridge(driver)
        if not bridge_ok(bridge):
            for s,a in (("-CONTRACT","semantic contract available"),("-TRANSPORT","exact bridge transport"),("-EFFECT","semantic feature effect")):
                record(results,f.feature_id+s,f.feature_id,a,HARNESS_FAILURE,"harness",route,phase,{"reason":"bridge unavailable","bridge":bridge},started)
        else:
            try:
                before_wire=bounded_script(driver,STORAGE_STATE_JS,
                                           lambda v:type(v) is dict and v.get("storageLoaded") is True,
                                           pause=3,args=[f.key])
                if type(before_wire) is not dict or before_wire.get("storageLoaded") is not True:
                    raise RuntimeError("storage-loaded provider handshake unavailable before primary baseline")
                before_state=state_from_wire(before_wire);prior_state_exact=True
                if f.key=="player_playback_speed":
                    companion_wire=bounded_script(driver,STORAGE_STATE_JS,
                                                  lambda v:type(v) is dict and v.get("storageLoaded") is True,
                                                  pause=3,args=[PLAYBACK_COMPANION_KEY])
                    if type(companion_wire) is not dict or companion_wire.get("storageLoaded") is not True:
                        raise RuntimeError("storage-loaded provider handshake unavailable before companion baseline")
                    companion_before_state=state_from_wire(companion_wire);companion_prior_state_exact=True
                    companion_requested=StorageState(True,True)
                    companion_sent=driver.script(SEND_STORAGE_JS,[storage_payload(PLAYBACK_COMPANION_KEY,companion_requested)])
                    companion_send_ok,companion_send_reason=cleanup_response_verified(companion_sent,PLAYBACK_COMPANION_KEY,companion_requested)
                    queue=companion_sent.get("queueDepth") if isinstance(companion_sent,dict) else None
                    companion_queue_ok=type(queue) is int and queue>=0
                    companion_setup={"key":PLAYBACK_COMPANION_KEY,"requested":asdict(companion_requested),"sent":companion_sent,
                                     "sendVerified":companion_send_ok,"sendReason":companion_send_reason,
                                     "queueDepth":queue,"queueVerified":companion_queue_ok}
                    if companion_send_ok and companion_queue_ok:
                        companion_wire=bounded_script(driver,STORAGE_STATE_JS,lambda v:state_is(v,companion_requested),pause=2,args=[PLAYBACK_COMPANION_KEY])
                        companion_actual=state_from_wire(companion_wire)
                        companion_setup_status=classify_transport(companion_requested,companion_actual,True,bridge_ok(bridge))
                        companion_setup["observed"]=asdict(companion_actual);companion_setup["status"]=companion_setup_status
                    else:
                        companion_setup_status=HARNESS_FAILURE
                        companion_setup["reason"]="typed companion setup acknowledgement or queue proof failed"
                    if companion_setup_status!=PASS:
                        eclass="product" if companion_setup_status==PRODUCT_FAILURE else "harness"
                        record(results,f.feature_id+"-TRANSPORT",f.feature_id,"exact bridge transport",companion_setup_status,eclass,route,phase,
                               {"reason":"playback prerequisite failed","companion":companion_setup},started)
                        record(results,f.feature_id+"-EFFECT",f.feature_id,"semantic feature effect",NOT_RUN,eclass,route,phase,
                               {"reason":"playback prerequisite failed","companion":companion_setup},started)
                setup=driver.script(c.setup_js) if companion_setup_status in (None,PASS) else None
                if companion_setup_status is not None and companion_setup_status != PASS:
                    pass
                elif not setup or setup.get("ok") is False:
                    for s,a in (("-TRANSPORT","exact bridge transport"),("-EFFECT","semantic feature effect")):
                        record(results,f.feature_id+s,f.feature_id,a,UNVERIFIED,"environment",route,phase,{"reason":"prerequisite unavailable","setup":setup,"companion":companion_setup},started)
                else:
                    before_obs=driver.script(c.before_observe_js)
                    try:
                        sent=driver.script(c.activation_js,[storage_payload(f.key,StorageState(True,c.activation_value))])
                        if f.key=="shortcut_activate_captions":driver.key("c")
                        after_obs=bounded_script(driver,c.after_observe_js,lambda v:observation_ready(c,v,before_obs,c.activation_value),pause=2)
                        requested_state=StorageState(True,c.activation_value)
                        after_state=state_from_wire(bounded_script(driver,STORAGE_STATE_JS,lambda v:state_is(v,requested_state),pause=2,args=[f.key]))
                        ts=classify_transport(StorageState(True,c.activation_value),after_state,bool(sent and sent.get("sent")),bridge_ok(bridge))
                        record(results,f.feature_id+"-TRANSPORT",f.feature_id,"exact bridge transport",ts,"transport" if ts==PASS else "product" if ts==PRODUCT_FAILURE else "harness",route,phase,{"requested":asdict(StorageState(True,c.activation_value)),"sent":sent,"observed":asdict(after_state),"before":asdict(before_state),"companion":companion_setup},started)
                        es,reason=classify_observation(c,before_obs,after_obs,c.activation_value)
                        record(results,f.feature_id+"-EFFECT",f.feature_id,"semantic feature effect",es,"live-semantic" if es==PASS else "product" if es==PRODUCT_FAILURE else "environment",route,phase,{"before":before_obs,"after":after_obs,"reason":reason},started)
                    except Exception as exc:
                        record(results,f.feature_id+"-TRANSPORT",f.feature_id,"exact bridge transport",HARNESS_FAILURE,"harness",route,phase,{"error":str(exc),"sent":sent,"companion":companion_setup},started)
                        record(results,f.feature_id+"-EFFECT",f.feature_id,"semantic feature effect",NOT_RUN,"harness",route,phase,{"reason":"activation raised","error":str(exc)},started)
            except Exception as exc:
                record(results,f.feature_id+"-TRANSPORT",f.feature_id,"exact bridge transport",HARNESS_FAILURE,"harness",route,phase,{"reason":"contract setup failed","error":str(exc),"companion":companion_setup},started)
                record(results,f.feature_id+"-EFFECT",f.feature_id,"semantic feature effect",NOT_RUN,"harness",route,phase,{"reason":"contract setup failed","error":str(exc),"companion":companion_setup},started)
    except Exception as exc:
        record(results,f.feature_id+"-CONTRACT",f.feature_id,"semantic contract available",HARNESS_FAILURE,"harness",route,phase,{"reason":"contract initialization failed","error":str(exc)},started)
        record(results,f.feature_id+"-TRANSPORT",f.feature_id,"exact bridge transport",HARNESS_FAILURE,"harness",route,phase,{"reason":"contract initialization failed","error":str(exc)},started)
        record(results,f.feature_id+"-EFFECT",f.feature_id,"semantic feature effect",NOT_RUN,"harness",route,phase,{"reason":"contract initialization failed","error":str(exc)},started)
    finally:
        # This is deliberately unconditional: failures before activation must
        # still leave a typed restoration row; cleanup requires exact baselines.
        try:
            restored=restore_contract_state(driver,f,c,route,results,before_state,prior_state_exact,phase,started,window_check,
                                             companion_key=PLAYBACK_COMPANION_KEY if f.key=="player_playback_speed" else None,
                                             companion_before_state=companion_before_state,
                                             companion_prior_state_exact=companion_prior_state_exact)
        except Exception as exc:
            # A finalizer bug must not erase the original activation/setup
            # failure.  The row helper is idempotent by assertion ID.
            restored=False
            existing=next((row for row in results if getattr(row,"assertion_id",None)==f.feature_id+"-RESTORATION"),None)
            if existing is None or getattr(existing,"status",None)==PASS:
                record(results,f.feature_id+"-RESTORATION",f.feature_id,"exact persisted restoration",ISOLATION_FAILURE,
                       "harness",route,"restoration",{"error":str(exc),"finalizerRaised":True,
                       "priorEvidence":getattr(existing,"evidence",None)},started)
        if not any(getattr(row,"assertion_id",None)==f.feature_id+"-RESTORATION" for row in results):
            record(results,f.feature_id+"-RESTORATION",f.feature_id,"exact persisted restoration",ISOLATION_FAILURE,
                   "harness",route,"restoration",{"reason":"restoration result was not emitted"},started)
    return restored

def run_falsy_probe(driver:WebDriver,f:Feature,route:str,results:list[Result],window_check:Callable[[str],dict[str,Any]]|None=None)->bool:
    """Exercise all five wire states without collapsing falsy values."""
    phase="falsy:"+f.key;started=time.monotonic();before=None;prior_state_exact=False;bridge=None
    requested_states=FALSY_PROBE_STATES;observations=[];emitted_operations=[];aggregate=PASS;restore_each=True;falsy_recorded=False;restored=False
    try:
        bridge=ensure_bridge(driver)
        if not bridge_ok(bridge):raise RuntimeError("bridge/provider unavailable before falsy baseline")
        before_wire=bounded_script(driver,STORAGE_STATE_JS,
                                   lambda v:type(v) is dict and v.get("storageLoaded") is True,
                                   pause=3,args=[f.key])
        if type(before_wire) is not dict or before_wire.get("storageLoaded") is not True:
            raise RuntimeError("storage-loaded provider handshake unavailable before falsy baseline")
        before=state_from_wire(before_wire);prior_state_exact=True
        for requested in requested_states:
            try:
                payload=storage_payload(f.key,requested);sent=driver.script(SEND_STORAGE_JS,[payload])
                actual=state_from_wire(bounded_script(driver,STORAGE_STATE_JS,lambda v:state_is(v,requested),pause=2,args=[f.key]))
                status=classify_transport(requested,actual,bool(sent and sent.get("sent")),bridge_ok(bridge));operation=sent.get("operation") if isinstance(sent,dict) else None
                emitted_operations.append({"operation":operation,"payload":payload})
                state_observation={"requested":asdict(requested),"payload":payload,"sent":sent,"observed":asdict(actual),"status":status}
                observations.append(state_observation)
                if status==HARNESS_FAILURE:aggregate=HARNESS_FAILURE
                elif status==PRODUCT_FAILURE and aggregate!=HARNESS_FAILURE:aggregate=PRODUCT_FAILURE
                elif status!=PASS and aggregate==PASS:aggregate=HARNESS_FAILURE
                restore_sent=driver.script(SEND_STORAGE_JS,[storage_payload(f.key,before)])
                send_ok,send_reason=cleanup_response_verified(restore_sent,f.key,before)
                restored_state=state_from_wire(bounded_script(driver,STORAGE_STATE_JS,lambda v:state_is(v,before),pause=2,args=[f.key]))
                state_observation["betweenStateRestore"]={"sent":restore_sent,"verified":send_ok,"reason":send_reason,"observed":asdict(restored_state)}
                restore_each=restore_each and send_ok and state_matches(restored_state,before)
                if not restore_each:aggregate=HARNESS_FAILURE;break
            except Exception as exc:
                observations.append({"requested":asdict(requested),"status":HARNESS_FAILURE,"error":str(exc)})
                aggregate=HARNESS_FAILURE;restore_each=False;break
        expected_operations=[
            {"operation":"set","payload":storage_payload(f.key,StorageState(True,False))},
            {"operation":"set","payload":storage_payload(f.key,StorageState(True,0))},
            {"operation":"set","payload":storage_payload(f.key,StorageState(True,""))},
            {"operation":"set","payload":storage_payload(f.key,StorageState(True,None))},
            {"operation":"delete","payload":storage_payload(f.key,StorageState(False,None))},
        ]
        emitted_keys={json.dumps(item,separators=(",",":"),sort_keys=True) for item in emitted_operations}
        all_five_requested=emitted_operations==expected_operations and len(emitted_keys)==5
        if not all_five_requested:aggregate=HARNESS_FAILURE
        record(results,f.feature_id+"-FALSY-TRANSPORT",f.feature_id,"falsy transport regression (false, 0, empty, null, and absence)",aggregate,
               "transport" if aggregate==PASS else "product" if aggregate==PRODUCT_FAILURE else "harness",route,phase,
               {"states":observations,"before":asdict(before),"emittedOperations":emitted_operations,"distinctEmittedOperations":len(emitted_keys),
                "allFiveRequested":all_five_requested,"restoredBetweenStates":restore_each},started);falsy_recorded=True
    except Exception as exc:
        aggregate=HARNESS_FAILURE
        if not falsy_recorded:
            record(results,f.feature_id+"-FALSY-TRANSPORT",f.feature_id,"falsy transport regression (false, 0, empty, null, and absence)",HARNESS_FAILURE,
                   "harness",route,phase,{"reason":"falsy setup/finalization failed","error":str(exc),"before":asdict(before) if before is not None else None},started)
            falsy_recorded=True
    finally:
        cleanup_contract=CONTRACTS.get(f.key) or FeatureContract(f.key,route,"",SEND_STORAGE_JS,"","",SEND_STORAGE_JS,("falsy cleanup",),"unknown",None)
        try:
            restored=restore_contract_state(driver,f,cleanup_contract,route,results,before,prior_state_exact,phase,started,window_check)
        except Exception as exc:
            restored=False
            existing=next((row for row in results if getattr(row,"assertion_id",None)==f.feature_id+"-RESTORATION"),None)
            if existing is None or getattr(existing,"status",None)==PASS:
                record(results,f.feature_id+"-RESTORATION",f.feature_id,"exact persisted restoration",ISOLATION_FAILURE,"harness",route,
                       "falsy-restoration",{"error":str(exc),"finalizerRaised":True,"priorEvidence":getattr(existing,"evidence",None)},started)
        if not any(getattr(row,"assertion_id",None)==f.feature_id+"-RESTORATION" for row in results):
            record(results,f.feature_id+"-RESTORATION",f.feature_id,"exact persisted restoration",ISOLATION_FAILURE,"harness",route,
                   "falsy-restoration",{"reason":"restoration result was not emitted"},started)
        if not falsy_recorded:
            record(results,f.feature_id+"-FALSY-TRANSPORT",f.feature_id,"falsy transport regression (false, 0, empty, null, and absence)",HARNESS_FAILURE,
                   "harness",route,phase,{"reason":"falsy result was not emitted"},started)
    return restored

def feature_failure_state(results:Iterable[Result],f:Feature)->str:
    """Classify only this feature's executed contract rows.

    Source-only/classification rows are intentionally ignored.  A harness or
    environment evidence class is fatal even if a legacy status was
    UNVERIFIED.  Isolation evidence is terminal even if a caller accidentally
    labels its status as a product failure; the continuation flag is never a
    classification override.  Only a product failure with an independently
    passing restoration row may be considered for the explicit continuation
    mode.
    """
    ids={f.feature_id+s for s in ("-TRANSPORT","-EFFECT","-RESTORATION","-FALSY-TRANSPORT")}
    rows=[row for row in results if getattr(row,"assertion_id",None) in ids and getattr(row,"status",None)!=NOT_RUN]
    if any(getattr(row,"evidence_class",None) in {"harness","environment","identity","containment","cleanup"} or getattr(row,"status",None) in {HARNESS_FAILURE,ENVIRONMENT_FAILURE} for row in rows):
        return "fatal"
    # Evidence class is part of the trusted result contract.  Treat an
    # isolation-class row as terminal even when its status was mislabeled as
    # PRODUCT_FAILURE, preventing a status-only relabel from bypassing the
    # lifecycle boundary.
    if any(getattr(row,"evidence_class",None)=="isolation" or getattr(row,"status",None)==ISOLATION_FAILURE for row in rows):
        return "isolation"
    if any(getattr(row,"status",None)==PRODUCT_FAILURE for row in rows):return "product"
    return "pass"

def exact_restoration_passed(results:Iterable[Result],f:Feature)->bool:
    """Return true only for one canonical, live-semantic restoration PASS.

    ``run_contract`` and ``run_falsy_probe`` emit this row only after their
    strict cleanup, reload, bridge, state, and containment checks.  Requiring
    the canonical evidence class as well as PASS prevents a product-labelled
    or otherwise synthetic restoration row from authorizing continuation.
    """
    rows=[row for row in results if getattr(row,"assertion_id",None)==f.feature_id+"-RESTORATION"]
    return len(rows)==1 and getattr(rows[0],"status",None)==PASS and getattr(rows[0],"evidence_class",None)=="live-semantic"

def mark_contract_blocked(results:list[Result],f:Feature,route:str,reason:str,eclass:str="isolation",
                          include_falsy:bool=False)->None:
    started=time.monotonic()
    for suffix,assertion in (("-TRANSPORT","exact bridge transport"),("-EFFECT","semantic feature effect"),("-RESTORATION","exact persisted restoration")):
        record(results,f.feature_id+suffix,f.feature_id,assertion,NOT_RUN,eclass,route,"blocked",{"reason":reason},started)
    if include_falsy:
        record(results,f.feature_id+"-FALSY-TRANSPORT",f.feature_id,"falsy transport regression (false, 0, empty, null, and absence)",NOT_RUN,eclass,route,"blocked",{"reason":reason},started)

def run_feature_contracts(driver:WebDriver,features:list[Feature],route:str,results:list[Result],
                          window_check:Callable[[str],dict[str,Any]],
                          continue_after_product_failure:bool=False,exercise_falsy:bool=False,
                          falsy_only:bool=False)->str:
    """Execute selected contracts with an explicit continuation policy.

    Every continuation crosses a new route/window containment observation.
    The return value is ``fatal`` for harness/environment failures, ``stopped``
    for default fail-fast product/isolation behavior, and ``continued`` when
    opted-in continuation retained a product failure whose exact restoration
    passed.  Isolation, restoration, harness, environment, identity, and
    containment failures always stop the session.
    """
    prior_product_failure=False;stop_reason=None
    for feature in features:
        if stop_reason:
            mark_contract_blocked(results,feature,route,"previous contract failed: "+stop_reason,
                                  "harness" if stop_reason=="fatal" else "isolation",exercise_falsy)
            continue
        if prior_product_failure:
            evidence=window_check("before-contract:"+feature.key)
            if type(evidence) is not dict or evidence.get("ok") is not True:
                raise RuntimeError("route/window containment recheck failed before continuing contracts")
        if falsy_only:
            restored=run_falsy_probe(driver,feature,route,results,window_check)
        else:
            restored=run_contract(driver,feature,CONTRACTS[feature.key],route,results,window_check)
        state=feature_failure_state(results,feature)
        if restored is not True and state=="pass":
            # Keep the boolean API fail-closed even for an injected/legacy
            # runner that forgot to emit its restoration row.
            record(results,feature.feature_id+"-RESTORATION",feature.feature_id,
                   "exact persisted restoration",ISOLATION_FAILURE,"isolation",route,"restoration",
                   {"reason":"contract runner reported restoration failure without a typed failure row"})
            state="isolation"
        # Every contract must have the canonical strict-finalizer proof.  A
        # missing, relabeled, or failed restoration is an isolation stop even
        # when the feature rows otherwise pass or say PRODUCT_FAILURE.
        if state not in {"fatal","isolation"} and (restored is not True or not exact_restoration_passed(results,feature)):
            existing=next((row for row in results if getattr(row,"assertion_id",None)==feature.feature_id+"-RESTORATION"),None)
            record(results,feature.feature_id+"-RESTORATION",feature.feature_id,
                   "exact persisted restoration",ISOLATION_FAILURE,"isolation",route,"restoration",
                   {"reason":"contract did not have a canonical passing restoration proof",
                    "returnedRestored":restored,"priorEvidence":getattr(existing,"evidence",None)})
            state="isolation"
        if exercise_falsy and not falsy_only and state not in {"fatal","isolation"}:
            run_falsy_probe(driver,feature,route,results,window_check)
            state=feature_failure_state(results,feature)
        if state=="fatal":
            stop_reason="fatal"
        elif state=="isolation":
            # Isolation (including restoration proof failure) can never be
            # crossed by the product-continuation flag.
            stop_reason="isolation"
        elif state=="product":
            prior_product_failure=True
            if not continue_after_product_failure:stop_reason=state
        # An isolation failure means the falsy probe cannot safely add another
        # mutation and the session must stop; leave its row NOT_RUN.
        if exercise_falsy and state in {"fatal","isolation"}:
            record(results,feature.feature_id+"-FALSY-TRANSPORT",feature.feature_id,
                   "falsy transport regression (false, 0, empty, null, and absence)",NOT_RUN,
                   "harness" if state=="fatal" else "isolation",route,
                   "blocked-after-failure",{"reason":"contract could not safely start falsy probe: "+state},time.monotonic())
    if stop_reason=="fatal":return "fatal"
    if stop_reason:return "stopped"
    return "continued" if prior_product_failure else "ok"

def coregraphics_windows()->list[dict[str,Any]]:
    swift=r'''import CoreGraphics
import Foundation
let raw=CGWindowListCopyWindowInfo([.optionOnScreenOnly,.excludeDesktopElements],kCGNullWindowID) as? [[String:Any]] ?? []
let windows=raw.compactMap { item -> [String:Any]? in
 guard let owner=item[kCGWindowOwnerName as String] as? String,owner=="Safari Technology Preview" else{return nil}
 guard (item[kCGWindowLayer as String] as? NSNumber)?.intValue == 0 else{return nil}
 guard let b=item[kCGWindowBounds as String] as? [String:Any] else{return nil}
 func n(_ k:String)->Double{(b[k] as? NSNumber)?.doubleValue ?? 0}
 return ["owner":owner,"name":item[kCGWindowName as String] as? String ?? "","pid":(item[kCGWindowOwnerPID as String] as? NSNumber)?.intValue ?? -1,"windowId":(item[kCGWindowNumber as String] as? NSNumber)?.intValue ?? -1,"alpha":(item[kCGWindowAlpha as String] as? NSNumber)?.doubleValue ?? 0,"x":n("X"),"y":n("Y"),"width":n("Width"),"height":n("Height")]
}
let d=try! JSONSerialization.data(withJSONObject:windows);print(String(data:d,encoding:.utf8)!)'''
    p=subprocess.run(["/usr/bin/swift","-e",swift],capture_output=True,text=True,timeout=45)
    if p.returncode:raise RuntimeError("CoreGraphics inspection failed: "+(p.stderr or p.stdout)[-500:])
    v=json.loads(p.stdout)
    if not isinstance(v,list):raise RuntimeError("CoreGraphics returned no window list")
    return v
def bounds_inside_kg271u(b:dict[str,Any])->bool:
    try:
        x,y,w,h=(float(b[k]) for k in ("x","y","width","height"));return x>=KG271U_BOUNDS["x"] and y>=KG271U_BOUNDS["y"] and x+w<=KG271U_BOUNDS["right"] and y+h<=KG271U_BOUNDS["bottom"]
    except (KeyError,TypeError,ValueError):return False
def verify_owned_windows(pid:int,window_id:int|None=None)->dict[str,Any]:
    if not pid or pid<1:raise RuntimeError("automation Safari PID is required for CoreGraphics identity")
    if window_id is None:raise RuntimeError("automation Safari window ID is required for scoped CoreGraphics identity")
    windows=coregraphics_windows()
    visible=[w for w in windows if w.get("pid")==pid and float(w.get("alpha",1))>0 and float(w.get("width",0))>0 and float(w.get("height",0))>0]
    target=next((w for w in visible if w.get("windowId")==window_id),None)
    if target is None:raise RuntimeError("automation window identity is not visible for PID")
    outside=[] if bounds_inside_kg271u(target) else [target]
    unrelated=[w for w in visible if w.get("windowId")!=window_id]
    return {"ok":not outside,"pid":pid,"windowId":window_id,"targetWindow":target,"ownedVisibleWindows":[target],"unrelatedVisibleWindows":unrelated,"outside":outside,"kg271u":KG271U_BOUNDS}

def identify_window_id(pid:int,requested:dict[str,Any])->int:
    if not pid or pid<1:raise RuntimeError("automation Safari PID is required for window identity")
    windows=coregraphics_windows();candidates=[]
    width=float(requested.get("width",0));height=float(requested.get("height",0))
    for window in windows:
        if window.get("pid")==pid and float(window.get("alpha",1))>0 and abs(float(window.get("width",0))-width)<=2 and abs(float(window.get("height",0))-height)<=2:
            candidates.append(window)
    if len(candidates)!=1:raise RuntimeError("could not uniquely identify automation window by PID and requested geometry")
    return int(candidates[0]["windowId"])
def port_open(host:str,port:int)->bool:
    try:
        with socket.create_connection((host,port),timeout=.5):return True
    except OSError:return False
def launch_process(command:list[str],log_path:Path)->subprocess.Popen[Any]:
    log=log_path.open("ab");return subprocess.Popen(command,stdout=log,stderr=log,start_new_session=True)
def terminate_process(p:subprocess.Popen[Any]|None)->None:
    if p is None:return
    if p.poll() is None:
        p.terminate()
        try:p.wait(timeout=10)
        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=10)
def create_session(driver:WebDriver,sut:str,extension_path:Path)->dict[str,Any]:
    driver.create();driver.set_timeouts(30000,30000);e={"sessionId":driver.session_id,"sut":"signed-testflight" if sut=="signed" else "unpacked-opt-in","extensionLoad":"not-requested","browserPid":getattr(driver,"browser_pid",None)}
    if sut=="unpacked":e["extensionId"]=driver.load_extension(extension_path);e["extensionLoad"]="webdriver-webextension"
    return e
def lifecycle_ownership(driver_mode:str)->dict[str,Any]:
    if driver_mode=="external":
        return {"driverProcess":"external-unowned","stpProcess":"external-unowned","automationWindow":"session-owned","unrelatedWindows":"untouched"}
    return {"driverProcess":"harness-owned","stpProcess":"harness-owned","automationWindow":"session-owned","unrelatedWindows":"untouched"}
def cleanup_success(driver_mode:str,session_closed:bool,window_closed:bool,port_clear:bool,external_reachable:bool,window_close_verified:bool=True)->bool:
    # An external safaridriver is deliberately expected to remain reachable;
    # only the WebDriver session and target window belong to this harness.
    required_port_state=port_clear if driver_mode=="internal" else external_reachable
    return (session_closed is True and window_closed is True and required_port_state is True
            and window_close_verified is True)

def session_close_verified(evidence:Any)->bool:
    if type(evidence) is not dict or evidence.get("verified") is not True:
        return False
    status=evidence.get("status")
    if status in {"already-absent","not-created"}:
        return True
    if status=="implicit-delete-by-last-window":
        return evidence.get("windowCloseVerified") is True
    # The production WebDriver wrapper records the decoded W3C ``value``
    # member for a successful DELETE /session.  Status alone is not proof of
    # a typed protocol response, so synthetic/partial evidence stays unknown.
    return (status=="deleted" and type(evidence.get("httpStatus")) is int
            and 200<=evidence["httpStatus"]<300 and "value" in evidence
            and evidence["value"] is None)

def close_webdriver_session(driver:WebDriver,session_created:bool)->dict[str,Any]:
    evidence={"sessionCreated":session_created,"sessionClosed":False,"windowCloseRequested":False,
              "windowCloseVerified":False,"implicitDeleteByLastWindow":False,
              "windowCloseEvidence":None,"sessionCloseEvidence":None}
    if not session_created:
        evidence.update({"sessionClosed":True,"windowCloseVerified":True,
                         "sessionCloseEvidence":{"verified":True,"status":"not-created"}})
        return evidence
    try:
        evidence["windowCloseRequested"]=True
        window_result=driver.close_window()
        if (type(window_result) is not dict or window_result.get("verified") is not True
                or window_result.get("status")!="deleted-window"
                or type(window_result.get("httpStatus")) is not int
                or not 200<=window_result["httpStatus"]<300
                or type(window_result.get("remainingHandles")) is not list
                or any(type(handle) is not str or not handle for handle in window_result["remainingHandles"])
                or len(set(window_result["remainingHandles"]))!=len(window_result["remainingHandles"])
                or type(window_result.get("lastWindow")) is not bool
                or window_result["lastWindow"]!=(len(window_result["remainingHandles"])==0)):
            raise RuntimeError("DELETE /window returned an unverified response shape")
        evidence["windowCloseEvidence"]=window_result;evidence["windowCloseVerified"]=True
        if window_result["lastWindow"]:
            if hasattr(driver,"session_id"):driver.session_id=""
            evidence.update({"sessionClosed":True,"implicitDeleteByLastWindow":True,
                             "sessionCloseEvidence":{"verified":True,"status":"implicit-delete-by-last-window",
                                                      "windowCloseVerified":True,"windowCloseEvidence":window_result}})
            return evidence
    except Exception as exc:
        evidence["windowCloseError"]=str(exc)
    try:
        close_result=driver.close()
        evidence["sessionCloseEvidence"]=close_result
        evidence["sessionClosed"]=session_close_verified(close_result)
    except Exception as exc:
        evidence["sessionCloseEvidence"]={"verified":False,"status":"failed","error":str(exc)}
    return evidence

def observer_binding_mode(args:Any)->str:
    """Select late binding by default; prebound identity is diagnostics-only."""
    pid=getattr(args,"stp_pid",None);window_id=getattr(args,"window_id",None)
    if (pid is None) != (window_id is None):
        return "invalid-prebound"
    if getattr(args,"driver_mode",None)!="external":
        return "internal"
    return "prebound-diagnostic" if pid is not None else "late"

def fresh_title_nonce()->str:
    return "ImprovedTube-E2E-"+secrets.token_urlsafe(32)

def expected_assertions(features:list[Feature],routes:Iterable[str],full_live:bool=False)->set[str]:
    e={"GLOBAL-IDENTITY","GLOBAL-DRIVER","GLOBAL-KG271U","GLOBAL-CLEANUP","GLOBAL-COVERAGE","GLOBAL-CONSOLE"}
    for f in features:e.update(feature_assertions(f,full_live))
    for route in routes:e.update({"ROUTE-"+route.upper()+s for s in ("-REAL","-EXTENSION","-SCREENSHOT","-KG271U","-CONSOLE")})
    return e

def _lifecycle(driver:WebDriver,step:Any,context:dict[str,Any]|None=None,allow_undefined:bool=False)->Any:
    """Await an async-function lifecycle body and require JSON-safe evidence."""
    if not isinstance(step,dict) or not isinstance(step.get("script"),str):raise RuntimeError("invalid executable lifecycle step")
    argv=list(step.get("args") or [])+[context or {"setup":None,"before":None,"postActivation":None,"activation":None,"accountFixture":None,"observedAccount":None}]
    try:json.dumps(argv,allow_nan=False)
    except (TypeError,ValueError) as exc:raise RuntimeError("lifecycle arguments are not serializable") from exc
    source=ASYNC_LIFECYCLE_JS.replace("/*__IT_LIFECYCLE_BODY__*/",step["script"])
    response=driver.script_async(source,[step["script"],argv,allow_undefined])
    if not isinstance(response,dict) or response.get("itLifecycle") is not True or response.get("ok") is not True:
        raise RuntimeError("async lifecycle failed: "+json.dumps(response,default=str))
    return response.get("value")

def _is_explicitly_unavailable(exc:RuntimeError)->bool:
    prefix="async lifecycle failed: ";text=str(exc)
    if not text.startswith(prefix):return False
    try:error=json.loads(text[len(prefix):]).get("error")
    except (AttributeError,json.JSONDecodeError):return False
    return isinstance(error,dict) and isinstance(error.get("message"),str) and re.search(r"\bunavailable\b",error["message"]) is not None

def _storage_maps_equal(left:dict[str,StorageSnapshot],right:dict[str,StorageSnapshot])->bool:
    if set(left)!=set(right):return False
    return all(left[key].present==right[key].present and (not left[key].present or deep_equal(left[key].value,right[key].value)) for key in left)

def _storage_diff(left:dict[str,StorageSnapshot],right:dict[str,StorageSnapshot])->dict[str,dict[str,Any]]:
    absent=lambda key:StorageSnapshot.capture(key,False)
    result={}
    for key in sorted(set(left)|set(right)):
        before,after=left.get(key,absent(key)),right.get(key,absent(key))
        if before.present!=after.present or (before.present and not deep_equal(before.value,after.value)):
            result[key]={"before":before.redacted(),"after":after.redacted()}
    return result

def _prove_youtube_fixture(driver:WebDriver,fixture:Any,window_check:Callable[[str],dict[str,Any]]|None,phase:str,recover:bool=False)->dict[str,Any]:
    if recover:
        recovery_url="data:text/html,<html><head><title>ImprovedTube%20recovery</title></head><body></body></html>"
        if hasattr(driver,"command"):driver.command("POST","/url",{"url":recovery_url},timeout=75);driver.in_frame=False
        else:driver.navigate(recovery_url)
    driver.navigate(fixture.exact_url)
    deadline=time.monotonic()+30;proof={}
    while time.monotonic()<deadline:
        observed=driver.script(FIXTURE_EVIDENCE_JS,[list(fixture.required_selectors)])
        proof=validate_fixture(fixture,observed)
        if proof["ok"]:break
        time.sleep(.25)
    if not proof.get("ok"):raise CandidateUnavailable("fixture candidate unavailable: "+json.dumps(proof,default=str))
    bridge=ensure_bridge(driver)
    if not bridge_ok(bridge):raise RuntimeError("fixture bridge failed: "+json.dumps(bridge,default=str))
    persisted=bounded_script(driver,PAGE_STORAGE_SNAPSHOT_JS,lambda value:isinstance(value,dict) and value.get("ok") is True,pause=3,args=[None])
    if not isinstance(persisted,dict) or persisted.get("ok") is not True:raise RuntimeError("fixture persisted storage unavailable")
    containment=window_check(phase) if window_check else {"ok":True,"phase":phase}
    if containment.get("ok") is not True:raise RuntimeError("fixture containment failed")
    return {"fixture":proof,"bridge":bridge,"persistedStorage":True,"containment":containment}

def _prove_youtube_redirect(driver:WebDriver,source_fixture:Any,post_fixture:Any,
                            window_check:Callable[[str],dict[str,Any]]|None,phase:str)->dict[str,Any]:
    """Navigate only to the declared source and prove the product reached the exact declared destination."""
    driver.navigate(source_fixture.exact_url);deadline=time.monotonic()+10;proof={}
    while time.monotonic()<deadline:
        observed=driver.script(FIXTURE_EVIDENCE_JS,[list(post_fixture.required_selectors)])
        proof=validate_fixture(post_fixture,observed)
        if proof["ok"]:break
        time.sleep(.25)
    redirect_observed=proof.get("ok") is True
    bridge=ensure_bridge(driver)
    if not bridge_ok(bridge):raise RuntimeError("redirect destination bridge failed: "+json.dumps(bridge,default=str))
    persisted=bounded_script(driver,PAGE_STORAGE_SNAPSHOT_JS,lambda value:isinstance(value,dict) and value.get("ok") is True,pause=3,args=[None])
    if not isinstance(persisted,dict) or persisted.get("ok") is not True:raise RuntimeError("redirect persisted storage unavailable")
    containment=window_check(phase) if window_check else {"ok":True,"phase":phase}
    if containment.get("ok") is not True:raise RuntimeError("redirect destination containment failed")
    return {"sourceFixtureId":source_fixture.fixture_id,"expectedFixtureId":post_fixture.fixture_id,
            "redirectObserved":redirect_observed,"fixture":proof,"bridge":bridge,"persistedStorage":True,"containment":containment}

class CandidateUnavailable(RuntimeError):pass

def _authority_roundtrip(driver:WebDriver,adapter:BrowserStorageAdapter,anchor:Any,
                         window_check:Callable[[str],dict[str,Any]]|None)->dict[str,Any]:
    """Prove that options storage and the active content bridge share one profile."""
    baseline=adapter.snapshot(None);key="__it_e2e_authority_"+secrets.token_hex(16);nonce=secrets.token_urlsafe(32)
    if key in baseline:raise RuntimeError("authority nonce key unexpectedly exists")
    try:
        adapter.set(key,nonce)
        route_write=_prove_youtube_fixture(driver,anchor,window_check,"authority-route-write",recover=True)
        deadline=time.monotonic()+10;mirror=None
        while time.monotonic()<deadline:
            mirror=driver.script(STORAGE_STATE_JS,[key])
            if isinstance(mirror,dict) and mirror.get("present") is True and mirror.get("mirrorOwn") is True and mirror.get("storageLoaded") is True and deep_equal(mirror.get("value"),nonce):break
            time.sleep(.1)
        else:raise RuntimeError("active content bridge did not observe authority nonce")
        adapter.enter_options();adapter.remove(key);restored=adapter.snapshot(None)
        if key in restored:raise RuntimeError("authority nonce remained in direct options storage")
        route_return=_prove_youtube_fixture(driver,anchor,window_check,"authority-route-return",recover=True)
        page=PageBridgeStorageAdapter(driver).snapshot(None)
        if not _storage_maps_equal(restored,page):raise RuntimeError("page storage mirror differs from current direct options storage")
        return {"baselineDigest":hashlib.sha256(json.dumps({k:v.redacted() for k,v in baseline.items()},sort_keys=True).encode()).hexdigest(),
                "restoredDigest":hashlib.sha256(json.dumps({k:v.redacted() for k,v in restored.items()},sort_keys=True).encode()).hexdigest(),
                "concurrentChanges":_storage_diff(baseline,restored),
                "nonceDigest":hashlib.sha256(nonce.encode()).hexdigest(),"writeReadback":True,"mirrorObserved":True,
                "removeReadback":True,"baselineRestored":True,"fullMirrorMatched":True,"routeWrite":route_write,"routeReturn":route_return}
    except Exception:
        try:
            adapter.enter_options();adapter.remove(key)
        except Exception:pass
        raise

def _account_target(contract:ContractSpec,args:Any)->dict[str,Any]|None:
    declared=getattr(args,"account_fixture_data",None)
    if not isinstance(declared,dict):return None
    targets=declared.get("targets")
    target=next((item for item in targets if isinstance(item,dict) and item.get("fixtureId")==contract.fixture_id),None) if isinstance(targets,list) else None
    if target is None:return None
    return {"accountId":declared.get("accountId"),"fixtureId":target.get("fixtureId"),"videoId":target.get("videoId"),"channelId":target.get("channelId")}

def load_account_fixture(path:str|Path)->dict[str,Any]:
    value=json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value,dict) or set(value)!={"accountId","targets"} or not isinstance(value["accountId"],str) or not value["accountId"].strip() or not isinstance(value["targets"],list) or not value["targets"]:
        raise ValueError("account fixture must be exact {accountId,targets}")
    seen=set()
    for target in value["targets"]:
        if not isinstance(target,dict) or set(target)!={"fixtureId","videoId","channelId"} or not isinstance(target["fixtureId"],str) or not target["fixtureId"]:
            raise ValueError("account target must be exact {fixtureId,videoId,channelId}")
        if target["fixtureId"] in seen:raise ValueError("account fixture targets must be unique")
        seen.add(target["fixtureId"])
        if target["videoId"] is not None and (not isinstance(target["videoId"],str) or not target["videoId"]):raise ValueError("account target videoId must be a string or null")
        if target["channelId"] is not None and (not isinstance(target["channelId"],str) or not target["channelId"]):raise ValueError("account target channelId must be a string or null")
    return value

def _observe_account_current(driver:WebDriver,contract:ContractSpec,target:dict[str,Any]|None)->dict[str,Any]|None:
    """Bind the current document; never navigate to make a mismatch disappear."""
    if target is None:return None
    observed=driver.script(ACCOUNT_CONTEXT_JS)
    if not isinstance(observed,dict) or observed.get("loggedIn") is not True or not observed.get("accountId"):
        raise RuntimeError("stable dedicated account identity is unavailable")
    shaped={"accountId":observed.get("accountId"),"fixtureId":contract.fixture_id,
            "videoId":observed.get("videoId"),"channelId":observed.get("channelId")}
    if not deep_equal(shaped,target):raise RuntimeError("current account/URL/player target does not equal approved account fixture")
    return shaped

def _enter_account_target(driver:WebDriver,contract:ContractSpec,target:dict[str,Any],
                          window_check:Callable[[str],dict[str,Any]]|None,phase:str)->dict[str,Any]:
    video_id=target.get("videoId")
    if not isinstance(video_id,str) or not re.fullmatch(r"[A-Za-z0-9_-]{11}",video_id):raise RuntimeError("approved account videoId is invalid")
    exact_url="https://www.youtube.com/watch?v="+video_id;driver.navigate(exact_url);deadline=time.monotonic()+10;observed={}
    while time.monotonic()<deadline:
        observed=driver.script(FIXTURE_EVIDENCE_JS,[["#player video"]])
        if (isinstance(observed,dict) and observed.get("url")==exact_url and observed.get("readyState")=="complete"
                and observed.get("selectors")==["#player video"]):break
        time.sleep(.1)
    else:raise RuntimeError("approved account target video did not load exactly")
    bridge=ensure_bridge(driver)
    if not bridge_ok(bridge):raise RuntimeError("approved account target bridge unavailable")
    containment=window_check(phase) if window_check else {"ok":True,"phase":phase}
    if containment.get("ok") is not True:raise RuntimeError("approved account target containment failed")
    binding=_observe_account_current(driver,contract,target);driver.script(INSTRUMENT_JS)
    return {"fixture":{"ok":True,"id":"approved-account-target","url":exact_url,"selectors":["#player video"]},
            "bridge":bridge,"containment":containment,"account":binding}

def _observe_account_fixture_resource_current(driver:WebDriver,contract:ContractSpec,target:dict[str,Any])->dict[str,Any]:
    fixture=ROUTE_FIXTURES[contract.fixture_id];observed=driver.script(ACCOUNT_CONTEXT_JS)
    if not isinstance(observed,dict) or observed.get("loggedIn") is not True or observed.get("accountId")!=target.get("accountId"):
        raise RuntimeError("stable dedicated account identity is unavailable on declared fixture")
    evidence=driver.script(FIXTURE_EVIDENCE_JS,[list(fixture.required_selectors)]);proof=validate_fixture(fixture,evidence)
    if not proof.get("ok"):raise RuntimeError("account fixture-card residence changed")
    return {"accountId":target.get("accountId"),"fixtureId":contract.fixture_id,
            "videoId":target.get("videoId"),"channelId":target.get("channelId")}

def _enter_account_fixture_resource(driver:WebDriver,contract:ContractSpec,target:dict[str,Any],
                                    window_check:Callable[[str],dict[str,Any]]|None,phase:str)->dict[str,Any]:
    resource=_enter_account_target(driver,contract,target,window_check,phase+":resource")
    fixture=ROUTE_FIXTURES[contract.fixture_id];residence=_prove_youtube_fixture(driver,fixture,window_check,phase+":residence")
    binding=_observe_account_fixture_resource_current(driver,contract,target);driver.script(INSTRUMENT_JS)
    return {"mode":"fixture-card","resourceProof":resource,"residenceProof":residence,"account":binding}

_VIDEO_PLAY_STEP={"script":"""const v=document.querySelector('#player video,video');if(!v)return {ok:false,reason:'real video unavailable'};
const start=v.currentTime;try{await v.play();}catch(error){return {ok:false,reason:String(error)}}
const deadline=Date.now()+3000;while(Date.now()<deadline&&(v.paused||v.currentTime<=start+.02))await new Promise(r=>setTimeout(r,50));
return {ok:!v.paused&&v.currentTime>start+.02,paused:v.paused,start,currentTime:v.currentTime};"""}
_VIDEO_TRIGGER_STEP={"script":"""const v=document.querySelector('#player video,video');if(!v)return {ok:false,reason:'real video unavailable'};
v.pause();await new Promise(r=>setTimeout(r,100));const start=v.currentTime;try{await v.play();}catch(error){return {ok:false,reason:String(error)}}
const deadline=Date.now()+3000;while(Date.now()<deadline&&(v.paused||v.currentTime<=start+.02))await new Promise(r=>setTimeout(r,50));
return {ok:!v.paused&&v.currentTime>start+.02,paused:v.paused,start,currentTime:v.currentTime,playTransition:true};"""}
_VIDEO_STATE_STEP={"script":"const v=document.querySelector('#player video,video');return {ok:!!v,present:!!v,paused:v?.paused??null,currentTime:v?.currentTime??null};"}

def _prepare_multi_window(driver:WebDriver,fixture:Any,second_fixture:Any,
                          window_check:Callable[[str],dict[str,Any]]|None,context:dict[str,Any])->dict[str,Any]:
    baseline_handles=driver.window_handles();main=driver.current_window_handle()
    main_play=_lifecycle(driver,_VIDEO_PLAY_STEP,context)
    if not isinstance(main_play,dict) or main_play.get("ok") is not True:raise CandidateUnavailable("main real video could not play")
    created=driver.new_window("tab");second=created["handle"]
    if second in baseline_handles:raise RuntimeError("new tab reused a baseline handle")
    try:
        driver.switch_to_window(second);second_proof=_prove_youtube_fixture(driver,second_fixture,window_check,"multi-window-second")
        second_play=_lifecycle(driver,_VIDEO_PLAY_STEP,context)
        if not isinstance(second_play,dict) or second_play.get("ok") is not True:raise CandidateUnavailable("second real video could not play")
        driver.switch_to_window(main);main_state=_lifecycle(driver,_VIDEO_STATE_STEP,context)
        driver.switch_to_window(second);second_state=_lifecycle(driver,_VIDEO_STATE_STEP,context);driver.switch_to_window(main)
        if main_state.get("paused") is not False or second_state.get("paused") is not False:raise CandidateUnavailable("two real players were not simultaneously playing")
    except Exception:
        try:driver.switch_to_window(second);driver.close_window();driver.switch_to_window(main)
        except Exception:pass
        raise
    return {"baselineHandles":baseline_handles,"mainHandle":main,"secondHandle":second,"secondFixtureId":second_fixture.fixture_id,
            "bothPlaying":True,"mainBefore":main_state,"secondBefore":second_state,"secondProof":second_proof}

def _trigger_multi_window(driver:WebDriver,state:dict[str,Any],context:dict[str,Any])->dict[str,Any]:
    main,second=state["mainHandle"],state["secondHandle"]
    driver.switch_to_window(second);before=_lifecycle(driver,_VIDEO_STATE_STEP,context)
    if before.get("paused") is not False:driver.switch_to_window(main);raise CandidateUnavailable("owned second player stopped before activation")
    driver.switch_to_window(main);trigger=_lifecycle(driver,_VIDEO_TRIGGER_STEP,context)
    if trigger.get("ok") is not True:raise CandidateUnavailable("main player activation could not play")
    driver.switch_to_window(second);deadline=time.monotonic()+5;after={}
    while time.monotonic()<deadline:
        after=_lifecycle(driver,_VIDEO_STATE_STEP,context)
        if after.get("paused") is True:break
        time.sleep(.1)
    driver.switch_to_window(main)
    return {"bothPlayingBefore":state["bothPlaying"],"mainTriggered":trigger.get("ok") is True,"otherPaused":after.get("paused") is True,"secondAfter":after}

def _close_multi_window(driver:WebDriver,state:dict[str,Any])->dict[str,Any]:
    main,second=state["mainHandle"],state["secondHandle"];driver.switch_to_window(second)
    close=driver.close_window()
    if second in close.get("remainingHandles",[]) or main not in close.get("remainingHandles",[]):raise RuntimeError("owned second tab close was not exact")
    driver.switch_to_window(main);remaining=driver.window_handles()
    if remaining!=state["baselineHandles"]:raise RuntimeError("multi-window handles did not restore exactly")
    return {"closedHandle":second,"mainHandle":main,"remainingHandles":remaining,"verified":True}

def _run_phased_activation(driver:WebDriver,activation:dict[str,Any],contract:ContractSpec,
                           context_factory:Callable[[],dict[str,Any]])->list[dict[str,Any]]:
    evidence=[];timeout=float(contract.settle["timeoutMs"])/1000;poll=float(contract.settle["pollMs"])/1000
    for index,phase in enumerate(activation["phases"]):
        prepared=_lifecycle(driver,phase["prepare"],context_factory())
        if not isinstance(prepared,dict) or prepared.get("ok") is not True:
            raise CandidateUnavailable("trusted activation phase "+str(index)+" preparation unavailable")
        driver.key_actions(phase["actions"]);deadline=time.monotonic()+timeout;observed=None
        while time.monotonic()<deadline:
            observed=_lifecycle(driver,phase["observe"],context_factory())
            if isinstance(observed,dict) and observed.get("ok") is True:break
            time.sleep(poll)
        if not isinstance(observed,dict) or observed.get("ok") is not True:
            raise CandidateUnavailable("trusted activation phase "+str(index)+" observation unavailable")
        evidence.append({"index":index,"prepare":prepared,"actions":phase["actions"],"observe":observed})
    return evidence

def _risk_allowed(contract:ContractSpec,args:Any)->tuple[bool,str]:
    fixture=ROUTE_FIXTURES.get(contract.fixture_id);account_required=contract.risk in {"account","destructive"} or getattr(fixture,"auth",None)=="dedicated_test_account"
    if contract.risk!="safe":
        flag={"permission":"allow_permission","account":"allow_account","destructive":"allow_destructive"}[contract.risk]
        if not getattr(args,flag,False):return False,"requires explicit --"+flag.replace("_","-")
    if account_required and _account_target(contract,args) is None:return False,"requires exact --account-fixture stable accountId and target"
    return True,("safe contract" if contract.risk=="safe" else "explicit "+contract.risk+" gate accepted")

def run_full_live_contracts(driver:WebDriver,features:list[Feature],plans:dict[str,FeaturePlan],identity:dict[str,Any],
                            results:list[Result],output:Path,args:Any,
                            window_check:Callable[[str],dict[str,Any]]|None=None)->dict[str,Any]:
    """Execute strict contracts serially; cleanup precedes every navigation."""
    anchor=ROUTE_FIXTURES["search.improvedtube"]
    anchor_proof=_prove_youtube_fixture(driver,anchor,window_check,"full-live-storage-anchor")
    adapter=BrowserStorageAdapter(driver,identity);context=adapter.bind_from_youtube()
    authority=_authority_roundtrip(driver,adapter,anchor,window_check)
    authority_ok=all(authority.get(key) is True for key in ("writeReadback","mirrorObserved","removeReadback","baselineRestored","fullMirrorMatched"))
    if not authority_ok:raise RuntimeError("browser authority roundtrip evidence is incomplete")
    page_adapter=PageBridgeStorageAdapter(driver,adapter)
    provider={"bound":True,"browserAuthoritative":authority_ok,"binding":"signed-options-page","authority":adapter.authority,
              "context":context,"anchor":anchor_proof,"authorityRoundtrip":authority}
    terminal=False;visited_routes:set[str]=set();route_screenshots:set[str]=set();route_console:dict[str,list[Any]]={}
    for feature in features:
        plan=plans.get(feature.key);contract=plan.contract if plan else None
        if terminal or not contract or contract.is_not_applicable:continue
        allowed,gate_reason=_risk_allowed(contract,args)
        record(results,feature.feature_id+"-GATE",feature.feature_id,"risk and surface gate",PASS if allowed else NOT_RUN,"coverage",contract.route,"gate",{"risk":contract.risk,"reason":gate_reason})
        if not allowed:continue
        fixture=ROUTE_FIXTURES.get(contract.fixture_id)
        if fixture is None:
            record(results,feature.feature_id+"-TRANSPORT",feature.feature_id,"exact direct storage transport",HARNESS_FAILURE,"harness",contract.route,"setup",{"error":"unknown fixture"});terminal=True;continue
        storage_adapter=adapter if fixture.surface=="extension-page" else page_adapter
        activation=contract.activation
        before_store:dict[str,StorageSnapshot]={};effect_store:dict[str,StorageSnapshot]={};changed={};setup=before_observation=post_activation=activation_result=after_observation=cleanup_result=None
        oracle_result=None;baseline_captured=False;effect_baseline_captured=False;surface_ready=False;feature_unavailable=False;unavailable_phase="setup";feature_error=None;restoration_ok=False
        cleanup_ready=False
        side_baseline=None;original_rect=None;artifact_baseline=None;account_fixture=_account_target(contract,args);observed_account=None;account_binding=None;storage_baseline_context={};multi_state=None;multi_cleanup=None
        before_path=output/(feature.feature_id+"-before.png");after_path=output/(feature.feature_id+"-after.png");before_shot=b"";before_bytes=0
        runtime_context=lambda:{"setup":setup,"before":before_observation,"postActivation":post_activation,"activation":activation_result,
                                "accountFixture":account_fixture,"observedAccount":observed_account,"accountBinding":account_binding,
                                "storageBaseline":storage_baseline_context}
        def enter_surface(phase:str,selected_fixture:Any=None)->dict[str,Any]:
            nonlocal surface_ready
            selected_fixture=selected_fixture or fixture
            if selected_fixture.surface=="extension-page":
                observed_context=adapter.enter_options();proof={"fixture":validate_fixture(selected_fixture,{"url":adapter.options_url,"readyState":"complete"}),"context":observed_context}
                if not proof["fixture"]["ok"]:raise RuntimeError("extension fixture failed")
                direct=adapter.snapshot([contract.storage_key,*contract.dependency_keys])
                proof["directStorage"]={key:value.redacted() for key,value in direct.items()}
            else:proof=_prove_youtube_fixture(driver,selected_fixture,window_check,phase)
            surface_ready=True;driver.script(INSTRUMENT_JS);return proof
        try:
            if fixture.surface=="extension-page":adapter.enter_options()
            before_store=storage_adapter.snapshot(list(contract.restore_scope));baseline_captured=True
            storage_baseline_context={key:{"present":before_store.get(key,StorageSnapshot.capture(key,False)).present,
                                           "value":before_store.get(key,StorageSnapshot.capture(key,False)).value}
                                      for key in contract.restore_scope}
            if contract.pre_activation_value is not MISSING:
                neutral=storage_adapter.set(contract.storage_key,contract.pre_activation_value)
                if not neutral.present or not deep_equal(neutral.value,contract.pre_activation_value):raise RuntimeError("preActivationValue direct readback mismatch")
            for key,value in contract.dependency_values.items():storage_adapter.set(key,value)
            dependency_readback=storage_adapter.snapshot(contract.dependency_keys)
            if any(not dependency_readback[key].present or not deep_equal(dependency_readback[key].value,value) for key,value in contract.dependency_values.items()):raise RuntimeError("dependencyValues direct readback mismatch")
            if activation["kind"]=="storage-multi-window":
                disabled=storage_adapter.set(contract.storage_key,False)
                if not disabled.present or disabled.value is not False:raise RuntimeError("multi-window disabled baseline readback mismatch")
            enter_surface("after-dependencies:"+feature.key)
            if account_fixture is not None and account_fixture.get("videoId") is not None:
                if contract.account_binding_mode=="fixture-card":account_surface=_enter_account_fixture_resource(driver,contract,account_fixture,window_check,"account-setup:"+feature.key);account_binding=account_surface
                else:account_surface=_enter_account_target(driver,contract,account_fixture,window_check,"account-setup:"+feature.key)
                surface_ready=True
                observed_account=account_surface["account"]
            else:observed_account=_observe_account_current(driver,contract,account_fixture)
            if contract.viewport_width is not None:
                original_rect=driver.get_window_rect();viewport=driver.script(VIEWPORT_JS);delta=max(0,int(original_rect["width"])-int(viewport["innerWidth"]))
                driver.set_window_rect(int(original_rect["x"]),int(original_rect["y"]),int(contract.viewport_width)+delta,int(original_rect["height"]))
                resized=driver.script(VIEWPORT_JS)
                if not isinstance(resized,dict) or int(resized.get("innerWidth",0))<contract.viewport_width:raise RuntimeError("viewportWidth was not achieved")
            if contract.side_effect_state:side_baseline=driver.script(SIDE_EFFECT_SNAPSHOT_JS,[contract.side_effect_state])
            if contract.risk!="safe":artifact_baseline={"handles":driver.window_handles(),"document":driver.script(ARTIFACT_STATE_JS)}
            effect_store=storage_adapter.snapshot(list(contract.restore_scope));effect_baseline_captured=True
            try:setup=_lifecycle(driver,contract.setup,runtime_context())
            except RuntimeError as exc:
                if _is_explicitly_unavailable(exc):raise CandidateUnavailable(str(exc))
                raise
            if not isinstance(setup,dict) or setup.get("ok") is not True:
                raise CandidateUnavailable(str(setup.get("reason","setup candidate unavailable")) if isinstance(setup,dict) else "setup candidate unavailable")
            cleanup_ready=contract.post_activation is None
            if activation["kind"]=="storage-multi-window":
                second_fixture=ROUTE_FIXTURES[activation["secondFixtureId"]]
                unavailable_phase="multiWindowSetup"
                multi_state=_prepare_multi_window(driver,fixture,second_fixture,window_check,runtime_context())
                activation_result={"script":None,"prompt":None,"redirect":None,"multiWindow":multi_state}
            if activation["kind"] in {"storage","storage-prompt","storage-redirect"}:
                before_observation=_lifecycle(driver,contract.before_oracle,runtime_context());before_shot=driver.screenshot();before_bytes=len(before_shot)
            elif activation["kind"]=="storage-multi-window":
                before_observation=_lifecycle(driver,contract.before_oracle,runtime_context());before_shot=driver.screenshot();before_bytes=len(before_shot)
            written=storage_adapter.set(contract.storage_key,activation["value"])
            if activation["kind"]=="storage-redirect":
                post_fixture=ROUTE_FIXTURES[activation["postFixtureId"]]
                unavailable_phase="postRedirect"
                post_proof=_prove_youtube_redirect(driver,fixture,post_fixture,window_check,"after-activation-redirect:"+feature.key);surface_ready=True;driver.script(INSTRUMENT_JS)
                activation_result={"script":None,"prompt":None,"redirect":{"expectedFixtureId":activation["postFixtureId"],"proof":post_proof}}
            elif account_fixture is not None and account_fixture.get("videoId") is not None:
                if contract.account_binding_mode=="fixture-card":post_proof=_enter_account_fixture_resource(driver,contract,account_fixture,window_check,"account-activation:"+feature.key);account_binding=post_proof
                else:post_proof=_enter_account_target(driver,contract,account_fixture,window_check,"account-activation:"+feature.key)
                surface_ready=True
                observed_account=post_proof["account"];activation_result={"script":None,"prompt":None,"redirect":None}
            else:
                post_proof=enter_surface("after-activation-storage:"+feature.key)
                if activation_result is None:activation_result={"script":None,"prompt":None,"redirect":None}
            if contract.post_activation is not None:
                unavailable_phase="postActivation"
                try:post_activation=_lifecycle(driver,contract.post_activation,runtime_context())
                except RuntimeError as exc:
                    if _is_explicitly_unavailable(exc):raise CandidateUnavailable(str(exc))
                    raise
                if (not isinstance(post_activation,dict) or post_activation.get("ok") is not True
                        or post_activation.get("verified") is not True):
                    redirect_missing=(activation["kind"]=="storage-redirect"
                                      and activation_result["redirect"]["proof"].get("redirectObserved") is not True)
                    if not redirect_missing:
                        raise CandidateUnavailable(str(post_activation.get("reason","post-activation candidate unavailable")) if isinstance(post_activation,dict) else "post-activation candidate unavailable")
                cleanup_ready=True
            observed_account=(_observe_account_fixture_resource_current(driver,contract,account_fixture)
                              if account_fixture is not None and contract.account_binding_mode=="fixture-card"
                              else _observe_account_current(driver,contract,account_fixture))
            try:script_result=_lifecycle(driver,{"script":activation["script"],"args":activation.get("args",[])},runtime_context(),allow_undefined=True) if activation.get("script") else None
            except RuntimeError as exc:
                if _is_explicitly_unavailable(exc):unavailable_phase="activation";raise CandidateUnavailable(str(exc))
                raise
            activation_result["script"]=script_result
            if activation["kind"]=="storage-key":
                before_observation=_lifecycle(driver,contract.before_oracle,runtime_context());before_shot=driver.screenshot();before_bytes=len(before_shot);driver.key_actions(activation["actions"])
            elif activation["kind"]=="storage-key-phased":
                before_observation=_lifecycle(driver,contract.before_oracle,runtime_context());before_shot=driver.screenshot();before_bytes=len(before_shot)
                unavailable_phase="activationPhase"
                activation_result["phases"]=_run_phased_activation(driver,activation,contract,runtime_context)
            elif activation["kind"]=="storage-multi-window":
                unavailable_phase="multiWindowActivation"
                multi_effect=_trigger_multi_window(driver,multi_state,runtime_context())
                activation_result["multiWindow"]={**multi_state,"effect":multi_effect}
            elif activation["kind"]=="storage-prompt":
                driver.script("location.href=arguments[0];return {requested:true};",[activation["navigationUrl"]])
                prompt_text=driver.alert_text()
                driver.accept_alert() if activation["promptAction"]=="accept" else driver.dismiss_alert()
                activation_result["prompt"]={"shown":True,"text":prompt_text,"action":activation["promptAction"],"handled":True,"navigationUrl":activation["navigationUrl"]}
            timeout=float(contract.settle["timeoutMs"])/1000;poll=float(contract.settle["pollMs"])/1000;deadline=time.monotonic()+timeout
            while True:
                after_observation=_lifecycle(driver,contract.after_oracle,runtime_context());oracle_result=dispatch_oracle(contract.oracle,before_observation,after_observation)
                if oracle_result or time.monotonic()>=deadline:break
                time.sleep(poll)
            shot=driver.screenshot()
            if contract.route not in route_screenshots:
                (output/("route-"+contract.route+".png")).write_bytes(shot);route_screenshots.add(contract.route)
            errors=driver.script(ERRORS_JS) or [];route_console.setdefault(contract.route,[]).extend(errors if isinstance(errors,list) else [])
            redirect_effect_ok=(activation["kind"]!="storage-redirect" or activation_result["redirect"]["proof"].get("redirectObserved") is True)
            semantic_effect_ok=bool(oracle_result) and redirect_effect_ok
            screenshots=[{"bytes":before_bytes,"sha256":hashlib.sha256(before_shot).hexdigest()},{"bytes":len(shot),"sha256":hashlib.sha256(shot).hexdigest()}]
            if not semantic_effect_ok:
                before_path.write_bytes(before_shot);after_path.write_bytes(shot);screenshots[0]["path"]=str(before_path);screenshots[1]["path"]=str(after_path)
            record(results,feature.feature_id+"-TRANSPORT",feature.feature_id,"exact direct storage transport",PASS,"transport",contract.route,"activation",{"requested":written.redacted(),"dependencies":contract.dependency_values,"context":context})
            record(results,feature.feature_id+"-EFFECT",feature.feature_id,"semantic feature effect",PASS if semantic_effect_ok else PRODUCT_FAILURE,"live-semantic",contract.route,"observe",{"setup":setup,"before":before_observation,"postActivation":post_activation,"activation":activation_result,"after":after_observation,"oracle":asdict(oracle_result) if oracle_result else None,"screenshots":screenshots})
            visited_routes.add(contract.route)
        except CandidateUnavailable as exc:
            feature_unavailable=True;feature_error=str(exc)
            record(results,feature.feature_id+"-TRANSPORT",feature.feature_id,"exact direct storage transport",NOT_RUN,"harness",contract.route,unavailable_phase,{"reason":feature_error})
            record(results,feature.feature_id+"-EFFECT",feature.feature_id,"semantic feature effect",UNVERIFIED,"live-semantic",contract.route,unavailable_phase,{"reason":feature_error})
        except Exception as exc:
            feature_error=str(exc);terminal=True
            record(results,feature.feature_id+"-TRANSPORT",feature.feature_id,"exact direct storage transport",HARNESS_FAILURE,"harness",contract.route,"execute",{"error":feature_error})
            record(results,feature.feature_id+"-EFFECT",feature.feature_id,"semantic feature effect",NOT_RUN,"harness",contract.route,"execute",{"reason":feature_error})
        finally:
            cleanup_error=None;restoration_evidence={}
            try:
                stage_errors=[]
                try:
                    if surface_ready and cleanup_ready and contract.cleanup is not None:
                        fresh_cleanup_account=(_observe_account_fixture_resource_current(driver,contract,account_fixture)
                                               if account_fixture is not None and contract.account_binding_mode=="fixture-card"
                                               else _observe_account_current(driver,contract,account_fixture))
                        if account_fixture is not None:
                            if not deep_equal(fresh_cleanup_account,observed_account):raise RuntimeError("cleanup account/target binding changed")
                            observed_account=fresh_cleanup_account
                        cleanup_result=_lifecycle(driver,contract.cleanup,runtime_context())
                        if not isinstance(cleanup_result,dict) or cleanup_result.get("ok") is not True:raise RuntimeError("cleanup did not prove ok=true")
                        if contract.risk!="safe" and cleanup_result.get("verified") is not True:raise RuntimeError("non-safe cleanup did not prove verified=true")
                        if (isinstance(activation_result,dict) and isinstance(activation_result.get("prompt"),dict)
                                and activation_result["prompt"].get("handled") is True and cleanup_result.get("navigationNeutralized") is not True):
                            raise RuntimeError("prompt cleanup did not neutralize navigation handler")
                    elif contract.risk!="safe":raise RuntimeError("non-safe contract has no cleanup")
                    elif contract.cleanup is not None:cleanup_result={"ok":True,"skipped":"cleanup baseline unavailable before activation"}
                except Exception as exc:stage_errors.append("cleanup: "+str(exc))
                if multi_state is not None:
                    try:
                        multi_cleanup=_close_multi_window(driver,multi_state)
                        if isinstance(activation_result,dict):activation_result["multiWindowCleanup"]=multi_cleanup
                        restoration_evidence["multiWindow"]=multi_cleanup
                    except Exception as exc:stage_errors.append("multi-window cleanup: "+str(exc))
                try:
                    if artifact_baseline is not None:
                        artifacts={"handles":driver.window_handles(),"document":driver.script(ARTIFACT_STATE_JS)}
                        if artifacts["handles"]!=artifact_baseline["handles"] or artifacts["document"].get("fullscreen") or artifacts["document"].get("pictureInPicture"):
                            raise RuntimeError("owned popup/fullscreen/PiP artifact was not restored")
                        restoration_evidence["artifacts"]=artifacts
                except Exception as exc:stage_errors.append("artifact restoration: "+str(exc))
                try:
                    if side_baseline is not None:
                        side_restore=driver.script(SIDE_EFFECT_RESTORE_JS,[side_baseline])
                        if not isinstance(side_restore,dict) or side_restore.get("ok") is not True or not deep_equal(side_restore.get("current"),side_baseline):raise RuntimeError("browser side-effect state was not exactly restored")
                        restoration_evidence["browserState"]=side_restore
                except Exception as exc:stage_errors.append("browser-state restoration: "+str(exc))
                storage_restored=False;undeclared=[];feature_changed={};restored_once=None
                try:
                    after_store=storage_adapter.snapshot(list(contract.restore_scope));changed=_storage_diff(before_store,after_store) if baseline_captured else {}
                    feature_changed=_storage_diff(effect_store,after_store) if effect_baseline_captured else {}
                    undeclared=sorted(set(feature_changed)-set(contract.restore_scope))
                    if undeclared:stage_errors.append("undeclared storage side effect: "+", ".join(undeclared))
                    for key in changed:
                        baseline=before_store.get(key,StorageSnapshot.capture(key,False));storage_adapter.set(key,baseline.value) if baseline.present else storage_adapter.remove(key)
                    restored_once=storage_adapter.snapshot(list(contract.restore_scope));storage_restored=baseline_captured and _storage_maps_equal(before_store,restored_once)
                    if not storage_restored:stage_errors.append("first exact storage restoration failed")
                    restoration_evidence["firstSnapshot"]=storage_restored
                except Exception as exc:stage_errors.append("direct storage restoration: "+str(exc))
                surface_unavailable=feature_unavailable and not surface_ready
                verification_fixture=anchor if fixture.surface=="extension-page" or surface_unavailable else fixture
                first_route=final_account=final_observation=None
                try:
                    if account_fixture is not None and account_fixture.get("videoId") is not None:
                        if contract.account_binding_mode=="fixture-card":first_route=_enter_account_fixture_resource(driver,contract,account_fixture,window_check,"after-restoration-account:"+feature.key);account_binding=first_route
                        else:first_route=_enter_account_target(driver,contract,account_fixture,window_check,"after-restoration-account:"+feature.key)
                        final_account=first_route["account"]
                    else:
                        first_route=_prove_youtube_fixture(driver,verification_fixture,window_check,"after-restoration-route:"+feature.key,recover=surface_unavailable);final_account=_observe_account_current(driver,contract,account_fixture)
                    if account_fixture is not None and not deep_equal(final_account,observed_account):raise RuntimeError("restored route account identity/target changed")
                    if fixture.surface=="extension-page":adapter.enter_options()
                    final_observation=_lifecycle(driver,contract.after_restoration,runtime_context()) if contract.after_restoration is not None and not feature_unavailable else None
                    if contract.after_restoration is not None and not feature_unavailable and (not isinstance(final_observation,dict) or final_observation.get("ok") is not True):raise RuntimeError("afterRestoration did not prove ok=true")
                except Exception as exc:stage_errors.append("first route/restoration observation: "+str(exc))
                second_snapshot=False
                try:
                    restored_twice=storage_adapter.snapshot(list(contract.restore_scope));second_snapshot=baseline_captured and _storage_maps_equal(before_store,restored_twice)
                    if not second_snapshot:stage_errors.append("second exact options snapshot differs from baseline")
                except Exception as exc:stage_errors.append("second options snapshot: "+str(exc))
                second_route=second_account=None
                try:
                    if account_fixture is not None and account_fixture.get("videoId") is not None:
                        if contract.account_binding_mode=="fixture-card":second_route=_enter_account_fixture_resource(driver,contract,account_fixture,window_check,"after-restoration-account-return:"+feature.key);account_binding=second_route
                        else:second_route=_enter_account_target(driver,contract,account_fixture,window_check,"after-restoration-account-return:"+feature.key)
                        second_account=second_route["account"]
                    else:
                        second_route=_prove_youtube_fixture(driver,verification_fixture,window_check,"after-restoration-return:"+feature.key,recover=surface_unavailable);second_account=_observe_account_current(driver,contract,account_fixture)
                    if account_fixture is not None and not deep_equal(second_account,observed_account):raise RuntimeError("second restored route account identity/target changed")
                except Exception as exc:stage_errors.append("second route proof: "+str(exc))
                try:
                    if original_rect is not None:
                        driver.set_window_rect(int(original_rect["x"]),int(original_rect["y"]),int(original_rect["width"]),int(original_rect["height"]));rect=driver.get_window_rect()
                        if any(int(rect[key])!=int(original_rect[key]) for key in ("x","y","width","height")):raise RuntimeError("window rect was not exactly restored")
                except Exception as exc:stage_errors.append("window restoration: "+str(exc))
                restoration_evidence.update({"firstRoute":first_route,"secondRoute":second_route,"finalObservation":final_observation,"finalAccount":final_account,"secondAccount":second_account,"secondSnapshot":second_snapshot})
                restoration_ok=not stage_errors
                if feature_unavailable:record(results,feature.feature_id+"-STORAGE",feature.feature_id,"direct storage snapshot and diff",NOT_RUN,"isolation",contract.route,"storage-diff",{"reason":feature_error,"changed":changed})
                else:record(results,feature.feature_id+"-STORAGE",feature.feature_id,"direct storage snapshot and diff",PASS if storage_restored else NOT_RUN,"isolation",contract.route,"storage-diff",{"changed":feature_changed,"restorationChanged":changed,"declared":list(contract.restore_scope),"undeclared":undeclared})
                if stage_errors:raise RuntimeError("; ".join(stage_errors))
            except Exception as exc:
                cleanup_error=str(exc);restoration_ok=False;terminal=True
                if not any(row.assertion_id==feature.feature_id+"-STORAGE" for row in results):record(results,feature.feature_id+"-STORAGE",feature.feature_id,"direct storage snapshot and diff",NOT_RUN,"harness",contract.route,"finally",{"reason":cleanup_error})
            record(results,feature.feature_id+"-RESTORATION",feature.feature_id,"exact persisted restoration",PASS if restoration_ok else ISOLATION_FAILURE,"isolation",contract.route,"finally",{"cleanup":cleanup_result,"error":cleanup_error,"restored":restoration_ok,**restoration_evidence})
            if not restoration_ok:terminal=True
    for route in sorted({plan.contract.route for plan in plans.values() if plan.contract and not plan.contract.is_not_applicable and plan.contract.surface=="youtube-page"}):
        visited=route in visited_routes;console=route_console.get(route,[]);attributed=[item for item in console if isinstance(item,dict) and (str(item.get("message","")).startswith("[ImprovedTube]") or "ImprovedTube" in str(item.get("source","")))]
        record(results,"ROUTE-"+route.upper()+"-REAL","GLOBAL","real YouTube application loaded",PASS if visited else NOT_RUN,"environment",route,"full-live",{"visited":visited})
        record(results,"ROUTE-"+route.upper()+"-EXTENSION","GLOBAL","signed extension context and bridge observed",PASS if visited else NOT_RUN,"environment",route,"full-live",{"provider":provider})
        record(results,"ROUTE-"+route.upper()+"-SCREENSHOT","GLOBAL","Safari screenshot captured as artifact",PASS if route in route_screenshots else NOT_RUN,"environment",route,"full-live",{"captured":route in route_screenshots})
        record(results,"ROUTE-"+route.upper()+"-KG271U","GLOBAL","owned Safari window remains inside KG271U",PASS if visited else NOT_RUN,"environment",route,"full-live",{"visited":visited})
        record(results,"ROUTE-"+route.upper()+"-CONSOLE","GLOBAL","candidate console errors attributed by route/phase",PASS if visited and not attributed else PRODUCT_FAILURE if attributed else NOT_RUN,"console",route,"full-live",{"all":console,"attributed":attributed})
    return {"provider":provider,"terminal":terminal,"visitedRoutes":sorted(visited_routes)}

def run(args:argparse.Namespace,features:list[Feature],source_root:Path,identity:dict[str,Any])->int:
    stamp=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ");output=RESULTS_ROOT/stamp;output.mkdir(parents=True,exist_ok=False)
    results=[]
    full_live=bool(getattr(args,"full_live",False));loaded_contracts=getattr(args,"loaded_contracts",None) or {}
    plan_list=build_full_live_plan(features,loaded_contracts);plan_map={item.key:item for item in plan_list}
    binding_mode=observer_binding_mode(args)
    selected=features
    if args.feature_keys:selected=[f for f in features if f.key in set(args.feature_keys)]
    if args.limit:selected=selected[:args.limit]
    if full_live:
        contract_routes=sorted({plan_map[f.key].contract.route for f in selected if plan_map.get(f.key) and plan_map[f.key].contract and not plan_map[f.key].contract.is_not_applicable and plan_map[f.key].contract.surface=="youtube-page"})
    else:contract_routes=sorted({CONTRACTS[f.key].route for f in selected if f.key in CONTRACTS})
    signed_provider_expected=signed_provider_expectation(identity)
    frozen_candidate=getattr(args,"candidate_identity",None) or candidate_surface_identity(ROOT)
    metadata={"startedAt":dt.datetime.now(dt.timezone.utc).isoformat(),"host":args.host,"port":args.port,"sourceRoot":str(source_root),"installedRoot":str(INSTALLED),"featureCount":len(features),"routes":ROUTES,
      "sut":"signed-testflight" if args.sut=="signed" else "unpacked-opt-in","driverMode":args.driver_mode,"observerBindingMode":binding_mode,"lifecycleOwnership":lifecycle_ownership(args.driver_mode),"observer":{"required":args.driver_mode=="external","socket":args.observer_socket if args.driver_mode=="external" else None,"runId":args.observer_run_id if args.driver_mode=="external" else None,"capability":"redacted" if args.driver_mode=="external" else None,"serverUid":None},"observerServerUID":{"required":args.driver_mode=="external","status":"not-attempted" if args.driver_mode=="external" else "not-required"},"signedIdentity":identity,"candidate":frozen_candidate,
      "signedProvider":{"sut":args.sut,"expected":signed_provider_expected,"observations":[],"bound":False},"observerPlacement":None,
      "windowRequested":{"x":args.window_x,"y":args.window_y,"width":args.window_width,"height":args.window_height},
      "contracts":sorted(item.key for item in plan_list if item.status=="contracted") if full_live else sorted(CONTRACTS),"selectedFeatures":[f.key for f in selected],
      "sourceOnlyFeatureCount":sum(item.status=="uncontracted" for item in plan_list) if full_live else sum(f.key not in CONTRACTS for f in features),"indexedFeatureCount":len(features),
      "continueAfterProductFailure":bool(getattr(args,"continue_after_product_failure",False)),"fullLive":full_live,
      "contractCatalog":getattr(args,"contract_catalog_diagnostics",None),
      "planDigest":hashlib.sha256(json.dumps([item.to_dict() for item in plan_list],sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest(),
      "planCounts":{"contracted":sum(item.status=="contracted" for item in plan_list),"notApplicable":sum(item.status=="not_applicable" for item in plan_list),"uncontracted":sum(item.status=="uncontracted" for item in plan_list)}}
    driver=WebDriver(args.host,args.port);driver_process=stp_process=None;abort_contracts=False;automation_pid=getattr(args,"stp_pid",None) if binding_mode=="prebound-diagnostic" else None;automation_window_id=getattr(args,"window_id",None) if binding_mode=="prebound-diagnostic" else None;window_identity_verified=False;observer=None;observer_claimed=False;observer_final=None;title_nonce_a=fresh_title_nonce();title_nonce_b=fresh_title_nonce();title_nonce=title_nonce_b;bootstrapped_route=None;session_created=False;session_closed=False;window_close_requested=False;session_close_evidence=None
    for f in features:source_only_results(results,f,full_live,plan_map.get(f.key))
    record(results,"GLOBAL-IDENTITY","GLOBAL","signed TestFlight bundle identity validated",PASS if identity.get("valid") else ENVIRONMENT_FAILURE,"identity","global","identity",identity)
    record(results,"GLOBAL-DRIVER","GLOBAL","Safari Technology Preview inspected session created",NOT_RUN,"environment","global","session",{"reason":"session not started"})
    record(results,"GLOBAL-KG271U","GLOBAL","actual Safari main window is inside KG271U",NOT_RUN,"environment","global","window",{"reason":"window not inspected"})
    record(results,"GLOBAL-CLEANUP","GLOBAL","WebDriver, driver process, STP window, and test port cleaned",NOT_RUN,"environment","global","cleanup",{"reason":"cleanup not reached"})
    for route in contract_routes:
        for suffix,label,eclass in (("-REAL","real YouTube application loaded","environment"),("-EXTENSION","ImprovedTube bridge behavior observed (provider attribution remains page-level)","environment"),("-SCREENSHOT","Safari screenshot captured as artifact","environment"),("-KG271U","owned Safari window remains inside KG271U","environment"),("-CONSOLE","candidate console errors attributed by route/phase","console")):
            record(results,"ROUTE-"+route.upper()+suffix,"GLOBAL",label,NOT_RUN,eclass,route,"route-load",{"reason":"route not visited"})
    containment_checks=[]
    def check_window(phase:str)->dict[str,Any]:
        if observer:
            # A route may change the native title; this optional marker is
            # always the already-bound second nonce, never a selector.
            driver.script(SET_TITLE_NONCE_JS,[title_nonce_b]);evidence=observer.call("observe",{"phase":phase})
            if not evidence.get("ok"):
                time.sleep(2.0);driver.script(SET_TITLE_NONCE_JS,[title_nonce_b]);evidence=observer.call("observe",{"phase":phase+":retry"})
        else:evidence=verify_owned_windows(automation_pid,automation_window_id)
        evidence["phase"]=phase;containment_checks.append(evidence);return evidence
    try:
        if binding_mode=="invalid-prebound":
            raise RuntimeError("--stp-pid and --window-id must be supplied together")
        if args.driver_mode=="external":
            try:
                observer_uid,uid_evidence=resolve_observer_server_uid(getattr(args,"observer_server_uid",None))
                metadata["observerServerUID"]=uid_evidence;metadata["observer"]["serverUid"]=observer_uid
                capability=args.observer_capability or os.environ.get(OBSERVER_CAPABILITY_ENV,"")
                observer=AquaObserverClient(args.observer_socket,args.observer_run_id,capability,server_uid_expected=observer_uid)
                observer.connect()
            except Exception as exc:
                uid_failure=dict(metadata.get("observerServerUID",{}))
                uid_failure.update({"required":True,"status":"failed","clientUid":os.getuid(),"error":str(exc)})
                metadata["observerServerUID"]=uid_failure
                raise
        if args.driver_mode=="external":
            if not port_open(args.host,args.port):raise RuntimeError("external Safari Technology Preview WebDriver port is not open")
            baseline_nonce=title_nonce_b if binding_mode=="prebound-diagnostic" else title_nonce_a
            baseline_request={"titleNonce":baseline_nonce,"bindingMode":binding_mode}
            if binding_mode=="prebound-diagnostic":baseline_request["pid"]=automation_pid
            baseline=observer.call("baseline",baseline_request)
            metadata["observerBaseline"]={k:v for k,v in baseline.items() if k!="capability"}
            if (not baseline.get("ok") or baseline.get("baselineClear") is not True
                    or baseline.get("bindingMode")!=binding_mode
                    or type(baseline.get("matchingCount")) is not int or baseline["matchingCount"]!=0
                    or (binding_mode=="late" and (baseline.get("pid") is not None or baseline.get("windowId") is not None))):
                raise RuntimeError("fresh title nonce was not proven absent before WebDriver session creation")
        else:
            if port_open(args.host,args.port):raise RuntimeError("dedicated Safari Technology Preview WebDriver port is already open")
            driver_process=launch_process(["/Applications/Safari Technology Preview.app/Contents/MacOS/safaridriver","--port",str(args.port)],output/"safaridriver.log")
            stp_process=launch_process(["/Applications/Safari Technology Preview.app/Contents/MacOS/Safari Technology Preview"],output/"safari-technology-preview.log")
            automation_pid=stp_process.pid
            time.sleep(2)
            if not port_open(args.host,args.port):raise RuntimeError("Safari Technology Preview WebDriver port did not open")
        session=create_session(driver,args.sut,Path(args.extension_path));session_created=True;record(results,"GLOBAL-DRIVER","GLOBAL","Safari Technology Preview inspected session created",PASS,"environment","global","session",session)
        webdriver_browser_pid=driver.browser_pid
        if driver.browser_pid and binding_mode!="late":
            if automation_pid and int(automation_pid)!=int(driver.browser_pid):raise RuntimeError("operator STP PID does not match current WebDriver STP process")
            automation_pid=int(driver.browser_pid)
        elif driver.browser_pid:
            metadata["webdriverBrowserPid"]=int(driver.browser_pid)
        requested_bounds={"x":args.window_x,"y":args.window_y,"width":args.window_width,"height":args.window_height}
        rect=driver.set_window_rect(args.window_x,args.window_y,args.window_width,args.window_height)
        try:
            time.sleep(1.0)
            if observer:
                if not contract_routes:raise RuntimeError("observer lease requires at least one tested route")
                if binding_mode=="late":
                    # Keep the first page intentionally minimal and stable:
                    # native-title binding is completed before any YouTube
                    # navigation can legitimately rename the window.
                    driver.command("POST","/url",{"url":"data:text/html,<html><head><title>ImprovedTube%20bootstrap</title></head><body>ImprovedTube%20bootstrap</body></html>"},timeout=75);driver.in_frame=False
                    webdriver_title=webdriver_title_binding_evidence(driver,webdriver_browser_pid,title_nonce_a)
                    metadata["webdriverTitleProbe"]={"requestedNonce":title_nonce_a,**webdriver_title}
                    time.sleep(1.0)
                    probe=await_observer_title_probe(observer,title_nonce_a,
                        request_evidence_fn=lambda:webdriver_title_binding_evidence(driver,webdriver_browser_pid,title_nonce_a))
                    metadata["observerTitleProbe"]={k:v for k,v in probe.items() if k!="capability"}
                    probe_mode=probe.get("bindingMode")
                    metadata["observerEffectiveBindingMode"]=probe_mode
                    standard_probe=(probe_mode=="late" and type(probe.get("nativeTitle")) is str
                                    and bool(probe.get("nativeTitle"))
                                    and type(probe.get("derivedPrefix")) is str and bool(probe.get("derivedPrefix")))
                    empty_title_probe=(probe_mode=="webdriver-pid-single-window-empty-cg-title"
                                       and probe.get("nativeTitle")=="" and probe.get("derivedPrefix") is None
                                       and type(probe.get("emptyCGTitleBinding")) is dict
                                       and probe["emptyCGTitleBinding"].get("verified") is True)
                    if (probe.get("ok") is not True or probe.get("titleNonce")!=title_nonce_a
                            or probe.get("ready") is not True or probe.get("retryable") is not False
                            or probe.get("readinessTimedOut") is not False
                            or not (standard_probe or empty_title_probe)
                            or type(probe.get("pid")) is not int or type(probe.get("windowId")) is not int
                            or type(probe.get("preBounds")) is not dict
                            or type(probe.get("titleProbe")) is not dict
                            or probe["titleProbe"].get("verified") is not True):
                        raise RuntimeError("observer title probe did not return a verified native-title binding")
                    placement_webdriver=webdriver_title_binding_evidence(driver,webdriver_browser_pid,title_nonce_b)
                    time.sleep(1.0)
                    placement=observer.call("place",{"bindingMode":probe_mode,"titleNonce":title_nonce_b,
                        "requestedBounds":requested_bounds,**placement_webdriver})
                    metadata["observerPlacement"]={k:v for k,v in placement.items() if k!="capability"}
                    provisional=placement.get("provisional")
                    if (placement.get("ok") is not True or placement.get("bindingMode")!=probe_mode
                            or placement.get("requestedBounds")!=requested_bounds
                            or type(placement.get("pid")) is not int or type(placement.get("windowId")) is not int
                            or type(provisional) is not dict or provisional.get("pid")!=placement.get("pid")
                            or provisional.get("windowId")!=placement.get("windowId")
                            or provisional.get("titleNonce")!=title_nonce_b
                            or type(provisional.get("nativeTitle")) is not str
                            or provisional.get("nativeTitle")!=placement.get("nativeTitle")
                            or provisional.get("derivedPrefix")!=probe.get("derivedPrefix")
                            or provisional.get("requestedBounds")!=requested_bounds
                            or type(placement.get("placementEvidence")) is not dict
                            or placement["placementEvidence"].get("verified") is not True
                            or placement["placementEvidence"].get("afterBounds")!=requested_bounds):
                        raise RuntimeError("observer placement did not return a verified provisional lease")
                    if webdriver_browser_pid is not None and int(webdriver_browser_pid)!=placement["pid"]:
                        raise RuntimeError("WebDriver browser PID disagrees with independently placed STP PID")
                    automation_pid=placement["pid"];automation_window_id=placement["windowId"]
                    claim_webdriver=webdriver_title_binding_evidence(driver,webdriver_browser_pid,title_nonce_b)
                    claim=observer.call("claim",{"bindingMode":probe_mode,"titleNonce":title_nonce_b,
                        "requestedBounds":requested_bounds,**claim_webdriver})
                else:
                    bootstrap_route="search" if "search" in ROUTES else contract_routes[0]
                    driver.navigate(ROUTES[bootstrap_route])
                    initial_real=bounded_script(driver,REAL_PAGE_JS,lambda v:real_youtube_page_ok(bootstrap_route,v),pause=3)
                    if not real_youtube_page_ok(bootstrap_route,initial_real):raise RuntimeError("observer lease bootstrap route did not reach the exact HTTPS YouTube route")
                    bootstrapped_route=bootstrap_route
                    driver.script(SET_TITLE_NONCE_JS,[title_nonce_b])
                    time.sleep(5.0)
                    if automation_pid is None or automation_window_id is None:raise RuntimeError("prebound diagnostics require PID and window ID")
                    claim=observer.call("claim",{"pid":automation_pid,"windowId":automation_window_id,"titleNonce":title_nonce_b,"requestedBounds":requested_bounds})
                if not claim.get("ok"):raise RuntimeError("observer claim rejected the automation window")
                metadata["observerClaim"]={k:v for k,v in claim.items() if k!="capability"}
                expected_claim_mode=probe_mode if binding_mode=="late" else binding_mode
                if claim.get("bindingMode")!=expected_claim_mode:
                    raise RuntimeError("observer claim binding mode did not match requested lifecycle")
                if type(claim.get("pid")) is not int or type(claim.get("windowId")) is not int:
                    raise RuntimeError("observer claim did not return bound PID and window ID")
                if binding_mode=="late" and webdriver_browser_pid is not None and int(webdriver_browser_pid)!=claim["pid"]:
                    raise RuntimeError("WebDriver browser PID disagrees with independently observed STP PID")
                automation_pid=claim["pid"];automation_window_id=claim["windowId"]
                observer_claimed=True
            if automation_window_id is None:automation_window_id=identify_window_id(automation_pid,{"width":args.window_width,"height":args.window_height})
            window_evidence=check_window("session-establishment");window_identity_verified=bool(window_evidence.get("ok"));metadata["coreGraphicsWindows"]=window_evidence.get("ownedVisibleWindows",[])
            record(results,"GLOBAL-KG271U","GLOBAL","owned Safari automation window remains inside KG271U",PASS if window_evidence.get("ok") else ENVIRONMENT_FAILURE,"environment","global","window",{"requested":rect,"identity":window_evidence})
        except Exception as exc:record(results,"GLOBAL-KG271U","GLOBAL","actual Safari main window is inside KG271U",ENVIRONMENT_FAILURE,"environment","global","window",{"error":str(exc),"requested":rect})
        if not window_identity_verified:raise RuntimeError("owned Safari automation window is not verifiably contained in KG271U")
        if full_live:
            full_outcome=run_full_live_contracts(driver,selected,plan_map,identity,results,output,args,check_window)
            metadata["fullLiveExecution"]=full_outcome
            metadata["signedProvider"]["observations"].append(full_outcome["provider"])
            abort_contracts=bool(full_outcome["terminal"])
        for route in ([] if full_live else contract_routes):
            if not (observer and route==bootstrapped_route):driver.navigate(ROUTES[route])
            real=bounded_script(driver,REAL_PAGE_JS,lambda v:real_youtube_page_ok(route,v),pause=3)
            route_window=check_window("after-bootstrap:"+route) if observer and route==bootstrapped_route else check_window("after-navigation:"+route);record(results,"ROUTE-"+route.upper()+"-KG271U","GLOBAL","owned Safari automation window remains inside KG271U",PASS if route_window.get("ok") else ENVIRONMENT_FAILURE,"environment",route,"route-window",route_window)
            if not route_window.get("ok"):raise RuntimeError("owned Safari automation window left KG271U after navigation")
            real_ok=real_youtube_page_ok(route,real)
            record(results,"ROUTE-"+route.upper()+"-REAL","GLOBAL","real YouTube application loaded",PASS if real_ok else ENVIRONMENT_FAILURE,"environment",route,"route-load",real)
            if not real_ok:
                for s,a in (("-EXTENSION","ImprovedTube bridge behavior observed (provider attribution remains page-level)"),("-SCREENSHOT","Safari screenshot captured as artifact"),("-CONSOLE","candidate console errors attributed by route/phase")):record(results,"ROUTE-"+route.upper()+s,"GLOBAL",a,NOT_RUN,"console" if s=="-CONSOLE" else "environment",route,"route-load",{"reason":"route prerequisite failed"})
                abort_contracts=True
                break
            bridge=ensure_bridge(driver);bridge_status=classify_bridge(bridge)
            provider=signed_provider_provenance(identity,bridge,args.sut);metadata["signedProvider"]["observations"].append({"route":route,**provider})
            extension_status=bridge_status
            record(results,"ROUTE-"+route.upper()+"-EXTENSION","GLOBAL","ImprovedTube bridge behavior observed (provider attribution remains page-level)",extension_status,"environment",route,"route-load",{"bridge":bridge,"provider":provider})
            if bridge_ok(bridge):
                try:
                    path=output/("route-"+route+".png");shot=driver.screenshot();path.write_bytes(shot);record(results,"ROUTE-"+route.upper()+"-SCREENSHOT","GLOBAL","Safari screenshot captured as artifact",PASS,"environment",route,"route-load",{"path":str(path),"bytes":len(shot)})
                except Exception as exc:record(results,"ROUTE-"+route.upper()+"-SCREENSHOT","GLOBAL","Safari screenshot captured as artifact",HARNESS_FAILURE,"harness",route,"route-load",{"error":str(exc)})
                route_features=[v for v in selected if v.route==route and v.key in CONTRACTS]
                contract_outcome=run_feature_contracts(driver,route_features,route,results,check_window,
                    continue_after_product_failure=bool(getattr(args,"continue_after_product_failure",False)),
                    exercise_falsy=bool(getattr(args,"exercise_falsy",False)),
                    falsy_only=bool(getattr(args,"falsy_only",False)))
                if contract_outcome in {"fatal","stopped"}:abort_contracts=True
            else:
                route_features=[v for v in selected if v.route==route and v.key in CONTRACTS]
                # Let each selected contract enter its own guarded/finally
                # path even when the route-level bridge prerequisite is
                # unavailable.  The first harness failure stops later
                # contracts, but its exact cleanup is still attempted.
                run_feature_contracts(driver,route_features,route,results,check_window,
                    continue_after_product_failure=False,exercise_falsy=bool(getattr(args,"exercise_falsy",False)),
                    falsy_only=bool(getattr(args,"falsy_only",False)))
                abort_contracts=True
            errors=driver.script(ERRORS_JS) or [];attr=[e for e in errors if isinstance(e,dict) and (str(e.get("message","")).startswith("[ImprovedTube]") or "ImprovedTube" in str(e.get("source","")))]
            record(results,"ROUTE-"+route.upper()+"-CONSOLE","GLOBAL","candidate console errors attributed by route/phase",PASS if not attr else PRODUCT_FAILURE,"console" if not attr else "product",route,"route-console",{"all":errors,"attributed":attr,"unattributed":[e for e in errors if e not in attr]})
            if abort_contracts:break
    except Exception as exc:
        metadata["fatalError"]=str(exc)
        if not any(r.assertion_id=="GLOBAL-DRIVER" and r.status==PASS for r in results):record(results,"GLOBAL-DRIVER","GLOBAL","Safari Technology Preview inspected session created",HARNESS_FAILURE,"harness","global","fatal",{"error":str(exc)})
    finally:
        session_created=session_created or bool(driver.session_id)
        webdriver_cleanup=close_webdriver_session(driver,session_created)
        session_closed=webdriver_cleanup["sessionClosed"]
        window_close_requested=webdriver_cleanup["windowCloseRequested"]
        session_close_evidence=webdriver_cleanup["sessionCloseEvidence"]
        metadata["webdriverCleanup"]=webdriver_cleanup
        if observer and observer_claimed:
            try:
                observer_final=observer.call("final")
                metadata["observerFinal"]={k:v for k,v in observer_final.items() if k!="capability"}
            except Exception as exc:metadata["observerFinal"]={"ok":False,"error":str(exc)}
        if observer:observer.close()
        if args.driver_mode=="internal":
            terminate_process(driver_process);terminate_process(stp_process)
            time.sleep(.5);port_state={"portOwnedByHarness":True,"portClear":not port_open(args.host,args.port)}
        else:
            port_state={"portOwnedByHarness":False,"externalDriverStillReachable":port_open(args.host,args.port),"portClear":False}
        window_closed=False
        if observer_final is not None:
            window_closed=bool(observer_final.get("ok") and observer_final.get("expired") and observer_final.get("matchingCount")==0)
        elif not session_created:
            window_closed=True
        elif session_closed:
            # A typed DELETE /session proves residue is gone only when the
            # preceding DELETE /window response was itself verified.  A
            # malformed/ambiguous close-window response keeps cleanup unknown.
            window_closed=webdriver_cleanup.get("windowCloseVerified") is True
        elif automation_pid:
            try:
                remaining=[w for w in coregraphics_windows() if w.get("pid")==automation_pid and (automation_window_id is None or w.get("windowId")==automation_window_id) and float(w.get("alpha",1))>0]
                window_closed=window_identity_verified and not remaining
            except Exception as exc:metadata["windowCloseCheckError"]=str(exc)
        else:
            window_closed=False
        cleanup_ok=cleanup_success(args.driver_mode,session_closed,window_closed,port_state["portClear"],port_state.get("externalDriverStillReachable",False),webdriver_cleanup.get("windowCloseVerified") is True)
        metadata["cleanupOwnership"]={"driverMode":args.driver_mode,"driverProcessKilled":args.driver_mode=="internal","stpProcessKilled":args.driver_mode=="internal","unrelatedWindowsTouched":False}
        record(results,"GLOBAL-CLEANUP","GLOBAL","WebDriver session and owned automation window cleaned without touching external resources",PASS if cleanup_ok else HARNESS_FAILURE,"environment" if cleanup_ok else "harness","global","cleanup",{"sessionCreated":session_created,"sessionClosed":session_closed,"windowCloseRequested":window_close_requested,"windowCloseVerified":webdriver_cleanup.get("windowCloseVerified"),"implicitDeleteByLastWindow":webdriver_cleanup.get("implicitDeleteByLastWindow"),"windowClosed":window_closed,"sessionCloseEvidence":session_close_evidence,**port_state,"ownership":metadata["cleanupOwnership"]})
    expected=expected_assertions(selected,contract_routes,full_live);console_fail=any(r.status==PRODUCT_FAILURE and r.assertion_id.endswith("-CONSOLE") for r in results)
    record(results,"GLOBAL-CONSOLE","GLOBAL","candidate console evidence accounted by route",PRODUCT_FAILURE if console_fail else PASS,"console","global","coverage",{"routeAssertions":[r.assertion_id for r in results if r.assertion_id.endswith("-CONSOLE")]})
    missing=sorted((expected-{"GLOBAL-COVERAGE"})-{r.assertion_id for r in results})
    record(results,"GLOBAL-COVERAGE","GLOBAL","all indexed assertions have explicit statuses",PASS if not missing else FAIL,"coverage","global","coverage",{"missing":missing,"indexed":len(expected),"recorded":len({r.assertion_id for r in results})})
    metadata["containmentChecks"]=containment_checks
    provider_observations=metadata["signedProvider"]["observations"]
    metadata["signedProvider"]["bound"]=bool(provider_observations) and all(item.get("bound") is True for item in provider_observations)
    metadata["signedProvider"]["browserAuthoritative"]=bool(provider_observations) and all(item.get("browserAuthoritative") is True for item in provider_observations)
    metadata.update({"finishedAt":dt.datetime.now(dt.timezone.utc).isoformat(),"missing":missing,"pass":sum(r.status==PASS for r in results),"fail":sum(r.status not in {PASS,UNVERIFIED,NOT_RUN,NOT_APPLICABLE} for r in results),"unverified":sum(r.status==UNVERIFIED for r in results),"notRun":sum(r.status==NOT_RUN for r in results),"notApplicable":sum(r.status==NOT_APPLICABLE for r in results),"releaseGate":release_gate(args.sut,identity,missing,results,metadata["signedProvider"],binding_mode,full_live)})
    index_text=getattr(args,"assertion_index_text",None)
    if type(index_text) is not str:index_text=render_index(selected,source_root,full_live,plan_list)
    atomic_json_dump(output/"metadata.json",metadata);atomic_json_dump(output/"results.json",[asdict(r) for r in results]);(output/"assertion-index.md").write_text(index_text)
    print(json.dumps({"output":str(output),**metadata},indent=2,default=str),flush=True);return 0 if metadata["releaseGate"] else 1

def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser();p.add_argument("--host",default="127.0.0.1");p.add_argument("--port",type=int,default=4444);p.add_argument("--app-path",default=str(APP_PATH));p.add_argument("--extension-path",default=str(INSTALLED));p.add_argument("--window-x",type=int,default=-2420);p.add_argument("--window-y",type=int,default=-2520);p.add_argument("--window-width",type=int,default=1360);p.add_argument("--window-height",type=int,default=2480);p.add_argument("--limit",type=int);p.add_argument("--feature",action="append",dest="feature_keys");p.add_argument("--exercise-falsy",action="store_true");p.add_argument("--continue-after-product-failure",action="store_true",help="continue unrelated contracts only after a product failure with exact restoration and containment proof; isolation or harness failures stop");p.add_argument("--index-only",action="store_true");p.add_argument("--source",choices=("installed","repository"),default="installed");p.add_argument("--sut",choices=("signed","unpacked"),default="signed");p.add_argument("--unpacked",action="store_true");p.add_argument("--driver-mode",choices=("internal","external"),default="internal");p.add_argument("--external-driver",action="store_true");p.add_argument("--stp-pid",type=int,help="optional prebound PID for non-release diagnostics; omit for late binding");p.add_argument("--window-id",type=int,help="optional prebound window ID for non-release diagnostics; omit for late binding");p.add_argument("--observer-socket");p.add_argument("--observer-run-id");p.add_argument("--observer-capability",default="");p.add_argument("--observer-capability-file");p.add_argument("--observer-server-uid",type=int)
    p.add_argument("--falsy-only",action="store_true")
    p.add_argument("--full-live",action="store_true",help="plan and gate every discovered control; refuses incomplete coverage before Safari starts")
    p.add_argument("--allow-permission",action="store_true",help="allow explicitly permission-risk full-live contracts")
    p.add_argument("--allow-account",action="store_true",help="allow explicitly account-risk full-live contracts")
    p.add_argument("--account-fixture",help="JSON file binding an exact disposable accountId to approved fixture/video/channel targets")
    p.add_argument("--allow-destructive",action="store_true",help="allow explicitly destructive full-live contracts")
    p.add_argument("--contract-file",action="append",default=[],dest="contract_files",help="disjoint JSON contract file keyed by menuSource (repeatable)")
    p.add_argument("--contracts-dir",dest="contracts_dir",help="directory of disjoint JSON contract files")
    a=p.parse_args(argv);a.sut="unpacked" if a.unpacked else a.sut;a.driver_mode="external" if a.external_driver else a.driver_mode;source=INSTALLED if a.source=="installed" else ROOT
    try:a.account_fixture_data=load_account_fixture(a.account_fixture) if a.account_fixture else None
    except (OSError,ValueError,json.JSONDecodeError) as exc:raise SystemExit("invalid account fixture: "+str(exc))
    if a.full_live and (a.limit is not None or a.feature_keys):raise SystemExit("--full-live requires the complete discovered plan; --limit/--feature are focused-mode options")
    if a.falsy_only:
        if not a.exercise_falsy:raise SystemExit("--falsy-only requires --exercise-falsy")
        if len(a.feature_keys or [])!=1:raise SystemExit("--falsy-only requires exactly one explicit --feature")
    if a.observer_capability_file:a.observer_capability=Path(a.observer_capability_file).read_text().strip()
    if not source.is_dir():raise SystemExit("feature source not found: "+str(source))
    features=discover_features(source)
    if not features:raise SystemExit("no feature controls discovered")
    contract_paths=list(a.contract_files)
    if a.contracts_dir:contract_paths.append(a.contracts_dir)
    try:loaded_contracts,catalog_diagnostics=load_full_live_contract_catalog(contract_paths,features)
    except (OSError,ValueError) as exc:raise SystemExit("invalid contract file: "+str(exc))
    if a.full_live:
        try:
            complete_contracts=_full_contracts(loaded_contracts)
        except ValueError as exc:
            raise SystemExit("invalid full-live contract set: "+str(exc))
        full_plan=build_full_live_plan(features,loaded_contracts);errors=framework_validate_plan(features,complete_contracts,"full-live")
        assertion_index_text=render_index(features,source,True,full_plan)
        if errors:raise SystemExit("full-live preflight failed: "+"; ".join(errors))
    else:
        errors=validate_contracts(features)
        if errors:raise SystemExit("invalid feature contracts: "+"; ".join(errors))
        assertion_index_text=render_index(features,source)
    candidate_identity=freeze_candidate_surface(assertion_index_text,ROOT)
    if a.sut=="unpacked" and a.extension_path==str(INSTALLED):a.extension_path=str(ROOT)
    if not a.index_only and a.driver_mode=="external" and (not a.observer_socket or not a.observer_run_id or not (a.observer_capability or os.environ.get(OBSERVER_CAPABILITY_ENV,""))):raise SystemExit("external driver mode requires one-run observer socket/run/capability")
    identity=inspect_signed_bundle(Path(a.app_path))
    if a.sut=="signed" and not identity.get("valid"):
        print(json.dumps({"signedIdentity":identity,"candidate":candidate_identity},indent=2),file=sys.stderr);raise SystemExit("signed TestFlight bundle unavailable or invalid")
    if a.feature_keys:
        known={f.key for f in features};unknown=sorted(set(a.feature_keys)-known)
        if unknown:raise SystemExit("unknown feature key(s): "+", ".join(unknown))
    if a.falsy_only and a.feature_keys[0] not in CONTRACTS:raise SystemExit("--falsy-only requires a live contract feature")
    a.loaded_contracts=loaded_contracts
    a.contract_catalog_diagnostics=catalog_diagnostics
    a.assertion_index_text=assertion_index_text if a.full_live else None
    a.candidate_identity=candidate_identity
    if a.index_only:
        if a.full_live:
            preflight=framework_preflight(features,_full_contracts(loaded_contracts))
            summary={"controls":len(features),"fullLive":True,
                     "contracted":sorted(item.key for item in preflight.plans if item.status=="contracted"),
                     "notApplicable":sorted(item.key for item in preflight.plans if item.status=="not_applicable"),
                     "uncontracted":sorted(item.key for item in preflight.plans if item.status=="uncontracted"),
                     "signedIdentityValid":identity.get("valid"),"candidate":candidate_identity,
                     "contractCatalog":catalog_diagnostics,"planDigest":preflight.plan_digest,"planCounts":preflight.counts}
        else:
            summary={"controls":len(features),"liveSemanticContracts":sorted(k for k in CONTRACTS if k in {f.key for f in features}),"sourceOnly":sorted(f.key for f in features if f.key not in CONTRACTS),"signedIdentityValid":identity.get("valid"),"candidate":candidate_identity}
        print(json.dumps(summary,indent=2),flush=True);return 0
    return run(a,features,source,identity)

if __name__=="__main__":sys.exit(main())
