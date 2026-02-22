"""
PC Checker v3 — OFL/FFL Forensic Scanner
Windows 11 black/white theme | PIN auth | Dual webhook+web reporting
Build: pyinstaller --onefile --noconsole pc_checker_v3.py
"""

# ============================================================
#  CONFIG
# ============================================================
import base64 as _b64
def _d(s): return _b64.b64decode(s).decode()

_KW_ENC = [
    "dm9sdA==","bWF0Y2hh","Y2x1bXN5","c29sYXJh","eGVubw==",
    "cG90YXNzaXVt","Y3J5cHRpYw==","dmVsb2NpdHk=","c2lyaHVydA==",
    "dm9sY2Fubw==","YnVubmkuZnVu","c2VsaXdhcmU=","bWF0cml4",
    "ZXhlY3V0b3I=","cm9ibG94aGFjaw==","cmJseFg=",
    "d2F2ZWV4cGxvaXQ=","ZWxlY3Rlcg==","c3lub2FwZQ==",
    "c2NyaXB0d2FyZQ==","ZmluYWxlZA==","YXdha2VuZWQ=",
]
KEYWORDS = [_d(k) for k in _KW_ENC]

_WH_ENC = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTQ3MzkwMDQ0MzQ4NTg2ODE4Ny9uTmVfbGF3VlpIYk5VNEtWd2FTblpSX1h2YzVnTWlVRy0zSjBFSGJfajZ2YkxMaklBZUlCV2Zlem5VMTIxQU4teUxCYw=="
WEBHOOK_URL = _d(_WH_ENC)

# ← Set this to your Railway/Render URL once deployed
WEBSITE_URL = "https://pccheckersitee-production.up.railway.app"

FALSE_POSITIVE_PATHS = [
    "microsoft","windows","edge","chrome","firefox","mozilla",
    "program files","programdata","windowsapps","system32","syswow64",
    "onedrive","office","teams","skype","nvidia","amd","realtek",
    "intel","logitech","razer","corsair","steam\\steamapps\\common",
    "epicgames","origin","ubisoft",
    "appdata\\local\\microsoft","appdata\\roaming\\microsoft",
    "appdata\\local\\google",
]

LEGIT_APP_ALLOWLIST = {
    "volt":     ["node_modules","volt-0.","volt-1.","volt-2.","\\volt\\resources"],
    "velocity": ["\\velocity\\","vscodium","code\\extensions"],
    "matrix":   ["element","matrix.org","\\matrix\\resources"],
    "cryptic":  ["champions online","star trek","neverwinter","crypticstudios"],
}

SUSPICIOUS_DIRS = {
    "downloads","desktop","appdata\\local\\temp",
    "appdata\\roaming","appdata\\local\\packages","programdata",
}

def matches_keyword(text):
    t = text.lower()
    if any(fp in t for fp in FALSE_POSITIVE_PATHS):
        return []
    hits = []
    for kw in KEYWORDS:
        if kw.lower() not in t:
            continue
        allowlist = LEGIT_APP_ALLOWLIST.get(kw.lower(), [])
        if allowlist and any(ap in t for ap in allowlist):
            continue
        hits.append(kw)
    return hits

# ============================================================
#  IMPORTS
# ============================================================
import os, sys, re, glob, struct, hashlib, datetime, threading, time
import urllib.request, urllib.error, json, http.client, ssl, tempfile
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog

try:
    import winreg
    WINDOWS = True
except ImportError:
    WINDOWS = False

# ============================================================
#  HELPERS
# ============================================================
def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def current_user():
    return os.environ.get("USERNAME", os.environ.get("USER", "unknown"))

def sha1_file(path):
    try:
        h = hashlib.sha1()
        with open(path,"rb") as f:
            while chunk := f.read(65536): h.update(chunk)
        return h.hexdigest()
    except Exception: return "N/A"

def filetime_to_dt(ft):
    try:
        ts = ft/10_000_000 - 11_644_473_600
        return datetime.datetime.utcfromtimestamp(ts)
    except Exception: return None

def rot13(s):
    r=[]
    for c in s:
        if 'a'<=c<='z': r.append(chr((ord(c)-ord('a')+13)%26+ord('a')))
        elif 'A'<=c<='Z': r.append(chr((ord(c)-ord('A')+13)%26+ord('A')))
        else: r.append(c)
    return ''.join(r)

def section(title, lines):
    return "\n".join([f"\n── {title} ──"] + lines + ["─"*60])

# ============================================================
#  PIN VALIDATION
# ============================================================
def _make_request(url, payload_dict, timeout=10):
    """Cross-platform HTTPS POST — SSL verification fully disabled for compatibility."""
    import urllib.request, urllib.error
    payload = json.dumps(payload_dict).encode("utf-8")
    # Completely bypass SSL verification — works on all Windows versions
    ctx = ssl._create_unverified_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json",
                 "User-Agent": "PCChecker/3.0"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            raw = resp.read()
            try: body = json.loads(raw.decode("utf-8"))
            except Exception: body = {"raw": raw.decode("utf-8","replace")[:200]}
            return resp.status, body
    except urllib.error.HTTPError as e:
        try: body = json.loads(e.read().decode("utf-8","replace"))
        except Exception: body = {"error": f"HTTP {e.code}"}
        return e.code, body
    except Exception as e:
        return 0, {"error": str(e)}

def validate_pin(pin, league):
    """Returns (valid: bool, error_msg: str)"""
    try:
        url = WEBSITE_URL.rstrip("/") + "/api/pins/validate"
        # Send pin uppercase, stripped, no spaces
        clean_pin = pin.upper().strip().replace(" ", "")
        status, body = _make_request(url, {"pin": clean_pin, "league": league.upper().strip()})
        if status == 200 and body.get("valid"):
            return True, ""
        # Show detailed error including status code so we can debug
        err = body.get("error", "Invalid PIN")
        return False, f"{err} (HTTP {status})"
    except Exception as e:
        return False, f"Server error: {type(e).__name__}: {e}"

# ============================================================
#  WEBHOOK + WEBSITE SUBMIT
# ============================================================
def _post_json(payload_dict, url_override=None, retries=3):
    target = url_override or WEBHOOK_URL
    payload = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
    url_ns  = target.replace("https://","").replace("http://","")
    host, path = url_ns.split("/",1)
    path = "/" + path
    last_err = ""
    for attempt in range(retries):
        try:
            ctx  = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host,443,context=ctx,timeout=20)
            conn.request("POST", path, body=payload,
                         headers={"Content-Type":"application/json",
                                  "Content-Length":str(len(payload)),
                                  "User-Agent":"Mozilla/5.0"})
            resp = conn.getresponse()
            body = resp.read().decode("utf-8",errors="ignore")
            conn.close()
            if resp.status in (200,204): return True, resp.status, ""
            if resp.status == 429:
                wait = 2
                try: wait = json.loads(body).get("retry_after",2)
                except Exception: pass
                time.sleep(float(wait)+0.5); last_err=f"429 rate limit"; continue
            last_err = f"HTTP {resp.status}: {body[:200]}"
            time.sleep(1)
        except Exception as e:
            last_err = str(e); time.sleep(1.5)
    return False, 0, last_err

def _chunk(text, limit=3800):
    chunks=[]
    while len(text)>limit:
        split=text.rfind("\n",0,limit)
        if split==-1: split=limit
        chunks.append(text[:split]); text=text[split:]
    if text.strip(): chunks.append(text)
    return chunks or ["(empty)"]

def send_webhook(results):
    verdict = results.get("verdict","UNKNOWN")
    total   = results.get("total_hits",0)
    color   = {"CHEATER":0xf87171,"SUSPICIOUS":0xfbbf24,"CLEAN":0x34d399}.get(verdict,0x6b7280)
    errors  = []
    try:
        accounts  = results.get("roblox_accounts",[])
        acc_str   = "\n".join(f"• {a}" for a in accounts) if accounts else "None"
        unsigned  = results.get("unsigned_hits",[])
        us_str    = "\n".join(f"• {os.path.basename(u['path'])}" for u in unsigned[:10]) if unsigned else "None"
        summary   = {
            "title": f"PC Checker — {verdict}",
            "color": color,
            "timestamp": datetime.datetime.utcnow().isoformat()+"Z",
            "fields":[
                {"name":"Verdict","value":f"**{verdict}**","inline":True},
                {"name":"Total Hits","value":str(total),"inline":True},
                {"name":"PC User","value":current_user(),"inline":True},
                {"name":"League","value":results.get("league","?"),"inline":True},
                {"name":"ShellBag","value":str(results.get("shellbag_hits",0)),"inline":True},
                {"name":"BAM","value":str(results.get("bam_hits",0)),"inline":True},
                {"name":"Prefetch","value":str(results.get("prefetch_hits",0)),"inline":True},
                {"name":"AppCompat","value":str(results.get("appcompat_hits",0)),"inline":True},
                {"name":"Cheat Files","value":str(results.get("cheat_hits",0)),"inline":True},
                {"name":"YARA","value":str(results.get("yara_hits",0)),"inline":True},
                {"name":"Unsigned","value":str(len(unsigned)),"inline":True},
                {"name":"Roblox Accounts","value":acc_str[:1024],"inline":False},
                {"name":"Unsigned EXEs","value":us_str[:512],"inline":False},
            ],
            "footer":{"text":f"PC Checker v3 · {now_str()} · {results.get('league','?')}"},
        }
        ok,_,err = _post_json({"embeds":[summary]})
        if not ok: errors.append(f"Summary: {err}")
        time.sleep(0.8)
        tabs = [
            ("ShellBags",   results.get("shellbags","")),
            ("BAM",         results.get("bam","")),
            ("Prefetch",    results.get("prefetch","")),
            ("AppCompat",   results.get("appcompat","")),
            ("Roblox Logs", results.get("roblox","")),
            ("Cheat Files", results.get("cheat","")),
            ("YARA",        results.get("yara","")),
            ("Unsigned",    results.get("unsigned","")),
            ("Recycle Bin", results.get("recycle","")),
        ]
        for name, text in tabs:
            if not text or not text.strip(): continue
            for i, chunk in enumerate(_chunk(text.strip())):
                embed={"title":name if i==0 else f"{name} (cont.)","color":color,
                       "description":f"```\n{chunk}\n```"}
                ok,_,err = _post_json({"embeds":[embed]})
                if not ok: errors.append(f"{name}: {err}")
                time.sleep(0.8)
    except Exception as e:
        errors.append(str(e))
    return (False,"\n".join(errors)) if errors else (True,"OK")

def send_website(results, pin):
    """Submit scan results to the web dashboard."""
    try:
        url = WEBSITE_URL.rstrip("/") + "/api/submit"

        # Build report — cap full_report at 50kb to keep payload manageable
        full_rep = results.get("full_report","")
        if len(full_rep) > 50000:
            full_rep = full_rep[:50000] + "\n[truncated]"

        report = results.get("report") or {}
        # Always ensure key fields are present
        report.setdefault("shellbag_hits",  results.get("shellbag_hits",0))
        report.setdefault("bam_hits",       results.get("bam_hits",0))
        report.setdefault("prefetch_hits",  results.get("prefetch_hits",0))
        report.setdefault("appcompat_hits", results.get("appcompat_hits",0))
        report.setdefault("cheat_hits",     results.get("cheat_hits",0))
        report.setdefault("yara_hits",      results.get("yara_hits",0))
        report.setdefault("sysmain_hits",   results.get("sysmain_hits",0))
        report.setdefault("sysmain_autofail", results.get("sysmain_autofail",False))
        report.setdefault("discord_accounts", results.get("discord_accounts",[]))
        report.setdefault("fastflags",      results.get("fastflag_hits",[]) or [])
        report["full_report"] = full_rep

        # Truncate raw text fields inside report too
        for key in ("shellbags_raw","bam_raw","prefetch_raw","appcompat_raw",
                    "roblox_raw","cheat_raw","unsigned_raw","recycle_raw","sysmain_raw"):
            if key in report and isinstance(report[key], str) and len(report[key]) > 8000:
                report[key] = report[key][:8000] + "\n[truncated]"

        payload = {
            "pin":             pin,
            "league":          results.get("league","?"),
            "pc_user":         current_user(),
            "verdict":         results.get("verdict","UNKNOWN"),
            "total_hits":      results.get("total_hits",0),
            "roblox_accounts": results.get("roblox_accounts",[]),
            "report":          report,
        }

        status, body = _make_request(url, payload, timeout=45)
        if status == 200:
            return True, ""
        else:
            return False, f"HTTP {status}: {body.get('error', str(body)[:80])}"
    except Exception as e:
        return False, str(e)

# ============================================================
#  SCANNERS  (all existing scanners kept, tamper detection added)
# ============================================================

def scan_shellbags():
    hits=[]
    if not WINDOWS: return section("ShellBag Detection",["Windows only"]),0,[]
    hive_keys=[(winreg.HKEY_CURRENT_USER,r"SOFTWARE\Microsoft\Windows\Shell\BagMRU"),
               (winreg.HKEY_CURRENT_USER,r"SOFTWARE\Microsoft\Windows\ShellNoRoam\BagMRU")]
    def walk(hive,key_path,prefix,results,depth=0):
        if depth>8: return
        try: key=winreg.OpenKey(hive,key_path,0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        except OSError: return
        try:
            i=0
            while True:
                try:
                    name,data,_=winreg.EnumValue(key,i)
                    if isinstance(data,bytes):
                        decoded=data.decode("utf-16-le",errors="ignore").rstrip("\x00")
                        if decoded and len(decoded)>2:
                            full=(prefix+"\\"+decoded).strip("\\")
                            results.append(full)
                    i+=1
                except OSError: break
        except Exception: pass
        try:
            j=0
            while True:
                try:
                    sub=winreg.EnumKey(key,j)
                    walk(hive,key_path+"\\"+sub,prefix,results,depth+1); j+=1
                except OSError: break
        except Exception: pass
        winreg.CloseKey(key)
    all_paths=[]
    for hive,base in hive_keys:
        try: walk(hive,base,"",all_paths)
        except Exception: pass
    for path in all_paths:
        kws=matches_keyword(path)
        if kws: hits.append((path,"N/A",kws))
    lines=[f"{'Path':<70}|Timestamp","-"*90]
    for path,ts,kws in hits:
        lines.append(f"{path:<70}|{ts}  [{', '.join(kws)}]")
    lines.append(f"\nIntegrity: {'SUSPICIOUS' if hits else 'Normal'}")
    return section("ShellBag Detection",lines),len(hits),hits

def scan_bam():
    hits=[]
    if not WINDOWS: return section("BAM Detection",["Windows only"]),0,[]
    try:
        base=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                            0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        idx=0
        while True:
            try:
                sid=winreg.EnumKey(base,idx)
                sk=winreg.OpenKey(base,sid,0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
                vi=0
                while True:
                    try:
                        name,data,_=winreg.EnumValue(sk,vi)
                        if name.startswith("\\Device\\") and isinstance(data,bytes):
                            ts=None
                            if len(data)>=8:
                                ft=struct.unpack_from("<Q",data,0)[0]
                                ts=filetime_to_dt(ft)
                            kws=matches_keyword(name)
                            if kws: hits.append((name,ts,kws))
                        vi+=1
                    except OSError: break
                winreg.CloseKey(sk); idx+=1
            except OSError: break
        winreg.CloseKey(base)
    except Exception: pass
    lines=[]
    for path,ts,kws in hits:
        ts_str=ts.strftime("%Y-%m-%d %H:%M:%S.%f") if ts else "N/A"
        lines.append(f"{path}\n  LastRun:{ts_str}  [{', '.join(kws)}]")
    lines.append(f"\nIntegrity: {'SUSPICIOUS' if hits else 'Normal'}")
    return section("BAM Detection",lines),len(hits),hits

def scan_prefetch():
    pf_dir=r"C:\Windows\Prefetch"; hits=[]
    def read_dir(path):
        try:
            with open(path,"rb") as f: data=f.read(4096)
            decoded=data.decode("utf-16-le",errors="ignore")
            found=re.findall(r"C:[/\\][^\x00]{3,80}",decoded)
            return found[-1].strip() if found else None
        except Exception: return None
    try:
        for pf in glob.glob(os.path.join(pf_dir,"*.pf")):
            name=os.path.basename(pf)
            kws=matches_keyword(name)
            if kws:
                try: mtime=datetime.datetime.fromtimestamp(os.stat(pf).st_mtime)
                except Exception: mtime=None
                hits.append((name,pf,mtime,read_dir(pf),kws))
    except Exception: pass
    lines=[]
    for name,path,mtime,src,kws in hits:
        mt=mtime.strftime("%Y-%m-%d %H:%M:%S") if mtime else "N/A"
        lines.append(f"{path}\n  Modified:{mt} | Dir:{src or 'N/A'}\n  [{', '.join(kws)}]")
    lines.append(f"\nIntegrity: {'SUSPICIOUS' if hits else 'Normal'}")
    return section("Prefetch Hits",lines),len(hits),hits

def scan_appcompat():
    if not WINDOWS: return section("AppCompat",["Windows only"]),0,[]
    ac_hits=[]; ua_hits=[]
    try:
        key=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
                           0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        data,_=winreg.QueryValueEx(key,"AppCompatCache"); winreg.CloseKey(key)
        offset=128 if data[:4]==b'\x30\x00\x00\x00' else 0
        while offset<len(data)-12:
            try:
                if data[offset:offset+4]!=b'10ts': offset+=4; continue
                data_len=struct.unpack_from("<I",data,offset+8)[0]
                path_len=struct.unpack_from("<H",data,offset+12)[0]
                path_off=offset+14
                if path_off+path_len>len(data): break
                path=data[path_off:path_off+path_len].decode("utf-16-le",errors="ignore")
                kws=matches_keyword(path)
                if kws: ac_hits.append((path,kws))
                offset+=14+path_len+data_len
            except Exception: offset+=4
    except Exception: pass
    try:
        key=winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                           r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                           0,winreg.KEY_READ)
        idx=0
        while True:
            try:
                sub=winreg.EnumKey(key,idx)
                try:
                    ck=winreg.OpenKey(key,sub+"\\Count",0,winreg.KEY_READ)
                    vi=0
                    while True:
                        try:
                            name,_,_=winreg.EnumValue(ck,vi)
                            decoded=rot13(name)
                            kws=matches_keyword(decoded)
                            if kws: ua_hits.append((decoded,kws))
                            vi+=1
                        except OSError: break
                    winreg.CloseKey(ck)
                except Exception: pass
                idx+=1
            except OSError: break
        winreg.CloseKey(key)
    except Exception: pass
    lines=[]
    for path,kws in ac_hits: lines.append(f"  AppCompat: {path}  [{', '.join(kws)}]")
    for path,kws in ua_hits: lines.append(f"  UserAssist: {path}  [{', '.join(kws)}]")
    if not lines: lines.append("  ✓ No matches")
    return section("AppCompat / UserAssist",lines),len(ac_hits)+len(ua_hits),ac_hits+ua_hits

def scan_roblox_logs():
    issues=[]; all_logs=[]; account_map={}
    possible_dirs=[
        os.path.expanduser(r"~\AppData\Local\Roblox\logs"),
        os.path.expanduser(r"~\AppData\Local\Packages\ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr\LocalState\logs"),
        r"C:\Program Files (x86)\Roblox\logs",r"C:\Program Files\Roblox\logs",
    ]
    log_dir=next((d for d in possible_dirs if os.path.exists(d)),None)
    if not log_dir: return section("Roblox Logs",["Log directory not found"]),0,[]

    PAT_JOIN_PAIR   = re.compile(r'"UserId"%3a(\d{6,15})%2c"UserName"%3a"([A-Za-z0-9_]{3,20})"')
    PAT_REPORT_UID  = re.compile(r'\buserid:(\d{6,15})')
    PAT_REPORT_PLACE= re.compile(r'\bplaceid:(\d{4,15})')
    PAT_URL_UID     = re.compile(r'"UserId"%3a(\d{6,15})')
    PAT_URL_UNAME   = re.compile(r'"UserName"%3a"([A-Za-z0-9_]{3,20})"')
    PAT_PLAYER_GUI  = re.compile(r'Players\.([A-Za-z0-9_]{3,20})\.PlayerGui')
    PAT_LOG_TIME    = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
    PAT_BLOXSTRAP   = re.compile(r'"placeId":\s*(\d{4,15})')
    PAT_BLOXSTRAP_U = re.compile(r'"userId":\s*(\d{6,15})')

    USERNAME_NOISE={
        "playerscripts","playermodules","loadingscreen","coregui","luaappscreengui",
        "rnappcontainer","navigatorview","focusroot","scene","topbarpagecontent",
        "homeomnifeed","loadingstatecontainer","scrollingframe","content","omnifeed",
        "pymkcarousel","collectioncontent","items","scrollingitems","pymkcarouselusertile",
        "carouselusertile","playertileframe","playertile","tile","thumbnail","image",
        "imagecontainer","backgroundimage","imagesetimage","topbarcontents","topbar",
        "navbar","appheaderbar","bar","threesectionbar","rightframe","rightcontent",
        "topbaritem","button","gamecarousel","gametile","gametilecontent","thumbnailframe",
        "main","loadplayerinvites","replicatedfirst","enableloadingscreen",
        "replicatedstorage","playerimagecache","chat","textchatservice","voicechat",
    }

    def add_acc(uid=None, uname=None, placeid=None, ts=None, source=""):
        if uname and uname.lower() in USERNAME_NOISE: uname=None
        if uid:
            if uid not in account_map:
                account_map[uid]={"username":None,"placeids":set(),"timestamps":[],"sources":set()}
            e=account_map[uid]
            if uname and not e["username"]: e["username"]=uname
            if placeid: e["placeids"].add(placeid)
            if ts: e["timestamps"].append(ts)
            e["sources"].add(source)
        elif uname:
            key=f"__u_{uname}"
            if key not in account_map:
                account_map[key]={"username":uname,"placeids":set(),"timestamps":[],"sources":set()}
            e=account_map[key]
            if placeid: e["placeids"].add(placeid)
            if ts: e["timestamps"].append(ts)
            e["sources"].add(source)

    # ── Log tampering detection ──
    def check_tamper(entry, content, size, mtime, prev_mtime, all_log_times):
        flags=[]
        # 1. Very small file
        if size<300: flags.append("Tiny log — possible wipe")
        # 2. Log has join URLs but no corresponding account data (selectively cleared)
        has_join = bool(re.search(r'joinScriptUrl|doTeleport', content, re.IGNORECASE))
        has_uid  = bool(re.search(r'"UserId"%3a\d', content))
        if has_join and not has_uid: flags.append("Join activity found but UserID scrubbed")
        # 3. Log file modified AFTER its internal timestamp (edited externally)
        ts_match=PAT_LOG_TIME.search(content[:500])
        if ts_match:
            try:
                internal=datetime.datetime.fromisoformat(ts_match.group(1))
                # If file mtime is more than 5min AFTER internal start time AND it was modified
                # more recently than expected, flag it
                diff=(mtime - internal).total_seconds()
                if diff < -300:  # mtime is BEFORE the log says it started — clearly tampered
                    flags.append(f"File timestamp precedes log start time (tampered?)")
            except Exception: pass
        # 4. Gap between this log and previous
        if prev_mtime:
            gap=abs((prev_mtime - mtime).days)
            if gap>7: flags.append(f"Log gap: {gap} days (possible wipe period)")
        # 5. Log directory was recently emptied (fewer logs than expected)
        if len(all_log_times) < 3 and any(t.date() < (datetime.datetime.now()-datetime.timedelta(days=7)).date() for t in all_log_times):
            flags.append("Unusually few old logs — directory may have been cleaned")
        # 6. Unicode/binary garbage injected (attempt to corrupt parsing)
        null_count=content.count('\x00')
        if null_count > 50: flags.append(f"Excessive null bytes ({null_count}) — possible corruption/injection")
        return flags

    try:
        entries=sorted([e for e in os.scandir(log_dir) if e.name.endswith(".log")],
                       key=lambda e:e.stat().st_mtime,reverse=True)
        all_log_times=[datetime.datetime.fromtimestamp(e.stat().st_mtime) for e in entries]
        prev_mtime=None
        for entry in entries:
            try:
                stat=entry.stat()
                mtime=datetime.datetime.fromtimestamp(stat.st_mtime)
                size=stat.st_size
                all_logs.append((entry.name,mtime,size))
                with open(entry.path,"r",encoding="utf-8",errors="ignore") as f:
                    content=f.read()
                # Tamper checks
                tamper_flags=check_tamper(entry,content,size,mtime,prev_mtime,all_log_times)
                for flag in tamper_flags:
                    issues.append((entry.name,mtime,flag))
                prev_mtime=mtime
                if size<300: continue
                log_ts=None
                for m in PAT_LOG_TIME.finditer(content[:500]):
                    try: log_ts=datetime.datetime.fromisoformat(m.group(1)); break
                    except Exception: pass
                for uid,uname in PAT_JOIN_PAIR.findall(content):
                    pids=PAT_REPORT_PLACE.findall(content)
                    add_acc(uid=uid,uname=uname,placeid=pids[0] if pids else None,ts=log_ts,source="joinURL")
                for uid in PAT_REPORT_UID.findall(content):
                    pids=PAT_REPORT_PLACE.findall(content)
                    add_acc(uid=uid,placeid=pids[0] if pids else None,ts=log_ts,source="report")
                for uid in PAT_URL_UID.findall(content): add_acc(uid=uid,ts=log_ts,source="urlUID")
                for u in PAT_URL_UNAME.findall(content):
                    if u.lower() not in USERNAME_NOISE: add_acc(uname=u,ts=log_ts,source="urlName")
                for u in PAT_PLAYER_GUI.findall(content):
                    if u.lower() not in USERNAME_NOISE: add_acc(uname=u,ts=log_ts,source="playerGUI")
                for pid in PAT_BLOXSTRAP.findall(content):
                    for uid in PAT_BLOXSTRAP_U.findall(content):
                        add_acc(uid=uid,placeid=pid,ts=log_ts,source="bloxstrap")
            except Exception: pass
    except Exception: pass

    # Cross-reference uname-only entries
    uid_entries={k:v for k,v in account_map.items() if not k.startswith("__u_")}
    uname_entries={k:v for k,v in account_map.items() if k.startswith("__u_")}
    for ukey,uval in uname_entries.items():
        uname=uval["username"]
        matched=False
        for uid,udata in uid_entries.items():
            if not udata["username"]:
                udata["username"]=uname; udata["sources"]|=uval["sources"]; matched=True; break
        if not matched: uid_entries[ukey]=uval

    result_accounts=[]
    seen=set()
    for uid,data in uid_entries.items():
        uname=data["username"] or "Unknown"
        clean_uid=uid if not uid.startswith("__") else None
        key=(uname.lower(),clean_uid)
        if key in seen: continue
        seen.add(key)
        ts_list=sorted(set(str(t) for t in data["timestamps"] if t),reverse=True)
        result_accounts.append({
            "username":uname,"userid":clean_uid,
            "placeids":sorted(data["placeids"]),
            "last_seen":ts_list[0] if ts_list else "Unknown",
            "sources":sorted(data["sources"]),
        })
    result_accounts.sort(key=lambda a:(0 if(a["userid"] and a["username"]!="Unknown") else 1 if a["userid"] else 2))

    named=[a for a in result_accounts if a["username"]!="Unknown"]
    multi=len(named)>1

    lines=[f"\nLog Dir: {log_dir}",f"Total Logs: {len(all_logs)}",f"Accounts: {len(result_accounts)}",""]
    if multi: lines.append(f"⚠ MULTIPLE ACCOUNTS ({len(named)}) — Possible ban evasion\n")
    if issues:
        lines.append("⚠ LOG TAMPERING / INTEGRITY ISSUES:")
        for fname,ts,reason in issues:
            lines.append(f"  {fname} | {ts.strftime('%m/%d/%Y %H:%M') if ts else 'N/A'} | {reason}")
        lines.append("")
    lines.append("━"*50)
    for acc in result_accounts:
        lines.append(f"\n  Username : {acc['username']}")
        lines.append(f"  UserID   : {acc['userid'] or 'Unknown'}")
        lines.append(f"  Last Seen: {acc['last_seen']}")
        lines.append(f"  Places   : {', '.join(acc['placeids']) or 'N/A'}")
        lines.append(f"  Sources  : {', '.join(acc['sources'])}")
        lines.append("  " + "─"*35)
    if not result_accounts: lines.append("  No accounts found.")

    flat=[]
    for acc in result_accounts:
        u=acc["username"]; i=acc["userid"] or ""
        if u!="Unknown" and i: flat.append(f"{u} (ID: {i})")
        elif u!="Unknown": flat.append(u)
        elif i: flat.append(f"UserID: {i}")

    tamper_count=len(issues)+(1 if multi else 0)
    return section("Roblox Log Analysis",lines),tamper_count,flat

def scan_cheat_files():
    scan_dirs=[os.path.expanduser("~\\Downloads"),os.path.expanduser("~\\Desktop"),
               os.path.expanduser("~\\AppData\\Local"),os.path.expanduser("~\\AppData\\Roaming"),"C:\\"]
    SKIP={"windows","system32","syswow64","programdata","program files","program files (x86)",
          "$recycle.bin","windowsapps","winsxs","servicing"}
    hits=[]; scanned=0
    for base in scan_dirs:
        if not os.path.exists(base): continue
        try:
            for root,dirs,files in os.walk(base):
                depth=root.replace(base,"").count(os.sep)
                if depth>3: dirs.clear(); continue
                dirs[:]=[d for d in dirs if d.lower() not in SKIP]
                for fname in files:
                    scanned+=1
                    fpath=os.path.join(root,fname)
                    kws=matches_keyword(fpath)
                    if kws:
                        try:
                            stat=os.stat(fpath); ctime=datetime.datetime.fromtimestamp(stat.st_ctime)
                            hits.append({"path":fpath,"name":fname,
                                         "sha1":sha1_file(fpath) if stat.st_size<50_000_000 else "N/A",
                                         "size":stat.st_size,"ext":os.path.splitext(fname)[1].lower(),
                                         "created":ctime,"keywords":kws})
                        except Exception: pass
        except Exception: pass
    lines=[f"\nScanned: {scanned}  Hits: {len(hits)}","="*50]
    for i,h in enumerate(hits,1):
        lines.append(f"\n[{i}] {', '.join(h['keywords'])}")
        lines.append(f"    {h['path']}")
        lines.append(f"    SHA1: {h['sha1']}  Size: {h['size']}b  Ext: {h['ext']}")
        lines.append(f"    Created: {h['created'].strftime('%Y-%m-%d %H:%M:%S')}")
    if not hits: lines.append("✓ No cheat files found.")
    return section("Cheat File Scan",lines),len(hits),hits

def scan_yara():
    scan_dirs=[os.path.expanduser("~\\Downloads"),os.path.expanduser("~\\AppData\\Local")]
    hits=[]; notes=[]
    try:
        import yara
        rules=yara.compile(source=r"""
        rule CheatTool {
            strings: $upx="UPX0" $vmp="VMProtect" $i1="VirtualAllocEx" $i2="WriteProcessMemory" $i3="CreateRemoteThread"
            condition: 2 of them
        }""")
        use_yara=True
    except ImportError:
        use_yara=False
        notes.append("⚠ yara-python not installed — using heuristic scan\n")
    for base in scan_dirs:
        if not os.path.exists(base): continue
        for root,dirs,files in os.walk(base):
            if root.replace(base,"").count(os.sep)>3: dirs.clear(); continue
            for fname in files:
                if not fname.lower().endswith((".exe",".dll")): continue
                fpath=os.path.join(root,fname)
                try:
                    size=os.path.getsize(fpath)
                    if use_yara:
                        m=rules.match(fpath,timeout=5)
                        if m: hits.append({"path":fpath,"size":size,"sha1":sha1_file(fpath),"reason":f"YARA:{[r.rule for r in m]}"})
                    else:
                        with open(fpath,"rb") as f: hdr=f.read(512)
                        if not hdr.startswith(b"MZ"): continue
                        reasons=[]
                        if b"UPX" in hdr: reasons.append("UPX")
                        if size<10240: reasons.append("Tiny EXE")
                        if matches_keyword(fpath): reasons.append("keyword")
                        if reasons: hits.append({"path":fpath,"size":size,"sha1":sha1_file(fpath),"reason":" | ".join(reasons)})
                except Exception: pass
    lines=notes+[f"Hits: {len(hits)}","="*50]
    for i,h in enumerate(hits,1):
        lines.append(f"\n[{i}] {h['reason']}\n    {h['path']}\n    {h['size']}b | {h['sha1']}")
    if not hits: lines.append("✓ No suspicious executables.")
    return section("YARA / Heuristic",lines),len(hits),hits

def scan_unsigned():
    import subprocess, tempfile
    scan_dirs=[os.path.expanduser("~\\Downloads"),os.path.expanduser("~\\Desktop"),
               os.path.expanduser("~\\AppData\\Local")]
    TRUSTED=["microsoft","google","nvidia","amd","intel","logitech","razer","corsair",
              "steam","valve","epic games","discord","twitch","obs","adobe","spotify","zoom"]
    hits=[]; scanned=0; candidates=[]
    for base in scan_dirs:
        if not os.path.exists(base): continue
        try:
            for root,dirs,files in os.walk(base):
                if root.replace(base,"").count(os.sep)>3: dirs.clear(); continue
                dirs[:]=[d for d in dirs if not any(t in d.lower() for t in TRUSTED)]
                for fname in files:
                    if not fname.lower().endswith((".exe",".dll")): continue
                    fpath=os.path.join(root,fname)
                    try:
                        sz=os.path.getsize(fpath)
                        if sz>=1024: candidates.append((fpath,sz)); scanned+=1
                    except Exception: pass
        except Exception: pass
    if not WINDOWS or not candidates:
        for fpath,size in candidates:
            try:
                with open(fpath,"rb") as f: hdr=f.read(256)
                if hdr.startswith(b"MZ") and matches_keyword(fpath):
                    hits.append({"path":fpath,"size":size,"sha1":sha1_file(fpath),"reason":"keyword","publisher":"N/A"})
            except Exception: pass
    else:
        try:
            with tempfile.NamedTemporaryFile(mode="w",suffix=".txt",delete=False,encoding="utf-8") as tf:
                tf_path=tf.name
                for fpath,_ in candidates: tf.write(fpath.replace("'","''")+"\n")
            ps=f"""
$results=@()
Get-Content '{tf_path}' | ForEach-Object {{
    $p=$_.Trim(); if($p -eq ''){{return}}
    try {{
        $s=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction SilentlyContinue
        $status=if($s){{$s.Status}}else{{'Unknown'}}
        $subject=if($s -and $s.SignerCertificate){{$s.SignerCertificate.Subject}}else{{''}}
        $results+="$status`t$subject`t$p"
    }} catch {{ $results+="Unknown`t`t$p" }}
}}
$results
"""
            si=subprocess.STARTUPINFO()
            si.dwFlags=subprocess.STARTF_USESHOWWINDOW; si.wShowWindow=0
            out=subprocess.run(["powershell","-NoProfile","-NonInteractive","-WindowStyle","Hidden","-Command",ps],
                               capture_output=True,text=True,timeout=120,
                               creationflags=subprocess.CREATE_NO_WINDOW,startupinfo=si)
            size_map={fp:sz for fp,sz in candidates}
            for line in out.stdout.splitlines():
                parts=line.strip().split("\t",2)
                if len(parts)<3: continue
                status,subject,fpath=parts
                if status.strip()=="Valid": continue
                if any(t in subject.strip().lower() for t in TRUSTED): continue
                sz=size_map.get(fpath.strip(),0)
                hits.append({"path":fpath.strip(),"size":sz,
                             "sha1":sha1_file(fpath.strip()) if sz<20_000_000 else "N/A",
                             "reason":f"Unsigned ({status.strip()})","publisher":subject.strip() or "None"})
        except Exception: pass
        finally:
            try: os.unlink(tf_path)
            except Exception: pass
    lines=[f"\nScanned: {scanned}  Unsigned: {len(hits)}","="*50]
    for i,h in enumerate(hits,1):
        lines.append(f"\n[{i}] {h['reason']}\n    {h['path']}\n    Publisher: {h.get('publisher','N/A')}\n    {h['size']}b | {h['sha1']}")
    if not hits: lines.append("✓ No suspicious unsigned executables.")
    return section("Unsigned Scan",lines),len(hits),hits

def scan_recycle_bin():
    rb="C:\\$Recycle.Bin"; last_mod="Unknown"; hits=[]; total=0
    try:
        stat=os.stat(rb)
        last_mod=datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        for root,dirs,files in os.walk(rb):
            for f in files:
                total+=1
                kws=matches_keyword(f)
                if kws:
                    try:
                        fp=os.path.join(root,f)
                        mt=datetime.datetime.fromtimestamp(os.stat(fp).st_mtime)
                        hits.append((f,mt,kws))
                    except Exception: hits.append((f,None,kws))
    except Exception as e:
        return section("Recycle Bin",[f"Could not read: {e}"]),0,"Unknown"
    lines=[f"\nLast Modified: {last_mod}  Total Items: {total}"]
    for fname,mt,kws in hits:
        mt_str=mt.strftime("%Y-%m-%d %H:%M:%S") if mt else "N/A"
        lines.append(f"  {fname} | {mt_str} | [{', '.join(kws)}]")
    if not hits: lines.append("✓ No cheat files in Recycle Bin.")
    return section("Recycle Bin",lines),len(hits),last_mod


def scan_sysmain():
    """
    Detect if SysMain (Superfetch) service is disabled.
    SysMain controls Prefetch — disabling it is a common technique
    to prevent execution traces from being written.
    If disabled AND prefetch folder is empty/missing = AUTO FAIL signal.
    """
    if not WINDOWS:
        return section("SysMain / Prefetch Service", ["Windows only"]), 0, False

    sysmain_disabled = False
    start_value      = None
    state_str        = "Unknown"
    lines            = []

    # Check registry for SysMain service start type
    # 2 = Auto, 3 = Manual, 4 = Disabled
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\SysMain",
            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        )
        start_value, _ = winreg.QueryValueEx(key, "Start")
        winreg.CloseKey(key)
        state_map  = {2: "Automatic (Normal)", 3: "Manual", 4: "DISABLED"}
        state_str  = state_map.get(start_value, f"Unknown ({start_value})")
        sysmain_disabled = (start_value == 4)
    except Exception as e:
        lines.append(f"  Could not read SysMain registry: {e}")

    # Check how many prefetch files exist
    pf_dir   = r"C:\Windows\Prefetch"
    pf_count = 0
    try:
        pf_count = len(glob.glob(os.path.join(pf_dir, "*.pf")))
    except Exception:
        pass

    # Determine auto-fail condition:
    # SysMain disabled + fewer than 5 prefetch files = deliberate trace hiding
    pf_empty     = pf_count < 5
    auto_fail    = sysmain_disabled and pf_empty
    hit_count    = 0

    lines.append(f"  SysMain Service State : {state_str}")
    lines.append(f"  Registry Start Value  : {start_value}")
    lines.append(f"  Prefetch File Count   : {pf_count}")
    lines.append("")

    if sysmain_disabled:
        hit_count += 3
        lines.append("  ⚠ SysMain is DISABLED — Prefetch logging suppressed")
        lines.append("  ⚠ This prevents execution history from being recorded")
        if pf_empty:
            hit_count += 5  # Extra weight — combined signal is very strong
            lines.append("")
            lines.append("  ✗ AUTO FAIL: SysMain disabled AND Prefetch folder nearly empty")
            lines.append("  ✗ This combination strongly indicates deliberate trace wiping")
        else:
            lines.append(f"  NOTE: {pf_count} prefetch files still present")
            lines.append("  This may indicate SysMain was recently disabled after use")
    else:
        lines.append(f"  ✓ SysMain is running normally ({state_str})")
        if pf_count < 10:
            hit_count += 1
            lines.append(f"  ⚠ Low prefetch count ({pf_count}) despite SysMain enabled — possible manual wipe")
        else:
            lines.append(f"  ✓ Prefetch file count normal ({pf_count} files)")

    return section("SysMain / Prefetch Service Check", lines), hit_count, auto_fail


# ============================================================
#  NEW DETECTIONS v3
# ============================================================

def scan_discord_cache():
    """Read Discord local storage/cache to find account usernames/IDs."""
    hits = []
    discord_paths = [
        os.path.expanduser(r"~\AppData\Roaming\discord\Local Storage\leveldb"),
        os.path.expanduser(r"~\AppData\Roaming\discordptb\Local Storage\leveldb"),
        os.path.expanduser(r"~\AppData\Roaming\discordcanary\Local Storage\leveldb"),
    ]
    TOKEN_RE  = re.compile(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}')
    ID_RE     = re.compile(r'"id"\s*:\s*"(\d{17,19})"')
    NAME_RE   = re.compile(r'"username"\s*:\s*"([^"]{2,32})"')
    accounts  = []
    seen_ids  = set()

    for base in discord_paths:
        if not os.path.exists(base): continue
        src = os.path.basename(os.path.dirname(base))
        try:
            for fname in os.listdir(base):
                if not (fname.endswith(".ldb") or fname.endswith(".log")): continue
                fpath = os.path.join(base, fname)
                try:
                    with open(fpath, "rb") as f: raw = f.read().decode("utf-8", errors="ignore")
                    ids    = ID_RE.findall(raw)
                    names  = NAME_RE.findall(raw)
                    tokens = TOKEN_RE.findall(raw)
                    for uid in ids:
                        if uid not in seen_ids:
                            seen_ids.add(uid)
                            uname = names[0] if names else "Unknown"
                            accounts.append({"id": uid, "username": uname,
                                             "has_token": bool(tokens), "source": src})
                except Exception: pass
        except Exception: pass

    lines = [f"\n  Discord cache paths scanned: {len(discord_paths)}",
             f"  Accounts found: {len(accounts)}", ""]
    for acc in accounts:
        lines.append(f"  Username : {acc['username']}")
        lines.append(f"  ID       : {acc['id']}")
        lines.append(f"  Token    : {'FOUND (suspicious)' if acc['has_token'] else 'Not found'}")
        lines.append(f"  Source   : {acc['source']}")
        lines.append("  " + "─"*30)
    if not accounts: lines.append("  No Discord accounts found in cache.")
    return section("Discord Cache", lines), len(accounts), accounts


def scan_factory_reset():
    """Detect Windows reinstall/factory reset history via registry."""
    if not WINDOWS:
        return section("Factory Reset", ["Windows only"]), False, ""
    resets = []
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\Setup",
                             0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        # Enumerate upgrade history
        try:
            hist_key = winreg.OpenKey(key, "Source OS", 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(hist_key, i)
                    sk  = winreg.OpenKey(hist_key, sub, 0, winreg.KEY_READ)
                    try:
                        prod,_  = winreg.QueryValueEx(sk, "ProductName")
                        build,_ = winreg.QueryValueEx(sk, "CurrentBuild")
                        when,_  = winreg.QueryValueEx(sk, "InstallDate")
                        resets.append(f"{prod} (Build {build}) installed {when}")
                    except Exception: pass
                    winreg.CloseKey(sk); i += 1
                except OSError: break
            winreg.CloseKey(hist_key)
        except Exception: pass
        winreg.CloseKey(key)
    except Exception: pass

    # Current install
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                             0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        prod,_  = winreg.QueryValueEx(key, "ProductName")
        build,_ = winreg.QueryValueEx(key, "CurrentBuild")
        try: rel,_ = winreg.QueryValueEx(key, "ReleaseId")
        except Exception: rel = "?"
        try: idate,_ = winreg.QueryValueEx(key, "InstallDate")
        except Exception: idate = "Unknown"
        current = f"Current: {prod} (Build {build}, Release {rel}) — InstallDate: {idate}"
        winreg.CloseKey(key)
    except Exception:
        current = "Could not read current Windows version"

    lines = [f"\n  {current}", ""]
    if resets:
        lines.append("  Previous installs / resets:")
        for r in resets: lines.append(f"    ► {r}")
    else:
        lines.append("  No previous installs found (may indicate fresh install or cleared history)")
    reset_text = current + ("\n  " + "\n  ".join(resets) if resets else "")
    return section("Factory Reset Detection", lines), bool(resets), reset_text


def scan_fastflags():
    """Detect Roblox FastFlags which can enable cheating features."""
    SUSPICIOUS_FLAGS = {
        "FFlagDebugGraphicsDisableDirect3D11": "Disables D3D11 (anti-cheat bypass)",
        "FFlagDisableNewIGMinDUA": "Disables input guard",
        "DFStringTaskSchedulerTargetFps": "Uncapped FPS exploit",
        "FFlagDebugRenderingSetDeterministic": "Rendering manipulation",
        "FFlagDisablePostFx": "Visual exploit flag",
        "FFlagEnableHyperscaleImpostors": "Known cheat flag",
        "FFlagFixGraphicsQuality": "Graphics bypass flag",
    }
    ff_paths = [
        os.path.expanduser(r"~\AppData\Local\Roblox\ClientSettings\ClientAppSettings.json"),
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\Modifications\ClientSettings\ClientAppSettings.json"),
    ]
    hits = []; all_flags = {}
    for path in ff_paths:
        if not os.path.exists(path): continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                flags = json.loads(f.read())
            for k, v in flags.items():
                all_flags[k] = v
                if k in SUSPICIOUS_FLAGS:
                    hits.append(f"{k} = {v}  [{SUSPICIOUS_FLAGS[k]}]")
        except Exception: pass

    lines = [f"\n  Total FastFlags found: {len(all_flags)}",
             f"  Suspicious flags: {len(hits)}", ""]
    if hits:
        for h in hits: lines.append(f"  ⚠ {h}")
    else:
        lines.append("  ✓ No suspicious FastFlags detected.")
    return section("FastFlag Detection", lines), len(hits), hits


def scan_drives():
    """Check for evidence of unplugged/external drives."""
    if not WINDOWS:
        return section("Drive Detection", ["Windows only"]), False, ""
    drives_found = []
    drive_warn   = False
    lines        = []
    # Check USB storage history in registry
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
                             0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        i = 0
        while True:
            try:
                device = winreg.EnumKey(key, i)
                dk = winreg.OpenKey(key, device, 0, winreg.KEY_READ)
                j = 0
                while True:
                    try:
                        inst = winreg.EnumKey(dk, j)
                        ik   = winreg.OpenKey(dk, inst, 0, winreg.KEY_READ)
                        try: friendly,_ = winreg.QueryValueEx(ik, "FriendlyName")
                        except Exception: friendly = device
                        drives_found.append(friendly)
                        winreg.CloseKey(ik); j += 1
                    except OSError: break
                winreg.CloseKey(dk); i += 1
            except OSError: break
        winreg.CloseKey(key)
    except Exception: pass

    # Current drives
    current_letters = []
    try:
        import string as _str
        for letter in _str.ascii_uppercase:
            if os.path.exists(f"{letter}:\\"):
                current_letters.append(f"{letter}:")
    except Exception: pass

    lines.append(f"  Current drives detected: {', '.join(current_letters) or 'None'}")
    lines.append(f"  USB storage devices (ever connected): {len(drives_found)}")
    if drives_found:
        lines.append("")
        for d in drives_found[:20]: lines.append(f"  ► {d}")
    if len(drives_found) > 3:
        drive_warn = True
        lines.append(f"\n  ⚠ {len(drives_found)} USB storage devices detected — check for external drives")

    info_str = f"Current: {', '.join(current_letters)} | USB history: {len(drives_found)} devices"
    return section("Drive Detection", lines), drive_warn, info_str

def run_full_scan(league="?"):
    sb_t,sb_h,_         = scan_shellbags()
    bm_t,bm_h,_         = scan_bam()
    pf_t,pf_h,_         = scan_prefetch()
    ac_t,ac_h,_         = scan_appcompat()
    rl_t,rl_h,accs      = scan_roblox_logs()
    cs_t,cs_h,_         = scan_cheat_files()
    yr_t,yr_h,_         = scan_yara()
    us_t,us_h,us_l      = scan_unsigned()
    rb_t,rb_h,rb_l      = scan_recycle_bin()
    sm_t,sm_h,auto_fail = scan_sysmain()
    dc_t,dc_h,dc_accs   = scan_discord_cache()
    fr_t,_,fr_text      = scan_factory_reset()
    ff_t,ff_h,ff_hits   = scan_fastflags()
    dv_t,dv_warn,dv_inf = scan_drives()

    total = sb_h+bm_h+pf_h+ac_h+cs_h+yr_h+us_h+rb_h+rl_h+sm_h+ff_h

    if auto_fail:
        verdict = "CHEATER"
    else:
        verdict = "CHEATER" if total>=5 else ("SUSPICIOUS" if total>=1 else "CLEAN")

    # Build rich roblox account objects if accs is just strings
    roblox_list = []
    if isinstance(accs, list):
        for a in accs:
            if isinstance(a, dict): roblox_list.append(a)
            else: roblox_list.append({"username": str(a), "userid": None, "sources": [], "placeids": [], "last_seen": None})

    return {
        "shellbags":sb_t,"bam":bm_t,"prefetch":pf_t,"appcompat":ac_t,
        "roblox":rl_t,"cheat":cs_t,"yara":yr_t,"unsigned":us_t,
        "recycle":rb_t,"sysmain":sm_t,"discord":dc_t,
        "shellbag_hits":sb_h,"bam_hits":bm_h,"prefetch_hits":pf_h,"appcompat_hits":ac_h,
        "cheat_hits":cs_h,"yara_hits":yr_h,"unsigned_hits":us_l,
        "sysmain_hits":sm_h,"sysmain_autofail":auto_fail,
        "fastflag_hits":ff_h,
        "roblox_accounts": roblox_list,
        "discord_accounts": dc_accs,
        "recycle_bin_time":rb_l if isinstance(rb_l,str) else "Unknown",
        "total_hits":total,"verdict":verdict,"league":league,
        "report": {
            "shellbag_hits":sb_h,"bam_hits":bm_h,"prefetch_hits":pf_h,"appcompat_hits":ac_h,
            "cheat_hits":cs_h,"yara_hits":yr_h,"unsigned_count":len(us_l) if isinstance(us_l,list) else us_h,
            "sysmain_hits":sm_h,"sysmain_autofail":auto_fail,"sysmain_raw":sm_t,
            "roblox_hits":rl_h,"fastflags":ff_hits,
            "discord_accounts":dc_accs,
            "factory_resets":fr_text,
            "drive_info":dv_inf,"drive_warn":dv_warn,
            "shellbags_raw":sb_t,"bam_raw":bm_t,"prefetch_raw":pf_t,"appcompat_raw":ac_t,
            "roblox_raw":rl_t,"cheat_raw":cs_t,"unsigned_raw":us_t,"recycle_raw":rb_t,
            "full_report":"\n".join([
                f"PC CHECKER v3  |  {now_str()}  |  User: {current_user()}  |  League: {league}","="*60,
                sb_t,bm_t,pf_t,ac_t,rl_t,cs_t,yr_t,us_t,rb_t,sm_t,dc_t,fr_t,ff_t,dv_t,
                f"\nAUTO FAIL: {auto_fail}",
                f"\nVERDICT: {verdict}  —  Total Hits: {total}"
            ]),
        },
        "full_report":"\n".join([
            f"PC CHECKER v3  |  {now_str()}  |  User: {current_user()}  |  League: {league}","="*60,
            sb_t,bm_t,pf_t,ac_t,rl_t,cs_t,yr_t,us_t,rb_t,sm_t,dc_t,fr_t,ff_t,dv_t,
            f"\nAUTO FAIL: {auto_fail}",
            f"\nVERDICT: {verdict}  —  Total Hits: {total}"
        ]),
    }

# ============================================================
#  GUI  — Windows 11 Black/White
# ============================================================
class App:
    # ── Palette ──
    BG      = "#0a0a0a"
    BG2     = "#111111"
    BG3     = "#181818"
    BG4     = "#1f1f1f"
    BORDER  = "#1e1e1e"
    BORDER2 = "#2a2a2a"
    FG      = "#f0f0f0"
    FG2     = "#707070"
    FG3     = "#383838"
    WHITE   = "#ffffff"
    RED     = "#ff3b3b"
    GREEN   = "#2aff8f"
    AMBER   = "#ffb703"
    BLUE    = "#4da6ff"

    def __init__(self, root):
        self.root         = root
        self.root.withdraw()          # hide until PIN validated
        self.results      = {}
        self.scanning     = False
        self._wh_sent     = False
        self._pin         = ""
        self._league      = "UFF"
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._show_tos_screen()

    # ╔══════════════════════════════════════════════════════╗
    # ║  TERMS OF SERVICE SCREEN                             ║
    # ╚══════════════════════════════════════════════════════╝
    def _show_tos_screen(self):
        self._tos_win = tk.Toplevel()
        self._tos_win.title("PC Checker — Terms of Service")
        self._tos_win.geometry("520x580")
        self._tos_win.configure(bg=self.BG)
        self._tos_win.resizable(False, False)
        self._tos_win.protocol("WM_DELETE_WINDOW", lambda: (self._tos_win.destroy(), self.root.destroy()))

        self._tos_win.update_idletasks()
        sw = self._tos_win.winfo_screenwidth()
        sh = self._tos_win.winfo_screenheight()
        self._tos_win.geometry(f"520x580+{(sw-520)//2}+{(sh-580)//2}")

        cv = tk.Canvas(self._tos_win, width=520, height=580, bg=self.BG, highlightthickness=0)
        cv.place(x=0, y=0)
        cv.create_line(0,0,48,0,fill=self.WHITE,width=2)
        cv.create_line(0,0,0,48,fill=self.WHITE,width=2)
        cv.create_line(520,580,472,580,fill=self.FG3,width=1)
        cv.create_line(520,580,520,532,fill=self.FG3,width=1)

        f = tk.Frame(self._tos_win, bg=self.BG)
        f.place(x=48, y=56, width=424)

        tk.Label(f, text="PC CHECKER", font=("Segoe UI", 9, "bold"),
                 fg=self.FG2, bg=self.BG).pack(anchor="w")
        tk.Label(f, text="Terms of Service", font=("Segoe UI", 20, "bold"),
                 fg=self.FG, bg=self.BG).pack(anchor="w", pady=(4,0))
        tk.Label(f, text="Last updated: 2/22/2026", font=("Segoe UI", 9),
                 fg=self.FG3, bg=self.BG).pack(anchor="w", pady=(2,16))

        # Scrolled text box for ToS
        txt_frame = tk.Frame(f, bg=self.BORDER, bd=0)
        txt_frame.pack(fill="x", pady=(0, 14))
        txt = tk.Text(txt_frame, width=52, height=14, font=("Segoe UI", 9),
                      bg=self.BG2, fg=self.FG2, bd=0, padx=10, pady=10,
                      relief="flat", wrap="word", cursor="arrow",
                      selectbackground=self.BG3)
        txt.pack(side="left", fill="both", expand=True)
        sb = tk.Scrollbar(txt_frame, orient="vertical", command=txt.yview)
        sb.pack(side="right", fill="y")
        txt.configure(yscrollcommand=sb.set)
        TOS_TEXT = (
            "By using this software, you acknowledge and agree that the creator "
            "of this software is NOT responsible for how the information obtained "
            "is used by third party leagues and members.\n\n"
            "This tool is provided to aid in the screensharing process and no "
            "information will be distributed by the owner of the software.\n\n"
            "If the league or individual using the software on you is NOT listed "
            "or has received proper authorization, please report it immediately "
            "by DMing Discord user: converts_19942 or by joining the Lite server "
            "and making a ticket.\n\n"
            "Unauthorized usage will be revoked."
        )
        txt.insert("1.0", TOS_TEXT)
        txt.configure(state="disabled")

        tk.Label(f, text="You must read and agree before the scan can begin.",
                 font=("Segoe UI", 9), fg=self.FG3, bg=self.BG).pack(anchor="w", pady=(0,10))

        agree_btn = tk.Button(f, text="I have read and agree to Terms of Service",
                              font=("Segoe UI", 10, "bold"),
                              bg=self.WHITE, fg="#000000", activebackground=self.FG,
                              bd=0, padx=14, pady=10, cursor="hand2",
                              command=self._tos_accepted)
        agree_btn.pack(fill="x")

        tk.Label(f, text="Declining will close the application.",
                 font=("Segoe UI", 8), fg=self.FG3, bg=self.BG).pack(pady=(6,0))
        tk.Button(f, text="Decline", font=("Segoe UI", 9),
                  bg=self.BG, fg=self.FG3, activebackground=self.BG2,
                  bd=0, pady=4, cursor="hand2",
                  command=lambda: (self._tos_win.destroy(), self.root.destroy())).pack(pady=(4,0))

    def _tos_accepted(self):
        self._tos_win.destroy()
        self._show_pin_screen()

    # ── Close ─────────────────────────────────────────────────
    def _on_close(self):
        if self.results and not self._wh_sent:
            try: send_webhook(self.results); send_website(self.results, self._pin)
            except Exception: pass
        self.root.destroy()

    # ╔══════════════════════════════════════════════════════╗
    # ║  PIN SCREEN                                          ║
    # ╚══════════════════════════════════════════════════════╝
    def _show_pin_screen(self):
        self._pin_win = tk.Toplevel()
        self._pin_win.title("PC Checker — Authorization")
        self._pin_win.geometry("440x560")
        self._pin_win.configure(bg=self.BG)
        self._pin_win.resizable(False, False)
        self._pin_win.protocol("WM_DELETE_WINDOW", lambda: (self._pin_win.destroy(), self.root.destroy()))

        # Center it
        self._pin_win.update_idletasks()
        sw = self._pin_win.winfo_screenwidth()
        sh = self._pin_win.winfo_screenheight()
        x  = (sw - 440) // 2
        y  = (sh - 560) // 2
        self._pin_win.geometry(f"440x560+{x}+{y}")

        # Corner accent (canvas)
        cv = tk.Canvas(self._pin_win, width=440, height=560, bg=self.BG,
                       highlightthickness=0)
        cv.place(x=0, y=0)
        cv.create_line(0, 0, 44, 0, fill=self.WHITE, width=2)
        cv.create_line(0, 0, 0, 44, fill=self.WHITE, width=2)
        cv.create_line(440, 560, 396, 560, fill=self.FG3, width=1)
        cv.create_line(440, 560, 440, 516, fill=self.FG3, width=1)

        f = tk.Frame(self._pin_win, bg=self.BG)
        f.place(x=48, y=64, width=344)

        tk.Label(f, text="PC CHECKER", font=("Segoe UI", 10, "bold"),
                 fg=self.FG2, bg=self.BG).pack(anchor="w")
        tk.Label(f, text="Forensic Scanner", font=("Segoe UI", 22, "bold"),
                 fg=self.FG, bg=self.BG).pack(anchor="w", pady=(6, 0))
        tk.Label(f, text="v3.0  ·  OFL / FFL", font=("Segoe UI", 10),
                 fg=self.FG3, bg=self.BG).pack(anchor="w", pady=(2, 32))

        # League selector
        tk.Label(f, text="LEAGUE", font=("Segoe UI", 9),
                 fg=self.FG2, bg=self.BG).pack(anchor="w", pady=(0, 6))

        sel_frame = tk.Frame(f, bg=self.BG2, bd=0, highlightthickness=1,
                             highlightbackground=self.BORDER2)
        sel_frame.pack(fill="x", pady=(0, 20))

        self._league_var = tk.StringVar(value="UFF")
        self._sel_lbl = tk.Label(sel_frame, textvariable=self._league_var,
                                  font=("Segoe UI Semibold", 12),
                                  fg=self.FG, bg=self.BG2,
                                  anchor="w", padx=14, pady=10)
        self._sel_lbl.pack(side="left", fill="x", expand=True)
        self._arr = tk.Label(sel_frame, text="∨", font=("Segoe UI", 11),
                             fg=self.FG2, bg=self.BG2, padx=12, pady=10)
        self._arr.pack(side="right")
        sel_frame.bind("<Button-1>", self._toggle_dropdown)
        self._sel_lbl.bind("<Button-1>", self._toggle_dropdown)
        self._arr.bind("<Button-1>", self._toggle_dropdown)
        self._dropdown_open = False

        # Dropdown menu (hidden initially)
        self._dd = tk.Frame(self._pin_win, bg=self.BG3,
                            highlightthickness=1, highlightbackground=self.BORDER2)
        self._dd_visible = False

        # PIN entry
        tk.Label(f, text="AUTHORIZATION PIN", font=("Segoe UI", 9),
                 fg=self.FG2, bg=self.BG).pack(anchor="w", pady=(0, 6))

        pin_frame = tk.Frame(f, bg=self.BG2, bd=0, highlightthickness=1,
                             highlightbackground=self.BORDER2)
        pin_frame.pack(fill="x", pady=(0, 8))
        self._pin_var = tk.StringVar()
        self._pin_entry = tk.Entry(pin_frame, textvariable=self._pin_var,
                                   font=("Segoe UI Semibold", 15),
                                   fg=self.FG, bg=self.BG2,
                                   insertbackground=self.WHITE,
                                   relief="flat", bd=0,
                                   show="●")
        self._pin_entry.pack(padx=14, pady=11, fill="x")
        self._pin_entry.bind("<Return>", lambda e: self._validate_pin())
        self._pin_entry.bind("<KeyRelease>", self._format_pin)

        tk.Label(f, text="8-character PIN provided by your DOJ agent",
                 font=("Segoe UI", 9), fg=self.FG3, bg=self.BG).pack(anchor="w", pady=(0, 28))

        # Submit button
        self._pin_btn = tk.Button(f, text="Authorize & Continue",
                                  font=("Segoe UI Semibold", 11),
                                  bg=self.WHITE, fg=self.BG,
                                  relief="flat", bd=0, cursor="hand2",
                                  padx=20, pady=12,
                                  command=self._validate_pin,
                                  activebackground="#dddddd",
                                  activeforeground=self.BG)
        self._pin_btn.pack(fill="x")

        self._pin_err = tk.Label(f, text="", font=("Segoe UI", 9),
                                 fg=self.RED, bg=self.BG, wraplength=320)
        self._pin_err.pack(pady=(10, 0), anchor="w")

        self._pin_status = tk.Label(f, text="", font=("Segoe UI", 9),
                                    fg=self.FG2, bg=self.BG)
        self._pin_status.pack(pady=(4, 0), anchor="w")

        self._pin_entry.focus_set()

    def _toggle_dropdown(self, e=None):
        if self._dd_visible:
            self._dd.place_forget()
            self._dd_visible = False
            self._arr.config(text="∨")
        else:
            # Calculate position relative to pin_win
            sel = self._sel_lbl.master
            x = sel.winfo_rootx() - self._pin_win.winfo_rootx()
            y = sel.winfo_rooty() - self._pin_win.winfo_rooty() + sel.winfo_height()
            self._dd.place(x=x, y=y, width=sel.winfo_width())
            # Clear and populate
            for w in self._dd.winfo_children():
                w.destroy()
            for league in ["UFF", "FFL"]:
                item = tk.Label(self._dd, text=league,
                                font=("Segoe UI Semibold", 12),
                                fg=self.FG, bg=self.BG3,
                                anchor="w", padx=14, pady=10, cursor="hand2")
                item.pack(fill="x")
                item.bind("<Enter>", lambda e, w=item: w.config(bg=self.BG4))
                item.bind("<Leave>", lambda e, w=item, l=league: w.config(bg=self.BG3))
                item.bind("<Button-1>", lambda e, l=league: self._pick_league(l))
            self._dd_visible = True
            self._arr.config(text="∧")

    def _pick_league(self, league):
        self._league_var.set(league)
        self._league = league
        self._dd.place_forget()
        self._dd_visible = False
        self._arr.config(text="∨")

    def _format_pin(self, e=None):
        v = self._pin_var.get().upper().replace(" ", "")[:8]
        self._pin_var.set(v)

    def _validate_pin(self):
        pin    = self._pin_var.get().upper().strip()
        league = self._league_var.get()
        if len(pin) < 4:
            self._pin_err.config(text="Please enter your PIN")
            return
        self._pin_btn.config(state="disabled", text="Validating…")
        self._pin_err.config(text="")
        self._pin_status.config(text="Contacting server…")
        threading.Thread(target=self._do_validate, args=(pin, league), daemon=True).start()

    def _do_validate(self, pin, league):
        valid, err = validate_pin(pin, league)
        if valid:
            self._pin = pin
            self._league = league
            self.root.after(0, self._pin_accepted)
        else:
            self.root.after(0, self._pin_rejected, err)

    def _pin_accepted(self):
        self._pin_win.destroy()
        self._build_main()
        self.root.deiconify()

    def _pin_rejected(self, err):
        self._pin_btn.config(state="normal", text="Authorize & Continue")
        self._pin_err.config(text=f"✗  {err}")
        self._pin_status.config(text="")

    # ╔══════════════════════════════════════════════════════╗
    # ║  MAIN WINDOW                                         ║
    # ╚══════════════════════════════════════════════════════╝
    def _build_main(self):
        self.root.title(f"PC Checker  ·  {self._league}  ·  {current_user()}")
        self.root.geometry("1220x800")
        self.root.configure(bg=self.BG)
        self.root.resizable(True, True)

        # Center
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"1220x800+{(sw-1220)//2}+{(sh-800)//2}")

        # ── Top bar
        topbar = tk.Frame(self.root, bg=self.BG2, height=52)
        topbar.pack(fill="x"); topbar.pack_propagate(False)
        tk.Frame(self.root, bg=self.BORDER, height=1).pack(fill="x")

        tk.Label(topbar, text="PC CHECKER", font=("Segoe UI Semibold", 13),
                 fg=self.FG, bg=self.BG2).pack(side="left", padx=(24, 0))
        self._league_badge = tk.Label(topbar,
                                       text=f" {self._league} ",
                                       font=("Segoe UI", 9),
                                       fg=self.FG2, bg=self.BG3,
                                       padx=6, pady=2)
        self._league_badge.pack(side="left", padx=8, pady=17)

        self._status_lbl = tk.Label(topbar, text="IDLE", font=("Segoe UI", 9),
                                    fg=self.FG3, bg=self.BG2)
        self._status_lbl.pack(side="right", padx=24)
        self._wh_lbl = tk.Label(topbar, text="", font=("Segoe UI", 9),
                                 fg=self.FG2, bg=self.BG2)
        self._wh_lbl.pack(side="right", padx=(0, 16))

        # ── Body: sidebar + content
        body = tk.Frame(self.root, bg=self.BG)
        body.pack(fill="both", expand=True)

        # Sidebar
        sidebar = tk.Frame(body, bg=self.BG2, width=192)
        sidebar.pack(side="left", fill="y"); sidebar.pack_propagate(False)
        tk.Frame(body, bg=self.BORDER, width=1).pack(side="left", fill="y")

        tk.Label(sidebar, text="MODULES", font=("Segoe UI", 8),
                 fg=self.FG3, bg=self.BG2, anchor="w").pack(fill="x", padx=16, pady=(18, 6))

        self.tabs = {}
        self._tab_frames = {}
        self._nav_btns   = {}
        tab_defs = [
            ("SUMMARY",     "summary"),
            ("SHELLBAGS",   "shellbags"),
            ("BAM",         "bam"),
            ("PREFETCH",    "prefetch"),
            ("APPCOMPAT",   "appcompat"),
            ("ROBLOX LOGS", "roblox"),
            ("CHEAT FILES", "cheat"),
            ("YARA",        "yara"),
            ("UNSIGNED",    "unsigned"),
            ("RECYCLE BIN", "recycle"),
            ("SYSMAIN",     "sysmain"),
        ]

        content_wrap = tk.Frame(body, bg=self.BG)
        content_wrap.pack(side="left", fill="both", expand=True)

        for label, key in tab_defs:
            # Sidebar nav button
            btn = tk.Label(sidebar, text=f"  {label}", font=("Segoe UI", 10),
                           fg=self.FG2, bg=self.BG2, anchor="w",
                           pady=8, padx=8, cursor="hand2")
            btn.pack(fill="x")
            btn.bind("<Enter>",   lambda e, b=btn: b.config(bg=self.BG3) if b != self._active_nav else None)
            btn.bind("<Leave>",   lambda e, b=btn: b.config(bg=self.BG2) if b != self._active_nav else None)
            btn.bind("<Button-1>",lambda e, k=key, b=btn: self._switch(k, b))
            self._nav_btns[key] = btn

            # Content frame
            f   = tk.Frame(content_wrap, bg=self.BG)
            txt = scrolledtext.ScrolledText(
                f, bg=self.BG2, fg=self.FG,
                font=("Cascadia Code", 9) if self._font_exists("Cascadia Code") else ("Consolas", 9),
                relief="flat", insertbackground=self.WHITE,
                wrap="word", selectbackground=self.BG3,
                padx=20, pady=16,
                borderwidth=0, highlightthickness=0,
            )
            txt.pack(fill="both", expand=True)
            txt.configure(state="disabled")
            self._tab_frames[key] = f
            self.tabs[key]        = txt

        self._active_nav = self._nav_btns["summary"]
        self._setup_tags()

        # ── Bottom bar
        tk.Frame(self.root, bg=self.BORDER, height=1).pack(fill="x")
        bot = tk.Frame(self.root, bg=self.BG2, height=52)
        bot.pack(fill="x"); bot.pack_propagate(False)

        # Progress canvas
        self._pb = tk.Canvas(bot, width=220, height=3, bg=self.BG3,
                             highlightthickness=0)
        self._pb.pack(side="left", padx=24, pady=24)
        self._pb_bar  = self._pb.create_rectangle(0,0,0,3, fill=self.WHITE, outline="")
        self._pb_pos  = 0
        self._pb_run  = False

        btn_area = tk.Frame(bot, bg=self.BG2)
        btn_area.pack(side="right", padx=20)
        self._run_btn = tk.Button(btn_area, text="Run Scan",
                                   font=("Segoe UI Semibold", 10),
                                   bg=self.WHITE, fg=self.BG, relief="flat", bd=0,
                                   padx=20, pady=7, cursor="hand2",
                                   command=self._start,
                                   activebackground="#dddddd", activeforeground=self.BG)
        self._run_btn.pack(side="left", padx=(0, 8))
        tk.Button(btn_area, text="Save Report",
                  font=("Segoe UI", 10), bg=self.BG3, fg=self.FG2,
                  relief="flat", bd=0, padx=16, pady=7, cursor="hand2",
                  command=self._save,
                  activebackground=self.BG4, activeforeground=self.FG,
                  highlightthickness=1, highlightbackground=self.BORDER2).pack(side="left")

        # Show summary by default
        self._switch("summary", self._nav_btns["summary"])

    def _font_exists(self, name):
        import tkinter.font as tkfont
        return name in tkfont.families()

    def _switch(self, key, btn):
        for f in self._tab_frames.values(): f.pack_forget()
        for b in self._nav_btns.values():
            b.config(bg=self.BG2, fg=self.FG2,
                     font=("Segoe UI", 10))
        self._tab_frames[key].pack(fill="both", expand=True)
        btn.config(bg=self.BG3, fg=self.FG,
                   font=("Segoe UI Semibold", 10))
        self._active_nav = btn

    def _setup_tags(self):
        for txt in self.tabs.values():
            txt.configure(state="normal"); txt.delete("1.0","end")
            txt.configure(state="disabled")
            txt.tag_configure("ok",    foreground=self.GREEN)
            txt.tag_configure("bad",   foreground=self.RED)
            txt.tag_configure("warn",  foreground=self.AMBER)
            txt.tag_configure("info",  foreground=self.BLUE)
            txt.tag_configure("dim",   foreground=self.FG2)
            txt.tag_configure("white", foreground=self.FG)
            txt.tag_configure("hl",    foreground=self.WHITE,
                               font=(("Cascadia Code" if self._font_exists("Cascadia Code") else "Consolas"), 9, "bold"))
            txt.tag_configure("head",  foreground=self.FG,
                               font=(("Cascadia Code" if self._font_exists("Cascadia Code") else "Consolas"), 10, "bold"))

    # ── Progress
    def _pb_start(self):
        self._pb_run=True; self._pb_pos=0; self._pb_tick()

    def _pb_stop(self):
        self._pb_run=False
        self._pb.coords(self._pb_bar,0,0,220,3)

    def _pb_tick(self):
        if not self._pb_run: return
        self._pb_pos=(self._pb_pos+4)%260
        x1=max(0,self._pb_pos-100); x2=min(220,self._pb_pos)
        self._pb.coords(self._pb_bar,x1,0,x2,3)
        self.root.after(14,self._pb_tick)

    # ── Write
    def _w(self,key,text,tag="white"):
        t=self.tabs[key]
        t.configure(state="normal"); t.insert("end",text,tag); t.see("end")
        t.configure(state="disabled")

    def _render(self,key,text):
        if not text: self._w(key,"  No data.\n","dim"); return
        for line in text.split("\n"):
            ll=line.lower()
            if any(x in ll for x in ["⚠","warning","suspicious","tamper","multiple account","detected"]):
                tag="warn"
            elif any(x in ll for x in ["✓","normal","clean","no cheat","no suspicious"]):
                tag="ok"
            elif any(x in ll for x in ["cheater","ban evasion","flagged"]):
                tag="bad"
            elif "──" in line or "━" in line or "═" in line:
                tag="hl"
            elif line.startswith("  username") or line.startswith("  userid"):
                tag="info"
            elif line.startswith("  ") or line.startswith("\t"):
                tag="dim"
            else:
                tag="white"
            self._w(key,line+"\n",tag)

    def _render_summary(self,r):
        k="summary"
        v=r.get("verdict","UNKNOWN")
        vt={"CHEATER":"bad","SUSPICIOUS":"warn","CLEAN":"ok"}.get(v,"white")
        vi={"CHEATER":"✗","SUSPICIOUS":"!","CLEAN":"✓"}.get(v,"?")

        self._w(k,"\n","white")
        self._w(k,f"  ┌── VERDICT ────────────────────────────────────┐\n","hl")
        self._w(k,f"  │  {vi}  {v:<45}│\n",vt)
        self._w(k,f"  └───────────────────────────────────────────────┘\n\n","hl")
        self._w(k,f"  Generated  :  {now_str()}\n","dim")
        self._w(k,f"  PC User    :  {current_user()}\n","dim")
        self._w(k,f"  League     :  {r.get('league','?')}\n\n","dim")
        self._w(k,"  ── Detection Scores ──────────────────────────────\n","dim")

        # Auto-fail banner
        if r.get("sysmain_autofail"):
            self._w(k,"  ╔══ AUTO FAIL ══════════════════════════════════╗\n","bad")
            self._w(k,"  ║  SysMain DISABLED + Prefetch empty            ║\n","bad")
            self._w(k,"  ║  Deliberate trace wiping detected             ║\n","bad")
            self._w(k,"  ╚═══════════════════════════════════════════════╝\n\n","bad")

        rows=[
            ("ShellBag Hits",   r.get("shellbag_hits",0)),
            ("BAM Hits",        r.get("bam_hits",0)),
            ("Prefetch Hits",   r.get("prefetch_hits",0)),
            ("AppCompat Hits",  r.get("appcompat_hits",0)),
            ("Cheat File Hits", r.get("cheat_hits",0)),
            ("YARA Hits",       r.get("yara_hits",0)),
            ("Unsigned EXEs",   len(r.get("unsigned_hits",[]))),
            ("Log Tamper Hits", r.get("roblox_hits",0) if "roblox_hits" in r else 0),
            ("SysMain Hits",    r.get("sysmain_hits",0)),
        ]
        for label,val in rows:
            bar="█"*min(val,24)
            tag="bad" if val>0 else "ok"
            sym="△" if val>0 else "○"
            self._w(k,f"  {sym}  {label:<22}  {val:>3}  {bar}\n",tag)

        total=r.get("total_hits",0)
        self._w(k,f"\n  ─────────────────────────────────────────────────\n","dim")
        self._w(k,f"  TOTAL HITS  :  {total}\n\n",vt)
        self._w(k,"  ── Roblox Accounts ───────────────────────────────\n","dim")
        accs=r.get("roblox_accounts",[])
        if accs:
            for a in accs:
                self._w(k,f"  ›  {a}\n","warn" if len(accs)>1 else "info")
            if len(accs)>1:
                self._w(k,f"\n  ⚠  {len(accs)} accounts detected — review for ban evasion\n","bad")
        else:
            self._w(k,"  No accounts detected\n","dim")
        self._w(k,f"\n  Recycle Bin Modified: {r.get('recycle_bin_time','Unknown')}\n","dim")

    # ── Scan
    def _start(self):
        if self.scanning: return
        self.scanning=True; self._wh_sent=False
        self._setup_tags()
        self._run_btn.config(state="disabled",text="Scanning…",bg=self.BG3,fg=self.FG2)
        self._status_lbl.config(text="SCANNING",fg=self.AMBER)
        self._wh_lbl.config(text="")
        self._pb_start()
        threading.Thread(target=self._do_scan,daemon=True).start()

    def _do_scan(self):
        try:
            r=run_full_scan(league=self._league)
            self.results=r
            self.root.after(0,self._show,r)
        except Exception as e:
            self.root.after(0,self._err,str(e))

    def _show(self,r):
        self._pb_stop(); self.scanning=False
        v=r.get("verdict","UNKNOWN")
        vc={"CHEATER":self.RED,"SUSPICIOUS":self.AMBER,"CLEAN":self.GREEN}.get(v,self.FG2)
        self._status_lbl.config(text=v,fg=vc)
        self._run_btn.config(state="normal",text="Run Scan",bg=self.WHITE,fg=self.BG)
        self._render_summary(r)
        for key in ("shellbags","bam","prefetch","appcompat","roblox","cheat","yara","unsigned","recycle","sysmain"):
            self._render(key,r.get(key,""))
        self._switch("summary",self._nav_btns["summary"])
        threading.Thread(target=self._do_send,daemon=True).start()

    def _err(self,msg):
        self._pb_stop(); self.scanning=False
        self._status_lbl.config(text="ERROR",fg=self.RED)
        self._run_btn.config(state="normal",text="Run Scan",bg=self.WHITE,fg=self.BG)
        messagebox.showerror("Scan Error",msg)

    def _do_send(self):
        self.root.after(0,lambda: self._wh_lbl.config(text="sending…",fg=self.AMBER))
        wh_ok,wh_err = send_webhook(self.results)
        wb_ok,wb_err = send_website(self.results, self._pin)
        self._wh_sent = wh_ok or wb_ok
        if wh_ok and wb_ok:
            self.root.after(0,lambda: self._wh_lbl.config(text="✓ results sent",fg=self.GREEN))
        elif wh_ok:
            self.root.after(0,lambda: self._wh_lbl.config(text=f"✓ webhook  ✗ web: {wb_err[:50]}",fg=self.AMBER))
        elif wb_ok:
            self.root.after(0,lambda: self._wh_lbl.config(text=f"✓ web  ✗ webhook: {wh_err[:50]}",fg=self.AMBER))
        else:
            err_show = (wb_err or wh_err or "unknown")[:90]
            self.root.after(0,lambda e=err_show: self._wh_lbl.config(text=f"✗ {e}",fg=self.RED))

    def _save(self):
        if not self.results:
            messagebox.showwarning("No Results","Run a scan first."); return
        path=filedialog.asksaveasfilename(defaultextension=".txt",
            filetypes=[("Text Report","*.txt"),("All Files","*.*")],
            initialfile="pc_checker_report.txt")
        if not path: return
        try:
            with open(path,"w",encoding="utf-8") as f: f.write(self.results.get("full_report","No report."))
            messagebox.showinfo("Saved",f"Saved to:\n{path}")
        except Exception as e: messagebox.showerror("Error",str(e))


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
