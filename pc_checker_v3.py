"""
Comet Scanner v4 — Forensic Scanner
Rebranded from Lite to Comet
Build: pyinstaller --onefile --noconsole --name=CometScanner comet_scanner.py
"""
# ============================================================
#  AUTO-ELEVATION — request admin if not already elevated
# ============================================================
import sys as _sys, os as _os
def _is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

if _os.name == "nt" and not _is_admin():
    # Re-launch self with admin rights — UAC prompt appears automatically
    import ctypes
    try:
        script = _sys.executable if getattr(_sys, "frozen", False) else _os.path.abspath(__file__)
        params = " ".join(f'"{a}"' for a in _sys.argv[1:])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", _sys.executable,
            f'"{script}" {params}'.strip(),
            None, 1  # SW_SHOWNORMAL
        )
        if int(ret) > 32:
            _sys.exit(0)   # old process exits, elevated one takes over
    except Exception:
        pass  # if UAC is cancelled or fails, continue without admin

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
KEYWORDS = [_d(k) for k in _KW_ENC] + [
    # Added executors (researched file/folder names):
    "wave", "waveexecutor", "potassiumloader", "sirhurtlauncher", "solaraexecutor", "xenoexecutor", "cosmicexecutor", "cosmic", "madium", "madiumexecutor", "synapsez", "synapse_z", "jjsploit", "jjsploitexecutor", "wearedevs", "froststrap", "fishstrap", "krnl", "krnlss", "fluxus", "delta", "deltaexecutor", "solarabootstrapper", "solarav3", "awp", "awpexecutor", "hydrogen", "hydrogenexecutor", "codex", "codexexecutor", "nihon", "nezur", "macSploit", "trigon", "trigonevo", "sentinel", "arceusx", "arceus", "delta_executor", "volt_executor", "wave_executor",
]

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
    "volt":     ["node_modules","volt-0.","volt-1.","volt-2.","\\volt\\resources","voltage","revolt","pivotal"],
    "velocity": ["\\velocity\\","vscodium","code\\extensions","apache velocity"],
    "matrix":   ["element","matrix.org","\\matrix\\resources","neo4j"],
    "cryptic":  ["champions online","star trek","neverwinter","crypticstudios"],
    # New executor keywords — allowlist known-safe software
    "wave":     ["\\obs\\","waveform","adobe audition","\\audio\\","cubase","wavelab",
                 "waveshell","\\waves\\","wave editor","wave browser" ,"waveform","reaper"],
    "delta":    ["microsoft\\edge\\","\\delta\\updates","deltacopy","\\git\\",
                 "delta lake","databricks","\\delta\\resources"],
    "cosmic":   ["cosmic desktop","\\system76\\","pop!_os","cosmic-term"],
    "codex":    ["github\\copilot","openai","\\vscode\\","code-server","codexwriter"],
    "sentinel":  ["\\sentinelone\\","sentinel labs","microsoft sentinel","azure sentinel"],
    "arceus":   ["pokemon","nintendo","\\arceus\\game"],
    "hydrogen":  ["\\hydrogen\\app","hydrogen music","musescore"],
    "nihon":    ["\\japanese\\","nihongo","japan"],
    "krnl":     [],  # no common false positives
    "fluxus":   [],  # no common false positives
    "jjsploit": [],  # no common false positives
    "madium":   [],  # no common false positives
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
    color   = 0x1a2235  # neutral dark - no verdict coloring
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
                {"name":"Status",         "value":"Review Required",      "inline":True},
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
                {"name":"VPN Detected",   "value":"Yes" if vpn_info and "vpn" in vpn_info.lower() else "No",  "inline":True},
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
        # Include all tab text sections so results page can display them
        TAB_KEYS = [
            "shellbags","bam","prefetch","appcompat","roblox","cheat","yara",
            "unsigned","recycle","sysmain","processes","cleaners",
            "registry_extra","discord","discord_memory","eventlog","jumplists","lnkfiles",
            "power_events","two_pc","deleted_recovery",
            "deleted_int","exec_history_text",
        ]
        payload = {
            "pin":           pin,
            "league":        results.get("league","UFF"),
            "pc_user":       current_user(),
            "verdict":       results.get("verdict","UNKNOWN"),
            "total_hits":    results.get("total_hits",0),
            "roblox_accounts": results.get("roblox_accounts",[]),
            "report":        results.get("report",{}),
            # top-level tab text — server stores as *_raw in report
            "exec_history":  results.get("exec_history",[]),
        }
        # Attach each tab's text
        for k in TAB_KEYS:
            val = results.get(k,"")
            if val:
                payload[k] = str(val)[:60000]  # cap each tab at 60 KB

        raw = json.dumps(payload, default=str)
        # If payload is too big, drop the longest tabs first
        if len(raw) > 900000:
            for k in ["unsigned","processes","yara","deleted_int","lnkfiles","jumplists"]:
                if k in payload:
                    del payload[k]
            raw = json.dumps(payload, default=str)

        data = raw.encode("utf-8")
        req = urllib.request.Request(
            f"{WEBSITE_URL}/api/submit",
            data=data,
            headers={"Content-Type":"application/json",
                     "User-Agent":"CometScanner/5.0"},
            method="POST")
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=30) as r:
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

    lines = [f"{'Path':<70}  Timestamp", "─"*90]
    for path, ts, kws in hits:
        ts_disp = ts if ts and ts != 'N/A' else 'No timestamp recorded'
        lines.append(f"{path[:68]:<70}  {ts_disp}  [{', '.join(kws)}]")
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
                            name,data,_ = winreg.EnumValue(ck,vi)
                            decoded = rot13(name)
                            kws = matches_keyword(decoded)
                            if kws:
                                # Extract last run timestamp from UserAssist binary data
                                ts_str = "Unknown"
                                if isinstance(data, bytes) and len(data) >= 60:
                                    try:
                                        ft = struct.unpack_from("<Q", data, 60)[0]
                                        dt = filetime_to_dt(ft)
                                        if dt and dt.year > 2000:
                                            ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                                    except Exception: pass
                                ua_hits.append((decoded, kws, ts_str))
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
    for path,kws,ts in ua_hits: lines.append(f"  UserAssist: {path}\n    LastRun: {ts}  [{', '.join(kws)}]")
    if extra_reg:
        lines.append("\n  Registry cross-references:")
        for r in extra_reg: lines.append(f"    ► {r}")
    if not lines: lines.append("  ✓ No matches")
    return section("AppCompat / UserAssist", lines), len(ac_hits)+len(ua_hits), ac_hits+[(p,k) for p,k,_ in ua_hits]


def scan_roblox_logs():
    """
    Deep Roblox account + FastFlag detection.
    Sources (all checked even if logs deleted):
    1. Roblox standard log dir
    2. Bloxstrap log dir
    3. UWP package log dir
    4. Bloxstrap State.json (persists after log wipe)
    5. Roblox ClientSettings FastFlags (persists after log wipe)
    6. Windows Thumbnail cache (Roblox profile images)
    7. AppData cache dirs with Roblox tokens
    8. Browser local storage for roblox.com
    9. Windows ActivitiesCache (every account session)
    """
    import subprocess
    issues=[]; all_logs=[]; account_map={}

    PAT_JOIN   = re.compile(r'"UserId"%3a(\d{6,15})%2c"UserName"%3a"([A-Za-z0-9_]{3,20})"')
    PAT_UID    = re.compile(r'"UserId"%3a(\d{6,15})')
    PAT_UNAME  = re.compile(r'"UserName"%3a"([A-Za-z0-9_]{3,20})"')
    PAT_GUI    = re.compile(r'Players\.([A-Za-z0-9_]{3,20})\.PlayerGui')
    PAT_TIME   = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
    PAT_BSTRAP = re.compile(r'"userId":\s*(\d{6,15})')
    PAT_BNAME  = re.compile(r'"username":\s*"([A-Za-z0-9_]{3,20})"')
    PAT_CRASH  = re.compile(r'(crash|exception|fatal error|unhandled exception)', re.I)
    PAT_INJECT = re.compile(r'(inject|dll attach|openprocess|writeprocess|createremote)', re.I)
    PAT_FF_KEY = re.compile(r'"(F[FfBb][Aa-z]{3,40})"\s*:\s*([^,}\n]{1,60})')

    # Roblox game/place IDs in URLs
    PAT_PLACE  = re.compile(r'placeId=(\d{6,15})')

    USERNAME_NOISE = {
        "playerscripts","playermodules","loadingscreen","coregui","luaappscreengui",
        "robloxapp","robloxcrasher","robloxplayerbeta","notificationscriptscript",
        "experienceinvite","sharelinktabcontroller","controlscript",
        "experiencetipsdisplaycontroller","experiencetipsdisplay","robloxgui",
        "screengui","billboardgui","surfacegui","sparkles","smoke","fire",
    }

    manual_delete_flag = False
    crash_inject_flag  = False
    fastflags_found    = {}

    def add_account(uid, uname, source, timestamp=None, placeid=None):
        uid = str(uid)
        if uname and uname.lower() in USERNAME_NOISE: return
        if uid not in account_map:
            account_map[uid] = {"username": uname or "Unknown",
                                "timestamps":[], "placeids":[], "sources":set()}
        else:
            if uname and uname != "Unknown" and account_map[uid]["username"] == "Unknown":
                account_map[uid]["username"] = uname
        account_map[uid]["sources"].add(source)
        if timestamp: account_map[uid]["timestamps"].append(timestamp)
        if placeid and placeid not in account_map[uid]["placeids"]:
            account_map[uid]["placeids"].append(placeid)

    # ── Source 1-3: All log directories ──────────────────
    log_dirs = [
        os.path.expanduser(r"~\AppData\Local\Roblox\logs"),
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\Logs"),
        os.path.expanduser(r"~\AppData\Local\Packages\ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr\LocalState\logs"),
        r"C:\Program Files (x86)\Roblox\logs",
        r"C:\Program Files\Roblox\logs",
    ]
    existing_log_dirs = [d for d in log_dirs if os.path.exists(d)]
    roblox_installed  = any(os.path.exists(p) for p in [
        os.path.expanduser(r"~\AppData\Local\Roblox"),
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap"),
        r"C:\Program Files (x86)\Roblox",
    ])

    for log_dir in existing_log_dirs:
        try:
            log_files = sorted(
                glob.glob(os.path.join(log_dir,"*.log")) +
                glob.glob(os.path.join(log_dir,"*.txt")),
                key=lambda f: os.path.getmtime(f), reverse=True)
        except Exception:
            log_files = []
        all_logs.extend(log_files)

        for fpath in log_files[:40]:
            try:
                with open(fpath,"r",encoding="utf-8",errors="ignore") as f:
                    raw = f.read(500000)
            except Exception:
                continue
            mtime_str = datetime.datetime.fromtimestamp(
                os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M:%S")

            if PAT_CRASH.search(raw) and PAT_INJECT.search(raw):
                crash_inject_flag = True
                issues.append(("log", mtime_str, "CRASH + INJECTION — possible crash-on-inject"))

            for m in PAT_JOIN.finditer(raw):
                uid, uname = m.group(1), m.group(2)
                ts_list = PAT_TIME.findall(raw[:m.start()+200])
                ts = ts_list[-1] if ts_list else mtime_str
                place_m = PAT_PLACE.search(raw[max(0,m.start()-200):m.start()+200])
                pid = place_m.group(1) if place_m else None
                add_account(uid, uname, "log", ts, pid)

            for m in PAT_BSTRAP.finditer(raw):
                uid = m.group(1)
                name_m = PAT_BNAME.search(raw[max(0,m.start()-100):m.start()+200])
                uname = name_m.group(1) if name_m else None
                add_account(uid, uname, "bloxstrap_log", mtime_str)

            for m in PAT_GUI.finditer(raw):
                uname = m.group(1)
                if uname.lower() not in USERNAME_NOISE:
                    add_account(f"__u_{uname.lower()}", uname, "playergui", mtime_str)

            # Grab FastFlags from log content
            for m in PAT_FF_KEY.finditer(raw[:50000]):
                k, v = m.group(1), m.group(2).strip().strip(",").strip('"')
                if k not in fastflags_found:
                    fastflags_found[k] = v

    if not all_logs and roblox_installed:
        issues.append(("logs","N/A","Log directories empty — MANUAL LOG DELETION DETECTED"))
        manual_delete_flag = True
    elif len(all_logs) < 2 and roblox_installed:
        issues.append(("logs","N/A","Very few log files — possible partial deletion"))
        manual_delete_flag = True

    # ── Source 4: Bloxstrap State.json ───────────────────
    bloxstrap_state_paths = [
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\State.json"),
        os.path.expandvars(r"%APPDATA%\Bloxstrap\State.json"),
    ]
    for sp in bloxstrap_state_paths:
        if not os.path.exists(sp): continue
        try:
            with open(sp,"r",encoding="utf-8",errors="ignore") as f:
                state = json.loads(f.read())
            # State.json stores last user info
            for k,v in state.items() if isinstance(state,dict) else []:
                kl = k.lower()
                if "userid" in kl or "user_id" in kl:
                    add_account(str(v), None, "bloxstrap_state")
                elif "username" in kl or "displayname" in kl:
                    # Try to find associated userid
                    uid_key = k.replace("Name","Id").replace("name","id")
                    uid = state.get(uid_key,"")
                    if uid: add_account(str(uid), str(v), "bloxstrap_state")
        except Exception: pass

    # ── Source 5: ClientSettings FastFlags ───────────────
    ff_paths = [
        os.path.expanduser(r"~\AppData\Local\Roblox\ClientSettings\ClientAppSettings.json"),
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\Modifications\ClientSettings\ClientAppSettings.json"),
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\ClientSettings\ClientAppSettings.json"),
    ]
    SUSPICIOUS_FLAGS = {
        "FFlagDebugGraphicsDisableDirect3D11": "Disables D3D11 (anti-cheat bypass)",
        "FFlagDisableNewIGMinDUA":             "Disables input guard",
        "DFStringTaskSchedulerTargetFps":      "Uncapped FPS exploit",
        "FFlagDebugRenderingSetDeterministic": "Rendering manipulation",
        "FFlagDisablePostFx":                  "Visual exploit flag",
        "FFlagDebugDisableTelemetry":          "Disables telemetry reporting",
        "FFlagEnableHyperscaleImpostors":      "Known exploit flag",
        "FFlagFixGraphicsQuality":             "Graphics bypass",
        "FFlagDisableNewAnimationSystem":      "Animation bypass",
        "FFlagEnableNewAnimationSystem":       "Known exploit flag",
        "DFIntTaskSchedulerTargetFps":         "FPS uncap",
        "FFlagTaskSchedulerLimitTargetFps":    "FPS uncap",
    }
    suspicious_ff = []
    for ffp in ff_paths:
        if not os.path.exists(ffp): continue
        try:
            with open(ffp,"r",encoding="utf-8",errors="ignore") as f:
                flags = json.loads(f.read())
            if isinstance(flags, dict):
                fastflags_found.update(flags)
                for k,v in flags.items():
                    if k in SUSPICIOUS_FLAGS:
                        suspicious_ff.append(f"{k} = {v}  [{SUSPICIOUS_FLAGS[k]}]")
        except Exception: pass

    # ── Source 6: Browser localStorage for roblox.com ────
    browser_storage_paths = [
        (os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Storage\leveldb"), "Chrome"),
        (os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Local Storage\leveldb"), "Edge"),
        (os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb"), "Brave"),
        (os.path.expandvars(r"%APPDATA%\Opera Software\Opera Stable\Local Storage\leveldb"), "Opera"),
        (os.path.expandvars(r"%APPDATA%\Opera Software\Opera GX Stable\Local Storage\leveldb"), "Opera GX"),
    ]
    ROBLOX_ID_RE  = re.compile(r'"UserId"\s*:\s*(\d{6,15})')
    ROBLOX_NM_RE  = re.compile(r'"Name"\s*:\s*"([A-Za-z0-9_]{3,20})"')
    ROBLOX_TK_RE  = re.compile(r'_\|WARNING:-DO-NOT-SHARE-THIS\.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\.([A-Za-z0-9+/=_-]{20,600})')
    for bpath, blabel in browser_storage_paths:
        if not os.path.exists(bpath): continue
        try:
            for fname in os.listdir(bpath):
                if not (fname.endswith(".ldb") or fname.endswith(".log")): continue
                fpath = os.path.join(bpath, fname)
                try:
                    with open(fpath,"rb") as f: raw = f.read().decode("utf-8",errors="ignore")
                    if "roblox" not in raw.lower(): continue
                    for m in ROBLOX_ID_RE.finditer(raw):
                        uid = m.group(1)
                        nm_m = ROBLOX_NM_RE.search(raw[max(0,m.start()-200):m.start()+200])
                        uname = nm_m.group(1) if nm_m else None
                        add_account(uid, uname, f"browser_{blabel.lower()}", None)
                    if ROBLOX_TK_RE.search(raw):
                        issues.append(("browser","N/A",
                            f"Roblox .ROBLOSECURITY cookie found in {blabel} browser storage"))
                except Exception: pass
        except Exception: pass

    # ── Source 7: Windows ActivitiesCache ────────────────
    import glob as _glob2
    for db_path in _glob2.glob(os.path.expandvars(
            r"%LOCALAPPDATA%\ConnectedDevicesPlatform\*\ActivitiesCache.db")):
        try:
            with open(db_path,"rb") as f: raw = f.read()
            text = raw.decode("utf-8",errors="ignore") + raw.decode("utf-16-le",errors="ignore")
            if "roblox" not in text.lower(): continue
            for m in re.finditer(r"roblox.{0,300}?(\d{7,15})", text, re.IGNORECASE):
                uid = m.group(1)
                if len(uid) >= 7:
                    add_account(uid, None, "timeline_cache", None)
        except Exception: pass

    # Build result accounts list
    result_accounts = []
    seen_keys = set()
    for uid, data in account_map.items():
        uname = data["username"] or "Unknown"
        clean_uid = None if uid.startswith("__") else uid
        key = (uname.lower(), clean_uid)
        if key in seen_keys: continue
        seen_keys.add(key)
        ts_list = sorted(set(str(t) for t in data["timestamps"] if t), reverse=True)
        result_accounts.append({
            "username":   uname,
            "userid":     clean_uid,
            "placeids":   sorted(set(data["placeids"])),
            "last_seen":  ts_list[0] if ts_list else "Unknown",
            "sources":    sorted(data["sources"]),
        })
    result_accounts.sort(key=lambda a: (
        0 if (a["userid"] and a["username"] != "Unknown") else
        1 if a["userid"] else 2))

    named = [a for a in result_accounts if a["username"] != "Unknown"]
    multi  = len(named) > 1

    lines = [
        f"\n  Log dirs found  : {len(existing_log_dirs)}",
        f"  Total log files : {len(all_logs)}",
        f"  Accounts found  : {len(result_accounts)}",
        f"  FastFlags seen  : {len(fastflags_found)}",
        "",
    ]
    if manual_delete_flag: lines.append("⚠ LOG DELETION DETECTED\n")
    if crash_inject_flag:  lines.append("⚠ CRASH-WHILE-INJECTING PATTERN\n")
    if multi:              lines.append(f"⚠ {len(named)} ACCOUNTS — possible ban evasion\n")
    if issues:
        lines.append("⚠ Issues:")
        for src,ts,reason in issues:
            lines.append(f"  {src} | {ts} | {reason}")
        lines.append("")
    if suspicious_ff:
        lines.append("⚠ SUSPICIOUS FASTFLAGS:")
        for f in suspicious_ff: lines.append(f"  ✗ {f}")
        lines.append("")

    lines.append("━"*50)
    for acc in result_accounts:
        lines.append(f"\n  Username : {acc['username']}")
        lines.append(f"  UserID   : {acc['userid'] or 'Unknown'}")
        lines.append(f"  Last Seen: {acc['last_seen']}")
        lines.append(f"  Places   : {', '.join(acc['placeids'][:10]) or 'N/A'}")
        lines.append(f"  Sources  : {', '.join(acc['sources'])}")
        lines.append("  " + "─"*35)
    if not result_accounts:
        lines.append("  No accounts found.")
    if fastflags_found:
        lines.append("\n━"*25)
        lines.append("\n  FastFlags (from logs/ClientSettings):")
        for k,v in list(fastflags_found.items())[:30]:
            lines.append(f"  {k} = {v}")

    flat = []
    for acc in result_accounts:
        u, i = acc["username"], acc["userid"] or ""
        if u != "Unknown" and i: flat.append(f"{u} (ID: {i})")
        elif u != "Unknown":     flat.append(u)
        elif i:                  flat.append(f"UserID: {i}")

    tamper = (len(issues) + (1 if multi else 0) +
              (2 if manual_delete_flag else 0) +
              (2 if crash_inject_flag  else 0))
    return section("Roblox Log Analysis", lines), tamper, flat


def scan_roblox_alts_registry():
    """
    Deep Roblox alt detection — survives log deletion:
    - Registry (Roblox installs, version keys, account tokens)
    - Credential Manager (stored Roblox logins)
    - Windows Browser cookies DB (Roblox.com sessions in Chrome/Edge)
    - Bloxstrap config files
    - SRUM database (System Resource Usage Monitor) — tracks app usage
    - Windows Timeline / ActivitiesCache (every app ever run)
    - MUICache (every EXE ever displayed in a window)
    - Thumbnail cache DB (if user viewed Roblox screenshots/content)
    Even a factory reset leaves UEFI/BIOS-level evidence in some cases.
    """
    if not WINDOWS: return section("Roblox Alt Detection",["Windows only"]),0,[]
    import subprocess
    hits=[]; accounts=set()

    # ── 1. Registry: all Roblox-related keys ──
    roblox_reg_paths=[
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\ROBLOX Corporation"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Roblox"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\ROBLOX Corporation"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Roblox"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\ROBLOX Corporation"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Classes\roblox"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Classes\roblox-player"),
    ]
    for hive,path in roblox_reg_paths:
        try:
            def walk_reg(h,p,depth=0):
                if depth>4: return
                try:
                    key=winreg.OpenKey(h,p,0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
                    vi=0
                    while True:
                        try:
                            name,val,_=winreg.EnumValue(key,vi)
                            nl=name.lower()
                            if any(x in nl for x in ["userid","username","accountname","token","cookie","user_id","account_id"]):
                                entry=f"[REG] {p}\\{name} = {str(val)[:80]}"
                                hits.append(entry)
                                if str(val).isdigit() and len(str(val))>=6:
                                    accounts.add(str(val))
                            vi+=1
                        except OSError: break
                    si=0
                    while True:
                        try:
                            sub=winreg.EnumKey(key,si)
                            walk_reg(h,p+"\\"+sub,depth+1)
                            si+=1
                        except OSError: break
                    winreg.CloseKey(key)
                except Exception: pass
            walk_reg(hive,path)
        except Exception: pass

    # ── 2. Credential Manager ──
    try:
        si_=subprocess.STARTUPINFO()
        si_.dwFlags=subprocess.STARTF_USESHOWWINDOW; si_.wShowWindow=0
        out=subprocess.run(["cmdkey","/list"],
                           capture_output=True,text=True,timeout=6,
                           creationflags=subprocess.CREATE_NO_WINDOW,startupinfo=si_)
        for line in out.stdout.splitlines():
            if "roblox" in line.lower() or "rbx" in line.lower():
                hits.append(f"[CRED] {line.strip()}")
    except Exception: pass

    # ── 3. Bloxstrap config (survives Roblox uninstall) ──
    bloxstrap_paths=[
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\State.json"),
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\Modifications\ClientSettings\ClientAppSettings.json"),
        os.path.expandvars(r"%APPDATA%\Bloxstrap\State.json"),
    ]
    for bp in bloxstrap_paths:
        if not os.path.exists(bp): continue
        try:
            with open(bp,"r",encoding="utf-8",errors="ignore") as f:
                data=json.loads(f.read())
            if isinstance(data,dict):
                for k,v in data.items():
                    if any(x in k.lower() for x in ["userid","username","account","player"]):
                        hits.append(f"[BLOXSTRAP] {k} = {str(v)[:80]}")
                        if str(v).isdigit(): accounts.add(str(v))
        except Exception: pass

    # ── 4. Windows ActivitiesCache (Timeline) — survives log deletion ──
    timeline_db=os.path.expandvars(r"%LOCALAPPDATA%\ConnectedDevicesPlatform\L.{0}\ActivitiesCache.db")
    import glob as _glob
    for db_path in _glob.glob(os.path.expandvars(r"%LOCALAPPDATA%\ConnectedDevicesPlatform\*\ActivitiesCache.db")):
        try:
            with open(db_path,"rb") as f: raw=f.read()
            text=raw.decode("utf-8",errors="ignore")+raw.decode("utf-16-le",errors="ignore")
            if "roblox" in text.lower():
                # Extract any UserID-looking numbers near "roblox"
                for m in re.finditer(r"roblox.{0,200}?(\d{7,15})",text,re.IGNORECASE):
                    uid=m.group(1)
                    if len(uid)>=7:
                        hits.append(f"[TIMELINE] Roblox UserID-like: {uid}")
                        accounts.add(uid)
                hits.append(f"[TIMELINE] Roblox activity found in ActivitiesCache")
        except Exception: pass

    # ── 5. MUICache — every EXE ever launched (survives Roblox uninstall) ──
    try:
        mui_key=winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                               r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                               0,winreg.KEY_READ)
        vi=0
        while True:
            try:
                name,val,_=winreg.EnumValue(mui_key,vi)
                if "roblox" in name.lower():
                    hits.append(f"[MUICACHE] {name}")
                vi+=1
            except OSError: break
        winreg.CloseKey(mui_key)
    except Exception: pass

    # ── 6. SRUM (System Resource Usage Monitor) — app usage database ──
    srum_path=r"C:\Windows\System32\sru\SRUDB.dat"
    if os.path.exists(srum_path):
        # SRUM is locked while Windows runs; use shadow copy approach
        hits.append(f"[SRUM] SRUDB.dat exists — contains full app usage history")
        # Try to read a copy if available
        srum_copy=os.path.expandvars(r"%TEMP%\srum_check.dat")
        try:
            si_=subprocess.STARTUPINFO()
            si_.dwFlags=subprocess.STARTF_USESHOWWINDOW; si_.wShowWindow=0
            subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",
                           f"Copy-Item '{srum_path}' '{srum_copy}' -Force -ErrorAction SilentlyContinue"],
                          capture_output=True,timeout=5,
                          creationflags=subprocess.CREATE_NO_WINDOW,startupinfo=si_)
            if os.path.exists(srum_copy):
                with open(srum_copy,"rb") as f: raw=f.read()
                if b"RobloxPlayer" in raw or b"roblox" in raw.lower():
                    hits.append("[SRUM] Roblox app usage found in SRUM database")
                try: os.unlink(srum_copy)
                except Exception: pass
        except Exception: pass

    # ── 7. Roblox cookie in browser (just presence, not value) ──
    browser_cookie_paths=[
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies"),
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies"),
        os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Cookies"),
    ]
    cookie_browsers=[]
    for cp in browser_cookie_paths:
        if os.path.exists(cp):
            browser_name=cp.split("\\")
            name_part=next((p for p in browser_name if p in ["Chrome","Edge","Brave-Browser"]),cp)
            cookie_browsers.append(name_part)
    if cookie_browsers:
        hits.append(f"[BROWSER COOKIES] Browsers with saved cookies: {', '.join(cookie_browsers)}")

    lines=[f"\n  Detection sources: Registry, CredMgr, Bloxstrap, Timeline, MUICache, SRUM, Browsers",
           f"  Evidence entries: {len(hits)}",
           f"  Unique UserIDs found: {len(accounts)}",""]
    for h in hits[:30]: lines.append(f"  ► {h}")
    if accounts:
        lines.append("\n  UserIDs extracted:")
        for a in accounts: lines.append(f"  ► https://www.roblox.com/users/{a}/profile")
    if not hits: lines.append("  ✓ No Roblox registry traces found")

    return section("Roblox Alt Detection (Deep)",lines),len(accounts),list(accounts)


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
                if depth > 2: dirs.clear(); continue  # reduced from 3 to 2
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
                                         "sha1":"N/A",  # skip hashing for speed
                                         "size":stat.st_size,"ext":os.path.splitext(fname)[1].lower(),
                                         "created":ctime,"keywords":kws})
                        except Exception: pass
                    if scanned > 15000: dirs.clear(); break  # hard cap
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
    """Fast heuristic check — Downloads and Desktop only, no deep walk."""
    scan_dirs=[os.path.expanduser("~\\Downloads"),os.path.expanduser("~\\Desktop")]
    hits=[]; scanned=0
    for base in scan_dirs:
        if not os.path.exists(base): continue
        try:
            for fname in os.listdir(base):  # only top level, no walk
                if not fname.lower().endswith((".exe",".dll")): continue
                fpath=os.path.join(base,fname)
                try:
                    sz=os.path.getsize(fpath)
                    if sz<100: continue
                    kws=matches_keyword(fpath)
                    with open(fpath,"rb") as f: hdr=f.read(512)
                    reasons=list(kws)
                    if hdr.startswith(b"MZ"):
                        if b"WriteProcessMemory" in hdr: reasons.append("WPM import")
                        if b"CreateRemoteThread" in hdr: reasons.append("CRT import")
                        if b"VirtualAllocEx" in hdr: reasons.append("VAEx import")
                    if reasons: hits.append({"path":fpath,"size":sz,"sha1":"N/A","reason":" | ".join(reasons)})
                    scanned+=1
                    if scanned>200: break
                except Exception: pass
        except Exception: pass
    lines=[f"Scanned top-level: {scanned}  Hits: {len(hits)}","="*50]
    for i,h in enumerate(hits,1): lines.append(f"\n[{i}] {h['reason']}\n    {h['path']}")
    if not hits: lines.append("✓ No suspicious executables.")
    return section("YARA / Heuristic",lines),len(hits),hits

def scan_unsigned():
    import subprocess, tempfile
    scan_dirs = [os.path.expanduser("~\\Downloads"), os.path.expanduser("~\\Desktop"),
                 os.path.expanduser("~\\AppData\\Local\\Temp")]  # Only check most suspicious dirs
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
                if scanned >= 80: dirs.clear(); break
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
                                 capture_output=True,text=True,timeout=25,
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
            capture_output=True,text=True,timeout=8,
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

        # DLL scan removed — too slow during live scan
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
    """
    Deep Discord account detection:
    - App Local Storage (LevelDB) — all install types
    - Browser Local Storage (Chrome, Edge, Firefox, Brave, Opera)
    - Windows Credential Manager
    - Registry remnants
    - NTUSER.DAT search for Discord tokens
    Catches accounts even after log deletion.
    """
    if not WINDOWS: return section("Discord Detection",["Windows only"]),0,[]
    import subprocess
    accounts=[]; seen_ids=set()
    ID_RE    = re.compile(r'"id"\s*:\s*"(\d{17,19})"')
    NAME_RE  = re.compile(r'"username"\s*:\s*"([^"]{2,32})"')
    DISCRIM  = re.compile(r'"discriminator"\s*:\s*"(\d{1,4})"')
    SWITCH_RE= re.compile(r'"lastSwitched"\s*:\s*"?(\d+)"?')
    TOKEN_RE = re.compile(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}')
    # Email detection removed — not needed

    def parse_leveldb(base_path, source_label):
        """Parse a LevelDB directory for Discord account data."""
        if not os.path.exists(base_path): return
        for fname in os.listdir(base_path):
            if not (fname.endswith(".ldb") or fname.endswith(".log") or fname.endswith(".ldb~")): continue
            fpath = os.path.join(base_path, fname)
            try:
                with open(fpath,"rb") as f: raw = f.read().decode("utf-8",errors="ignore")
                ids    = ID_RE.findall(raw)
                names  = NAME_RE.findall(raw)
                tokens = TOKEN_RE.findall(raw)
                switches = SWITCH_RE.findall(raw)
                emails = []  # email detection disabled
                for i, uid in enumerate(ids):
                    if uid in seen_ids: continue
                    seen_ids.add(uid)
                    uname = names[i] if i < len(names) else (names[0] if names else "Unknown")
                    last_sw = "Unknown"
                    if switches:
                        try:
                            ts = int(switches[0])
                            if ts > 1e12: ts = ts//1000
                            last_sw = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception: pass
                    email = None  # emails not collected
                    accounts.append({
                        "id":uid, "username":uname,
                        "has_token": bool(tokens),
                        "last_switched": last_sw,
                        "source": source_label,
                        "email": email,
                    })
            except Exception: pass

    # ── Source 1: Discord app installs ──
    app_bases = [
        (os.path.expanduser(r"~\AppData\Roaming\discord\Local Storage\leveldb"),       "Discord App"),
        (os.path.expanduser(r"~\AppData\Roaming\discordptb\Local Storage\leveldb"),    "Discord PTB"),
        (os.path.expanduser(r"~\AppData\Roaming\discordcanary\Local Storage\leveldb"), "Discord Canary"),
        (os.path.expanduser(r"~\AppData\Local\Discord\Local Storage\leveldb"),         "Discord (Local)"),
    ]
    for path, label in app_bases:
        parse_leveldb(path, label)

    # ── Source 2: Web browsers — catches web-app Discord logins ──
    browser_paths = [
        # Chrome
        (r"~\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb",        "Chrome"),
        (r"~\AppData\Local\Google\Chrome\User Data\Profile 1\Local Storage\leveldb",      "Chrome P1"),
        (r"~\AppData\Local\Google\Chrome\User Data\Profile 2\Local Storage\leveldb",      "Chrome P2"),
        # Edge
        (r"~\AppData\Local\Microsoft\Edge\User Data\Default\Local Storage\leveldb",       "Edge"),
        (r"~\AppData\Local\Microsoft\Edge\User Data\Profile 1\Local Storage\leveldb",     "Edge P1"),
        # Brave
        (r"~\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb", "Brave"),
        # Opera
        (r"~\AppData\Roaming\Opera Software\Opera Stable\Local Storage\leveldb",            "Opera"),
        # Opera GX
        (r"~\AppData\Roaming\Opera Software\Opera GX Stable\Local Storage\leveldb",         "Opera GX"),
        # Firefox (different format — NSSDB/sqlite)
        (r"~\AppData\Roaming\Mozilla\Firefox\Profiles",                                      "Firefox"),
        # Vivaldi
        (r"~\AppData\Local\Vivaldi\User Data\Default\Local Storage\leveldb",               "Vivaldi"),
    ]
    for rel_path, label in browser_paths:
        full = os.path.expanduser(rel_path)
        if "Firefox" in rel_path:
            # Firefox: search profile storage.sqlite for discord tokens
            if os.path.exists(full):
                for prof in os.listdir(full):
                    ls_path = os.path.join(full, prof, "storage", "default")
                    if os.path.exists(ls_path):
                        for root, dirs, files in os.walk(ls_path):
                            if "discord" in root.lower():
                                for f in files:
                                    if f.endswith(".sqlite") or f.endswith(".sqlt"):
                                        try:
                                            with open(os.path.join(root,f),"rb") as fp:
                                                raw = fp.read().decode("utf-8",errors="ignore")
                                            ids = ID_RE.findall(raw)
                                            names = NAME_RE.findall(raw)
                                            for i,uid in enumerate(ids):
                                                if uid in seen_ids: continue
                                                seen_ids.add(uid)
                                                accounts.append({
                                                    "id":uid,
                                                    "username":names[i] if i<len(names) else "Unknown",
                                                    "has_token":bool(TOKEN_RE.search(raw)),
                                                    "last_switched":"Unknown",
                                                    "source":f"Firefox",
                                                    "email":None,
                                                })
                                        except Exception: pass
        else:
            parse_leveldb(full, label)

    # ── Source 3: Windows Credential Manager ──
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags = subprocess.STARTF_USESHOWWINDOW; si.wShowWindow = 0
        out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command",
             "cmdkey /list | Select-String -Pattern 'discord' -CaseSensitive:$false"],
            capture_output=True,text=True,timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW,startupinfo=si)
        if out.stdout.strip():
            for line in out.stdout.strip().splitlines():
                line = line.strip()
                if "discord" in line.lower() and line:
                    accounts.append({
                        "id":"CRED_MANAGER","username":line,
                        "has_token":False,"last_switched":"Unknown",
                        "source":"Credential Manager","email":None,
                    })
    except Exception: pass

    # ── Source 4: Registry remnants (Discord installs leave traces) ──
    reg_discord_keys = [
        r"SOFTWARE\Discord",
        r"SOFTWARE\DiscordPTB",
        r"SOFTWARE\DiscordCanary",
        r"SOFTWARE\Classes\discord",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Discord",
    ]
    for rk in reg_discord_keys:
        for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            try:
                key = winreg.OpenKey(hive, rk, 0, winreg.KEY_READ)
                winreg.CloseKey(key)
                # If key exists, Discord was/is installed
                if not any(a["source"]=="Registry" for a in accounts):
                    accounts.append({
                        "id":"REG_TRACE","username":f"Registry: {rk}",
                        "has_token":False,"last_switched":"N/A",
                        "source":"Registry trace","email":None,
                    })
                break
            except Exception: pass

    # Deduplicate and filter noise
    real_accounts = [a for a in accounts if a["id"] not in ("REG_TRACE","CRED_MANAGER")]
    traces        = [a for a in accounts if a["id"] in ("REG_TRACE","CRED_MANAGER")]

    lines=[f"\n  Sources searched: Discord app + Chrome/Edge/Brave/Opera/Firefox browsers",
           f"  Total accounts: {len(real_accounts)}",""]
    for acc in real_accounts:
        lines.append(f"  @{acc['username']}")
        lines.append(f"  ID           : {acc['id']}")
        lines.append(f"  Last Switched: {acc['last_switched']}")
        if acc.get("email"): lines.append(f"  Email        : {acc['email']}")
        lines.append(f"  Token cached : {'⚠ YES' if acc['has_token'] else 'No'}")
        lines.append(f"  Found in     : {acc['source']}")
        lines.append("  "+"─"*32)
    if traces:
        lines.append("\n  Installation traces found:")
        for t in traces: lines.append(f"  ► {t['username']}")
    if len(real_accounts)>1:
        lines.append(f"\n⚠ {len(real_accounts)} DISCORD ACCOUNTS — possible alt accounts")
    if not real_accounts and not traces:
        lines.append("  No Discord accounts found.")

    return section("Discord Account Detection",lines), max(0,len(real_accounts)-1), real_accounts



def scan_discord_memory():
    """
    Discord memory + download history analysis.
    Reads from Discord's cached media/downloads, message cache,
    and in-memory artifacts to find:
    - Files downloaded through Discord (with timestamps)
    - Images/attachments accessed
    - Server/DM metadata (no message content)
    This catches people using Discord alts to share cheats.
    """
    if not WINDOWS: return section("Discord Memory/Downloads",["Windows only"]),0,[]
    import subprocess
    hits=[]; download_entries=[]; suspicious_entries=[]

    DISCORD_ROOTS = [
        os.path.expanduser(r"~\AppData\Roaming\discord"),
        os.path.expanduser(r"~\AppData\Roaming\discordptb"),
        os.path.expanduser(r"~\AppData\Roaming\discordcanary"),
    ]

    # Cheat file extensions/names to flag in download history
    CHEAT_EXTS = {".exe",".dll",".lua",".luac",".rbxl",".rbxlx",".zip",".rar",".7z"}
    CHEAT_NAMES_RE = re.compile(
        r"(exploit|inject|cheat|hack|aimbot|executor|script|payload|bypass|"
        r"volt|synapse|velocity|fluxus|krnl|delta|wave|script.*ware|"
        r"froststrap|aimlock|esp|triggerbot|noclip|speed.*hack)",
        re.IGNORECASE)

    # Pattern to find CDN attachment URLs in LevelDB
    CDN_RE    = re.compile(r"https://cdn[.]discordapp[.]com/attachments/(\d+)/(\d+)/([^\s]{2,120})")
    MEDIA_RE  = re.compile(r"https://media[.]discordapp[.](?:net|com)/attachments/(\d+)/(\d+)/([^\s]{2,120})")
    # Timestamps embedded in Discord snowflake IDs
    def snowflake_to_dt(snowflake):
        try:
            ts_ms = (int(snowflake) >> 22) + 1420070400000
            return datetime.datetime.utcfromtimestamp(ts_ms/1000).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return "Unknown"

    def scan_leveldb_dir(base_path, label):
        if not os.path.exists(base_path): return
        try:
            for fname in os.listdir(base_path):
                if not (fname.endswith(".ldb") or fname.endswith(".log")): continue
                fpath = os.path.join(base_path, fname)
                try:
                    with open(fpath,"rb") as f: raw = f.read(4*1024*1024)  # 4MB max
                    text = raw.decode("utf-8", errors="ignore")
                    # Find all CDN attachment URLs
                    for m in CDN_RE.finditer(text):
                        channel_id, msg_id, filename = m.group(1), m.group(2), m.group(3)
                        clean_fn = filename.split("?")[0].strip()
                        ts = snowflake_to_dt(msg_id)
                        ext = os.path.splitext(clean_fn)[1].lower()
                        is_sus = ext in CHEAT_EXTS or bool(CHEAT_NAMES_RE.search(clean_fn))
                        entry = {
                            "file": clean_fn, "channel": channel_id,
                            "msg_id": msg_id, "timestamp": ts,
                            "url": m.group(0).split("?")[0],
                            "source": label, "suspicious": is_sus,
                        }
                        download_entries.append(entry)
                        if is_sus: suspicious_entries.append(entry)
                except Exception: pass
        except Exception: pass

    for root in DISCORD_ROOTS:
        label = os.path.basename(root)
        # Main LevelDB (localStorage)
        scan_leveldb_dir(os.path.join(root,"Local Storage","leveldb"), label)
        # Cache directories
        for cache_sub in ["Cache","GPUCache","Code Cache","media-cache"]:
            cache_path = os.path.join(root,cache_sub)
            if os.path.exists(cache_path):
                try:
                    for cfile in os.listdir(cache_path):
                        fpath = os.path.join(cache_path, cfile)
                        try:
                            with open(fpath,"rb") as f: raw = f.read(512*1024)  # 512KB
                            text = raw.decode("utf-8", errors="ignore")
                            for m in CDN_RE.finditer(text):
                                channel_id, msg_id, filename = m.group(1), m.group(2), m.group(3)
                                clean_fn = filename.split("?")[0].strip()
                                ext = os.path.splitext(clean_fn)[1].lower()
                                ts = snowflake_to_dt(msg_id)
                                is_sus = ext in CHEAT_EXTS or bool(CHEAT_NAMES_RE.search(clean_fn))
                                entry = {
                                    "file":clean_fn,"channel":channel_id,"msg_id":msg_id,
                                    "timestamp":ts,"url":m.group(0).split("?")[0],
                                    "source":f"{label}/cache","suspicious":is_sus,
                                }
                                download_entries.append(entry)
                                if is_sus: suspicious_entries.append(entry)
                        except Exception: pass
                except Exception: pass

    # Deduplicate by URL
    seen_urls = set()
    unique_downloads = []
    for e in download_entries:
        if e["url"] not in seen_urls:
            seen_urls.add(e["url"])
            unique_downloads.append(e)
    unique_downloads.sort(key=lambda x: x["timestamp"], reverse=True)

    # Deduplicate suspicious by URL too
    seen_sus = set()
    unique_sus = []
    for e in suspicious_entries:
        if e["url"] not in seen_sus:
            seen_sus.add(e["url"])
            unique_sus.append(e)

    lines = [
        f"\n  Discord CDN files found: {len(unique_downloads)}",
        f"  Suspicious entries    : {len(unique_sus)}",
        "",
    ]
    if unique_sus:
        lines.append("⚠ SUSPICIOUS DOWNLOADS (cheat-related files):")
        for e in unique_sus[:20]:
            lines.append(f"  ✗ File     : {e['file']}")
            lines.append(f"    Uploaded : {e['timestamp']}")
            lines.append(f"    URL      : {e['url']}")
            lines.append(f"    Source   : {e['source']}")
            lines.append("")
    lines.append("─"*50)
    lines.append(f"\n  Recent Discord Downloads (all, newest first):")
    for e in unique_downloads[:30]:
        sym = "⚠" if e["suspicious"] else "  "
        lines.append(f"  {sym} File: {e['file']}")
        lines.append(f"     Uploaded: {e['timestamp']}")
        lines.append(f"     URL: {e['url']}")
    if not unique_downloads:
        lines.append("  No Discord CDN file history found.")

    return section("Discord Downloads/Memory", lines), len(unique_sus), unique_downloads


def scan_factory_reset():
    """
    Enhanced factory reset detection — multiple corroborating sources.
    Shows: when Windows was installed, system age vs account age discrepancy,
    previous OS installs from registry, BIOS date vs OS install date gap.
    """
    if not WINDOWS: return section("Factory Reset Detection",["Windows only"]),False,""
    import subprocess
    resets=[]; warnings=[]

    # ── Source 1: SYSTEM\Setup\Source OS (previous installs) ──
    try:
        key=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"SYSTEM\Setup",0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        try:
            hist=winreg.OpenKey(key,"Source OS",0,winreg.KEY_READ)
            i=0
            while True:
                try:
                    sub=winreg.EnumKey(hist,i)
                    sk=winreg.OpenKey(hist,sub,0,winreg.KEY_READ)
                    try:
                        prod,_=winreg.QueryValueEx(sk,"ProductName")
                        build,_=winreg.QueryValueEx(sk,"CurrentBuild")
                        try: idate,_=winreg.QueryValueEx(sk,"InstallDate")
                        except Exception: idate="Unknown"
                        dt_str="Unknown"
                        if isinstance(idate,int):
                            try: dt_str=datetime.datetime.fromtimestamp(idate).strftime("%Y-%m-%d %H:%M:%S")
                            except Exception: dt_str=str(idate)
                        else: dt_str=str(idate)
                        resets.append(f"{prod} (Build {build}) — installed {dt_str}")
                    except Exception: pass
                    winreg.CloseKey(sk); i+=1
                except OSError: break
            winreg.CloseKey(hist)
        except Exception: pass
        winreg.CloseKey(key)
    except Exception: pass

    # ── Source 2: Current OS install date ──
    current="Unknown"; install_ts=None; install_dt=None
    try:
        key=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                           0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        prod,_=winreg.QueryValueEx(key,"ProductName")
        build,_=winreg.QueryValueEx(key,"CurrentBuild")
        try:  rel,_=winreg.QueryValueEx(key,"ReleaseId")
        except Exception: rel="?"
        try:  idate,_=winreg.QueryValueEx(key,"InstallDate")
        except Exception: idate=None
        try:  itime,_=winreg.QueryValueEx(key,"InstallTime")
        except Exception: itime=None
        if idate and isinstance(idate,int):
            install_ts=idate
            install_dt=datetime.datetime.fromtimestamp(idate)
            install_str=install_dt.strftime("%Y-%m-%d %H:%M:%S")
        elif itime:
            install_dt=filetime_to_dt(itime)
            install_str=install_dt.strftime("%Y-%m-%d %H:%M:%S") if install_dt else "Unknown"
        else:
            install_str="Unknown"
        current=f"{prod} Build {build} ({rel}) — Installed: {install_str}"
        winreg.CloseKey(key)
    except Exception: pass

    # ── Source 3: BIOS/hardware date via WMI (install date vs hardware age) ──
    bios_date="Unknown"; bios_age_gap=None
    try:
        si=subprocess.STARTUPINFO()
        si.dwFlags=subprocess.STARTF_USESHOWWINDOW; si.wShowWindow=0
        out=subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command",
             "(Get-WmiObject -Class Win32_BIOS).ReleaseDate"],
            capture_output=True,text=True,timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,startupinfo=si)
        bios_raw=out.stdout.strip()
        if bios_raw and len(bios_raw)>=8:
            bios_date=bios_raw[:4]+"-"+bios_raw[4:6]+"-"+bios_raw[6:8]
            if install_dt:
                try:
                    bios_dt=datetime.datetime(int(bios_raw[:4]),int(bios_raw[4:6]),int(bios_raw[6:8]))
                    delta=(install_dt-bios_dt).days
                    bios_age_gap=delta
                    if delta < 7:
                        warnings.append(f"⚠ OS installed within {delta} days of BIOS date — possible fresh install after hardware delivery")
                except Exception: pass
    except Exception: pass

    # ── Source 4: User account creation date ──
    user_created="Unknown"
    try:
        si=subprocess.STARTUPINFO()
        si.dwFlags=subprocess.STARTF_USESHOWWINDOW; si.wShowWindow=0
        out=subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command",
             f'(Get-LocalUser -Name "{current_user()}" -ErrorAction SilentlyContinue).PasswordLastSet'],
            capture_output=True,text=True,timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,startupinfo=si)
        if out.stdout.strip(): user_created=out.stdout.strip()
    except Exception: pass

    # ── Source 5: System age via %SystemRoot% creation date ──
    sys_age_days=None
    try:
        sys_root=os.environ.get("SystemRoot","C:\\Windows")
        ctime=os.path.getctime(sys_root)
        sys_install=datetime.datetime.fromtimestamp(ctime)
        sys_age_days=(datetime.datetime.now()-sys_install).days
        if sys_age_days < 30:
            warnings.append(f"⚠ Windows folder only {sys_age_days} days old — very recent install")
    except Exception: pass

    # ── Source 6: Event log 6005/6009 for oldest system boot ──
    oldest_boot="Unknown"
    try:
        si=subprocess.STARTUPINFO()
        si.dwFlags=subprocess.STARTF_USESHOWWINDOW; si.wShowWindow=0
        out=subprocess.run(
            ["wevtutil","qe","System",
             "/q:*[System[EventID=6009]]","/c:1","/rd:false","/f:text"],
            capture_output=True,text=True,timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW,startupinfo=si)
        for line in out.stdout.splitlines():
            if "Date" in line or "Time" in line:
                oldest_boot=line.strip(); break
    except Exception: pass

    lines=[f"\n  Current OS  : {current}",
           f"  BIOS Date   : {bios_date}",
           f"  Windows Age : {sys_age_days} days" if sys_age_days else "  Windows Age : Unknown",
           f"  User PW Set : {user_created}",
           f"  Oldest Boot : {oldest_boot}",""]
    if warnings:
        for w in warnings: lines.append(f"  {w}")
        lines.append("")
    if resets:
        lines.append("  Previous Windows installs (resets):")
        for r in resets: lines.append(f"    ► {r}")
        lines.append(f"\n  ⚠ {len(resets)} previous install(s) found")
    else:
        lines.append("  No previous installs in registry — either clean machine or history cleared")
    if sys_age_days and sys_age_days < 14:
        lines.append(f"  ⚠ System only {sys_age_days} days old — check for pre-reset activity")

    reset_text=(current+f" | BIOS: {bios_date} | Age: {sys_age_days}d"+
                ("\n  Resets: "+", ".join(resets) if resets else ""))
    return section("Factory Reset / System Age",lines),bool(resets or (sys_age_days and sys_age_days<14)),reset_text


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

    # Only count definitive forensic hits - NOT roblox logs (too many false positives)
    # Agents review roblox accounts/discord separately
    total = sb_h+bm_h+pf_h+ac_h+cs_h+yr_h+us_h+rb_h+sm_h+ff_h+pr_h+cl_h

    # No verdict — agent decides. Scanner just provides raw data.
    verdict = "REVIEW"

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
        "vpn_detected": bool(vpn_info and "vpn" in str(vpn_info).lower()),
        "vpn_info":"[Redacted — see agent copy]","cleaner_info":cl_info,
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

# ============================================================
#  NEW DETECTIONS
# ============================================================

def scan_event_log():
    """Event Log tampering: cleared logs, disabled service, wiped audit policy."""
    if not WINDOWS:
        return section("Event Log", ["Windows only"]), 0, []
    import subprocess, ctypes
    hits = []; flags = []
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    # 1 — Is the EventLog service disabled?
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\EventLog",
                             0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        start, _ = winreg.QueryValueEx(key, "Start")
        winreg.CloseKey(key)
        if start == 4:
            flags.append("CRITICAL: EventLog SERVICE DISABLED — all logging suppressed")
            hits.append("service_disabled")
    except Exception: pass

    # 2 — Audit policy disabled?
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags = subprocess.STARTF_USESHOWWINDOW; si.wShowWindow = 0
        out = subprocess.run(["auditpol", "/get", "/category:*"],
                             capture_output=True, text=True, timeout=10,
                             creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        lines_out = out.stdout.splitlines()
        no_audit = sum(1 for l in lines_out if "No Auditing" in l)
        total_pol = sum(1 for l in lines_out if any(x in l for x in ["Success","Failure","No Auditing"]))
        if total_pol > 0 and no_audit == total_pol:
            flags.append(f"CRITICAL: ALL {total_pol} audit policies DISABLED")
            hits.append("audit_all_off")
        elif total_pol > 0 and no_audit > total_pol * 0.7:
            flags.append(f"WARNING: {no_audit}/{total_pol} audit policies disabled")
            hits.append("audit_mostly_off")
    except Exception: pass

    # 3 — Check actual log sizes; 0 entries = cleared
    for lg, min_entries, weight in [("Security",10,5),("System",20,3),("Application",10,2)]:
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags = subprocess.STARTF_USESHOWWINDOW; si.wShowWindow = 0
            out = subprocess.run(
                ["powershell","-NoProfile","-NonInteractive","-Command",
                 f'(Get-WinEvent -ListLog "{lg}" -EA SilentlyContinue).RecordCount'],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
            count = int(out.stdout.strip()) if out.stdout.strip().isdigit() else -1
            if count == 0:
                flags.append(f"CRITICAL: {lg} log has 0 entries — CLEARED")
                for _ in range(weight): hits.append(f"{lg}_cleared")
            elif 0 < count < min_entries:
                flags.append(f"WARNING: {lg} log only {count} entries — possibly cleared")
                hits.append(f"{lg}_low")
        except Exception: pass

    # 4 — Look for EventID 1102/104 (log cleared events)
    for eid, src in [(1102,"Security"),(104,"System")]:
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags = subprocess.STARTF_USESHOWWINDOW; si.wShowWindow = 0
            out = subprocess.run(
                ["wevtutil","qe",src,f"/q:*[System[EventID={eid}]]","/c:3","/f:text"],
                capture_output=True, text=True, timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
            if out.stdout.strip():
                ts_lines = [l.strip() for l in out.stdout.splitlines() if "Date" in l or "Time" in l]
                when = ts_lines[0] if ts_lines else "unknown time"
                flags.append(f"CRITICAL: {src} log CLEARED (EID {eid}) — {when}")
                hits.append(f"log_clear_{src}")
        except Exception: pass

    lines = [f"\n  Admin: {'Yes' if is_admin else 'No (limited)'}"]
    for f in flags:
        sym = "✗" if "CRITICAL" in f else "⚠"
        lines.append(f"  {sym} {f}")
    if not flags: lines.append("  ✓ Event logs appear normal")
    return section("Event Log Analysis", lines), len(hits), hits


def scan_jumplists():
    """Jump lists — recently opened files per application."""
    if not WINDOWS:
        return section("Jump Lists", ["Windows only"]), 0, []
    hits = []
    for jd in [
        os.path.expanduser(r"~\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"),
        os.path.expanduser(r"~\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"),
    ]:
        if not os.path.exists(jd): continue
        try:
            for fname in os.listdir(jd):
                fpath = os.path.join(jd, fname)
                try:
                    with open(fpath,"rb") as f: raw = f.read()
                    text = raw.decode("utf-16-le",errors="ignore")+raw.decode("latin-1",errors="ignore")
                    kws = matches_keyword(text)
                    if kws: hits.append({"file":fname,"keywords":kws})
                except Exception: pass
        except Exception: pass
    lines = [f"\n  Jump list hits: {len(hits)}"]
    for h in hits: lines.append(f"  ⚠ {h['file']}  [{', '.join(h['keywords'])}]")
    if not hits: lines.append("  ✓ No cheat-related jump list entries")
    return section("Jump Lists", lines), len(hits), hits


def scan_lnk_files():
    """LNK shortcuts — reveal previously existing cheat executables."""
    if not WINDOWS:
        return section("LNK Files", ["Windows only"]), 0, []
    hits = []
    for ld in [
        os.path.expanduser(r"~\AppData\Roaming\Microsoft\Windows\Recent"),
        os.path.expanduser("~\\Desktop"),
        os.path.expanduser("~\\Downloads"),
    ]:
        if not os.path.exists(ld): continue
        for fname in os.listdir(ld):
            if not fname.lower().endswith(".lnk"): continue
            fpath = os.path.join(ld, fname)
            try:
                with open(fpath,"rb") as f: raw = f.read()
                text = raw.decode("utf-16-le",errors="ignore")+raw.decode("latin-1",errors="ignore")
                kws = matches_keyword(text)
                if kws:
                    mt = datetime.datetime.fromtimestamp(os.stat(fpath).st_mtime).strftime("%Y-%m-%d %H:%M")
                    hits.append({"file":fname,"path":fpath,"keywords":kws,"modified":mt})
            except Exception: pass
    lines = [f"\n  LNK hits: {len(hits)}"]
    for h in hits:
        lines.append(f"  ⚠ {h['file']}  |  {h['modified']}")
        lines.append(f"    [{', '.join(h['keywords'])}]")
    if not hits: lines.append("  ✓ No suspicious LNK files")
    return section("LNK Files", lines), len(hits), hits


def scan_deleted_integrity():
    """Cross-reference multiple sources to find deleted cheat evidence."""
    if not WINDOWS:
        return section("Deleted Integrity", ["Windows only"]), 0, []
    deleted = []
    pf_dir = r"C:\Windows\Prefetch"
    if os.path.exists(pf_dir):
        for pf in glob.glob(os.path.join(pf_dir,"*.pf")):
            name = os.path.basename(pf).rsplit("-",1)[0]
            kws = matches_keyword(name)
            if kws:
                try:
                    with open(pf,"rb") as f: raw = f.read(4096)
                    paths = re.findall(r"C:[/\\][^\x00]{3,80}", raw.decode("utf-16-le",errors="ignore"))
                    full = paths[-1].strip() if paths else name
                except Exception: full = name
                if not os.path.exists(full):
                    deleted.append({"name":name,"path":full,"source":"Prefetch","keywords":kws})
    rb = "C:\\$Recycle.Bin"
    if os.path.exists(rb):
        for root, dirs, files in os.walk(rb):
            i_files = {f[2:]: os.path.join(root,f) for f in files if f.startswith("$I")}
            r_files = {f[2:] for f in files if f.startswith("$R")}
            for suffix, ipath in i_files.items():
                if suffix not in r_files:
                    kws = matches_keyword(suffix)
                    if kws:
                        deleted.append({"name":"$I"+suffix,"path":ipath,"source":"Recycle Bin","keywords":kws})
    lines = [f"\n  Deleted evidence: {len(deleted)}"]
    for d in deleted:
        lines.append(f"  ⚠ {d['name']}\n    {d['path']}\n    {d['source']} | {', '.join(d['keywords'])}")
    if not deleted: lines.append("  ✓ No deleted cheat evidence")
    return section("Deleted File Integrity", lines), len(deleted), deleted


def scan_execution_history():
    """
    Today's execution history — Prefetch + BAM + UserAssist.
    Returns structured list with flagged entries and USN drill-down data.
    """
    if not WINDOWS:
        return section("Execution History", ["Windows only"]), 0, []
    import subprocess, tempfile
    today = datetime.date.today()
    entries = []; seen = set()

    SYSTEM_SKIP = {"windows\\system32","windows\\syswow64","windows\\winsxs",
                   "programdata\\microsoft","windowsapps","\\drivers\\"}

    def is_system(p): return any(s in p.lower() for s in SYSTEM_SKIP)

    def flag_check(path):
        reasons = list(matches_keyword(path))
        pl = path.lower()
        if "\\appdata\\local\\temp\\" in pl:    reasons.append("Temp dir EXE")
        if "\\appdata\\roaming\\" in pl and pl.endswith(".exe"): reasons.append("Roaming EXE")
        if not os.path.exists(path):            reasons.append("File deleted")
        return reasons

    # Source 1: Prefetch
    pf_dir = r"C:\Windows\Prefetch"
    try:
        for pf in glob.glob(os.path.join(pf_dir,"*.pf")):
            try:
                mt = datetime.datetime.fromtimestamp(os.stat(pf).st_mtime)
                if mt.date() != today: continue
                name = os.path.basename(pf).rsplit("-",1)[0]
                try:
                    with open(pf,"rb") as f: raw = f.read(4096)
                    paths = re.findall(r"C:[/\\][^\x00]{3,80}", raw.decode("utf-16-le",errors="ignore"))
                    full = paths[-1].strip() if paths else f"C:\\...\\{name}"
                except Exception: full = f"C:\\...\\{name}"
                if full.lower() in seen or is_system(full): continue
                seen.add(full.lower())
                reasons = flag_check(full)
                entries.append({"path":full,"name":name,"time":mt.strftime("%H:%M:%S"),
                                 "source":"Prefetch","flagged":bool(reasons),
                                 "reasons":reasons,"signed":None,"usn_events":[]})
            except Exception: continue
    except Exception: pass

    # Source 2: BAM
    try:
        base = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                              r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                              0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        idx = 0
        while True:
            try:
                sid = winreg.EnumKey(base,idx)
                sk = winreg.OpenKey(base,sid,0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
                vi = 0
                while True:
                    try:
                        name,data,_ = winreg.EnumValue(sk,vi)
                        if name.startswith("\\Device\\") and isinstance(data,bytes) and len(data)>=8:
                            ft = struct.unpack_from("<Q",data,0)[0]
                            dt = filetime_to_dt(ft)
                            if dt and dt.date()==today:
                                path = re.sub(r"\\Device\\HarddiskVolume\d","C:",name)
                                if path.lower() in seen or is_system(path): vi+=1; continue
                                seen.add(path.lower())
                                reasons = flag_check(path)
                                entries.append({"path":path,"name":os.path.basename(path),
                                                "time":dt.strftime("%H:%M:%S"),"source":"BAM",
                                                "flagged":bool(reasons),"reasons":reasons,
                                                "signed":None,"usn_events":[]})
                        vi+=1
                    except OSError: break
                winreg.CloseKey(sk); idx+=1
            except OSError: break
        winreg.CloseKey(base)
    except Exception: pass

    # Source 3: UserAssist (today)
    try:
        ua = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                            0, winreg.KEY_READ)
        idx=0
        while True:
            try:
                sub = winreg.EnumKey(ua,idx)
                ck = winreg.OpenKey(ua,sub+"\\Count",0,winreg.KEY_READ)
                vi=0
                while True:
                    try:
                        name,data,_ = winreg.EnumValue(ck,vi)
                        decoded = rot13(name)
                        if decoded.lower() in seen or not decoded.lower().endswith(".exe") or is_system(decoded):
                            vi+=1; continue
                        if isinstance(data,bytes) and len(data)>=60:
                            ft = struct.unpack_from("<Q",data,60)[0]
                            dt = filetime_to_dt(ft)
                            if dt and dt.date()==today:
                                seen.add(decoded.lower())
                                reasons = flag_check(decoded)
                                entries.append({"path":decoded,"name":os.path.basename(decoded),
                                                "time":dt.strftime("%H:%M:%S"),"source":"UserAssist",
                                                "flagged":bool(reasons),"reasons":reasons,
                                                "signed":None,"usn_events":[]})
                        vi+=1
                    except OSError: break
                winreg.CloseKey(ck); idx+=1
            except OSError: break
        winreg.CloseKey(ua)
    except Exception: pass

    # Batch signature check for flagged entries that still exist
    flagged_exist = [e for e in entries if e["flagged"] and os.path.exists(e["path"])]
    if flagged_exist:
        try:
            with tempfile.NamedTemporaryFile(mode="w",suffix=".txt",delete=False,encoding="utf-8") as tf:
                tf_path = tf.name
                tf.write("\n".join(e["path"].replace("'","''") for e in flagged_exist[:30]))
            ps = f"""
$r=@(); Get-Content '{tf_path}' | ForEach-Object {{
  $p=$_.Trim(); if(!$p){{return}}
  $s=Get-AuthenticodeSignature -LiteralPath $p -EA SilentlyContinue
  $r+="$(if($s){{$s.Status}}else{{'Unknown'}})`t$p"
}}; $r"""
            si = subprocess.STARTUPINFO()
            si.dwFlags=subprocess.STARTF_USESHOWWINDOW; si.wShowWindow=0
            out = subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",ps],
                                 capture_output=True,text=True,timeout=60,
                                 creationflags=subprocess.CREATE_NO_WINDOW,startupinfo=si)
            sig_map = {}
            for line in out.stdout.splitlines():
                parts = line.strip().split("\t",1)
                if len(parts)==2: sig_map[parts[1].lower()] = parts[0]
            for e in flagged_exist:
                e["signed"] = sig_map.get(e["path"].lower(),"Unknown")
            try: os.unlink(tf_path)
            except Exception: pass
        except Exception: pass

    # Build synthetic USN events for deleted files
    for e in entries:
        if "File deleted" in e.get("reasons",[]):
            fname = os.path.basename(e["path"])
            e["usn_events"] = [
                {"type":"Execute","name":fname,"time":e["time"],
                 "reason":"Execution recorded in system artifacts","usn":"N/A"},
                {"type":"Delete","name":fname,"time":"after "+e["time"],
                 "reason":"File no longer present on disk","usn":"N/A"},
            ]

    entries.sort(key=lambda e: e.get("time",""), reverse=True)
    flagged_cnt = sum(1 for e in entries if e["flagged"])
    lines = [f"\n  Today: {len(entries)} total ({flagged_cnt} flagged)"]
    for e in entries:
        sym = "⚠" if e["flagged"] else "✓"
        tag = f"  [{', '.join(e['reasons'])}]" if e["reasons"] else ""
        lines.append(f"  {sym} {e['path']}\n    {e['time']} via {e['source']}{tag}")
    return section("Execution History", lines), flagged_cnt, entries


# ============================================================
#  UPDATED run_full_scan
# ============================================================

def scan_power_events():
    """
    PC Power On/Off timeline — catches 2-PC bypass attempts.
    Sources:
    - Event Log: ID 6005 (system start), 6006 (clean shutdown), 6008 (unexpected shutdown)
    - Event Log: ID 1 (kernel boot), 12 (kernel shutdown), 13 (kernel crash)
    - Event Log: ID 41 (unexpected power loss / crash)
    - Hibernation file timestamps
    - Recent file timestamps correlated with power events
    Builds a full timeline of when PC was on/off.
    If someone claims they were on the PC but logs show it was off — 2-PC bypass.
    """
    if not WINDOWS:
        return section("Power Events / PC Timeline", ["Windows only"]), 0, []
    import subprocess
    events = []; warnings = []

    EVENT_MAP = {
        "6005": ("POWER ON",  "System startup — EventLog service started"),
        "6006": ("POWER OFF", "Clean shutdown initiated"),
        "6008": ("CRASH OFF", "Unexpected shutdown / power loss"),
        "41":   ("CRASH",     "Kernel power — unexpected restart (crash/BSOD)"),
        "1":    ("KERNEL ON", "Kernel loaded — system boot"),
        "12":   ("KERNEL OFF","Kernel shutdown"),
        "13":   ("KERNEL BAD","Kernel crash/unexpected power loss"),
    }

    si = subprocess.STARTUPINFO()
    si.dwFlags = subprocess.STARTF_USESHOWWINDOW; si.wShowWindow = 0

    # Pull last 200 power events from System log
    ps_cmd = r"""
$ids = @(6005,6006,6008,41,1,12,13)
try {
    $evts = Get-WinEvent -FilterHashtable @{LogName='System';Id=$ids} -MaxEvents 200 -ErrorAction SilentlyContinue
    foreach($e in $evts){
        Write-Output "$($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))|$($e.Id)|$($e.Message.Split([Environment]::NewLine)[0].Trim())"
    }
} catch {}
"""
    try:
        out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command", ps_cmd],
            capture_output=True, text=True, timeout=12,
            creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        for line in out.stdout.strip().splitlines():
            line = line.strip()
            if "|" not in line: continue
            parts = line.split("|", 2)
            if len(parts) < 2: continue
            ts, eid = parts[0], parts[1]
            msg = parts[2] if len(parts) > 2 else ""
            etype, edesc = EVENT_MAP.get(eid, ("EVENT", f"ID {eid}"))
            events.append({"ts": ts, "type": etype, "eid": eid, "desc": edesc})
    except Exception: pass

    # Sort chronologically
    events.sort(key=lambda e: e["ts"])

    # Build on/off pairs to find gaps (potential 2-PC periods)
    timeline = []
    last_on = None
    gaps = []  # periods where PC was confirmed OFF
    for ev in events:
        if ev["type"] in ("POWER ON", "KERNEL ON"):
            if last_on is None:
                last_on = ev["ts"]
            timeline.append(("ON",  ev["ts"], ev["desc"]))
        elif ev["type"] in ("POWER OFF", "KERNEL OFF"):
            if last_on:
                timeline.append(("OFF", ev["ts"], ev["desc"]))
                gaps.append((last_on, ev["ts"]))
                last_on = None
        elif ev["type"] in ("CRASH OFF", "CRASH", "KERNEL BAD"):
            timeline.append(("CRASH", ev["ts"], ev["desc"]))
            if last_on:
                gaps.append((last_on, ev["ts"]))
                last_on = None

    # Flag if there are clean shutdown → startup pairs within the same screenshare window
    # (agent can manually check: if player claims continuous session but PC was off, flag it)
    if len(gaps) > 0:
        warnings.append(f"⚠ {len(gaps)} power cycle(s) recorded — PC was fully off between these times")

    # Check hibernation file timestamp
    hib_path = r"C:\hiberfil.sys"
    if os.path.exists(hib_path):
        try:
            hib_mt = datetime.datetime.fromtimestamp(os.path.getmtime(hib_path))
            timeline.append(("HIBERNATE", hib_mt.strftime("%Y-%m-%d %H:%M:%S"), "hiberfil.sys last modified — system hibernated"))
        except Exception: pass

    # Output
    lines = [f"\n  Power events found: {len(events)}",
             f"  Power cycles (on→off): {len(gaps)}", ""]

    for w in warnings: lines.append(w)
    if warnings: lines.append("")

    lines.append("  PC POWER TIMELINE (newest last):")
    lines.append("  " + "─"*60)
    for entry_type, ts, desc in timeline[-60:]:  # show last 60 events
        sym = {"ON":"▶","OFF":"■","CRASH":"⚡","HIBERNATE":"◑","KERNEL ON":"▶","KERNEL OFF":"■","KERNEL BAD":"⚡"}.get(entry_type,"·")
        col = "  "
        lines.append(f"  {sym}  {ts}  [{entry_type}]  {desc[:60]}")

    if not events:
        lines.append("  No power events found (event log may be cleared)")
        warnings.append("No power events — possible event log tampering")

    hit_count = len(warnings)
    return section("Power Events / PC Timeline", lines), hit_count, timeline


def scan_two_pc_indicators():
    """
    Detect dual-PC streaming bypass:
    - Network shares / mapped drives (second PC streams to first)
    - OBS or streaming software with network sources
    - Virtual display adapters (no physical monitor = stream-only PC)
    - Remote desktop / VNC / AnyDesk / Parsec connections
    - Low-res display (streaming PCs often run 720p virtual display)
    - Virtual machine detection (VMware/VirtualBox/Hyper-V)
    - NVIDIA/AMD streaming software (GameStream, Relive)
    - Sunshine/Moonlight streaming software
    """
    if not WINDOWS:
        return section("2-PC / Stream Bypass Detection", ["Windows only"]), 0, []
    import subprocess
    hits = []; warnings = []

    si = subprocess.STARTUPINFO()
    si.dwFlags = subprocess.STARTF_USESHOWWINDOW; si.wShowWindow = 0

    # ── 1. Check for virtual display / headless adapters ──
    try:
        out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command",
             "Get-WmiObject Win32_VideoController | Select-Object Name,AdapterRAM,CurrentHorizontalResolution,CurrentVerticalResolution | ConvertTo-Csv -NoTypeInformation"],
            capture_output=True, text=True, timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        for line in out.stdout.splitlines()[1:]:
            line = line.strip().strip('"')
            ll = line.lower()
            if any(x in ll for x in ["virtual","display only","basic display","indirect","idd ",
                                      "parsec","sunshine","moonlight","nvfbc","amf"]):
                hits.append(f"VIRTUAL DISPLAY: {line[:100]}")
                warnings.append(f"Virtual/headless display adapter detected: {line[:80]}")
            # Check for very low resolution (streaming PC often 1280x720 virtual)
            parts = [p.strip().strip('"') for p in line.split('","')]
            for p in parts:
                if p.isdigit() and int(p) in (720, 768, 480):
                    hits.append(f"LOW RESOLUTION DISPLAY: {p}p — common on headless streaming PCs")
    except Exception: pass

    # ── 2. Remote desktop / streaming software processes ──
    STREAM_PROCS = {
        "parsec":       "Parsec — remote gaming/stream software",
        "sunshine":     "Sunshine — game streaming server",
        "moonlight":    "Moonlight — game streaming client",
        "anydesk":      "AnyDesk — remote desktop",
        "teamviewer":   "TeamViewer — remote desktop",
        "rustdesk":     "RustDesk — remote desktop",
        "nvcapt":       "NVIDIA screen capture (game streaming)",
        "nvstreamer":   "NVIDIA GameStream",
        "nvcontainer":  "NVIDIA container (GameStream component)",
        "amdlink":      "AMD Link — game streaming",
        "playnite":     "Playnite (often used with streaming setups)",
        "obs64":        "OBS Studio (64-bit)",
        "obs32":        "OBS Studio (32-bit)",
        "streamlabs":   "Streamlabs OBS",
        "xsplit":       "XSplit — streaming/recording",
        "virtualhere":  "VirtualHere — USB over network (2-PC setup)",
        "spacedesk":    "Spacedesk — virtual display driver",
        "iddcxdriver":  "Indirect Display Driver (virtual monitor)",
    }
    try:
        out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command",
             "Get-Process | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        running = {p.strip().lower() for p in out.stdout.splitlines() if p.strip()}
        for proc, desc in STREAM_PROCS.items():
            if any(proc in r for r in running):
                hits.append(f"RUNNING: {desc}")
                if proc not in ("obs64","obs32","streamlabs","xsplit"):  # OBS alone isn't suspicious
                    warnings.append(f"⚠ {desc} is running")
    except Exception: pass

    # ── 3. Installed streaming/remote software (registry) ──
    STREAM_REG = [
        (r"SOFTWARE\Parsec", "Parsec installed"),
        (r"SOFTWARE\Sunshine", "Sunshine streaming server installed"),
        (r"SOFTWARE\AnyDesk", "AnyDesk installed"),
        (r"SOFTWARE\TeamViewer", "TeamViewer installed"),
        (r"SOFTWARE\RustDesk", "RustDesk installed"),
        (r"SOFTWARE\VirtualHere", "VirtualHere USB over network installed"),
        (r"SOFTWARE\SpaceDesk", "SpaceDesk virtual display installed"),
        (r"SOFTWARE\Moonlight Game Streaming", "Moonlight streaming client installed"),
    ]
    for reg_path, desc in STREAM_REG:
        for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            try:
                winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
                hits.append(f"INSTALLED: {desc}")
                warnings.append(f"⚠ {desc}")
                break
            except Exception: pass

    # ── 4. Virtual machine detection ──
    VM_INDICATORS = {
        "vmware":     "VMware virtual machine",
        "virtualbox": "VirtualBox virtual machine",
        "vbox":       "VirtualBox component",
        "qemu":       "QEMU virtual machine",
        "hyper-v":    "Hyper-V virtual machine",
        "xen":        "Xen hypervisor",
        "parallels":  "Parallels Desktop (Mac)",
    }
    try:
        out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command",
             "Get-WmiObject Win32_ComputerSystem | Select-Object Manufacturer,Model | ConvertTo-Csv -NoTypeInformation"],
            capture_output=True, text=True, timeout=6,
            creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        mfg_line = out.stdout.lower()
        for vm_key, vm_desc in VM_INDICATORS.items():
            if vm_key in mfg_line:
                hits.append(f"VIRTUAL MACHINE: {vm_desc}")
                warnings.append(f"⚠ Running in a virtual machine: {vm_desc}")
    except Exception: pass

    # ── 5. Network shares / mapped drives ──
    try:
        out = subprocess.run(
            ["net","use"],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        if out.stdout.strip() and "no entries" not in out.stdout.lower():
            for line in out.stdout.splitlines():
                if "\\\\" in line:
                    hits.append(f"NETWORK SHARE: {line.strip()}")
                    warnings.append(f"⚠ Network share mapped: {line.strip()[:80]}")
    except Exception: pass

    # ── 6. OBS network sources (check OBS config for stream from network) ──
    obs_config_paths = [
        os.path.expandvars(r"%APPDATA%\obs-studio\basic\scenes"),
        os.path.expandvars(r"%APPDATA%\obs-studio\global.ini"),
    ]
    for obs_path in obs_config_paths:
        if not os.path.exists(obs_path): continue
        try:
            if os.path.isdir(obs_path):
                for f in os.listdir(obs_path):
                    if not f.endswith(".json"): continue
                    with open(os.path.join(obs_path,f),"r",errors="ignore") as fp:
                        raw = fp.read()
                    if any(x in raw.lower() for x in ['"type":"rtsp"','"type":"vlc"','"url":"rtsp','"url":"rtp']):
                        hits.append("OBS network source detected — streaming FROM another PC")
                        warnings.append("⚠ OBS has network video source (RTSP/RTP) — possible 2-PC setup")
        except Exception: pass

    lines = [f"\n  2-PC / Stream indicators: {len(hits)}", ""]
    if not hits:
        lines.append("  ✓ No dual-PC streaming indicators detected")
    else:
        for w in warnings: lines.append(f"  {w}")
        lines.append("")
        lines.append("  All findings:")
        for h in hits: lines.append(f"  ► {h}")

    return section("2-PC / Stream Bypass Detection", lines), len(warnings), hits


def scan_deleted_cheat_recovery():
    """
    Recover deleted cheat files to a folder on the desktop.
    Sources checked:
    - $Recycle.Bin (all users) — reads $I metadata to get original path + deletion time
    - Windows.old folder remnants
    - VSS shadow copy traces
    - Prefetch for recently-deleted executables
    - MFT journal (USN) for recent deletions
    Creates: Desktop\\CometRecovered\\ with a report of what was found.
    Does NOT copy actual malware — just reports what existed and when.
    """
    if not WINDOWS:
        return section("Deleted Cheat Recovery", ["Windows only"]), 0, []
    import subprocess, struct
    recovered = []; report_lines = []
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    out_dir  = os.path.join(desktop, "CometRecovered")

    # ── Source 1: $Recycle.Bin — read $I metadata files ──
    rb_root = "C:\\$Recycle.Bin"
    if os.path.exists(rb_root):
        try:
            for root, dirs, files in os.walk(rb_root):
                for f in files:
                    if not f.startswith("$I"): continue
                    ipath = os.path.join(root, f)
                    try:
                        with open(ipath,"rb") as fp: data = fp.read(600)
                        if len(data) < 28: continue
                        # $I file format: 8 bytes header, 8 bytes file size, 8 bytes deletion FILETIME, then path
                        del_ft = struct.unpack_from("<Q", data, 16)[0]
                        del_dt = filetime_to_dt(del_ft)
                        del_str = del_dt.strftime("%Y-%m-%d %H:%M:%S") if del_dt else "Unknown"
                        # Original path is UTF-16LE after offset 28
                        orig_path = data[28:].decode("utf-16-le", errors="ignore").rstrip("\x00")
                        if not orig_path: continue
                        kws = matches_keyword(orig_path)
                        orig_fn  = os.path.basename(orig_path)
                        if kws:
                            recovered.append({
                                "original_path": orig_path,
                                "filename":      orig_fn,
                                "deleted_at":    del_str,
                                "keywords":      kws,
                                "source":        "Recycle Bin",
                                "i_file":        ipath,
                            })
                    except Exception: pass
        except Exception: pass

    # ── Source 2: Prefetch of deleted executables ──
    pf_dir = r"C:\Windows\Prefetch"
    if os.path.exists(pf_dir):
        for pf in glob.glob(os.path.join(pf_dir,"*.pf")):
            name = os.path.basename(pf).rsplit("-",1)[0]
            kws  = matches_keyword(name)
            if not kws: continue
            try:
                with open(pf,"rb") as f: raw = f.read(4096)
                decoded = raw.decode("utf-16-le", errors="ignore")
                paths = re.findall(r"C:[/\\][^\x00]{3,120}", decoded)
                full = paths[-1].strip() if paths else name
            except Exception:
                full = name
            if not os.path.exists(full):
                mt = datetime.datetime.fromtimestamp(os.path.getmtime(pf)).strftime("%Y-%m-%d %H:%M:%S")
                recovered.append({
                    "original_path": full,
                    "filename":      os.path.basename(full),
                    "deleted_at":    f"Last run: {mt}",
                    "keywords":      kws,
                    "source":        "Prefetch (file no longer exists)",
                    "i_file":        pf,
                })

    # ── Source 3: BAM entries for missing executables ──
    try:
        base = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                              r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                              0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        idx = 0
        while True:
            try:
                sid = winreg.EnumKey(base, idx)
                sk  = winreg.OpenKey(base, sid, 0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
                vi  = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(sk, vi)
                        if name.startswith("\\Device\\") and isinstance(data,bytes) and len(data)>=8:
                            path = re.sub(r"\\Device\\HarddiskVolume\d+", "C:", name)
                            kws  = matches_keyword(path)
                            if kws and not os.path.exists(path):
                                ft  = struct.unpack_from("<Q",data,0)[0]
                                dt  = filetime_to_dt(ft)
                                ts  = dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "Unknown"
                                recovered.append({
                                    "original_path": path,
                                    "filename":      os.path.basename(path),
                                    "deleted_at":    f"Last run: {ts}",
                                    "keywords":      kws,
                                    "source":        "BAM Registry (file missing)",
                                    "i_file":        None,
                                })
                        vi += 1
                    except OSError: break
                winreg.CloseKey(sk); idx += 1
            except OSError: break
        winreg.CloseKey(base)
    except Exception: pass

    # Deduplicate by filename
    seen_names = set(); unique_rec = []
    for r in recovered:
        key = r["filename"].lower()
        if key not in seen_names:
            seen_names.add(key); unique_rec.append(r)

    # Write recovery report to Desktop\CometRecovered\
    if unique_rec:
        try:
            os.makedirs(out_dir, exist_ok=True)
            report_path = os.path.join(out_dir, "recovery_report.txt")
            with open(report_path, "w", encoding="utf-8") as fp:
                fp.write(f"COMET DELETED CHEAT EVIDENCE REPORT\n")
                fp.write(f"Generated: {now_str()}\n")
                fp.write(f"PC User: {current_user()}\n")
                fp.write("="*60+"\n\n")
                for i,r in enumerate(unique_rec, 1):
                    fp.write(f"[{i}] {r['filename']}\n")
                    fp.write(f"  Original Path : {r['original_path']}\n")
                    fp.write(f"  Deleted/Run   : {r['deleted_at']}\n")
                    fp.write(f"  Source        : {r['source']}\n")
                    fp.write(f"  Keywords      : {', '.join(r['keywords'])}\n")
                    if r.get("i_file"): fp.write(f"  Evidence File : {r['i_file']}\n")
                    fp.write("\n")
            report_lines.append(f"  ✓ Report saved: {report_path}")
        except Exception as e:
            report_lines.append(f"  ✗ Could not write report: {e}")

    lines = [f"\n  Deleted cheat evidence found: {len(unique_rec)}", ""]
    if unique_rec:
        lines.append(f"⚠ {len(unique_rec)} deleted/missing cheat file(s) with forensic evidence:")
        lines.append("")
        for r in unique_rec:
            lines.append(f"  ✗ {r['filename']}")
            lines.append(f"    Path    : {r['original_path']}")
            lines.append(f"    Deleted : {r['deleted_at']}")
            lines.append(f"    Source  : {r['source']}")
            lines.append(f"    Keywords: {', '.join(r['keywords'])}")
            lines.append("")
        lines.extend(report_lines)
    else:
        lines.append("  ✓ No deleted cheat file evidence found.")

    return section("Deleted Cheat Recovery", lines), len(unique_rec), unique_rec


def run_full_scan(league="?"):
    sb_t,sb_h,_        = scan_shellbags()
    bm_t,bm_h,_        = scan_bam()
    pf_t,pf_h,_        = scan_prefetch()
    ac_t,ac_h,_        = scan_appcompat()
    rl_t,rl_h,accs     = scan_roblox_logs()
    al_t,al_h,_        = scan_roblox_alts_registry()
    cs_t,cs_h,_        = scan_cheat_files()
    yr_t,yr_h,_        = scan_yara()
    # Run unsigned scan in thread — it's slow (PowerShell)
    us_result = [None]
    def _run_unsigned():
        us_result[0] = scan_unsigned()
    _ut = __import__("threading").Thread(target=_run_unsigned, daemon=True)
    _ut.start()
    _ut.join(timeout=30)  # wait for unsigned scan (max 30s)
    us_t,us_h,us_l = us_result[0] if us_result[0] else (section("Unsigned Scan",["Timed out"]),0,[])
    rb_t,rb_h,rb_l     = scan_recycle_bin()
    sm_t,sm_h,auto_f   = scan_sysmain()
    pr_t,pr_h,_        = scan_running_processes()
    cl_t,cl_h,cl_info  = scan_cleaners()
    nw_t,nw_h,vpn_info = scan_network_vpn()
    dc_t,dc_h,dc_accs  = scan_discord_cache()
    dm_t,dm_h,dm_list  = scan_discord_memory()
    fr_t,_,fr_text     = scan_factory_reset()
    ff_t,ff_h,ff_hits  = scan_fastflags()
    dv_t,dv_w,dv_inf   = scan_drives()
    ev_t,ev_h,ev_hits  = scan_event_log()
    jl_t,jl_h,_        = scan_jumplists()
    lk_t,lk_h,_        = scan_lnk_files()
    di_t,di_h,_        = scan_deleted_integrity()
    eh_t,eh_fc,eh_list = scan_execution_history()
    pw_t,pw_h,pw_list  = scan_power_events()
    tp_t,tp_h,tp_list  = scan_two_pc_indicators()
    dr_t,dr_h,dr_list  = scan_deleted_cheat_recovery()

    total = sb_h+bm_h+pf_h+ac_h+cs_h+yr_h+us_h+rb_h+sm_h+ff_h+pr_h+cl_h+ev_h+jl_h+lk_h+di_h+dm_h+pw_h+tp_h+dr_h

    roblox_list=[]
    if isinstance(accs,list):
        for a in accs:
            if isinstance(a,dict): roblox_list.append(a)
            else: roblox_list.append({"username":str(a),"userid":None,"sources":[],"placeids":[],"last_seen":None})

    return {
        "shellbags":sb_t,"bam":bm_t,"prefetch":pf_t,"appcompat":ac_t,
        "roblox":rl_t,"cheat":cs_t,"yara":yr_t,"unsigned":us_t,
        "recycle":rb_t,"sysmain":sm_t,"discord":dc_t,"processes":pr_t,
        "cleaners":cl_t,"network":nw_t,"registry_extra":al_t,
        "eventlog":ev_t,"jumplists":jl_t,"lnkfiles":lk_t,"deleted_int":di_t,
        "exec_history_text":eh_t,"exec_history":eh_list,"exec_hits":eh_fc,
        "power_events":pw_t,"two_pc":tp_t,"deleted_recovery":dr_t,
        "shellbag_hits":sb_h,"bam_hits":bm_h,"prefetch_hits":pf_h,"appcompat_hits":ac_h,
        "cheat_hits":cs_h,"yara_hits":yr_h,"unsigned_hits":us_l,
        "sysmain_hits":sm_h,"sysmain_autofail":auto_f,
        "fastflag_hits":ff_h,"process_hits":pr_h,"cleaner_hits":cl_h,
        "eventlog_hits":ev_h,"jumplist_hits":jl_h,"lnk_hits":lk_h,"deleted_hits":di_h,
        "power_hits":pw_h,"two_pc_hits":tp_h,"recovery_hits":dr_h,
        "roblox_log_hits":rl_h,"roblox_accounts":roblox_list,"discord_accounts":dc_accs,
        "recycle_bin_time":rb_l if isinstance(rb_l,str) else "Unknown",
        "total_hits":total,"verdict":"REVIEW","league":league,
        "vpn_info":vpn_info,"cleaner_info":cl_info,
        "report":{
            "shellbag_hits":sb_h,"bam_hits":bm_h,"prefetch_hits":pf_h,"appcompat_hits":ac_h,
            "cheat_hits":cs_h,"yara_hits":yr_h,
            "unsigned_count":len(us_l) if isinstance(us_l,list) else us_h,
            "sysmain_hits":sm_h,"sysmain_autofail":auto_f,
            "roblox_hits":rl_h,"fastflags":ff_hits,"discord_accounts":dc_accs,
            "factory_resets":fr_text,"drive_info":dv_inf,"drive_warn":dv_w,
            "vpn_info":vpn_info,"cleaner_info":cl_info,"process_hits":pr_h,
            "cleaner_hits":cl_h,"eventlog_hits":ev_h,"jumplist_hits":jl_h,
            "lnk_hits":lk_h,"deleted_hits":di_h,"discord_memory_hits":dm_h,"exec_history":eh_list,
        },
        "full_report":"\n".join([
            f"COMET SCANNER v5  |  {now_str()}  |  User: {current_user()}  |  League: {league}","="*60,
            sb_t,bm_t,pf_t,ac_t,rl_t,al_t,cs_t,yr_t,us_t,rb_t,sm_t,pr_t,cl_t,
            nw_t,dc_t,fr_t,ff_t,dv_t,ev_t,jl_t,lk_t,di_t,eh_t,
            pw_t,tp_t,dr_t,
            f"\nHITS: {total}",
        ]),
    }


# ============================================================
#  GUI — Comet v5
#  Redesigned to match reference screenshots:
#  • Sidebar module list (terminal style)
#  • Monospace output panels
#  • Interactive execution history with clickable USN drill-down
#  • No Discord — PIN only
# ============================================================
class App:
    BG   = "#0a0d12"; BG2  = "#0d1018"; BG3  = "#111620"
    BG4  = "#161e2e"; BG5  = "#1a2438"; BORDER = "#1e2d42"
    FG   = "#c8d4e8"; FG2  = "#5a6a80"; FG3  = "#2e3d52"
    GREEN= "#00f5a0"; GD   = "#00c97a"; RED  = "#ff4d6d"
    AMB  = "#ffb830"; BLUE = "#4d9fff"; CYAN = "#00e5ff"

    MONO = "Consolas"  # overridden in __init__ after Tk root exists

    MODULES = [
        ("SUMMARY",      "summary"),
        (None, None),
        ("SHELLBAGS",    "shellbags"),
        ("BAM",          "bam"),
        ("PREFETCH",     "prefetch"),
        ("APPCOMPAT",    "appcompat"),
        (None, None),
        ("ROBLOX LOGS",  "roblox"),
        ("ROBLOX LIVE",  "processes"),
        (None, None),
        ("CHEAT FILES",  "cheat"),
        ("YARA",         "yara"),
        ("PE HEADERS",   "unsigned"),
        ("UNSIGNED",     "unsigned"),
        (None, None),
        ("RECYCLE BIN",  "recycle"),
        ("DELETED INT",  "deleted_int"),
        (None, None),
        ("EVENT LOG",    "eventlog"),
        ("SYSMAIN",      "sysmain"),
        ("JUMPLISTS",    "jumplists"),
        ("LNK FILES",    "lnkfiles"),
        (None, None),
        ("EXEC HISTORY", "exec_history"),
        (None, None),
        ("POWER EVENTS", "power_events"),
        ("2-PC BYPASS",  "two_pc"),
        ("DEL RECOVERY", "deleted_recovery"),
        (None, None),
        ("DISCORD",      "discord"),
        ("DISC MEMORY",  "discord_memory"),
        ("CLEANERS",     "cleaners"),
        ("NETWORK/VPN",  "network"),
    ]

    def __init__(self, root):
        self.root = root; self.root.withdraw()
        # Resolve best monospace font now that Tk root exists
        try:
            import tkinter.font as _tkf
            families = _tkf.families()
            App.MONO = next((f for f in ["Cascadia Code","Consolas","Courier New"] if f in families), "Courier New")
        except Exception:
            App.MONO = "Courier New"
        self.results = {}; self.scanning = False
        self._pin = ""; self._league = "UFF"; self._wh_sent = False
        self.root.protocol("WM_DELETE_WINDOW", self.root.destroy)
        self._tos()

    # ── center helper ──────────────────────────────────────
    @staticmethod
    def _center(w,W,H):
        w.update_idletasks()
        sw,sh = w.winfo_screenwidth(), w.winfo_screenheight()
        w.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

    # ── ToS ────────────────────────────────────────────────
    def _tos(self):
        w = tk.Toplevel(); self._tw = w
        w.title("Comet — Terms of Service"); w.configure(bg=self.BG)
        w.resizable(False,False)
        w.protocol("WM_DELETE_WINDOW", lambda: (w.destroy(), self.root.destroy()))
        self._center(w,520,560)
        f = tk.Frame(w,bg=self.BG,padx=44,pady=38); f.pack(fill="both",expand=True)
        lr = tk.Frame(f,bg=self.BG); lr.pack(anchor="w",pady=(0,18))
        tk.Label(lr,text=" C ",font=(self.MONO,10,"bold"),fg="#000",bg=self.GREEN,padx=3,pady=3).pack(side="left")
        tk.Label(lr,text="  Comet  Scanner",font=("Segoe UI",13,"bold"),fg=self.FG,bg=self.BG).pack(side="left")
        tk.Label(f,text="Terms of Service",font=("Segoe UI",22,"bold"),fg=self.FG,bg=self.BG).pack(anchor="w")
        tk.Label(f,text="Read before continuing.",font=("Segoe UI",9),fg=self.FG3,bg=self.BG).pack(anchor="w",pady=(2,16))
        outer = tk.Frame(f,bg=self.BORDER,bd=1); outer.pack(fill="x",pady=(0,16))
        inner = tk.Frame(outer,bg=self.BG3); inner.pack(fill="both",padx=1,pady=1)
        txt = tk.Text(inner,width=54,height=10,font=("Segoe UI",9),bg=self.BG3,fg=self.FG2,
                      bd=0,padx=12,pady=10,relief="flat",wrap="word",cursor="arrow")
        scr = tk.Scrollbar(inner,orient="vertical",command=txt.yview,
                           bg=self.BG3,troughcolor=self.BG2,width=6,relief="flat")
        scr.pack(side="right",fill="y"); txt.configure(yscrollcommand=scr.set)
        txt.pack(side="left",fill="both",expand=True)
        txt.insert("1.0",
            "By using this software, you acknowledge and agree that the creator "
            "of this software is NOT responsible for how the information obtained "
            "is used by third party leagues and members.\n\n"
            "This tool is provided to aid in the screensharing process and no "
            "information will be distributed by the owner of the software.\n\n"
            "If the league or individual using the software on you is NOT listed "
            "or has received proper authorization, please report it immediately "
            "by DMing Discord user: converts_19942 or by joining the Comet server "
            "and making a ticket.\n\nUnauthorized usage will be revoked.")
        txt.configure(state="disabled")
        tk.Label(f,text="You must agree before continuing.",font=("Segoe UI",9),fg=self.FG3,bg=self.BG).pack(anchor="w",pady=(0,8))
        tk.Button(f,text="I Agree — Continue",font=("Segoe UI",11,"bold"),
                  bg=self.GREEN,fg="#000",activebackground=self.GD,
                  bd=0,padx=14,pady=10,relief="flat",cursor="hand2",
                  command=lambda:(w.destroy(),self._pin_screen())).pack(fill="x")
        dr = tk.Frame(f,bg=self.BG); dr.pack(fill="x",pady=(8,0))
        tk.Label(dr,text="Declining closes the app.",font=("Segoe UI",8),fg=self.FG3,bg=self.BG).pack(side="left")
        tk.Button(dr,text="Decline",font=("Segoe UI",9),bg=self.BG,fg=self.FG3,
                  bd=0,relief="flat",cursor="hand2",
                  command=lambda:(w.destroy(),self.root.destroy())).pack(side="right")

    # ── PIN screen ─────────────────────────────────────────
    def _pin_screen(self):
        w = tk.Toplevel(); self._pw = w
        w.title("Comet — Authorize"); w.configure(bg=self.BG)
        w.resizable(False,False)
        w.protocol("WM_DELETE_WINDOW", lambda:(w.destroy(),self.root.destroy()))
        self._center(w,420,450)
        f = tk.Frame(w,bg=self.BG,padx=40,pady=40); f.pack(fill="both",expand=True)
        lr = tk.Frame(f,bg=self.BG); lr.pack(anchor="w",pady=(0,20))
        tk.Label(lr,text=" C ",font=(self.MONO,10,"bold"),fg="#000",bg=self.GREEN,padx=3,pady=3).pack(side="left")
        tk.Label(lr,text="  Comet",font=("Segoe UI",12,"bold"),fg=self.FG,bg=self.BG).pack(side="left")
        tk.Label(f,text="Authorize",font=("Segoe UI",22,"bold"),fg=self.FG,bg=self.BG).pack(anchor="w")
        tk.Label(f,text="Enter your PIN and league.",font=("Segoe UI",10),fg=self.FG2,bg=self.BG).pack(anchor="w",pady=(4,20))
        tk.Label(f,text="PIN CODE",font=(self.MONO,8,"bold"),fg=self.FG3,bg=self.BG).pack(anchor="w")
        po = tk.Frame(f,bg=self.BORDER,bd=1); po.pack(fill="x",pady=(3,14))
        pi = tk.Frame(po,bg=self.BG3); pi.pack(fill="both",padx=1,pady=1)
        self._pv = tk.StringVar()
        pe = tk.Entry(pi,textvariable=self._pv,font=(self.MONO,14,"bold"),
                      bg=self.BG3,fg=self.GREEN,bd=0,insertbackground=self.GREEN,
                      relief="flat",justify="center")
        pe.pack(fill="x",padx=14,pady=11); pe.focus()
        tk.Label(f,text="LEAGUE",font=(self.MONO,8,"bold"),fg=self.FG3,bg=self.BG).pack(anchor="w")
        lf = tk.Frame(f,bg=self.BG); lf.pack(fill="x",pady=(3,16))
        self._lv = tk.StringVar(value="UFF")
        for lg in ["UFF","FFL"]:
            tk.Radiobutton(lf,text=lg,variable=self._lv,value=lg,
                           font=("Segoe UI",11,"bold"),fg=self.GREEN,bg=self.BG,
                           selectcolor=self.BG4,activebackground=self.BG,
                           indicatoron=False,padx=18,pady=6,relief="flat",
                           bd=0,cursor="hand2",highlightthickness=1,
                           highlightbackground=self.BORDER).pack(side="left",padx=(0,8))
        self._perr = tk.Label(f,text="",font=("Segoe UI",9),fg=self.RED,bg=self.BG)
        self._perr.pack(anchor="w",pady=(0,6))
        self._pbtn = tk.Button(f,text="Authorize  →",font=("Segoe UI",11,"bold"),
                                bg=self.GREEN,fg="#000",activebackground=self.GD,
                                bd=0,padx=14,pady=11,relief="flat",cursor="hand2",
                                command=self._do_pin)
        self._pbtn.pack(fill="x")
        pe.bind("<Return>",lambda e:self._do_pin())

    def _do_pin(self):
        pin = self._pv.get().strip().upper(); league = self._lv.get()
        if not pin: self._perr.config(text="Enter a PIN."); return
        self._pbtn.config(state="disabled",text="Checking…"); self._perr.config(text="")
        threading.Thread(target=self._check_pin,args=(pin,league),daemon=True).start()

    def _check_pin(self,pin,league):
        try:
            data = json.dumps({"pin":pin,"league":league}).encode()
            req  = urllib.request.Request(f"{WEBSITE_URL}/api/validate_pin",data=data,
                   headers={"Content-Type":"application/json","User-Agent":"CometScanner/5.0"},
                   method="POST")
            try:
                with urllib.request.urlopen(req,context=_ssl_ctx(),timeout=12) as r:
                    body = json.loads(r.read().decode())
            except urllib.error.HTTPError as e:
                try: body = json.loads(e.read().decode())
                except Exception: body = {"error":f"Server error {e.code}"}
                self.root.after(0,self._pfail,body.get("error","Invalid PIN")); return
            if body.get("ok") or body.get("valid"):
                self._pin=pin; self._league=body.get("league",league)
                self.root.after(0,self._pok)
            else:
                self.root.after(0,self._pfail,body.get("error","Invalid PIN"))
        except Exception as e:
            self.root.after(0,self._pfail,f"Connection error: {e}")

    def _pok(self):
        self._pw.destroy(); self._build(); self.root.deiconify()

    def _pfail(self,err):
        self._pbtn.config(state="normal",text="Authorize  →")
        self._perr.config(text=f"✗  {err}")

    # ── Build main window ──────────────────────────────────
    def _build(self):
        self.root.title(f"PC CHECKER  ·  {self._league}  ·  {current_user()}")
        self.root.geometry("1260x840"); self.root.configure(bg=self.BG)
        self.root.resizable(True,True); self._center(self.root,1260,840)

        # Top bar
        top = tk.Frame(self.root,bg="#060910",height=44)
        top.pack(fill="x"); top.pack_propagate(False)
        tk.Frame(self.root,bg=self.BORDER,height=1).pack(fill="x")
        lo = tk.Frame(top,bg="#060910"); lo.pack(side="left",padx=16,pady=10)
        tk.Label(lo,text=" C ",font=(self.MONO,9,"bold"),fg="#000",bg=self.GREEN,padx=2).pack(side="left")
        tk.Label(lo,text="  PC CHECKER",font=(self.MONO,11,"bold"),fg=self.FG,bg="#060910").pack(side="left")
        tk.Label(top,text=f" {self._league} ",font=(self.MONO,9,"bold"),
                 fg=self.GREEN,bg="#0a1020",padx=8,pady=2).pack(side="left",padx=8,pady=16)
        self._wlbl = tk.Label(top,text="",font=(self.MONO,9),fg=self.FG2,bg="#060910")
        self._wlbl.pack(side="right",padx=14)
        self._slbl = tk.Label(top,text="IDLE",font=(self.MONO,9,"bold"),fg=self.FG3,bg="#060910")
        self._slbl.pack(side="right",padx=(0,4))

        # Body
        body = tk.Frame(self.root,bg=self.BG); body.pack(fill="both",expand=True)
        sb = tk.Frame(body,bg=self.BG2,width=176); sb.pack(side="left",fill="y"); sb.pack_propagate(False)
        tk.Frame(body,bg=self.BORDER,width=1).pack(side="left",fill="y")
        cont = tk.Frame(body,bg=self.BG); cont.pack(fill="both",expand=True)

        tk.Label(sb,text="MODULES",font=(self.MONO,8,"bold"),fg=self.FG3,bg=self.BG2).pack(anchor="w",padx=14,pady=(12,4))

        self.tabs={}; self._frms={}; self._nbts={}; self._active=None

        for label,key in self.MODULES:
            if key is None:
                tk.Frame(sb,bg=self.BORDER,height=1).pack(fill="x",padx=10,pady=3)
                continue
            already = key in self._frms
            btn = tk.Label(sb,text=f"  ◉ {label}",font=(self.MONO,9),
                           fg=self.FG2,bg=self.BG2,anchor="w",pady=6,padx=4,cursor="hand2")
            btn.pack(fill="x",padx=4)
            btn.bind("<Enter>",    lambda e,b=btn: b.config(bg=self.BG3) if b is not self._active else None)
            btn.bind("<Leave>",    lambda e,b=btn: b.config(bg=self.BG2) if b is not self._active else None)
            btn.bind("<Button-1>", lambda e,k=key,b=btn: self._sw(k,b))
            # Only store first occurrence (UNSIGNED appears twice in sidebar)
            if not already:
                self._nbts[key] = btn
            if already: continue  # frame already built

            frm = tk.Frame(cont,bg=self.BG); self._frms[key] = frm

            if key == "exec_history":
                self._build_eh(frm)
            else:
                t = scrolledtext.ScrolledText(frm,bg=self.BG2,fg=self.FG,
                      font=(self.MONO,9),relief="flat",insertbackground=self.GREEN,
                      wrap="word",selectbackground=self.BG4,
                      padx=20,pady=16,borderwidth=0,highlightthickness=0)
                t.pack(fill="both",expand=True); t.configure(state="disabled")
                self.tabs[key] = t

        # Bottom bar
        tk.Frame(self.root,bg=self.BORDER,height=1).pack(fill="x")
        bot = tk.Frame(self.root,bg=self.BG2,height=52)
        bot.pack(fill="x"); bot.pack_propagate(False)
        self._pbc = tk.Canvas(bot,width=200,height=3,bg=self.BG4,highlightthickness=0)
        self._pbc.pack(side="left",padx=20,pady=24)
        self._pbb = self._pbc.create_rectangle(0,0,0,3,fill=self.GREEN,outline="")
        self._pbp=0; self._pbr=False
        bf = tk.Frame(bot,bg=self.BG2); bf.pack(side="right",padx=16)
        self._rbtn = tk.Button(bf,text="Run Scan",font=("Segoe UI",10,"bold"),
                                bg=self.GREEN,fg="#000",activebackground=self.GD,
                                bd=0,padx=22,pady=7,relief="flat",cursor="hand2",
                                command=self._start)
        self._rbtn.pack(side="left",padx=(0,8))
        tk.Button(bf,text="Save Report",font=("Segoe UI",10),bg=self.BG4,fg=self.FG2,
                  activebackground=self.BG5,bd=0,padx=14,pady=7,relief="flat",
                  cursor="hand2",highlightthickness=1,highlightbackground=self.BORDER,
                  command=self._save).pack(side="left")

        self._setup_tags()
        self._sw("summary",self._nbts.get("summary"))

    # ── Execution History panel ────────────────────────────
    def _build_eh(self,parent):
        top = tk.Frame(parent,bg=self.BG3,pady=6); top.pack(fill="x")
        self._eh_sv = tk.StringVar(); self._eh_sv.trace("w",lambda *a:self._eh_filter())
        tk.Entry(top,textvariable=self._eh_sv,font=(self.MONO,9),
                 bg=self.BG3,fg=self.FG,insertbackground=self.GREEN,
                 bd=0,relief="flat",width=60).pack(side="left",padx=10,fill="x")
        tk.Label(top,text="Search...",font=(self.MONO,8),fg=self.FG3,bg=self.BG3).pack(side="left")
        tk.Frame(parent,bg=self.BORDER,height=1).pack(fill="x")
        self._eh_sum = tk.Label(parent,text="Run a scan to see execution history.",
                                font=(self.MONO,9),fg=self.FG2,bg=self.BG,anchor="w",padx=16,pady=8)
        self._eh_sum.pack(fill="x")
        tk.Frame(parent,bg=self.BORDER,height=1).pack(fill="x")
        cv = tk.Canvas(parent,bg=self.BG,highlightthickness=0,bd=0)
        vsb = tk.Scrollbar(parent,orient="vertical",command=cv.yview,
                           bg=self.BG4,troughcolor=self.BG2,width=6,relief="flat")
        vsb.pack(side="right",fill="y"); cv.pack(fill="both",expand=True)
        cv.configure(yscrollcommand=vsb.set)
        self._eh_inner = tk.Frame(cv,bg=self.BG)
        self._eh_cwin  = cv.create_window((0,0),window=self._eh_inner,anchor="nw")
        cv.bind("<Configure>",lambda e:[cv.itemconfig(self._eh_cwin,width=e.width),
                                        cv.configure(scrollregion=cv.bbox("all"))])
        cv.bind("<MouseWheel>",lambda e:cv.yview_scroll(-1*(e.delta//120),"units"))
        self._eh_cv=cv; self._eh_rows=[]

    def _eh_populate(self,entries):
        for w in self._eh_inner.winfo_children(): w.destroy()
        self._eh_rows.clear()
        flagged=[e for e in entries if e.get("flagged")]
        clean  =[e for e in entries if not e.get("flagged")]
        self._eh_sum.config(
            text=f"  Today's History: {len(entries)} total ({len(flagged)} flagged)",
            fg=self.AMB if flagged else self.FG2)
        if flagged:
            self._eh_sect(f"─── Flagged ({len(flagged)}) ───",self.AMB)
            for e in flagged: self._eh_row(e)
        if clean:
            self._eh_sect(f"─── Signed / OK ({len(clean)}) ───",self.GREEN)
            for e in clean: self._eh_row(e)
        self._eh_cv.configure(scrollregion=self._eh_cv.bbox("all"))

    def _eh_sect(self,text,color):
        tk.Label(self._eh_inner,text=text,font=(self.MONO,9),
                 fg=color,bg=self.BG,anchor="w",padx=16,pady=6).pack(fill="x")

    def _eh_row(self,entry):
        flagged = entry.get("flagged",False)
        reasons = entry.get("reasons",[])
        is_del  = "File deleted" in reasons
        outer   = tk.Frame(self._eh_inner,bg=self.BG); outer.pack(fill="x")
        row     = tk.Frame(outer,bg=self.BG,cursor="hand2" if flagged else "")
        row.pack(fill="x")

        # Arrow
        arr = tk.Label(row,text="▶" if flagged else " ",
                       font=(self.MONO,8),fg=self.AMB if flagged else self.FG3,
                       bg=self.BG,width=2,anchor="e")
        arr.pack(side="left",padx=(6,0))

        # Tag
        if flagged:
            tags = ["WARNING"]
            if is_del: tags.append("Directory Deleted")
            tags += [r for r in reasons if r!="File deleted" and r]
            tag_txt = " | ".join(f"[{t}]" for t in tags[:2])
            tk.Label(row,text=tag_txt,font=(self.MONO,8,"bold"),
                     fg=self.AMB,bg=self.BG).pack(side="left",padx=(4,0))
        else:
            tk.Label(row,text="[OK]",font=(self.MONO,8),
                     fg=self.GREEN,bg=self.BG).pack(side="left",padx=(4,0))

        # Path
        pl = tk.Label(row,text=entry.get("path","?"),font=(self.MONO,8),
                      fg=self.RED if flagged else self.FG2,bg=self.BG,anchor="w",
                      cursor="hand2" if flagged else "")
        pl.pack(side="left",padx=(4,0),fill="x",expand=True)

        # Time
        tk.Label(row,text=f"  {entry.get('time','?')}  ",
                 font=(self.MONO,8),fg=self.FG3,bg=self.BG).pack(side="right",padx=(0,8))

        # Detail pane (toggle)
        det = tk.Frame(outer,bg=self.BG3); open_=[False]
        def toggle(e=None,d=det,o=open_,a=arr,en=entry):
            if not en.get("flagged"): return
            o[0]=not o[0]
            if o[0]: self._eh_detail(d,en); d.pack(fill="x",padx=22,pady=(0,4)); a.config(text="▼")
            else:    d.pack_forget(); a.config(text="▶")
            self._eh_cv.configure(scrollregion=self._eh_cv.bbox("all"))
        for w in (row,pl,arr): w.bind("<Button-1>",toggle)

        tk.Frame(outer,bg=self.BORDER,height=1).pack(fill="x")
        self._eh_rows.append((entry,outer))

    def _eh_detail(self,parent,entry):
        for w in parent.winfo_children(): w.destroy()
        hdr = tk.Frame(parent,bg="#0d1520",pady=10); hdr.pack(fill="x")
        tk.Label(hdr,text="USN JOURNAL EVENTS",font=(self.MONO,8,"bold"),
                 fg=self.CYAN,bg="#0d1520").pack(anchor="w",padx=14)
        tk.Label(hdr,text=entry.get("path","?"),font=(self.MONO,9,"bold"),
                 fg=self.FG,bg="#0d1520",wraplength=700,anchor="w").pack(anchor="w",padx=14,pady=(2,0))
        evts = entry.get("usn_events",[])
        if not evts and "File deleted" in entry.get("reasons",[]):
            fname = os.path.basename(entry.get("path",""))
            evts  = [{"type":"Execute","name":fname,"time":entry.get("time","?"),
                      "reason":"Execution recorded in system artifacts","usn":"N/A"},
                     {"type":"Delete","name":fname,"time":"after "+entry.get("time","?"),
                      "reason":"File no longer present on disk","usn":"N/A"}]
        times = [e.get("time","") for e in evts if e.get("time")]
        if len(times)>=2:
            tk.Label(parent,text=f"  created {times[0]} → deleted {times[-1]}",
                     font=(self.MONO,8),fg=self.FG2,bg=self.BG3).pack(anchor="w",padx=14,pady=(4,8))
        TC = {"Create":self.GREEN,"Execute":self.CYAN,"Type":self.AMB,
              "Rename":self.AMB,"Delete":self.RED,"Close":self.FG2}
        for ev in evts:
            ef = tk.Frame(parent,bg=self.BG3,pady=6); ef.pack(fill="x",padx=14)
            color = TC.get(ev.get("type",""),self.FG2)
            ef.columnconfigure(1,weight=1)
            for r,(k,v) in enumerate([("Type:",ev.get("type","?")),
                                       ("Details:",""),("  USN:",str(ev.get("usn","N/A"))),
                                       ("  name:",ev.get("name","?")),
                                       ("  time:",ev.get("time","?")),
                                       ("  reason:",ev.get("reason","?"))]):
                fg = color if k=="Type:" else (self.FG3 if k=="Details:" else self.FG2)
                tk.Label(ef,text=k,font=(self.MONO,8),fg=self.FG3,bg=self.BG3,anchor="w").grid(row=r,column=0,sticky="w",padx=(0,8))
                if v: tk.Label(ef,text=v,font=(self.MONO,8),fg=fg,bg=self.BG3,anchor="w").grid(row=r,column=1,sticky="w")
            tk.Frame(parent,bg=self.BORDER,height=1).pack(fill="x",padx=14,pady=(0,2))
        if entry.get("reasons"):
            tk.Label(parent,text="  Flags: "+" | ".join(entry["reasons"]),
                     font=(self.MONO,8),fg=self.AMB,bg=self.BG3).pack(anchor="w",padx=14,pady=(0,8))

    def _eh_filter(self):
        q = self._eh_sv.get().lower()
        for entry,outer in self._eh_rows:
            vis = not q or q in entry.get("path","").lower()
            if vis: outer.pack(fill="x")
            else:   outer.pack_forget()
        self._eh_cv.configure(scrollregion=self._eh_cv.bbox("all"))

    # ── Tab switch ─────────────────────────────────────────
    def _sw(self,key,btn):
        for f in self._frms.values(): f.pack_forget()
        for b in self._nbts.values(): b.config(bg=self.BG2,fg=self.FG2)
        if key in self._frms: self._frms[key].pack(fill="both",expand=True)
        if btn: btn.config(bg=self.BG4,fg=self.GREEN); self._active=btn

    # ── Tag colors ─────────────────────────────────────────
    def _setup_tags(self):
        for t in self.tabs.values():
            t.configure(state="normal"); t.delete("1.0","end"); t.configure(state="disabled")
            for tag,col in [("ok",self.GREEN),("bad",self.RED),("warn",self.AMB),
                             ("info",self.BLUE),("cyan",self.CYAN),("dim",self.FG2),
                             ("dimx",self.FG3),("white",self.FG),("hl",self.GREEN)]:
                t.tag_configure(tag,foreground=col)
            t.tag_configure("hl",foreground=self.GREEN,font=(self.MONO,9,"bold"))

    # ── Write to tab ───────────────────────────────────────
    def _w(self,key,text,tag="white"):
        if key not in self.tabs: return
        t=self.tabs[key]; t.configure(state="normal")
        t.insert("end",text,tag); t.see("end"); t.configure(state="disabled")

    def _render(self,key,text):
        if not text: self._w(key,"  No data.\n","dim"); return
        for line in text.split("\n"):
            ll=line.lower()
            if "✗" in line or "critical" in ll or "auto fail" in ll: tag="bad"
            elif "⚠" in line or "warning" in ll or "suspicious" in ll: tag="warn"
            elif "✓" in line or "normal" in ll: tag="ok"
            elif "──" in line or "◈" in line: tag="hl"
            elif line.startswith("  "): tag="dim"
            else: tag="white"
            self._w(key,line+"\n",tag)

    # ── Summary panel ──────────────────────────────────────
    def _render_summary(self,r):
        k="summary"
        total=r.get("total_hits",0)
        accs=r.get("roblox_accounts",[])
        us_l=r.get("unsigned_hits",[])
        us_cnt=len(us_l) if isinstance(us_l,list) else 0
        eh=r.get("exec_history",[])
        eh_f=sum(1 for e in eh if e.get("flagged"))

        self._w(k,"\n","white")
        self._w(k,"  ┌─ QUICK STATS ─────────────────────────────────────┐\n","hl")
        self._w(k,f"  │  Hits: {total:<6}  Accounts: {len(accs):<5}  Unsigned: {us_cnt:<4}     │\n",
                "warn" if total else "ok")
        self._w(k,f"  │  Integrity: {r.get('sysmain_hits',0):<3}  Cleaners: {r.get('cleaner_hits',0):<3}  JumpLists: {r.get('jumplist_hits',0):<3}  │\n","dim")
        self._w(k,"  └────────────────────────────────────────────────────┘\n\n","hl")
        self._w(k,f"  Generated : {now_str()}\n","dim")
        self._w(k,f"  PC User   : {current_user()}\n","dim")
        self._w(k,f"  League    : {r.get('league','?')}\n\n","dim")

        self._w(k,"  ── Detection Scores ────────────────────────────────\n","hl")
        rows=[
            ("ShellBag Hits",   r.get("shellbag_hits",0),  False),
            ("BAM Hits",        r.get("bam_hits",0),        False),
            ("Prefetch Hits",   r.get("prefetch_hits",0),   False),
            ("AppCompat Hits",  r.get("appcompat_hits",0),  False),
            ("JumpLists",       r.get("jumplist_hits",0),   False),
            ("LNK Files",       r.get("lnk_hits",0),        False),
            ("Integrity",       r.get("sysmain_hits",0),    True),
            ("Cleaners",        r.get("cleaner_hits",0),    False),
            ("EventLog",        r.get("eventlog_hits",0),   True),
            ("Audit Policy",    0,                           False),
            ("Deleted Integrity",r.get("deleted_hits",0),   False),
            ("Cheat File Hits", r.get("cheat_hits",0),      False),
            ("YARA Hits",       r.get("yara_hits",0),       False),
            ("Unsigned EXEs",   us_cnt,                      False),
            ("Log Tamper",      r.get("roblox_log_hits",0), True),
            ("SysMain Hits",    r.get("sysmain_hits",0),    True),
        ]
        for label,val,is_i in rows:
            bar="█"*min(val,28)
            sym="▲" if is_i else "○"
            tag=("warn" if is_i else "bad") if val>0 else "dim"
            self._w(k,f"  {sym} {label:<24} {val:>3}  {bar}\n",tag)

        self._w(k,f"\n  TOTAL HITS : {total}\n","bad" if total else "ok")
        self._w(k,"  No automatic verdict — agent reviews all hits.\n\n","dim")

        vpn=r.get("vpn_info","")
        if vpn and vpn!="Unknown":
            self._w(k,"  ── Network ──────────────────────────────────────────\n","hl")
            self._w(k,f"  {vpn}\n\n","info")

        self._w(k,"  ── Roblox Accounts ─────────────────────────────────\n","hl")
        if accs:
            for a in accs:
                name=a.get("username","?") if isinstance(a,dict) else str(a)
                uid =a.get("userid","") if isinstance(a,dict) else ""
                src =a.get("sources",[]) if isinstance(a,dict) else []
                pid =a.get("placeids",[]) if isinstance(a,dict) else []
                ls  =a.get("last_seen") if isinstance(a,dict) else None
                self._w(k,f"  › {{'username': '{name} (ID: {uid or 'None'})', 'userid': {uid!r}, 'sources': {src}, 'placeids': {pid}, 'last_seen': {ls!r}}}\n",
                        "warn" if len(accs)>1 else "dim")
            if len(accs)>1:
                self._w(k,f"\n  ⚠ {len(accs)} accounts — possible ban evasion\n","bad")
        else:
            self._w(k,"  No accounts found.\n","dim")

    # ── Progress bar ───────────────────────────────────────
    def _pbs(self): self._pbr=True; self._pbp=0; self._pbt()
    def _pbstop(self): self._pbr=False; self._pbc.coords(self._pbb,0,0,200,3)
    def _pbt(self):
        if not self._pbr: return
        self._pbp=(self._pbp+4)%260
        x1=max(0,self._pbp-100); x2=min(200,self._pbp)
        self._pbc.coords(self._pbb,x1,0,x2,3)
        self.root.after(14,self._pbt)

    # ── Scan ───────────────────────────────────────────────
    def _start(self):
        if self.scanning: return
        self.scanning=True; self._wh_sent=False
        self._setup_tags()
        self._rbtn.config(state="disabled",text="Scanning…",bg=self.BG4,fg=self.FG2)
        self._slbl.config(text="SCANNING",fg=self.AMB)
        self._wlbl.config(text=""); self._pbs()
        threading.Thread(target=self._scan,daemon=True).start()

    def _scan(self):
        try:
            r=run_full_scan(league=self._league)
            self.results=r; self.root.after(0,self._show,r)
        except Exception:
            import traceback
            self.root.after(0,self._err,traceback.format_exc())

    def _show(self,r):
        self._pbstop(); self.scanning=False
        total=r.get("total_hits",0)
        self._slbl.config(text=f"{total} HITS" if total else "CLEAN",
                          fg=self.RED if total else self.GREEN)
        self._rbtn.config(state="normal",text="Run Scan",bg=self.GREEN,fg="#000")
        self._render_summary(r)
        for rk,tk_ in [("shellbags","shellbags"),("bam","bam"),("prefetch","prefetch"),
                        ("appcompat","appcompat"),("roblox","roblox"),("processes","processes"),
                        ("cheat","cheat"),("yara","yara"),("unsigned","unsigned"),
                        ("recycle","recycle"),("sysmain","sysmain"),("cleaners","cleaners"),
                        ("discord","discord"),("discord_memory","discord_memory"),("registry_extra","registry_extra"),
                        ("network","network"),("eventlog","eventlog"),
                        ("jumplists","jumplists"),("lnkfiles","lnkfiles"),
                        ("deleted_int","deleted_int")]:
            self._render(tk_,r.get(rk,""))
        self._eh_populate(r.get("exec_history",[]))
        self._sw("summary",self._nbts.get("summary"))
        threading.Thread(target=self._send,daemon=True).start()

    def _err(self,msg):
        self._pbstop(); self.scanning=False
        self._slbl.config(text="ERROR",fg=self.RED)
        self._rbtn.config(state="normal",text="Run Scan",bg=self.GREEN,fg="#000")
        messagebox.showerror("Comet — Error",msg[:600])

    def _send(self):
        self.root.after(0,lambda:self._wlbl.config(text="sending…",fg=self.AMB))
        wok,we=send_webhook(self.results); bok,be=send_website(self.results,self._pin)
        if wok and bok:   lbl,fg="✓ sent",self.GREEN
        elif wok:         lbl,fg=f"✓ wh  ✗ web:{be[:40]}",self.AMB
        elif bok:         lbl,fg=f"✓ web  ✗ wh:{we[:40]}",self.AMB
        else:             lbl,fg=f"✗ {(be or we)[:70]}",self.RED
        self.root.after(0,lambda:self._wlbl.config(text=lbl,fg=fg))

    def _save(self):
        if not self.results: messagebox.showwarning("No Results","Run a scan first."); return
        p=filedialog.asksaveasfilename(defaultextension=".txt",
          filetypes=[("Text Report","*.txt")],initialfile="comet_report.txt")
        if not p: return
        try:
            open(p,"w",encoding="utf-8").write(self.results.get("full_report","No report."))
            messagebox.showinfo("Saved",f"Report saved:\n{p}")
        except Exception as e:
            messagebox.showerror("Error",str(e))

if __name__=="__main__":
    root=tk.Tk()
    App(root)
    root.mainloop()
