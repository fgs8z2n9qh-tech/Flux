"""
VRAM Monitor - a tiny, zero-dependency GPU video-memory monitor for Windows.

Shows total dedicated VRAM in use vs. the card's real capacity, a live history
graph, and which processes are using the memory.

Data sources (all in-process, no subprocess, no pip installs):
  * Live usage   : Windows PDH performance counters
                   \\GPU Adapter Memory(*)\\Dedicated Usage / Shared Usage
                   \\GPU Process Memory(*)\\Dedicated Usage  (per-process)
  * True capacity: registry HardwareInformation.qwMemorySize
                   (WMI's AdapterRAM is capped at 4 GB and is unreliable)
  * Process names: Toolhelp32 snapshot via kernel32

Works for AMD / NVIDIA / Intel because the GPU memory counters are part of the
Windows Display Driver Model (WDDM), independent of the vendor.
"""

import ctypes
import datetime
import json
import re
import sys
import os
import threading
import time
import winreg
import winsound
from collections import deque
from ctypes import wintypes

import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox

# --------------------------------------------------------------------------- #
#  Win32 / PDH plumbing via ctypes
# --------------------------------------------------------------------------- #

pdh = ctypes.WinDLL("pdh.dll")
kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

ERROR_SUCCESS = 0
PDH_MORE_DATA = 0x800007D2
PDH_FMT_LARGE = 0x00000400            # return values as 64-bit integers
PDH_CSTATUS_VALID_DATA = 0x00000000
PDH_CSTATUS_NEW_DATA = 0x00000001


class PDH_FMT_COUNTERVALUE(ctypes.Structure):
    # CStatus (DWORD) + 4 bytes padding (auto) + 8-byte union value
    _fields_ = [("CStatus", wintypes.DWORD),
                ("largeValue", ctypes.c_longlong)]


class PDH_FMT_COUNTERVALUE_ITEM_W(ctypes.Structure):
    _fields_ = [("szName", wintypes.LPWSTR),
                ("FmtValue", PDH_FMT_COUNTERVALUE)]


pdh.PdhOpenQueryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p,
                              ctypes.POINTER(wintypes.HANDLE)]
pdh.PdhAddEnglishCounterW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR,
                                      ctypes.c_void_p,
                                      ctypes.POINTER(wintypes.HANDLE)]
pdh.PdhCollectQueryData.argtypes = [wintypes.HANDLE]
pdh.PdhGetFormattedCounterArrayW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]
pdh.PdhCloseQuery.argtypes = [wintypes.HANDLE]
for _f in (pdh.PdhOpenQueryW, pdh.PdhAddEnglishCounterW,
           pdh.PdhCollectQueryData, pdh.PdhGetFormattedCounterArrayW,
           pdh.PdhCloseQuery):
    _f.restype = wintypes.DWORD


def read_counter_instances(counter_path):
    """Return [(instance_name, value_int), ...] for a wildcard counter path.

    Opens a fresh query each call so newly-started processes are always picked
    up (PDH expands wildcards at add-time, so a persistent query goes stale)."""
    query = wintypes.HANDLE()
    if pdh.PdhOpenQueryW(None, None, ctypes.byref(query)) != ERROR_SUCCESS:
        return []
    try:
        counter = wintypes.HANDLE()
        if pdh.PdhAddEnglishCounterW(query, counter_path, None,
                                     ctypes.byref(counter)) != ERROR_SUCCESS:
            return []
        # Memory counters are instantaneous; two back-to-back collects (no
        # sleep) guarantee a formatted value is available.
        pdh.PdhCollectQueryData(query)
        pdh.PdhCollectQueryData(query)

        size = wintypes.DWORD(0)
        count = wintypes.DWORD(0)
        status = pdh.PdhGetFormattedCounterArrayW(
            counter, PDH_FMT_LARGE, ctypes.byref(size),
            ctypes.byref(count), None)
        if status != PDH_MORE_DATA or size.value == 0:
            return []

        buf = (ctypes.c_byte * size.value)()
        status = pdh.PdhGetFormattedCounterArrayW(
            counter, PDH_FMT_LARGE, ctypes.byref(size),
            ctypes.byref(count), buf)
        if status != ERROR_SUCCESS:
            return []

        items = ctypes.cast(
            buf, ctypes.POINTER(PDH_FMT_COUNTERVALUE_ITEM_W * count.value)
        ).contents
        out = []
        for it in items:
            if it.FmtValue.CStatus in (PDH_CSTATUS_VALID_DATA,
                                       PDH_CSTATUS_NEW_DATA):
                out.append((it.szName, int(it.FmtValue.largeValue)))
        return out
    finally:
        pdh.PdhCloseQuery(query)


# ---- Process name lookup via Toolhelp32 snapshot --------------------------- #

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * 260)]


kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE,
                                     ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.argtypes = [wintypes.HANDLE,
                                    ctypes.POINTER(PROCESSENTRY32W)]
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


def process_names():
    """Return {pid: exe_name} for all running processes."""
    names = {}
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE or snap is None:
        return names
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            names[entry.th32ProcessID] = entry.szExeFile
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
        return names
    finally:
        kernel32.CloseHandle(snap)


# ---- Ending a process to free its VRAM ------------------------------------- #

PROCESS_TERMINATE = 0x0001
ERROR_ACCESS_DENIED = 5

kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.TerminateProcess.restype = wintypes.BOOL
kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]

# Processes we refuse to end: killing these can crash Windows or the desktop
# session. Names are lower-case, without the ".exe".
CRITICAL_PROCESSES = {
    "system", "registry", "smss", "csrss", "wininit", "winlogon",
    "services", "lsass", "svchost", "dwm", "fontdrvhost", "sihost",
    "ctfmon", "explorer", "taskhostw", "dllhost", "conhost", "audiodg",
}


def terminate_pids(pids, expected_name):
    """Force-terminate the given pids — but only those that STILL belong to a
    process called `expected_name`.

    Windows recycles PIDs aggressively, and these pids were captured a sampling
    cycle (and a confirmation dialog) ago. Re-checking the live name at kill
    time stops us from terminating an unrelated process that inherited the pid,
    and keeps the critical-process guard honest even after reuse.

    Returns (killed, denied, failed, skipped)."""
    expected = expected_name.lower()
    current = process_names()  # fresh snapshot at kill time
    killed = denied = failed = skipped = 0
    for pid in pids:
        name = current.get(int(pid))
        if name is None:
            skipped += 1            # process already exited
            continue
        norm = re.sub(r"\.exe$", "", name, flags=re.IGNORECASE).lower()
        if norm != expected or norm in CRITICAL_PROCESSES:
            skipped += 1            # pid reused by a different / critical proc
            continue
        h = kernel32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
        if not h:
            # No intervening call, so last-error is OpenProcess's.
            if ctypes.get_last_error() == ERROR_ACCESS_DENIED:
                denied += 1
            else:
                failed += 1
            continue
        ok = kernel32.TerminateProcess(h, 1)
        # Capture the error NOW, before CloseHandle overwrites the saved slot.
        err = 0 if ok else ctypes.get_last_error()
        kernel32.CloseHandle(h)
        if ok:
            killed += 1
        elif err == ERROR_ACCESS_DENIED:
            denied += 1
        else:
            failed += 1
    return killed, denied, failed, skipped


# ---- True VRAM capacity from the registry ---------------------------------- #

def vram_total_bytes():
    """Largest HardwareInformation.qwMemorySize across display adapters."""
    best = 0
    best_name = "GPU"
    base = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
    except OSError:
        return best, best_name
    try:
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            if not sub.isdigit():
                continue
            try:
                k = winreg.OpenKey(root, sub)
            except OSError:
                continue
            try:
                mem, _ = winreg.QueryValueEx(k, "HardwareInformation.qwMemorySize")
                if isinstance(mem, int) and mem > best:
                    best = mem
                    try:
                        best_name, _ = winreg.QueryValueEx(k, "DriverDesc")
                    except OSError:
                        pass
            except OSError:
                pass
            finally:
                winreg.CloseKey(k)
    finally:
        winreg.CloseKey(root)
    return best, best_name


# --------------------------------------------------------------------------- #
#  Sampling
# --------------------------------------------------------------------------- #

_PID_RE = re.compile(r"pid_(\d+)")


def sample(name_cache=None, force_names=False):
    """Collect one snapshot of GPU memory usage.

    Returns dict with: dedicated, shared (bytes) and `procs`, a list of
    (name, bytes, [pids]) for the heaviest consumers, sorted descending.

    Naming: a full Toolhelp32 snapshot (`process_names`) is ~4 ms and dominates
    the per-tick cost, yet only the handful of pids actually using GPU memory
    ever need a name. Pass a persistent `name_cache` dict and we snapshot only
    when a *new* GPU pid appears (or `force_names` for a periodic self-heal
    against pid reuse); otherwise the cached names are reused for free."""
    dedicated = sum(v for _, v in read_counter_instances(
        r"\GPU Adapter Memory(*)\Dedicated Usage"))
    shared = sum(v for _, v in read_counter_instances(
        r"\GPU Adapter Memory(*)\Shared Usage"))

    self_pid = os.getpid()
    per_pid = {}
    for name, val in read_counter_instances(
            r"\GPU Process Memory(*)\Dedicated Usage"):
        m = _PID_RE.search(name or "")
        if not m:
            continue
        pid = int(m.group(1))
        per_pid[pid] = per_pid.get(pid, 0) + val

    # Resolve names for the GPU-using pids only, via the cache when supplied.
    gpu_pids = [p for p, v in per_pid.items() if v > 0 and p != self_pid]
    if name_cache is None:
        names = process_names()
    elif force_names or any(p not in name_cache for p in gpu_pids):
        allnames = process_names()
        name_cache.clear()                   # rebuild → bounded, no stale pids
        for p in gpu_pids:
            name_cache[p] = allnames.get(p)
        names = name_cache
    else:
        names = name_cache                   # set unchanged → snapshot skipped

    per_name = {}  # label -> [bytes, set(pids)]
    for pid, val in per_pid.items():
        if val <= 0 or pid == self_pid:
            continue
        label = names.get(pid)
        if not label:
            label = f"pid {pid}"
        else:
            label = re.sub(r"\.exe$", "", label, flags=re.IGNORECASE)
        entry = per_name.setdefault(label, [0, set()])
        entry[0] += val
        entry[1].add(pid)

    procs = sorted(
        ((name, v[0], sorted(v[1])) for name, v in per_name.items()),
        key=lambda t: t[1], reverse=True)
    tracked = sum(per_pid.values())          # all pids, incl. ones we don't list
    nproc = sum(1 for x in per_pid.values() if x > 0)
    return {"dedicated": dedicated, "shared": shared, "procs": procs,
            "tracked": tracked, "nproc": nproc}


# --------------------------------------------------------------------------- #
#  GPU utilization — a rate counter, so it needs two samples a refresh apart
# --------------------------------------------------------------------------- #

PDH_FMT_DOUBLE = 0x00000200
GPU_ENGINE_COUNTER = r"\GPU Engine(*)\Utilization Percentage"
_ENGTYPE_RE = re.compile(r"engtype_(\w+)")


class PDH_FMT_COUNTERVALUE_DOUBLE(ctypes.Structure):
    _fields_ = [("CStatus", wintypes.DWORD),
                ("doubleValue", ctypes.c_double)]


class PDH_ITEM_DOUBLE(ctypes.Structure):
    _fields_ = [("szName", wintypes.LPWSTR),
                ("FmtValue", PDH_FMT_COUNTERVALUE_DOUBLE)]


def _read_double_array(counter):
    size = wintypes.DWORD(0)
    count = wintypes.DWORD(0)
    st = pdh.PdhGetFormattedCounterArrayW(
        counter, PDH_FMT_DOUBLE, ctypes.byref(size), ctypes.byref(count), None)
    if st != PDH_MORE_DATA or size.value == 0:
        return []
    buf = (ctypes.c_byte * size.value)()
    if pdh.PdhGetFormattedCounterArrayW(
            counter, PDH_FMT_DOUBLE, ctypes.byref(size),
            ctypes.byref(count), buf) != ERROR_SUCCESS:
        return []
    items = ctypes.cast(
        buf, ctypes.POINTER(PDH_ITEM_DOUBLE * count.value)).contents
    return [(it.szName, it.FmtValue.doubleValue)
            for it in items if it.FmtValue.CStatus in (0, 1)]


class RateSampler:
    """Reads a wildcard *rate* counter (utilization), which needs two samples a
    refresh apart. Keeps a query primed from the previous tick and opens a fresh
    one each read, so newly-started processes appear with one tick of latency."""

    def __init__(self, path):
        self.path = path
        self._primed = None

    def _open_primed(self):
        q = wintypes.HANDLE()
        if pdh.PdhOpenQueryW(None, None, ctypes.byref(q)) != ERROR_SUCCESS:
            return None
        c = wintypes.HANDLE()
        if pdh.PdhAddEnglishCounterW(q, self.path, None,
                                     ctypes.byref(c)) != ERROR_SUCCESS:
            pdh.PdhCloseQuery(q)
            return None
        pdh.PdhCollectQueryData(q)        # first sample (prime)
        return (q, c)

    def read(self):
        out = []
        if self._primed is not None:
            q, c = self._primed
            if pdh.PdhCollectQueryData(q) == ERROR_SUCCESS:
                out = _read_double_array(c)
            pdh.PdhCloseQuery(q)
        self._primed = self._open_primed()
        return out


def gpu_utilization(sampler):
    """Returns (headline %, by-engine-type dict). Headline = busiest engine
    type (3D / Video / Copy / Compute …)."""
    by_type = {}
    for name, val in sampler.read():
        m = _ENGTYPE_RE.search(name or "")
        t = m.group(1) if m else "?"
        by_type[t] = by_type.get(t, 0.0) + min(100.0, max(0.0, val))
    busiest = max(by_type.values()) if by_type else 0.0
    return max(0.0, min(100.0, busiest)), by_type


def cpu_percent(sampler):
    """Total CPU % from a RateSampler on \\Processor(_Total)\\% Processor Time."""
    for name, val in sampler.read():
        if name and name.lower() == "_total":
            return max(0.0, min(100.0, val))
    return 0.0


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


def ram_info():
    """(percent used, used bytes, total bytes) of physical RAM."""
    m = MEMORYSTATUSEX()
    m.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
        return 0.0, 0, 0
    used = m.ullTotalPhys - m.ullAvailPhys
    return float(m.dwMemoryLoad), used, m.ullTotalPhys


CPU_COUNTER = r"\Processor(_Total)\% Processor Time"


# --------------------------------------------------------------------------- #
#  UI
# --------------------------------------------------------------------------- #

BG          = "#0a0e0c"   # window base (matches gradient bottom)
GRAD_TOP    = (22, 74, 58)   # deep green — top of the backdrop gradient
GRAD_BOT    = (9, 13, 11)    # near-black green — bottom
PANEL       = "#101714"   # cards
PANEL_HOVER = "#15211c"
TRACK       = "#0a120e"   # recessed bar tracks / mini-bars inside cards
GRID        = "#1f2a26"   # gridlines / disabled controls
FG          = "#e9f1ec"
MUTED       = "#8aa399"
ACCENT      = "#34d399"   # green
ACCENT_DIM  = "#1f8a66"   # scrollbar thumb
ACCENT_WARN = "#fbbf24"   # amber
ACCENT_HOT  = "#f87171"   # red (✕ buttons)
ACCENT_HOT2 = "#ff5a5a"   # brighter red (✕ hover)
GPU_LINE    = "#5eead4"   # teal — GPU-load history line

# Selectable accent themes: (accent, scrollbar-dim, secondary-line)
ACCENTS = {
    "green":  ("#34d399", "#1f8a66", "#5eead4"),
    "blue":   ("#38bdf8", "#1e6f99", "#7dd3fc"),
    "purple": ("#a78bfa", "#6d51c4", "#c4b5fd"),
    "pink":   ("#f472b6", "#9d3a73", "#f9a8d4"),
    "amber":  ("#fbbf24", "#a87c12", "#fcd34d"),
    "cyan":   ("#22d3ee", "#157f8f", "#67e8f9"),
}


def apply_accent(name):
    """Swap the accent colour globally (canvas elements re-read it each paint)."""
    global ACCENT, ACCENT_DIM, GPU_LINE
    if name in ACCENTS:
        ACCENT, ACCENT_DIM, GPU_LINE = ACCENTS[name]

REFRESH_MS = 1000
HISTORY = 120
ALERT_PCT = 90            # toast + beep when VRAM crosses this
LEAK_GB = 1.5             # cached-with-no-owner above this → flag a possible leak
LOG_EVERY = 60            # ticks (≈ seconds) between log rows


def gb(n):
    return n / (1024 ** 3)


def fmt_gb(n):
    return f"{gb(n):.1f}"


def usage_color(pct):
    if pct >= 90:
        return ACCENT_HOT
    if pct >= 70:
        return ACCENT_WARN
    return ACCENT


def _hwnd(root):
    """Top-level window handle for a Tk root."""
    return ctypes.windll.user32.GetParent(root.winfo_id()) or root.winfo_id()


def _win_chrome(root):
    """A borderless window that still gets a taskbar button, Windows 11 rounded
    corners and a drop shadow. Call once after the window is realised."""
    try:
        hwnd = _hwnd(root)
        u = ctypes.windll.user32
        GWL_EXSTYLE, WS_EX_APPWINDOW, WS_EX_TOOLWINDOW = -20, 0x40000, 0x80
        ex = u.GetWindowLongW(hwnd, GWL_EXSTYLE)
        u.SetWindowLongW(hwnd, GWL_EXSTYLE,
                         (ex & ~WS_EX_TOOLWINDOW) | WS_EX_APPWINDOW)
        dwm = ctypes.windll.dwmapi
        # DWMWA_WINDOW_CORNER_PREFERENCE = 33, DWMWCP_ROUND = 2
        pref = ctypes.c_int(2)
        dwm.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(pref),
                                  ctypes.sizeof(pref))

        class MARGINS(ctypes.Structure):
            _fields_ = [("l", ctypes.c_int), ("r", ctypes.c_int),
                        ("t", ctypes.c_int), ("b", ctypes.c_int)]
        dwm.DwmExtendFrameIntoClientArea(hwnd, ctypes.byref(MARGINS(1, 1, 1, 1)))
        root.withdraw()
        root.after(10, root.deiconify)
    except Exception:
        pass


def _round_corners(win):
    """Apply Windows 11 rounded corners to a borderless Tk window."""
    try:
        hwnd = _hwnd(win)
        pref = ctypes.c_int(2)               # DWMWCP_ROUND
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 33, ctypes.byref(pref), ctypes.sizeof(pref))
    except Exception:
        pass


def _app_dir():
    """Folder of the running app (next to the exe when frozen)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _migrate_legacy_file(new_name, old_name):
    """One-time rename of a legacy vrameter_* data file to its flux_* name, so
    the rebrand keeps the user's settings and leak-log (never orphan them)."""
    d = _app_dir()
    new, old = os.path.join(d, new_name), os.path.join(d, old_name)
    if os.path.exists(old) and not os.path.exists(new):
        try:
            os.replace(old, new)
        except OSError:
            pass


class Config:
    """Tiny JSON settings store kept next to the app."""
    DEFAULTS = {"refresh_ms": 1000, "alert_pct": 90, "accent": "green",
                "show_temp": True, "show_cpu": True, "geometry": None,
                "mini_geometry": None}

    def __init__(self):
        _migrate_legacy_file("flux_config.json", "vrameter_config.json")
        self.path = os.path.join(_app_dir(), "flux_config.json")
        self.data = dict(self.DEFAULTS)
        try:
            with open(self.path, encoding="utf-8") as f:
                self.data.update(json.load(f))
        except Exception:
            pass

    def get(self, k):
        return self.data.get(k, self.DEFAULTS.get(k))

    def set(self, k, v):
        self.data[k] = v
        self.save()

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
        except Exception:
            pass


class GpuSensors:
    """Optional GPU temperature / clocks / power / fan via LibreHardwareMonitor
    (pythonnet). AMD/NVIDIA/Intel GPU sensors are read through the user-mode
    driver, so no administrator rights are needed. Silently disables itself if
    pythonnet or the DLLs aren't available — the app still runs without temps."""

    def __init__(self):
        self.ok = False
        self.data = {}
        self._gpu = None
        try:
            dll = resource_path("LibreHardwareMonitorLib.dll")
            d = os.path.dirname(dll)
            try:
                os.add_dll_directory(d)
            except Exception:
                pass
            if d not in sys.path:
                sys.path.append(d)
            import clr
            clr.AddReference(dll)
            from LibreHardwareMonitor.Hardware import Computer
            self._comp = Computer()
            self._comp.IsGpuEnabled = True
            self._comp.Open()
            for hw in self._comp.Hardware:
                if "Gpu" in str(hw.HardwareType):
                    self._gpu = hw
                    break
            self.ok = self._gpu is not None
        except Exception as exc:
            print("GPU sensors unavailable:", exc, file=sys.stderr)

    def read(self):
        if not self.ok:
            return self.data
        try:
            self._gpu.Update()
            out = {}
            for s in self._gpu.Sensors:
                v = s.Value
                if v is None:
                    continue
                t, n = str(s.SensorType), s.Name
                if t == "Temperature":
                    if n == "GPU Core":
                        out["temp"] = v
                    elif "Hot Spot" in n:
                        out["hotspot"] = v
                    elif n == "GPU Memory":
                        out["vramtemp"] = v
                elif t == "Clock":
                    if n == "GPU Core":
                        out["coreclk"] = v
                    elif n == "GPU Memory":
                        out["memclk"] = v
                elif t == "Power" and ("Package" in n or "Total" in n):
                    out["power"] = v
                elif t == "Fan":
                    out["fan"] = v
            self.data = out
            return out
        except Exception:
            return self.data


class _HotkeyThread(threading.Thread):
    """Registers a global hotkey and sets an Event when it's pressed. Runs its
    own Win32 message loop on a daemon thread; the Tk side polls the flag."""

    def __init__(self, mod, vk, flag):
        super().__init__(daemon=True)
        self.mod, self.vk, self.flag = mod, vk, flag

    def run(self):
        u = ctypes.windll.user32
        if not u.RegisterHotKey(None, 1, self.mod, self.vk):
            return
        msg = wintypes.MSG()
        while u.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            if msg.message == 0x0312:        # WM_HOTKEY
                self.flag.set()


class _Scrollbar(tk.Canvas):
    """Slim, themed vertical scrollbar wired to a target canvas's yview."""

    def __init__(self, parent, target, width=7, bg=BG):
        super().__init__(parent, width=width, highlightthickness=0, bd=0, bg=bg)
        self.target = target
        self.first, self.last = 0.0, 1.0
        target.configure(yscrollcommand=self._set)
        self.bind("<Configure>", lambda e: self._draw())
        self.bind("<Button-1>", self._jump)
        self.bind("<B1-Motion>", self._jump)

    def _set(self, first, last):
        self.first, self.last = float(first), float(last)
        self._draw()

    def _draw(self):
        self.delete("all")
        h = self.winfo_height() or 1
        w = int(self["width"])
        if self.last - self.first >= 0.999:
            return                       # everything fits; no thumb
        y0 = self.first * h
        y1 = max(self.last * h, y0 + w + 2)
        self.create_oval(0, y0, w, y0 + w, fill=ACCENT_DIM, outline="")
        self.create_oval(0, y1 - w, w, y1, fill=ACCENT_DIM, outline="")
        self.create_rectangle(0, y0 + w / 2, w, y1 - w / 2,
                              fill=ACCENT_DIM, outline="")

    def _jump(self, e):
        h = self.winfo_height() or 1
        span = max(0.0, self.last - self.first)
        self.target.yview_moveto(min(max(0.0, e.y / h - span / 2),
                                     1.0 - span))


class App:
    def __init__(self, root):
        self.root = root
        self.cfg = Config()
        apply_accent(self.cfg.get("accent"))
        self.refresh_ms = int(self.cfg.get("refresh_ms"))
        self.alert_pct = int(self.cfg.get("alert_pct"))
        self.show_cpu = bool(self.cfg.get("show_cpu"))
        self.show_temp_pref = bool(self.cfg.get("show_temp"))

        self.total, self.gpu_name = vram_total_bytes()
        self.hist_vram = deque([0.0] * HISTORY, maxlen=HISTORY)
        self.hist_gpu = deque([0.0] * HISTORY, maxlen=HISTORY)
        self.hist_temp = deque([0.0] * HISTORY, maxlen=HISTORY)
        self.gpu_sampler = RateSampler(GPU_ENGINE_COUNTER)
        self.cpu_sampler = RateSampler(CPU_COUNTER)
        self.sensors = GpuSensors()
        self.sensors_data = {}
        self.gpu_engines = {}
        self.cpu = 0.0
        self.ram = (0.0, 0, 0)
        self.last = None
        self.filter = ""                 # process search filter
        self._status_after = None
        self._resize_after = None
        self._last_paint = 0.0
        self._peak = 0
        self._ever_visible = False       # window has been shown at least once
        self._proc_hist = {}             # name -> deque of recent bytes (growth)
        self._growing = set()            # names whose VRAM keeps climbing
        self._cache_since = None
        self._alerted = False
        self._prev_used = 0
        self._snap_cooldown = 0
        self._tickn = 0
        self._name_cache = {}            # pid -> exe name, for GPU-using pids
        _migrate_legacy_file("flux_log.csv", "vrameter_log.csv")
        self._log_path = os.path.join(_app_dir(), "flux_log.csv")

        self.temp_on = self.sensors.ok and self.show_temp_pref

        root.title("Flux")
        root.configure(bg=BG)
        cb = 248                              # top + VRAM + GPU-load cards
        if self.temp_on:
            cb += 112
        cb += 58                              # FREE / SHARED row
        if self.show_cpu:
            cb += 58                          # CPU / RAM row
        cb += 40                              # cached note
        w, h = 720, cb + 84
        self._minw, self._minh = w, h
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        # Width is fixed by design; only the height + position are remembered.
        m = re.match(r"\d+x(\d+)\+(-?\d+)\+(-?\d+)", self.cfg.get("geometry") or "")
        if m:
            sv_h, x, yy = m.groups()
            root.geometry(f"{w}x{max(h, int(sv_h))}+{x}+{yy}")
        else:
            root.geometry(f"{w}x{h}+{max(0,(sw-w)//2)}+{max(0,(sh-h)//3)}")
        root.overrideredirect(True)          # remove the native title bar

        self.f_cap = tkfont.Font(family="Segoe UI", size=8)
        self.f_title = tkfont.Font(family="Segoe UI Semibold", size=12)
        self.f_titlebar = tkfont.Font(family="Segoe UI Semibold", size=10)
        self.f_icon = tkfont.Font(family="Segoe MDL2 Assets", size=10)
        self.f_huge = tkfont.Font(family="Segoe UI", size=34, weight="bold")
        self.f_pct = tkfont.Font(family="Segoe UI", size=21, weight="bold")
        self.f_cardnum = tkfont.Font(family="Segoe UI", size=22, weight="bold")
        self.f_mid = tkfont.Font(family="Segoe UI", size=10)
        self.f_stat = tkfont.Font(family="Segoe UI Semibold", size=13)
        self.f_small = tkfont.Font(family="Segoe UI", size=9)
        self.f_mono = tkfont.Font(family="Consolas", size=9)

        # Custom title bar (replaces the OS one) ---------------------------- #
        self._pinned = False
        self._maxed = False
        tb = tk.Frame(root, bg=BG, height=40)
        tb.pack(fill="x", side="top")
        tb.pack_propagate(False)
        # Flux mark: two flowing waves (echoes the app icon), in the accent hue
        logo = tk.Canvas(tb, width=22, height=20, bg=BG, highlightthickness=0)
        logo.pack(side="left", padx=(14, 8))
        logo.create_line(1, 8, 6, 5, 11, 8, 16, 11, 21, 8,
                         fill=GPU_LINE, width=2, smooth=True, capstyle="round")
        logo.create_line(1, 13, 6, 10, 11, 13, 16, 16, 21, 13,
                         fill=ACCENT, width=2, smooth=True, capstyle="round")
        title = tk.Label(tb, text="Flux", bg=BG, fg=FG,
                         font=self.f_titlebar)
        title.pack(side="left")
        self._btn_close = self._winbtn(tb, "", self._close, close=True)
        self._btn_max = self._winbtn(tb, "", self._toggle_max)
        self._btn_min = self._winbtn(tb, "", self._minimize)
        self._btn_pin = self._winbtn(tb, "", self._toggle_pin, pin=True)
        self._winbtn(tb, "", self._open_settings)   # gear
        self._winbtn(tb, "", self._open_log)        # history / log
        self._winbtn(tb, "", self._enter_mini)  # collapse to mini strip
        for wdg in (tb, title, logo):
            wdg.bind("<Button-1>", self._start_move)
            wdg.bind("<B1-Motion>", self._do_move)
            wdg.bind("<Double-Button-1>", lambda e: self._toggle_max())
        tk.Frame(root, bg=GRID, height=1).pack(fill="x")

        # Status line (full width, bottom) ---------------------------------- #
        self.lbl_status = tk.Label(root, text="", bg=BG, fg=MUTED,
                                   font=self.f_small, anchor="w")
        self.lbl_status.pack(side="bottom", fill="x", padx=16, pady=(2, 8))

        # Body: metric cards on the LEFT, processes on the RIGHT ------------- #
        body = tk.Frame(root, bg=BG)
        body.pack(fill="both", expand=True)

        # Left — metric cards (fixed-width column, drawn on a canvas)
        self.cards = tk.Canvas(body, width=300, highlightthickness=0, bd=0,
                               bg=BG)
        self.cards.pack(side="left", fill="y")
        self.cards.bind("<Configure>", self._on_cards_resize)

        # Right — processes card
        card = tk.Frame(body, bg=PANEL)
        card.pack(side="left", fill="both", expand=True, padx=(2, 14),
                  pady=(8, 6))
        phead = tk.Frame(card, bg=PANEL)
        phead.pack(fill="x", padx=12, pady=(10, 4))
        self.lbl_prochead = tk.Label(phead, text="PROCESSES", bg=PANEL,
                                     fg=MUTED, font=self.f_small)
        self.lbl_prochead.pack(side="left")
        self.search = tk.Entry(phead, bg=TRACK, fg=FG, insertbackground=FG,
                               font=self.f_small, width=18, relief="flat",
                               highlightthickness=1, highlightbackground=GRID,
                               highlightcolor=ACCENT)
        self.search.pack(side="right", ipady=2)
        self.search.bind("<KeyRelease>", self._on_search)
        tk.Label(phead, text="", bg=PANEL, fg=MUTED,
                 font=self.f_icon).pack(side="right", padx=(0, 6))
        lwrap = tk.Frame(card, bg=PANEL)
        lwrap.pack(fill="both", expand=True, padx=(12, 6), pady=(0, 10))
        # The process list is drawn as canvas ITEMS (not embedded widgets) — a
        # frame-of-widgets here made every window resize re-lay-out ~120 widgets
        # (~270 ms). Canvas items repaint in a few ms and scroll for free.
        self.plist = tk.Canvas(lwrap, bg=PANEL, highlightthickness=0, bd=0)
        self.plist.pack(side="left", fill="both", expand=True)
        self.scroll = _Scrollbar(lwrap, self.plist, bg=PANEL)
        self.scroll.pack(side="right", fill="y", padx=(5, 0))
        self._plist_w = 0
        self._proc_list = []          # (name, bytes, pids, critical) per row
        self._hover_i = -1
        self.plist.bind_all("<MouseWheel>", self._on_wheel)
        self.plist.bind("<Configure>", self._on_plist_config)
        self.plist.bind("<Button-1>", self._plist_click)
        self.plist.bind("<Motion>", self._plist_motion)
        self.plist.bind("<Leave>", lambda e: self._plist_hover(-1))

        # Resize grip (bottom-right) ----------------------------------------- #
        grip = tk.Canvas(root, width=16, height=16, bg=BG,
                         highlightthickness=0, cursor="sb_v_double_arrow")
        grip.place(relx=1.0, rely=1.0, x=-3, y=-3, anchor="se")
        for o in (4, 8, 12):
            grip.create_line(15, o, o, 15, fill=GRID)
        grip.bind("<B1-Motion>", self._do_resize)

        # Compact mini-mode strip (own borderless top-most window, hidden) -- #
        self._mini_on = False
        self.mini = tk.Toplevel(root)
        self.mini.title("Flux mini")
        self.mini.withdraw()
        self.mini.overrideredirect(True)
        self.mini.attributes("-topmost", True)
        self.mini.configure(bg=BG)
        self.mini.geometry("360x44")
        mf = tk.Frame(self.mini, bg=PANEL)
        mf.pack(fill="both", expand=True)
        mclose = tk.Label(mf, text=chr(0xE8BB), font=self.f_icon, bg=PANEL,
                          fg=MUTED, width=3)
        mclose.pack(side="right", fill="y")
        mclose.bind("<Button-1>", lambda e: self._close())
        mclose.bind("<Enter>", lambda e: mclose.config(bg="#c42b1c", fg="#fff"))
        mclose.bind("<Leave>", lambda e: mclose.config(bg=PANEL, fg=MUTED))
        mexp = tk.Label(mf, text=chr(0xE740), font=self.f_icon, bg=PANEL,
                        fg=MUTED, width=3)
        mexp.pack(side="right", fill="y")
        mexp.bind("<Button-1>", lambda e: self._exit_mini())
        mexp.bind("<Enter>", lambda e: mexp.config(bg=PANEL_HOVER, fg=FG))
        mexp.bind("<Leave>", lambda e: mexp.config(bg=PANEL, fg=MUTED))
        self.mini_canvas = tk.Canvas(mf, bg=PANEL, highlightthickness=0, bd=0)
        self.mini_canvas.pack(side="left", fill="both", expand=True,
                              padx=(11, 2))
        for wdg in (mf, self.mini_canvas):
            wdg.bind("<Button-1>", self._mini_start)
            wdg.bind("<B1-Motion>", self._mini_move)
            wdg.bind("<Double-Button-1>", lambda e: self._exit_mini())

        # Global show/hide hotkey: Ctrl+Alt+V (MOD_ALT|MOD_CONTROL, 'V')
        self._hidden = False
        self._hk_flag = threading.Event()
        _HotkeyThread(0x0001 | 0x0002, 0x56, self._hk_flag).start()
        self._poll_hotkey()

        self.tick()

    def _poll_hotkey(self):
        if self._hk_flag.is_set():
            self._hk_flag.clear()
            self._toggle_visible()
        self.root.after(120, self._poll_hotkey)

    def _toggle_visible(self):
        win = self.mini if self._mini_on else self.root
        if self._hidden:
            win.deiconify()
            win.lift()
            win.attributes("-topmost", True)
            if win is self.root:
                win.after(350,
                          lambda: win.attributes("-topmost", self._pinned))
            self._hidden = False
        else:
            win.withdraw()
            self._hidden = True

    # -- compact mini mode ------------------------------------------------- #
    def _enter_mini(self):
        try:
            if not self._maxed:
                self.cfg.set("geometry", self.root.geometry())
        except Exception:
            pass
        # Place the strip at the top-right of wherever the MAIN window is right
        # now, so it stays on the same monitor you're looking at.
        mx, my = self.root.winfo_x(), self.root.winfo_y()
        mw = self.root.winfo_width()
        self.root.withdraw()
        self.mini.geometry(f"360x44+{mx + mw - 360}+{max(my, 0)}")
        self.mini.deiconify()
        self.mini.lift()
        self.mini.attributes("-topmost", True)
        self.mini.update_idletasks()
        _round_corners(self.mini)
        self._mini_on = True
        self._mini_paint(self.last or {})

    def _exit_mini(self):
        try:
            self.cfg.set("mini_geometry", self.mini.geometry())
        except Exception:
            pass
        self.mini.withdraw()
        self._mini_on = False
        self.root.deiconify()
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.after(300, lambda: self.root.attributes("-topmost",
                                                          self._pinned))

    def _mini_start(self, e):
        self._mmx = e.x_root - self.mini.winfo_x()
        self._mmy = e.y_root - self.mini.winfo_y()

    def _mini_move(self, e):
        self.mini.geometry(f"+{e.x_root - self._mmx}+{e.y_root - self._mmy}")

    def _mini_paint(self, d):
        c = self.mini_canvas
        c.delete("all")
        y = (c.winfo_height() or 42) / 2
        used = d.get("dedicated", 0)
        pct = (used / self.total * 100) if self.total else 0
        col = usage_color(pct)
        gpu = d.get("gpu", 0.0)
        temp = self.sensors_data.get("temp")
        fs, fsm = self.f_stat, self.f_small

        def txt(x, s, fill, fnt):
            c.create_text(x, y, anchor="w", text=s, fill=fill, font=fnt)
            return x + fnt.measure(s)

        x = txt(0, fmt_gb(used), FG, fs) + 4
        x = txt(x, f"/ {fmt_gb(self.total)}", MUTED, fsm) + 10
        # thin usage bar
        bw = 46
        self._round_rect(c, x, y - 3, x + bw, y + 3, 3, fill=TRACK)
        fw = bw * min(pct, 100) / 100
        if fw > 2:
            self._round_rect(c, x, y - 3, x + fw, y + 3, 3, fill=col)
        x += bw + 9
        x = txt(x, f"{pct:.0f}%", col, fs) + 13
        x = txt(x, f"GPU {gpu:.0f}%", MUTED, fsm) + 11
        if temp is not None:
            tcol = (ACCENT if temp < 75 else
                    ACCENT_WARN if temp < 85 else ACCENT_HOT)
            txt(x, f"{temp:.0f}°", tcol, fsm)

    def _on_wheel(self, e):
        self.plist.yview_scroll(int(-e.delta / 120), "units")

    def _on_cards_resize(self, e):
        # Throttle resize repaints to ~30 fps: paint now if enough time has
        # passed, else schedule a single trailing repaint. Keeps resize smooth.
        if time.monotonic() - self._last_paint >= 0.033:
            self._paint_cards()
        elif self._resize_after is None:
            self._resize_after = self.root.after(33, self._paint_cards)

    # -- custom window chrome (title bar buttons, move, resize) ------------ #
    def _winbtn(self, parent, glyph, cmd, close=False, pin=False):
        b = tk.Label(parent, text=glyph, font=self.f_icon, bg=BG, fg=MUTED,
                     width=4)
        b.pack(side="right", fill="y")
        hbg = "#c42b1c" if close else PANEL_HOVER
        hfg = "#ffffff" if close else FG
        b.bind("<Enter>", lambda e: b.config(bg=hbg, fg=hfg))
        b.bind("<Leave>", lambda e: b.config(
            bg=BG, fg=ACCENT if (pin and self._pinned) else MUTED))
        b.bind("<Button-1>", lambda e: cmd())
        return b

    def _start_move(self, e):
        self._mx = e.x_root - self.root.winfo_x()
        self._my = e.y_root - self.root.winfo_y()

    def _do_move(self, e):
        if not self._maxed:
            self.root.geometry(f"+{e.x_root - self._mx}+{e.y_root - self._my}")

    def _close(self):
        try:
            if not self._maxed:
                self.cfg.set("geometry", self.root.geometry())
        except Exception:
            pass
        self.root.destroy()

    def _on_search(self, e=None):
        self.filter = self.search.get().strip()
        if self.last:
            self._draw_procs(self.last["procs"])

    def _minimize(self):
        self.root.update_idletasks()
        ctypes.windll.user32.ShowWindow(_hwnd(self.root), 6)   # SW_MINIMIZE

    def _toggle_pin(self):
        self._pinned = not self._pinned
        self.root.wm_attributes("-topmost", self._pinned)
        self._btn_pin.config(fg=ACCENT if self._pinned else MUTED)

    def _toggle_max(self):
        if not self._maxed:
            self._restore_geom = self.root.geometry()
            r = wintypes.RECT()
            ctypes.windll.user32.SystemParametersInfoW(
                0x0030, 0, ctypes.byref(r), 0)             # SPI_GETWORKAREA
            self.root.geometry(f"{self.root.winfo_width()}x{r.bottom - r.top}"
                               f"+{self.root.winfo_x()}+{r.top}")
            self._btn_max.config(text="")            # restore glyph
            self._maxed = True
        else:
            self.root.geometry(self._restore_geom)
            self._btn_max.config(text="")
            self._maxed = False

    def _do_resize(self, e):
        # Height-only: the width is fixed (widening just stretches bars into
        # dead space and forces a costly re-layout of every process row).
        # Throttled to ~60 fps so a drag stays smooth.
        if self._maxed:
            return
        now = time.monotonic()
        if now - getattr(self, "_resize_t", 0.0) < 0.016:
            return
        self._resize_t = now
        sh = self.root.winfo_screenheight()
        h = max(self._minh, min(int(e.y_root - self.root.winfo_y()), sh))
        self.root.geometry(f"{self.root.winfo_width()}x{h}")

    # -- settings / log windows -------------------------------------------- #
    def _relayout(self):
        """Recompute which cards show + the window height, then repaint."""
        self.temp_on = self.sensors.ok and self.show_temp_pref
        cb = 248 + (112 if self.temp_on else 0) + 58
        cb += 58 if self.show_cpu else 0
        cb += 40
        self._minh = cb + 84
        m = re.match(r"(\d+)x(\d+)\+(-?\d+)\+(-?\d+)", self.root.geometry())
        if m and not self._maxed:
            wd, _, x, yy = m.groups()
            self.root.geometry(f"{wd}x{self._minh}+{x}+{yy}")
        self._paint_cards()

    def _open_settings(self):
        if getattr(self, "_set_win", None) and self._set_win.winfo_exists():
            self._set_win.lift()
            return
        t = tk.Toplevel(self.root)
        self._set_win = t
        t.title("Flux settings")
        t.configure(bg=BG)
        t.resizable(False, False)
        t.attributes("-topmost", True)
        try:
            t.iconbitmap(resource_path("Flux.ico"))
        except Exception:
            pass
        pad = tk.Frame(t, bg=BG)
        pad.pack(fill="both", expand=True, padx=16, pady=14)

        def cap(text):
            tk.Label(pad, text=text, bg=BG, fg=MUTED,
                     font=self.f_cap).pack(anchor="w", pady=(10, 2))

        def mkscale(frm, lo, hi, step, val, fmt, cb):
            wrap = tk.Frame(frm, bg=BG)
            wrap.pack(fill="x")
            out = tk.Label(wrap, text=fmt(val), bg=BG, fg=FG, font=self.f_stat,
                           width=8, anchor="e")
            out.pack(side="right")
            sc = tk.Scale(wrap, from_=lo, to=hi, resolution=step,
                          orient="horizontal", showvalue=False, bg=BG, fg=FG,
                          troughcolor=TRACK, highlightthickness=0, bd=0,
                          activebackground=ACCENT, sliderrelief="flat",
                          length=200)
            sc.set(val)
            sc.pack(side="left", fill="x", expand=True)
            sc.config(command=lambda v: (out.config(text=fmt(float(v))),
                                         cb(float(v))))
            return sc

        cap("REFRESH RATE")
        mkscale(pad, 250, 5000, 250, self.refresh_ms,
                lambda v: f"{v/1000:.2f}s",
                lambda v: (setattr(self, "refresh_ms", int(v)),
                           self.cfg.set("refresh_ms", int(v))))
        cap("ALERT THRESHOLD")
        mkscale(pad, 50, 100, 1, self.alert_pct, lambda v: f"{v:.0f}%",
                lambda v: (setattr(self, "alert_pct", int(v)),
                           self.cfg.set("alert_pct", int(v))))

        cap("ACCENT")
        sw = tk.Frame(pad, bg=BG)
        sw.pack(fill="x")
        for nm, cols in ACCENTS.items():
            b = tk.Label(sw, bg=cols[0], width=3, height=1, cursor="hand2",
                         relief="flat")
            b.pack(side="left", padx=(0, 6))
            b.bind("<Button-1>", lambda e, n=nm: self._set_accent(n))

        cap("CARDS")
        self._v_temp = tk.BooleanVar(value=self.show_temp_pref)
        self._v_cpu = tk.BooleanVar(value=self.show_cpu)

        def chk(text, var, key, attr):
            def toggle():
                setattr(self, attr, var.get())
                self.cfg.set(key, var.get())
                self._relayout()
            c = tk.Checkbutton(pad, text=text, variable=var, command=toggle,
                               bg=BG, fg=FG, selectcolor=PANEL, font=self.f_mid,
                               activebackground=BG, activeforeground=FG,
                               highlightthickness=0, bd=0, anchor="w")
            c.pack(fill="x")
            return c
        tc = chk("GPU temperature card", self._v_temp, "show_temp",
                 "show_temp_pref")
        if not self.sensors.ok:
            tc.config(state="disabled")
            tk.Label(pad, text="(temp sensors unavailable)", bg=BG, fg=MUTED,
                     font=self.f_cap).pack(anchor="w")
        chk("CPU / RAM card", self._v_cpu, "show_cpu", "show_cpu")

    def _set_accent(self, name):
        apply_accent(name)
        self.cfg.set("accent", name)
        self.search.config(highlightcolor=ACCENT)
        self._paint_cards()

    def _open_log(self):
        if getattr(self, "_log_win", None) and self._log_win.winfo_exists():
            self._log_win.lift()
            return
        t = tk.Toplevel(self.root)
        self._log_win = t
        t.title("Flux log")
        t.configure(bg=BG)
        t.geometry("560x420")
        t.attributes("-topmost", True)
        txt = tk.Text(t, bg=PANEL, fg=FG, font=self.f_mono, bd=0,
                      highlightthickness=0, padx=12, pady=10, wrap="none")
        txt.pack(fill="both", expand=True)
        txt.insert("end", self._log_report())
        txt.config(state="disabled")

    def _log_report(self):
        try:
            rows = []
            with open(self._log_path, encoding="utf-8") as f:
                header = f.readline()
                for line in f:
                    parts = line.rstrip("\n").split(",", 6)
                    if len(parts) >= 6:
                        rows.append(parts)
        except FileNotFoundError:
            return "No log yet — it's written once a minute to:\n" \
                   + self._log_path
        if not rows:
            return "Log is empty so far."
        out = [f"{len(rows)} samples logged  ({self._log_path})", ""]
        peak = max(rows, key=lambda r: float(r[1] or 0))
        out.append(f"Peak VRAM: {peak[1]} GB ({peak[2]}%) at {peak[0]}")
        # biggest climbs between consecutive samples
        climbs = []
        for a, b in zip(rows, rows[1:]):
            try:
                d = float(b[1]) - float(a[1])
            except ValueError:
                continue
            if d > 0.5:
                climbs.append((d, b[0], a[1], b[1], b[6] if len(b) > 6 else ""))
        climbs.sort(reverse=True)
        out.append("")
        out.append("Biggest VRAM climbs:")
        if not climbs:
            out.append("  (none over 0.5 GB between samples)")
        for d, when, fr, to, top in climbs[:8]:
            out.append(f"  +{d:.1f} GB  {when}   {fr}->{to} GB")
            if top:
                out.append(f"        top: {top[:70]}")
        out.append("")
        out.append("Recent samples (time · used · % · cached · gpu · temp):")
        for r in rows[-12:]:
            out.append(f"  {r[0]}  {r[1]:>5} GB  {r[2]:>3}%  "
                       f"cache {r[3]:>5}  gpu {r[4]:>3}  {r[5]}")
        return "\n".join(out)

    # -- metric cards (flat, drawn as canvas items) ------------------------ #
    @staticmethod
    def _round_rect(c, x0, y0, x1, y1, r, **kw):
        r = max(0, min(r, (x1 - x0) / 2, (y1 - y0) / 2))
        pts = [x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r, x1, y1 - r, x1, y1,
               x1 - r, y1, x0 + r, y1, x0, y1, x0, y1 - r, x0, y0 + r, x0, y0]
        return c.create_polygon(pts, smooth=True, **kw)

    @staticmethod
    def _tint(hexcol, basehex):
        # mix an accent toward a base colour (Tk has no real alpha)
        h = lambda s, i: int(s[i:i + 2], 16)
        mix = lambda a, b: int(a * 0.22 + b * 0.78)
        return "#" + "".join(
            f"{mix(h(hexcol, i), h(basehex, i)):02x}" for i in (1, 3, 5))

    def _card(self, c, x0, y0, x1, y1):
        self._round_rect(c, x0, y0, x1, y1, 9, fill=PANEL, tags="fg")

    def _spark(self, c, data, x0, y0, x1, y1, color):
        if x1 - x0 < 4 or len(data) < 2:
            return
        step = (x1 - x0) / (len(data) - 1)
        hh = y1 - y0
        pts = [(x0 + i * step, y1 - (hh - 2) * min(v, 100) / 100 - 1)
               for i, v in enumerate(data)]
        flat = [k for p in pts for k in p]
        c.create_polygon([x0, y1] + flat + [x1, y1],
                         fill=self._tint(color, PANEL), outline="", tags="fg")
        c.create_line(flat, fill=color, width=1.5, smooth=True, tags="fg")

    def _mini(self, c, x0, y, x1, label, value, vcol=FG):
        self._card(c, x0, y, x1, y + 50)
        c.create_text(x0 + 12, y + 15, text=label, anchor="w", fill=MUTED,
                      font=self.f_cap, tags="fg")
        c.create_text(x0 + 12, y + 35, text=value, anchor="w", fill=vcol,
                      font=self.f_stat, tags="fg")

    def _paint_cards(self):
        self._resize_after = None
        self._last_paint = time.monotonic()
        c = self.cards
        w = c.winfo_width()
        if w <= 1:
            w = 300
        c.delete("fg")
        d = self.last or {}
        used = d.get("dedicated", 0)
        pct = (used / self.total * 100) if self.total else 0
        col = usage_color(pct)
        gpu = d.get("gpu", 0.0)
        free = max(0, self.total - used)
        shared = d.get("shared", 0)
        s = self.sensors_data
        P = 14
        x0, x1 = P, w - P
        gap = 10
        midx = (x0 + x1) / 2

        c.create_text(x0 + 2, 14, text=self.gpu_name, anchor="w", fill=FG,
                      font=self.f_titlebar, tags="fg")

        # --- VRAM card ---
        y = 30
        y1 = y + 112
        self._card(c, x0, y, x1, y1)
        c.create_text(x0 + 12, y + 17, text="VRAM", anchor="w", fill=MUTED,
                      font=self.f_cap, tags="fg")
        c.create_text(x1 - 12, y + 16, text=f"{pct:.0f}%", anchor="e",
                      fill=col, font=self.f_stat, tags="fg")
        if self._peak:
            c.create_text(x1 - 12, y + 33, text=f"peak {fmt_gb(self._peak)}",
                          anchor="e", fill=MUTED, font=self.f_cap, tags="fg")
        c.create_text(x0 + 12, y + 47, text=fmt_gb(used), anchor="w", fill=FG,
                      font=self.f_cardnum, tags="fg")
        nwm = self.f_cardnum.measure(fmt_gb(used))
        c.create_text(x0 + 12 + nwm + 6, y + 53,
                      text=f"/ {fmt_gb(self.total)} GB", anchor="w",
                      fill=MUTED, font=self.f_small, tags="fg")
        bx0, bx1, by = x0 + 12, x1 - 12, y + 66
        self._round_rect(c, bx0, by, bx1, by + 7, 3, fill=TRACK, tags="fg")
        fw = (bx1 - bx0) * min(pct, 100) / 100
        if fw > 3:
            self._round_rect(c, bx0, by, bx0 + fw, by + 7, 3, fill=col, tags="fg")
        self._spark(c, list(self.hist_vram), bx0, y + 82, bx1, y1 - 8, ACCENT)
        y = y1 + gap

        # --- GPU LOAD card (+ power, + per-engine breakdown) ---
        y1 = y + 86
        self._card(c, x0, y, x1, y1)
        c.create_text(x0 + 12, y + 17, text="GPU LOAD", anchor="w", fill=MUTED,
                      font=self.f_cap, tags="fg")
        c.create_text(x0 + 12, y + 45, text=f"{gpu:.0f}%", anchor="w",
                      fill=usage_color(gpu), font=self.f_cardnum, tags="fg")
        if "power" in s:
            c.create_text(x1 - 12, y + 20, text=f"{s['power']:.0f} W",
                          anchor="e", fill=MUTED, font=self.f_stat, tags="fg")
        eng = self.gpu_engines
        order = [("3D", "3D"), ("VideoDecode", "Dec"), ("VideoEncode", "Enc"),
                 ("Video", "Vid"), ("Copy", "Cpy"), ("Compute", "Cmp")]
        parts = [f"{lab} {eng[k]:.0f}" for k, lab in order
                 if k in eng and eng[k] >= 1]
        c.create_text(x1 - 12, y + 47, text="  ".join(parts[:4]) or "idle",
                      anchor="e", fill=MUTED, font=self.f_small, tags="fg")
        self._spark(c, list(self.hist_gpu), x0 + 12, y + 60, x1 - 12, y1 - 8,
                    GPU_LINE)
        y = y1 + gap

        # --- GPU TEMP card (optional, with its own trend) ---
        if self.temp_on:
            y1 = y + 102
            self._card(c, x0, y, x1, y1)
            c.create_text(x0 + 12, y + 17, text="GPU TEMP", anchor="w",
                          fill=MUTED, font=self.f_cap, tags="fg")
            temp = s.get("temp")
            if temp is not None:
                tcol = (ACCENT if temp < 75 else
                        ACCENT_WARN if temp < 85 else ACCENT_HOT)
                c.create_text(x0 + 12, y + 47, text=f"{temp:.0f}°C", anchor="w",
                              fill=tcol, font=self.f_cardnum, tags="fg")
            extra = []
            if "hotspot" in s:
                extra.append(f"hotspot {s['hotspot']:.0f}°")
            if "vramtemp" in s:
                extra.append(f"vram {s['vramtemp']:.0f}°")
            c.create_text(x1 - 12, y + 22, text="   ".join(extra), anchor="e",
                          fill=MUTED, font=self.f_small, tags="fg")
            clk = []
            if "coreclk" in s:
                clk.append(f"{s['coreclk']:.0f} core")
            if "memclk" in s:
                clk.append(f"{s['memclk']:.0f} mem")
            if "fan" in s:
                clk.append(f"{s['fan']:.0f} rpm")
            c.create_text(x0 + 12, y + 68, text="  ·  ".join(clk), anchor="w",
                          fill=MUTED, font=self.f_small, tags="fg")
            self._spark(c, list(self.hist_temp), x0 + 12, y + 78, x1 - 12,
                        y1 - 8, ACCENT_WARN)
            y = y1 + gap

        # --- FREE / SHARED (+ CPU / RAM) mini-cards ---
        self._mini(c, x0, y, midx - gap / 2, "FREE", f"{fmt_gb(free)} GB")
        self._mini(c, midx + gap / 2, y, x1, "SHARED", f"{fmt_gb(shared)} GB")
        y += 50 + 8
        if self.show_cpu:
            ramp, ramu, ramt = self.ram
            self._mini(c, x0, y, midx - gap / 2, "CPU", f"{self.cpu:.0f}%",
                       usage_color(self.cpu))
            self._mini(c, midx + gap / 2, y, x1, "RAM",
                       f"{gb(ramu):.1f} / {gb(ramt):.0f} GB" if ramt else "—",
                       usage_color(ramp))
            y += 50 + 8

        # --- driver-cached / leak-watch note ---
        cached = used - d.get("tracked", 0)
        if cached > 0.25 * (1024 ** 3):
            since = (f" since {self._cache_since:%H:%M}"
                     if self._cache_since is not None else "")
            c.create_text(x0 + 2, y + 10,
                          text=f"⚠ {fmt_gb(cached)} GB driver-cached{since}",
                          anchor="w", fill=ACCENT_WARN, font=self.f_small,
                          tags="fg")
            c.create_text(x0 + 2, y + 27,
                          text="no app owns it — Win+Ctrl+Shift+B to flush",
                          anchor="w", fill=MUTED, font=self.f_small, tags="fg")

    ROWH = 24

    def _on_plist_config(self, e):
        # Reflow only when the WIDTH changes (height resize must stay cheap).
        if e.width != self._plist_w:
            self._plist_w = e.width
            if self.last:
                self._draw_procs(self.last["procs"])

    def _plist_row_at(self, e):
        return int(self.plist.canvasy(e.y) // self.ROWH)

    def _plist_motion(self, e):
        w = self.plist.winfo_width()
        i = self._plist_row_at(e)
        over_x = (e.x >= w - 26 and 0 <= i < len(self._proc_list)
                  and not self._proc_list[i][3])
        self.plist.config(cursor="hand2" if over_x else "")
        self._plist_hover(i if over_x else -1)

    def _plist_hover(self, i):
        if i != self._hover_i:
            self._hover_i = i
            if self.last:
                self._draw_procs(self.last["procs"])

    def _plist_click(self, e):
        w = self.plist.winfo_width()
        i = self._plist_row_at(e)
        if 0 <= i < len(self._proc_list) and e.x >= w - 26:
            name, val, pids, crit = self._proc_list[i]
            if not crit and pids:
                self._kill(name, pids)

    def _draw_procs(self, procs):
        if self.filter:
            f = self.filter.lower()
            procs = [p for p in procs if f in p[0].lower()]
        c = self.plist
        c.delete("all")
        w = c.winfo_width()
        if w < 60:
            w = 380
        self._proc_list = []
        if not procs:
            c.create_text(2, 14, anchor="w", fill=MUTED, font=self.f_small,
                          text="No match" if self.filter else "No GPU memory in use")
            c.configure(scrollregion=(0, 0, w, self.ROWH))
            return
        maxv = procs[0][1] or 1
        rh = self.ROWH
        # Reserve the right end for the MB value (up to "16,384 MB") + the ✕,
        # so the bar never runs under the number.
        xx = w - 12
        mbx = w - 30
        bx0, bx1 = 168, w - 104
        for i, (name, val, pids) in enumerate(procs):
            crit = name.lower() in CRITICAL_PROCESSES
            self._proc_list.append((name, val, pids, crit))
            y = i * rh + rh / 2
            if name in self._growing:
                c.create_text(4, y, text="↑", anchor="w", fill=ACCENT_WARN,
                              font=self.f_mid)
            c.create_text(18, y, text=name[:22], anchor="w", fill=FG,
                          font=self.f_mid)
            if bx1 > bx0:
                self._round_rect(c, bx0, y - 3, bx1, y + 3, 3, fill=TRACK,
                                 outline="")
                fw = (bx1 - bx0) * val / maxv
                if fw > 2:
                    self._round_rect(c, bx0, y - 3, bx0 + fw, y + 3, 3,
                                     fill=ACCENT, outline="")
            c.create_text(mbx, y, text=f"{gb(val) * 1024:,.0f} MB", anchor="e",
                          fill=MUTED, font=self.f_mono)
            xcol = (GRID if crit else
                    ACCENT_HOT2 if i == self._hover_i else ACCENT_HOT)
            c.create_text(xx, y, text="✕", anchor="e", fill=xcol,
                          font=self.f_mid)
        c.configure(scrollregion=(0, 0, w, len(procs) * rh + 4))

    # -- ending a process -------------------------------------------------- #
    def _kill(self, name, pids):
        n = len(pids)
        plural = "process" if n == 1 else f"{n} processes"
        if not messagebox.askyesno(
                "End process",
                f"End {name} ({plural}) and free its VRAM?\n\n"
                f"This force-closes the app — any unsaved work will be lost.",
                icon="warning", parent=self.root, default="no"):
            return
        killed, denied, failed, skipped = terminate_pids(pids, name)
        if killed and not denied and not failed and not skipped:
            self._status(f"Ended {name}.", ACCENT)
        elif killed:
            # Partial success — say so rather than hiding the freed VRAM.
            if denied:
                note = f" ({denied} need admin)"
            elif failed or skipped:
                note = f" ({failed + skipped} couldn't be ended)"
            else:
                note = ""
            self._status(f"Ended {killed} of {n} for {name}.{note}", ACCENT_WARN)
        elif denied:
            self._status(
                f"Access denied ending {name} — run Flux as administrator.",
                ACCENT_WARN)
        elif skipped and not failed:
            self._status(f"{name} already exited.", MUTED)
        else:
            self._status(f"Couldn't end {name}.", ACCENT_HOT)
        # Re-sample soon so the freed VRAM shows up.
        self.root.after(400, self.refresh)

    def _status(self, text, color=MUTED):
        self.lbl_status.config(text=text, fg=color)
        if self._status_after:
            self.root.after_cancel(self._status_after)
        self._status_after = self.root.after(
            5000, lambda: self.lbl_status.config(text=""))

    # -- loop -------------------------------------------------------------- #
    def refresh(self):
        try:
            # Reuse the name cache; force a full re-read every ~10 s so a reused
            # pid can't keep a stale name (display-only — the kill path always
            # re-validates names against a fresh snapshot before terminating).
            data = sample(self._name_cache, force_names=self._tickn % 10 == 0)
        except Exception as exc:  # keep the UI alive on transient errors
            data = {"dedicated": 0, "shared": 0, "procs": [],
                    "tracked": 0, "nproc": 0}
            print("sample error:", exc, file=sys.stderr)
        try:
            data["gpu"], self.gpu_engines = gpu_utilization(self.gpu_sampler)
        except Exception:
            data["gpu"] = 0.0
        try:
            self.cpu = cpu_percent(self.cpu_sampler)
            self.ram = ram_info()
        except Exception:
            pass
        self.last = data
        self._tickn += 1

        used = data["dedicated"]
        pct = (used / self.total * 100) if self.total else 0
        cached = used - data.get("tracked", 0)
        self.hist_vram.append(pct)
        self.hist_gpu.append(data["gpu"])

        # Is the UI actually on screen? Skip the expensive repaint (and needless
        # sensor reads) while minimised/hidden — this app runs in the background.
        vis = self._mini_on or bool(self.root.winfo_viewable())
        if vis:
            self._ever_visible = True
        log_now = self._tickn % LOG_EVERY == 1

        # GPU sensors (temp/clocks/power) — a ~15 ms LHM read; only when they'll
        # be shown or logged soon, and only every 3rd tick (they change slowly).
        if self.sensors.ok and (vis or log_now) and self._tickn % 3 == 0:
            self.sensors_data = self.sensors.read()
        self.hist_temp.append(self.sensors_data.get("temp", 0) or 0)

        # session peak
        if used > self._peak:
            self._peak = used

        # per-process growth detection (the live leak hunter)
        self._update_growth(data.get("procs", []))

        # leak-watch: remember when cached-with-no-owner first crossed the line
        if cached > LEAK_GB * (1024 ** 3):
            if self._cache_since is None:
                self._cache_since = datetime.datetime.now()
        else:
            self._cache_since = None

        # auto-snapshot when VRAM jumps suddenly (catch the culprit in the act)
        if self._snap_cooldown > 0:
            self._snap_cooldown -= 1
        elif self._prev_used and used - self._prev_used > 1.0 * (1024 ** 3):
            self._snapshot(data, used, pct, cached)
            self._snap_cooldown = 30
        self._prev_used = used

        # threshold alert (rising edge, with hysteresis)
        if pct >= self.alert_pct and not self._alerted:
            self._alerted = True
            self._toast(f"VRAM at {pct:.0f}%  —  "
                        f"{fmt_gb(used)} / {fmt_gb(self.total)} GB")
            try:
                winsound.MessageBeep(0x30)
            except Exception:
                pass
        elif pct < self.alert_pct - 5:
            self._alerted = False

        # periodic log row
        if self._tickn % LOG_EVERY == 1:
            self._log_snapshot(data, used, pct, cached)

        if self._mini_on:
            self._mini_paint(data)
            return
        if self._ever_visible and not vis:
            return                        # minimised / hidden — skip the repaint
        self.lbl_prochead.config(text=f"PROCESSES ({data.get('nproc', 0)})")
        self._paint_cards()
        self._draw_procs(data["procs"])

    def _update_growth(self, procs):
        """Flag processes whose VRAM has climbed steadily over recent samples."""
        seen = set()
        for nm, val, _ in procs:
            seen.add(nm)
            h = self._proc_hist.get(nm)
            if h is None:
                h = self._proc_hist[nm] = deque(maxlen=20)
            h.append(val)
        for nm in list(self._proc_hist):
            if nm not in seen:
                del self._proc_hist[nm]
        growing = set()
        for nm, h in self._proc_hist.items():
            if len(h) >= 12:
                rise = h[-1] - h[0]
                # climbed > 200 MB across the window and ended near its max
                if rise > 200 * 1024 ** 2 and h[-1] >= max(h) - 30 * 1024 ** 2:
                    growing.add(nm)
        self._growing = growing

    def _snapshot(self, data, used, pct, cached, tag="spike"):
        """Write a full all-process snapshot to a timestamped file."""
        try:
            ts = datetime.datetime.now()
            path = os.path.join(_app_dir(),
                                f"flux_snapshot_{ts:%Y%m%d_%H%M%S}.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"Flux snapshot ({tag})  {ts:%Y-%m-%d %H:%M:%S}\n")
                f.write(f"GPU: {self.gpu_name}\n")
                f.write(f"VRAM used: {fmt_gb(used)} / {fmt_gb(self.total)} GB "
                        f"({pct:.0f}%)   cached(no app): {fmt_gb(cached)} GB\n")
                f.write(f"GPU load: {data.get('gpu', 0):.0f}%   "
                        f"temp: {self.sensors_data.get('temp', '?')}\n\n")
                f.write("All GPU processes (name, MB):\n")
                for nm, val, _ in data.get("procs", []):
                    flag = "  <= GROWING" if nm in self._growing else ""
                    f.write(f"  {nm:32} {gb(val) * 1024:8.0f} MB{flag}\n")
            self._status(f"Snapshot saved: {os.path.basename(path)}", ACCENT)
        except Exception as exc:
            print("snapshot error:", exc, file=sys.stderr)

    def _log_snapshot(self, data, used, pct, cached):
        try:
            new = not os.path.exists(self._log_path)
            with open(self._log_path, "a", encoding="utf-8") as f:
                if new:
                    f.write("time,used_gb,pct,cached_gb,gpu_pct,temp_c,"
                            "top_processes\n")
                top = ";".join(f"{n}={gb(v) * 1024:.0f}MB"
                               for n, v, _ in data.get("procs", [])[:5])
                f.write(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S},"
                        f"{gb(used):.2f},{pct:.0f},{gb(cached):.2f},"
                        f"{data.get('gpu', 0):.0f},"
                        f"{self.sensors_data.get('temp', '')},{top}\n")
            self._trim_log()
        except Exception as exc:
            print("log error:", exc, file=sys.stderr)

    def _trim_log(self):
        """Keep the CSV from growing forever: cap it at ~20k rows (~2 weeks),
        checked cheaply once every few hours."""
        if self._tickn % (LOG_EVERY * 180) != 1:      # ~ every 3 hours
            return
        try:
            if os.path.getsize(self._log_path) < 2_000_000:
                return
            with open(self._log_path, encoding="utf-8") as f:
                lines = f.readlines()
            if len(lines) > 20000:
                with open(self._log_path, "w", encoding="utf-8") as f:
                    f.writelines(lines[:1])            # header
                    f.writelines(lines[-20000:])
        except Exception:
            pass

    def _toast(self, text, color=ACCENT_WARN):
        try:
            t = tk.Toplevel(self.root)
            t.overrideredirect(True)
            t.attributes("-topmost", True)
            t.configure(bg=color)
            inner = tk.Frame(t, bg=PANEL)
            inner.pack(padx=1, pady=1)
            tk.Label(inner, text=f"⚠  {text}", bg=PANEL, fg=FG,
                     font=self.f_mid, padx=16, pady=11).pack()
            t.update_idletasks()
            sw, sh = t.winfo_screenwidth(), t.winfo_screenheight()
            t.geometry(f"+{sw - t.winfo_width() - 24}"
                       f"+{sh - t.winfo_height() - 60}")
            t.after(4500, t.destroy)
        except Exception:
            pass

    def tick(self):
        self.refresh()
        self._tick_after = self.root.after(self.refresh_ms, self.tick)


def resource_path(name):
    """Path to a bundled resource, whether running from source or a PyInstaller
    one-file exe (which unpacks data into sys._MEIPASS)."""
    base = getattr(sys, "_MEIPASS",
                   os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def main():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    try:
        root.iconbitmap(resource_path("Flux.ico"))
    except Exception:
        pass
    App(root)
    root.update_idletasks()
    _win_chrome(root)          # taskbar button + rounded corners + shadow
    root.lift()
    root.mainloop()


if __name__ == "__main__":
    main()
