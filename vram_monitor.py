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
import struct
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

# Per-process "mini task manager" views — all via PDH, no new dependencies.
PROC_CPU_COUNTER = r"\Process(*)\% Processor Time"        # rate (0..100*ncpu)
PROC_RAM_COUNTER = r"\Process(*)\Working Set - Private"   # instantaneous bytes
_PROC_INST_SKIP = {"_total", "idle"}                      # PDH pseudo-instances
_HASHNUM_RE = re.compile(r"#\d+$")


def _agg_proc_by_name(pairs):
    """Aggregate \\Process(*) instances by base image name — PDH suffixes
    duplicate names with '#1', '#2' — dropping the _Total / Idle pseudo rows."""
    out = {}
    for name, val in pairs:
        if not name:
            continue
        base = _HASHNUM_RE.sub("", name)
        if base.lower() in _PROC_INST_SKIP:
            continue
        out[base] = out.get(base, 0) + val
    return out


def cpu_procs(sampler, ncpu):
    """[(name, cpu_percent_of_total, None), ...] busiest first. The rate counter
    reports 0..100 per core, so divide the per-name sum by the core count."""
    agg = _agg_proc_by_name(sampler.read())
    procs = [(n, v / max(1, ncpu), None) for n, v in agg.items() if v > 0.05]
    procs.sort(key=lambda t: t[1], reverse=True)
    return procs


def ram_procs():
    """[(name, private_working_set_bytes, None), ...] biggest first."""
    agg = _agg_proc_by_name(read_counter_instances(PROC_RAM_COUNTER))
    procs = [(n, v, None) for n, v in agg.items() if v > 0]
    procs.sort(key=lambda t: t[1], reverse=True)
    return procs


# Total network throughput (no per-process — that needs ETW/admin). Rate
# counters, so via RateSampler.
NET_RX_COUNTER = r"\Network Interface(*)\Bytes Received/sec"
NET_TX_COUNTER = r"\Network Interface(*)\Bytes Sent/sec"
# Skip loopback / tunnels / virtual adapters — Hyper-V, WSL, VPN and VM bridges
# mirror the physical NIC's traffic (and can flip its direction), so summing all
# interfaces double-counts. We pick the single busiest real interface instead.
_NET_SKIP = ("loopback", "isatap", "teredo", "pseudo", "vethernet", "virtual",
             "vmware", "hyper-v", "tap-windows", "tunnel", "vpn",
             "wan miniport", "wi-fi direct", "bluetooth")


def _net_real(pairs):
    return {n: max(0.0, v) for n, v in pairs
            if n and not any(s in n.lower() for s in _NET_SKIP)}


def net_rates(rx_sampler, tx_sampler):
    """(rx_bytes_s, tx_bytes_s) for the busiest real interface — one adapter,
    so mirrored virtual-adapter traffic isn't counted twice."""
    rx = _net_real(rx_sampler.read())
    tx = _net_real(tx_sampler.read())
    names = set(rx) | set(tx)
    if not names:
        return 0.0, 0.0
    best = max(names, key=lambda n: rx.get(n, 0.0) + tx.get(n, 0.0))
    return rx.get(best, 0.0), tx.get(best, 0.0)


# --------------------------------------------------------------------------- #
#  Per-process network via ETW (the one admin-only feature). Traces the kernel
#  network provider; the owning pid + byte count sit in each event's payload
#  (pid @0, size @4 — validated empirically). Structures are defined in full so
#  ctypes gets the 64-bit offsets right (a wrong size crashes ProcessTrace).
# --------------------------------------------------------------------------- #
_ULONG, _USHORT, _UCHAR = wintypes.ULONG, wintypes.USHORT, ctypes.c_ubyte
_LONG, _U64, _I64 = wintypes.LONG, ctypes.c_uint64, ctypes.c_int64
TRACEHANDLE = ctypes.c_uint64


class _ETW_GUID(ctypes.Structure):
    _fields_ = [("Data1", _ULONG), ("Data2", _USHORT), ("Data3", _USHORT),
                ("Data4", _UCHAR * 8)]


def _mkguid(d1, d2, d3, d4):
    g = _ETW_GUID()
    g.Data1, g.Data2, g.Data3 = d1, d2, d3
    for i, b in enumerate(d4):
        g.Data4[i] = b
    return g


# Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88}
_KERNEL_NET = _mkguid(0x7DD42A49, 0x5329, 0x4832,
                      (0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88))


class _WNODE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", _ULONG), ("ProviderId", _ULONG),
                ("HistoricalContext", _U64), ("TimeStamp", _I64),
                ("Guid", _ETW_GUID), ("ClientContext", _ULONG), ("Flags", _ULONG)]


class _EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [("Wnode", _WNODE_HEADER), ("BufferSize", _ULONG),
                ("MinimumBuffers", _ULONG), ("MaximumBuffers", _ULONG),
                ("MaximumFileSize", _ULONG), ("LogFileMode", _ULONG),
                ("FlushTimer", _ULONG), ("EnableFlags", _ULONG),
                ("AgeLimit", _LONG), ("NumberOfBuffers", _ULONG),
                ("FreeBuffers", _ULONG), ("EventsLost", _ULONG),
                ("BuffersWritten", _ULONG), ("LogBuffersLost", _ULONG),
                ("RealTimeBuffersLost", _ULONG), ("LoggerThreadId", wintypes.HANDLE),
                ("LogFileNameOffset", _ULONG), ("LoggerNameOffset", _ULONG)]


class _SYSTEMTIME(ctypes.Structure):
    _fields_ = [(n, _USHORT) for n in ("y", "mo", "dow", "d", "h", "mi", "s", "ms")]


class _TZI(ctypes.Structure):
    _fields_ = [("Bias", _LONG), ("StdName", ctypes.c_wchar * 32),
                ("StdDate", _SYSTEMTIME), ("StdBias", _LONG),
                ("DltName", ctypes.c_wchar * 32), ("DltDate", _SYSTEMTIME),
                ("DltBias", _LONG)]


class _TRACE_LOGFILE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", _ULONG), ("Version", _ULONG),
                ("ProviderVersion", _ULONG), ("NumberOfProcessors", _ULONG),
                ("EndTime", _I64), ("TimerResolution", _ULONG),
                ("MaximumFileSize", _ULONG), ("LogFileMode", _ULONG),
                ("BuffersWritten", _ULONG), ("LogInstanceGuid", _ETW_GUID),
                ("LoggerName", ctypes.c_void_p), ("LogFileName", ctypes.c_void_p),
                ("TimeZone", _TZI), ("BootTime", _I64), ("PerfFreq", _I64),
                ("StartTime", _I64), ("ReservedFlags", _ULONG),
                ("BuffersLost", _ULONG)]


class _EVENT_TRACE_HEADER(ctypes.Structure):
    _fields_ = [("Size", _USHORT), ("FieldTypeFlags", _USHORT), ("Version", _ULONG),
                ("ThreadId", _ULONG), ("ProcessId", _ULONG), ("TimeStamp", _I64),
                ("Guid", _ETW_GUID), ("ClientContext", _ULONG), ("Flags", _ULONG)]


class _ETW_BUFFER_CONTEXT(ctypes.Structure):
    _fields_ = [("ProcessorNumber", _UCHAR), ("Alignment", _UCHAR),
                ("LoggerId", _USHORT)]


class _EVENT_TRACE(ctypes.Structure):
    _fields_ = [("Header", _EVENT_TRACE_HEADER), ("InstanceId", _ULONG),
                ("ParentInstanceId", _ULONG), ("ParentGuid", _ETW_GUID),
                ("MofData", ctypes.c_void_p), ("MofLength", _ULONG),
                ("ClientContext", _ULONG)]


class _EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("Id", _USHORT), ("Version", _UCHAR), ("Channel", _UCHAR),
                ("Level", _UCHAR), ("Opcode", _UCHAR), ("Task", _USHORT),
                ("Keyword", _U64)]


class _EVENT_HEADER(ctypes.Structure):
    _fields_ = [("Size", _USHORT), ("HeaderType", _USHORT), ("Flags", _USHORT),
                ("EventProperty", _USHORT), ("ThreadId", _ULONG),
                ("ProcessId", _ULONG), ("TimeStamp", _I64),
                ("ProviderId", _ETW_GUID), ("EventDescriptor", _EVENT_DESCRIPTOR),
                ("KernelTime", _ULONG), ("UserTime", _ULONG),
                ("ActivityId", _ETW_GUID)]


class _EVENT_RECORD(ctypes.Structure):
    _fields_ = [("EventHeader", _EVENT_HEADER),
                ("BufferContext", _ETW_BUFFER_CONTEXT),
                ("ExtendedDataCount", _USHORT), ("UserDataLength", _USHORT),
                ("ExtendedData", ctypes.c_void_p), ("UserData", ctypes.c_void_p),
                ("UserContext", ctypes.c_void_p)]


_EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(_EVENT_RECORD))


class _EVENT_TRACE_LOGFILE(ctypes.Structure):
    _fields_ = [("LogFileName", wintypes.LPWSTR), ("LoggerName", wintypes.LPWSTR),
                ("CurrentTime", _I64), ("BuffersRead", _ULONG),
                ("ProcessTraceMode", _ULONG), ("CurrentEvent", _EVENT_TRACE),
                ("LogfileHeader", _TRACE_LOGFILE_HEADER),
                ("BufferCallback", ctypes.c_void_p), ("BufferSize", _ULONG),
                ("Filled", _ULONG), ("EventsLost", _ULONG),
                ("EventRecordCallback", _EVENT_RECORD_CALLBACK),
                ("IsKernelTrace", _ULONG), ("Context", ctypes.c_void_p)]


advapi32 = ctypes.WinDLL("advapi32.dll")
advapi32.StartTraceW.argtypes = [ctypes.POINTER(TRACEHANDLE), wintypes.LPCWSTR,
                                 ctypes.POINTER(_EVENT_TRACE_PROPERTIES)]
advapi32.StartTraceW.restype = _ULONG
advapi32.EnableTraceEx2.argtypes = [TRACEHANDLE, ctypes.POINTER(_ETW_GUID), _ULONG,
                                    _UCHAR, _U64, _U64, _ULONG, ctypes.c_void_p]
advapi32.EnableTraceEx2.restype = _ULONG
advapi32.ControlTraceW.argtypes = [TRACEHANDLE, wintypes.LPCWSTR,
                                   ctypes.POINTER(_EVENT_TRACE_PROPERTIES), _ULONG]
advapi32.ControlTraceW.restype = _ULONG
advapi32.OpenTraceW.argtypes = [ctypes.POINTER(_EVENT_TRACE_LOGFILE)]
advapi32.OpenTraceW.restype = TRACEHANDLE
advapi32.ProcessTrace.argtypes = [ctypes.POINTER(TRACEHANDLE), _ULONG,
                                  ctypes.c_void_p, ctypes.c_void_p]
advapi32.ProcessTrace.restype = _ULONG
advapi32.CloseTrace.argtypes = [TRACEHANDLE]
advapi32.CloseTrace.restype = _ULONG

_WNODE_FLAG_TRACED_GUID = 0x00020000
_ETW_REAL_TIME_MODE = 0x00000100
_PTM_REAL_TIME = 0x00000100
_PTM_EVENT_RECORD = 0x10000000
_ENABLE_PROVIDER = 1
_CTRL_STOP = 1
_LEVEL_VERBOSE = 5
_KW_IPV4, _KW_IPV6 = 0x10, 0x20
_ERR_ALREADY_EXISTS = 183
_INVALID_TRACEHANDLE = 0xFFFFFFFFFFFFFFFF


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class NetEtw:
    """Per-process network throughput via a real-time ETW trace of the kernel
    network provider. Needs admin (EnableTraceEx2 is ACCESS_DENIED otherwise).
    ProcessTrace blocks, so it runs on a daemon thread; the callback tallies
    bytes per pid and sample() returns bytes/sec per pid since the last call."""
    SESSION = "FluxNet"
    SEND_IDS = {10, 26, 42, 58}
    RECV_IDS = {11, 27, 43, 59}

    def __init__(self):
        self.ok = False
        self.attempted = False
        self.admin_needed = False
        self._h = TRACEHANDLE(0)
        self._th = 0
        self._thread = None
        self._cb = None
        self._lock = threading.Lock()
        self._acc = {}
        self._last_t = None

    def _props(self):
        size = ctypes.sizeof(_EVENT_TRACE_PROPERTIES) + (len(self.SESSION) + 1) * 2 + 8
        buf = (ctypes.c_byte * size)()
        p = ctypes.cast(buf, ctypes.POINTER(_EVENT_TRACE_PROPERTIES))
        p.contents.Wnode.BufferSize = size
        p.contents.Wnode.Flags = _WNODE_FLAG_TRACED_GUID
        p.contents.Wnode.ClientContext = 1
        p.contents.LogFileMode = _ETW_REAL_TIME_MODE
        p.contents.LoggerNameOffset = ctypes.sizeof(_EVENT_TRACE_PROPERTIES)
        return buf, p

    def _on_event(self, rec):
        r = rec.contents
        eid = r.EventHeader.EventDescriptor.Id
        if (eid in self.SEND_IDS or eid in self.RECV_IDS) and \
                r.UserData and r.UserDataLength >= 8:
            pid, size = struct.unpack_from("<II", ctypes.string_at(r.UserData, 8))
            with self._lock:
                self._acc[pid] = self._acc.get(pid, 0) + size

    def start(self):
        if self.ok:
            return True
        self.attempted = True
        buf, p = self._props()
        st = advapi32.StartTraceW(ctypes.byref(self._h), self.SESSION, p)
        if st == _ERR_ALREADY_EXISTS:            # stale session from a crash
            advapi32.ControlTraceW(0, self.SESSION, p, _CTRL_STOP)
            buf, p = self._props()
            st = advapi32.StartTraceW(ctypes.byref(self._h), self.SESSION, p)
        if st != 0:
            self.admin_needed = st == 5
            return False
        en = advapi32.EnableTraceEx2(
            self._h, ctypes.byref(_KERNEL_NET), _ENABLE_PROVIDER, _LEVEL_VERBOSE,
            _KW_IPV4 | _KW_IPV6, 0, 0, None)
        if en != 0:
            self.admin_needed = en == 5
            advapi32.ControlTraceW(self._h, self.SESSION, p, _CTRL_STOP)
            return False
        self._cb = _EVENT_RECORD_CALLBACK(self._on_event)
        lf = _EVENT_TRACE_LOGFILE()
        lf.LoggerName = self.SESSION
        lf.ProcessTraceMode = _PTM_REAL_TIME | _PTM_EVENT_RECORD
        lf.EventRecordCallback = self._cb
        self._th = advapi32.OpenTraceW(ctypes.byref(lf))
        if self._th == _INVALID_TRACEHANDLE:
            advapi32.ControlTraceW(self._h, self.SESSION, p, _CTRL_STOP)
            return False
        self._last_t = time.monotonic()
        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()
        self.ok, self.admin_needed = True, False
        return True

    def _pump(self):
        advapi32.ProcessTrace((TRACEHANDLE * 1)(self._th), 1, None, None)

    def sample(self):
        """{pid: bytes_per_sec} since the previous call."""
        now = time.monotonic()
        with self._lock:
            acc, self._acc = self._acc, {}
        dt = max(1e-3, now - (self._last_t or now))
        self._last_t = now
        return {pid: b / dt for pid, b in acc.items()}

    def stop(self):
        if self._h.value == 0:
            return
        try:
            buf, p = self._props()
            advapi32.ControlTraceW(self._h, self.SESSION, p, _CTRL_STOP)
            if self._th:
                advapi32.CloseTrace(self._th)
            if self._thread:
                self._thread.join(timeout=2)
        except Exception:
            pass
        self.ok = False
        self._h = TRACEHANDLE(0)
        self._th = 0
        self._thread = None


def net_procs(netetw):
    """[(name, bytes_per_sec, None), ...] busiest first, aggregated by name."""
    rates = netetw.sample()
    names = process_names()
    agg = {}
    for pid, rate in rates.items():
        nm = names.get(pid)
        nm = re.sub(r"\.exe$", "", nm, flags=re.IGNORECASE) if nm else f"pid {pid}"
        agg[nm] = agg.get(nm, 0.0) + rate
    procs = [(n, v, None) for n, v in agg.items() if v > 0]
    procs.sort(key=lambda t: t[1], reverse=True)
    return procs


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


def fmt_bits(bytes_per_sec):
    """Network rate in bits/s (Task Manager style): Mbps / Kbps / bps."""
    bits = bytes_per_sec * 8
    if bits >= 1e6:
        return f"{bits / 1e6:.1f} Mbps"
    if bits >= 1e3:
        return f"{bits / 1e3:.0f} Kbps"
    return f"{bits:.0f} bps"


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
                "show_temp": True, "show_cpu": True, "show_net": True,
                "geometry": None, "mini_geometry": None, "proc_mode": "vram"}

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
        self.on_scroll = None            # fired after a drag moves the view
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
        if self.on_scroll:
            self.on_scroll()


class App:
    def __init__(self, root):
        self.root = root
        self.cfg = Config()
        apply_accent(self.cfg.get("accent"))
        self.refresh_ms = int(self.cfg.get("refresh_ms"))
        self.alert_pct = int(self.cfg.get("alert_pct"))
        self.show_cpu = bool(self.cfg.get("show_cpu"))
        self.show_net = bool(self.cfg.get("show_net"))
        self.show_temp_pref = bool(self.cfg.get("show_temp"))

        self.total, self.gpu_name = vram_total_bytes()
        self.hist_vram = deque([0.0] * HISTORY, maxlen=HISTORY)
        self.hist_gpu = deque([0.0] * HISTORY, maxlen=HISTORY)
        self.hist_temp = deque([0.0] * HISTORY, maxlen=HISTORY)
        self.hist_net_rx = deque([0.0] * HISTORY, maxlen=HISTORY)
        self.hist_net_tx = deque([0.0] * HISTORY, maxlen=HISTORY)
        self.gpu_sampler = RateSampler(GPU_ENGINE_COUNTER)
        self.cpu_sampler = RateSampler(CPU_COUNTER)
        self.proc_cpu_sampler = RateSampler(PROC_CPU_COUNTER)  # per-process CPU
        self.net_rx_sampler = RateSampler(NET_RX_COUNTER)
        self.net_tx_sampler = RateSampler(NET_TX_COUNTER)
        self.net_rx = self.net_tx = 0.0
        self._ncpu = os.cpu_count() or 1
        self._proc_mode = self.cfg.get("proc_mode")   # vram | cpu | ram | net
        self._active_procs = []                        # rows for the current mode
        self.net_etw = NetEtw()                        # per-process net (admin)
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
        if self.show_net:
            cb += 96                          # NETWORK card
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

        # Right — processes card, drawn as a rounded PANEL on a background
        # canvas so the whole panel has soft corners like the metric cards.
        holder = tk.Frame(body, bg=BG)
        holder.pack(side="left", fill="both", expand=True, padx=(2, 14),
                    pady=(8, 6))
        pbg = tk.Canvas(holder, bg=BG, highlightthickness=0, bd=0)
        pbg.place(x=0, y=0, relwidth=1, relheight=1)
        pbg.bind("<Configure>", lambda e: (
            pbg.delete("all"),
            self._round_rect(pbg, 1, 1, e.width - 1, e.height - 1, 14,
                             fill=PANEL, outline="")))
        card = tk.Frame(holder, bg=PANEL)
        card.place(x=9, y=9, relwidth=1, relheight=1, width=-18, height=-18)
        phead = tk.Frame(card, bg=PANEL)
        phead.pack(fill="x", padx=6, pady=(8, 5))
        # segmented VRAM / CPU / RAM / NET selector — the "mini task manager"
        self._seg = tk.Canvas(phead, width=176, height=24, bg=PANEL,
                              highlightthickness=0, bd=0, cursor="hand2")
        self._seg.pack(side="left")
        self._seg.bind("<Button-1>", self._seg_click)
        self._draw_seg()
        self.lbl_prochead = tk.Label(phead, text="", bg=PANEL, fg=MUTED,
                                     font=self.f_cap, width=4, anchor="w")
        self.lbl_prochead.pack(side="left", padx=(8, 0))
        # rounded search box: a borderless Entry embedded in a small rounded
        # canvas whose outline turns accent-coloured on focus.
        sbox = tk.Canvas(phead, width=116, height=26, bg=PANEL,
                         highlightthickness=0, bd=0)
        sbox.pack(side="right")
        self._search_box = sbox
        self._draw_search_box(False)
        self.search = tk.Entry(sbox, bg=TRACK, fg=FG, insertbackground=FG,
                               font=self.f_small, relief="flat", bd=0,
                               highlightthickness=0)
        sbox.create_window(12, 13, window=self.search, anchor="w", width=94,
                           height=18)
        self.search.bind("<KeyRelease>", self._on_search)
        self.search.bind("<FocusIn>", lambda e: self._draw_search_box(True))
        self.search.bind("<FocusOut>", lambda e: self._draw_search_box(False))
        tk.Label(phead, text="", bg=PANEL, fg=MUTED,
                 font=self.f_icon).pack(side="right", padx=(0, 6))
        lwrap = tk.Frame(card, bg=PANEL)
        lwrap.pack(fill="both", expand=True, padx=(6, 4), pady=(0, 8))
        # The process list is drawn as canvas ITEMS (not embedded widgets) — a
        # frame-of-widgets here made every window resize re-lay-out ~120 widgets
        # (~270 ms). Canvas items repaint in a few ms and scroll for free.
        self.plist = tk.Canvas(lwrap, bg=PANEL, highlightthickness=0, bd=0)
        self.plist.pack(side="left", fill="both", expand=True)
        self.scroll = _Scrollbar(lwrap, self.plist, bg=PANEL)
        self.scroll.pack(side="right", fill="y", padx=(5, 0))
        self.scroll.on_scroll = self._redraw_rows   # virtualize on drag-scroll
        self._plist_w = 0
        self._proc_list = []          # (name, bytes, pids, critical) — ALL rows
        self._filtered = []           # rows after search filter (for redraw)
        self._maxv = 1                # top value, for bar scaling
        self._show_growth = False
        self._xitems = {}             # {row: ✕ canvas id} for VISIBLE rows only
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
        self._redraw_rows()                         # virtualize on wheel-scroll

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
        self.net_etw.stop()               # never orphan the ETW session
        self.root.destroy()

    def _on_search(self, e=None):
        self.filter = self.search.get().strip()
        if self.last:
            self._draw_procs()

    def _draw_search_box(self, focused):
        """Rounded backing for the search Entry; accent outline when focused.
        (Embedded canvas windows always draw above items, so this stays behind
        the Entry without needing an explicit lower.)"""
        c = self._search_box
        c.delete("box")
        w, h = int(c["width"]), int(c["height"])
        self._round_rect(c, 1, 1, w - 1, h - 1, 8, fill=TRACK,
                         outline=ACCENT if focused else GRID, tags="box")

    # -- process view selector (VRAM / CPU / RAM / NET) -------------------- #
    _PROC_MODES = [("vram", "VRAM"), ("cpu", "CPU"), ("ram", "RAM"),
                   ("net", "NET")]

    def _draw_seg(self):
        """Segmented pill selector; the active mode gets an accent-filled pill."""
        c = self._seg
        c.delete("all")
        w, h = int(c["width"]), int(c["height"])
        seg = w / len(self._PROC_MODES)
        self._round_rect(c, 0, 0, w, h, 7, fill=TRACK, outline="")
        for i, (mode, label) in enumerate(self._PROC_MODES):
            x0 = i * seg
            active = mode == self._proc_mode
            if active:
                self._round_rect(c, x0 + 2, 2, x0 + seg - 2, h - 2, 6,
                                 fill=ACCENT, outline="")
            c.create_text(x0 + seg / 2, h / 2, text=label, anchor="center",
                          fill=BG if active else MUTED, font=self.f_small)

    def _seg_click(self, e):
        seg = int(self._seg["width"]) / len(self._PROC_MODES)
        i = int(e.x // seg)
        if 0 <= i < len(self._PROC_MODES):
            self._set_proc_mode(self._PROC_MODES[i][0])

    def _set_proc_mode(self, mode):
        if mode == self._proc_mode:
            return
        if mode == "net":
            if not self.net_etw.admin_needed:
                self.net_etw.start()      # begin the ETW trace (needs admin)
        elif self._proc_mode == "net":
            self.net_etw.stop()           # stop tracing when leaving NET
        self._proc_mode = mode
        self.cfg.set("proc_mode", mode)
        self.filter = ""
        self.search.delete(0, "end")
        self._draw_seg()
        self._refresh_active_procs()
        self.lbl_prochead.config(text=str(len(self._active_procs)))
        self._draw_procs()

    def _refresh_active_procs(self):
        """Recompute the per-process list for the current mode (VRAM rows come
        free from the last sample; CPU/RAM are their own PDH reads)."""
        try:
            if self._proc_mode == "cpu":
                self._active_procs = cpu_procs(self.proc_cpu_sampler, self._ncpu)
            elif self._proc_mode == "ram":
                self._active_procs = ram_procs()
            elif self._proc_mode == "net":
                if not self.net_etw.ok and not self.net_etw.attempted:
                    self.net_etw.start()          # lazy start (persisted NET mode)
                self._active_procs = (net_procs(self.net_etw)
                                      if self.net_etw.ok else [])
            else:
                self._active_procs = (self.last or {}).get("procs", [])
        except Exception:
            self._active_procs = []

    def _fmt_val(self, val):
        if self._proc_mode == "cpu":
            return f"{val:.0f}%"
        if self._proc_mode == "net":
            return fmt_bits(val)
        mb = gb(val) * 1024                        # vram + ram: GB once it's big
        return f"{mb / 1024:.1f} GB" if mb >= 1024 else f"{mb:,.0f} MB"

    def _pids_for_name(self, name):
        """All live pids whose exe base-name matches (for CPU/RAM kill, where the
        per-tick rows carry no pids). Kill still re-validates each pid's name."""
        key = name.lower()
        return [pid for pid, nm in process_names().items()
                if re.sub(r"\.exe$", "", nm, flags=re.IGNORECASE).lower() == key]

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
        cb = 248 + (112 if self.temp_on else 0) + (96 if self.show_net else 0)
        cb += 58
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
            # Custom rounded slider (rounded track + circular thumb) — tk.Scale
            # has a blocky trough/handle that can't be rounded.
            wrap = tk.Frame(frm, bg=BG)
            wrap.pack(fill="x")
            out = tk.Label(wrap, text=fmt(val), bg=BG, fg=FG, font=self.f_stat,
                           width=8, anchor="e")
            out.pack(side="right")
            sc = tk.Canvas(wrap, height=24, bg=BG, highlightthickness=0, bd=0)
            sc.pack(side="left", fill="x", expand=True)
            st = {"v": float(val)}

            def draw():
                sc.delete("all")
                w = sc.winfo_width() or 200
                x0, x1, cy = 10, w - 10, 12
                if x1 <= x0:
                    return
                frac = (st["v"] - lo) / (hi - lo) if hi > lo else 0
                tx = x0 + (x1 - x0) * min(1, max(0, frac))
                self._round_rect(sc, x0, cy - 3, x1, cy + 3, 3, fill=TRACK,
                                 outline="")
                if tx > x0 + 1:
                    self._round_rect(sc, x0, cy - 3, tx, cy + 3, 3, fill=ACCENT,
                                     outline="")
                sc.create_oval(tx - 8, cy - 8, tx + 8, cy + 8, fill=ACCENT,
                               outline=BG, width=2)

            def setpx(px):
                w = sc.winfo_width() or 200
                x0, x1 = 10, w - 10
                frac = min(1, max(0, (px - x0) / (x1 - x0))) if x1 > x0 else 0
                v = min(hi, max(lo, round((lo + frac * (hi - lo)) / step) * step))
                if v != st["v"]:
                    st["v"] = v
                    out.config(text=fmt(v))
                    cb(v)
                draw()

            sc.bind("<Configure>", lambda e: draw())
            sc.bind("<Button-1>", lambda e: setpx(e.x))
            sc.bind("<B1-Motion>", lambda e: setpx(e.x))
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
            b = tk.Canvas(sw, width=28, height=22, bg=BG, highlightthickness=0,
                          bd=0, cursor="hand2")
            self._round_rect(b, 1, 1, 27, 21, 7, fill=cols[0], outline="")
            b.pack(side="left", padx=(0, 6))
            b.bind("<Button-1>", lambda e, n=nm: self._set_accent(n))

        cap("CARDS")
        self._v_temp = tk.BooleanVar(value=self.show_temp_pref)
        self._v_cpu = tk.BooleanVar(value=self.show_cpu)
        self._v_net = tk.BooleanVar(value=self.show_net)

        def chk(text, var, key, attr, enabled=True):
            # Rounded checkbox (canvas) + label — tk.Checkbutton's indicator is
            # a hard square.
            row = tk.Frame(pad, bg=BG)
            row.pack(fill="x", pady=2)
            cur = "hand2" if enabled else ""
            box = tk.Canvas(row, width=20, height=20, bg=BG,
                            highlightthickness=0, bd=0, cursor=cur)
            box.pack(side="left")
            lbl = tk.Label(row, text=text, bg=BG, fg=FG if enabled else GRID,
                           font=self.f_mid, anchor="w", cursor=cur)
            lbl.pack(side="left", padx=(8, 0))

            def redraw():
                box.delete("all")
                on = var.get()
                fill = ACCENT if (on and enabled) else TRACK
                out = (ACCENT if on else GRID) if enabled else GRID
                self._round_rect(box, 2, 2, 18, 18, 6, fill=fill, outline=out)
                if on:
                    box.create_line(6, 10, 9, 13, 14, 6,
                                    fill=BG if enabled else GRID, width=2,
                                    capstyle="round", joinstyle="round")

            def toggle(e=None):
                var.set(not var.get())
                setattr(self, attr, var.get())
                self.cfg.set(key, var.get())
                redraw()
                self._relayout()

            if enabled:
                box.bind("<Button-1>", toggle)
                lbl.bind("<Button-1>", toggle)
            redraw()

        chk("GPU temperature card", self._v_temp, "show_temp",
            "show_temp_pref", enabled=self.sensors.ok)
        if not self.sensors.ok:
            tk.Label(pad, text="(temp sensors unavailable)", bg=BG, fg=MUTED,
                     font=self.f_cap).pack(anchor="w")
        chk("CPU / RAM card", self._v_cpu, "show_cpu", "show_cpu")
        chk("Network card", self._v_net, "show_net", "show_net")

    def _set_accent(self, name):
        apply_accent(name)
        self.cfg.set("accent", name)
        self._draw_search_box(self.search.focus_get() is self.search)
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

    def _net_spark(self, c, x0, y0, x1, y1):
        """Download (filled accent) + upload (secondary line) on a shared,
        auto-scaled axis — network rates have no fixed 0..100 range."""
        rx, tx = list(self.hist_net_rx), list(self.hist_net_tx)
        peak = max(max(rx), max(tx), 1.0)
        self._spark(c, [v / peak * 100 for v in rx], x0, y0, x1, y1, ACCENT)
        tn = [v / peak * 100 for v in tx]
        if x1 - x0 >= 4 and len(tn) >= 2:
            step = (x1 - x0) / (len(tn) - 1)
            hh = y1 - y0
            pts = [k for i, v in enumerate(tn)
                   for k in (x0 + i * step, y1 - (hh - 2) * min(v, 100) / 100 - 1)]
            c.create_line(pts, fill=GPU_LINE, width=1.5, smooth=True, tags="fg")

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

        # --- NETWORK card (total throughput, down + up) ---
        if self.show_net:
            y1 = y + 86
            self._card(c, x0, y, x1, y1)
            c.create_text(x0 + 12, y + 17, text="NETWORK", anchor="w",
                          fill=MUTED, font=self.f_cap, tags="fg")
            c.create_text(x0 + 12, y + 45, text=f"↓ {fmt_bits(self.net_rx)}",
                          anchor="w", fill=ACCENT, font=self.f_stat, tags="fg")
            c.create_text(x1 - 12, y + 45, text=f"↑ {fmt_bits(self.net_tx)}",
                          anchor="e", fill=GPU_LINE, font=self.f_stat, tags="fg")
            self._net_spark(c, x0 + 12, y + 58, x1 - 12, y1 - 8)
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
        # Width change → full reflow (bar geometry depends on width). Height
        # change → just re-fill the (now differently sized) visible window.
        if e.width != self._plist_w:
            self._plist_w = e.width
            if self.last:
                self._draw_procs()
        elif self.last:
            self._redraw_rows()

    def _plist_row_at(self, e):
        return int(self.plist.canvasy(e.y) // self.ROWH)

    def _plist_motion(self, e):
        w = self.plist.winfo_width()
        i = self._plist_row_at(e)
        valid = 0 <= i < len(self._proc_list)
        over_x = valid and e.x >= w - 26 and not self._proc_list[i][3]
        self.plist.config(cursor="hand2" if over_x else "")
        self._plist_hover(i if valid else -1)          # highlight the whole row

    def _plist_hover(self, i):
        # Update just the hover highlight + the two affected ✕ marks — a full
        # _draw_procs() here cost ~14 ms per row-crossing on a long list.
        if i == self._hover_i:
            return
        prev, self._hover_i = self._hover_i, i
        c = self.plist
        for idx in (prev, i):
            xi = self._xitems.get(idx)
            if xi is not None and 0 <= idx < len(self._proc_list):
                crit = self._proc_list[idx][3]
                c.itemconfig(xi, fill=(
                    GRID if crit else
                    ACCENT_HOT2 if idx == self._hover_i else ACCENT_HOT))
        self._draw_hover_hl()

    def _draw_hover_hl(self):
        """Task-Manager-style highlight behind the hovered row."""
        c = self.plist
        c.delete("hl")
        i = self._hover_i
        if 0 <= i < len(self._proc_list):
            w = c.winfo_width() or 380
            y0 = i * self.ROWH
            self._round_rect(c, 2, y0 + 1, w - 2, y0 + self.ROWH - 1, 6,
                             fill=PANEL_HOVER, outline="", tags="hl")
            c.tag_lower("hl")                          # sit behind the row items

    def _plist_click(self, e):
        if self._proc_mode == "net" and not self.net_etw.ok:
            self._restart_as_admin()        # the "click to restart elevated" cue
            return
        w = self.plist.winfo_width()
        i = self._plist_row_at(e)
        if 0 <= i < len(self._proc_list) and e.x >= w - 26:
            name, val, pids, crit = self._proc_list[i]
            if crit:
                return
            if pids is None:                # CPU/RAM/NET row → resolve pids now
                pids = self._pids_for_name(name)
            if pids:
                self._kill(name, pids)

    def _restart_as_admin(self):
        """Relaunch Flux elevated (UAC) so the ETW net trace can run, then close
        this instance. No-op if the user declines the prompt."""
        try:
            if not self._maxed:
                self.cfg.set("geometry", self.root.geometry())
        except Exception:
            pass
        try:
            if getattr(sys, "frozen", False):
                exe, params = sys.executable, None
            else:
                exe = sys.executable
                params = f'"{os.path.abspath(sys.argv[0])}"'
            rc = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", exe, params, None, 1)
            if rc > 32:                      # >32 = launched (UAC accepted)
                self.net_etw.stop()
                self.root.destroy()
            else:
                self._status("Elevation cancelled.", MUTED)
        except Exception:
            pass

    def _draw_procs(self):
        mode = self._proc_mode
        procs = self._active_procs
        if self.filter:
            f = self.filter.lower()
            procs = [p for p in procs if f in p[0].lower()]
        c = self.plist
        c.delete("all")
        w = c.winfo_width()
        if w < 60:
            w = 380
        self._proc_list = []
        self._xitems = {}
        self._filtered = procs
        self._show_growth = mode == "vram"
        if not procs:
            if mode == "net" and not self.net_etw.ok and not self.filter:
                c.create_text(2, 14, anchor="w", fill=ACCENT_WARN,
                              font=self.f_small,
                              text="Per-process network needs administrator.")
                c.create_text(2, 36, anchor="w", fill=ACCENT, font=self.f_small,
                              text="↻  Click here to restart Flux elevated")
                c.configure(scrollregion=(0, 0, w, self.ROWH * 2))
                return
            if self.filter:
                msg = "No match"
            elif mode == "cpu":
                msg = "Measuring CPU…"
            elif mode == "net":
                msg = "Measuring network…"
            elif mode == "ram":
                msg = "No processes"
            else:
                msg = "No GPU memory in use"
            c.create_text(2, 14, anchor="w", fill=MUTED, font=self.f_small,
                          text=msg)
            c.configure(scrollregion=(0, 0, w, self.ROWH))
            return
        self._maxv = procs[0][1] or 1
        self._proc_list = [(n, v, p, n.lower() in CRITICAL_PROCESSES)
                           for n, v, p in procs]
        c.configure(scrollregion=(0, 0, w, len(procs) * self.ROWH + 4))
        self._redraw_rows()

    def _redraw_rows(self):
        """Draw only the rows in the viewport (± a small buffer). The list can be
        100+ long; drawing all of them every tick cost ~14 ms — this is ~2 ms."""
        procs = self._filtered
        if not procs:
            return
        c = self.plist
        c.delete("row")
        c.delete("hl")
        self._xitems = {}
        w = c.winfo_width()
        if w < 60:
            w = 380
        rh = self.ROWH
        maxv = self._maxv
        xx, mbx = w - 12, w - 30      # value ends before the ✕; bar clears both
        bx0, bx1 = 168, w - 104
        top = c.canvasy(0)
        vh = c.winfo_height() or 1
        first = max(0, int(top // rh) - 2)
        last = min(len(procs), int((top + vh) // rh) + 3)
        for i in range(first, last):
            name, val, pids = procs[i]
            crit = self._proc_list[i][3]
            y = i * rh + rh / 2
            if self._show_growth and name in self._growing:
                c.create_text(4, y, text="↑", anchor="w", fill=ACCENT_WARN,
                              font=self.f_mid, tags="row")
            c.create_text(18, y, text=name[:22], anchor="w", fill=FG,
                          font=self.f_mid, tags="row")
            if bx1 > bx0:
                self._round_rect(c, bx0, y - 3, bx1, y + 3, 3, fill=TRACK,
                                 outline="", tags="row")
                fw = (bx1 - bx0) * val / maxv
                if fw > 2:
                    self._round_rect(c, bx0, y - 3, bx0 + fw, y + 3, 3,
                                     fill=ACCENT, outline="", tags="row")
            c.create_text(mbx, y, text=self._fmt_val(val), anchor="e",
                          fill=MUTED, font=self.f_mono, tags="row")
            xcol = (GRID if crit else
                    ACCENT_HOT2 if i == self._hover_i else ACCENT_HOT)
            self._xitems[i] = c.create_text(xx, y, text="✕", anchor="e",
                                            fill=xcol, font=self.f_mid, tags="row")
        self._draw_hover_hl()

    # -- ending a process -------------------------------------------------- #
    def _kill(self, name, pids):
        n = len(pids)
        plural = "process" if n == 1 else f"{n} processes"
        if not messagebox.askyesno(
                "End process",
                f"End {name} ({plural})?\n\n"
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
        if self.show_net:
            try:
                self.net_rx, self.net_tx = net_rates(
                    self.net_rx_sampler, self.net_tx_sampler)
            except Exception:
                pass
        self.hist_net_rx.append(self.net_rx)
        self.hist_net_tx.append(self.net_tx)
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
        self._refresh_active_procs()
        self.lbl_prochead.config(text=str(len(self._active_procs)))
        self._paint_cards()
        self._draw_procs()

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
            _round_corners(t)              # soft corners on the toast
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
