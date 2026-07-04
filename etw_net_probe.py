"""Standalone validation probe for per-process network via ETW.

Runs a real-time trace of the Microsoft-Windows-Kernel-Network provider for a
few seconds and prints bytes/PID (send + recv), to confirm the mechanism before
wiring it into Flux. Needs admin — it self-elevates via a UAC prompt and writes
results to etw_probe_out.txt next to this file.

    python etw_net_probe.py
"""
import ctypes
import os
import struct
import sys
import threading
import time
from ctypes import wintypes

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "etw_probe_out.txt")

# --------------------------------------------------------------------------- #
#  Structures (evntrace.h / relogger.h) — full definitions so ctypes gets the
#  64-bit alignment/offsets right (a wrong size crashes ProcessTrace).
# --------------------------------------------------------------------------- #
ULONG = wintypes.ULONG
USHORT = wintypes.USHORT
UCHAR = ctypes.c_ubyte
LONG = wintypes.LONG
ULONG64 = ctypes.c_uint64
LARGE_INTEGER = ctypes.c_int64
TRACEHANDLE = ctypes.c_uint64


class GUID(ctypes.Structure):
    _fields_ = [("Data1", ULONG), ("Data2", USHORT), ("Data3", USHORT),
                ("Data4", UCHAR * 8)]


def make_guid(d1, d2, d3, d4):
    g = GUID()
    g.Data1, g.Data2, g.Data3 = d1, d2, d3
    for i, b in enumerate(d4):
        g.Data4[i] = b
    return g


# Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88}
KERNEL_NET = make_guid(0x7DD42A49, 0x5329, 0x4832,
                       (0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88))


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", ULONG), ("ProviderId", ULONG),
                ("HistoricalContext", ULONG64), ("TimeStamp", LARGE_INTEGER),
                ("Guid", GUID), ("ClientContext", ULONG), ("Flags", ULONG)]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [("Wnode", WNODE_HEADER), ("BufferSize", ULONG),
                ("MinimumBuffers", ULONG), ("MaximumBuffers", ULONG),
                ("MaximumFileSize", ULONG), ("LogFileMode", ULONG),
                ("FlushTimer", ULONG), ("EnableFlags", ULONG),
                ("AgeLimit", LONG), ("NumberOfBuffers", ULONG),
                ("FreeBuffers", ULONG), ("EventsLost", ULONG),
                ("BuffersWritten", ULONG), ("LogBuffersLost", ULONG),
                ("RealTimeBuffersLost", ULONG), ("LoggerThreadId", wintypes.HANDLE),
                ("LogFileNameOffset", ULONG), ("LoggerNameOffset", ULONG)]


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [(n, USHORT) for n in ("wYear", "wMonth", "wDayOfWeek", "wDay",
                                      "wHour", "wMinute", "wSecond", "wMs")]


class TIME_ZONE_INFORMATION(ctypes.Structure):
    _fields_ = [("Bias", LONG), ("StandardName", ctypes.c_wchar * 32),
                ("StandardDate", SYSTEMTIME), ("StandardBias", LONG),
                ("DaylightName", ctypes.c_wchar * 32),
                ("DaylightDate", SYSTEMTIME), ("DaylightBias", LONG)]


class TRACE_LOGFILE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", ULONG), ("Version", ULONG),
                ("ProviderVersion", ULONG), ("NumberOfProcessors", ULONG),
                ("EndTime", LARGE_INTEGER), ("TimerResolution", ULONG),
                ("MaximumFileSize", ULONG), ("LogFileMode", ULONG),
                ("BuffersWritten", ULONG), ("LogInstanceGuid", GUID),
                ("LoggerName", ctypes.c_void_p), ("LogFileName", ctypes.c_void_p),
                ("TimeZone", TIME_ZONE_INFORMATION), ("BootTime", LARGE_INTEGER),
                ("PerfFreq", LARGE_INTEGER), ("StartTime", LARGE_INTEGER),
                ("ReservedFlags", ULONG), ("BuffersLost", ULONG)]


class EVENT_TRACE_HEADER(ctypes.Structure):
    _fields_ = [("Size", USHORT), ("FieldTypeFlags", USHORT), ("Version", ULONG),
                ("ThreadId", ULONG), ("ProcessId", ULONG),
                ("TimeStamp", LARGE_INTEGER), ("Guid", GUID),
                ("ClientContext", ULONG), ("Flags", ULONG)]


class ETW_BUFFER_CONTEXT(ctypes.Structure):
    _fields_ = [("ProcessorNumber", UCHAR), ("Alignment", UCHAR),
                ("LoggerId", USHORT)]


class EVENT_TRACE(ctypes.Structure):
    _fields_ = [("Header", EVENT_TRACE_HEADER), ("InstanceId", ULONG),
                ("ParentInstanceId", ULONG), ("ParentGuid", GUID),
                ("MofData", ctypes.c_void_p), ("MofLength", ULONG),
                ("ClientContext", ULONG)]


class EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("Id", USHORT), ("Version", UCHAR), ("Channel", UCHAR),
                ("Level", UCHAR), ("Opcode", UCHAR), ("Task", USHORT),
                ("Keyword", ULONG64)]


class EVENT_HEADER(ctypes.Structure):
    _fields_ = [("Size", USHORT), ("HeaderType", USHORT), ("Flags", USHORT),
                ("EventProperty", USHORT), ("ThreadId", ULONG),
                ("ProcessId", ULONG), ("TimeStamp", LARGE_INTEGER),
                ("ProviderId", GUID), ("EventDescriptor", EVENT_DESCRIPTOR),
                ("KernelTime", ULONG), ("UserTime", ULONG),
                ("ActivityId", GUID)]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [("EventHeader", EVENT_HEADER), ("BufferContext", ETW_BUFFER_CONTEXT),
                ("ExtendedDataCount", USHORT), ("UserDataLength", USHORT),
                ("ExtendedData", ctypes.c_void_p), ("UserData", ctypes.c_void_p),
                ("UserContext", ctypes.c_void_p)]


EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(EVENT_RECORD))


class EVENT_TRACE_LOGFILE(ctypes.Structure):
    _fields_ = [("LogFileName", wintypes.LPWSTR), ("LoggerName", wintypes.LPWSTR),
                ("CurrentTime", LARGE_INTEGER), ("BuffersRead", ULONG),
                ("ProcessTraceMode", ULONG), ("CurrentEvent", EVENT_TRACE),
                ("LogfileHeader", TRACE_LOGFILE_HEADER),
                ("BufferCallback", ctypes.c_void_p), ("BufferSize", ULONG),
                ("Filled", ULONG), ("EventsLost", ULONG),
                ("EventRecordCallback", EVENT_RECORD_CALLBACK),
                ("IsKernelTrace", ULONG), ("Context", ctypes.c_void_p)]


advapi32 = ctypes.WinDLL("advapi32.dll")
advapi32.StartTraceW.argtypes = [ctypes.POINTER(TRACEHANDLE), wintypes.LPCWSTR,
                                 ctypes.POINTER(EVENT_TRACE_PROPERTIES)]
advapi32.StartTraceW.restype = ULONG
advapi32.EnableTraceEx2.argtypes = [TRACEHANDLE, ctypes.POINTER(GUID), ULONG,
                                    UCHAR, ULONG64, ULONG64, ULONG, ctypes.c_void_p]
advapi32.EnableTraceEx2.restype = ULONG
advapi32.ControlTraceW.argtypes = [TRACEHANDLE, wintypes.LPCWSTR,
                                   ctypes.POINTER(EVENT_TRACE_PROPERTIES), ULONG]
advapi32.ControlTraceW.restype = ULONG
advapi32.OpenTraceW.argtypes = [ctypes.POINTER(EVENT_TRACE_LOGFILE)]
advapi32.OpenTraceW.restype = TRACEHANDLE
advapi32.ProcessTrace.argtypes = [ctypes.POINTER(TRACEHANDLE), ULONG,
                                  ctypes.c_void_p, ctypes.c_void_p]
advapi32.ProcessTrace.restype = ULONG
advapi32.CloseTrace.argtypes = [TRACEHANDLE]
advapi32.CloseTrace.restype = ULONG

WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
EVENT_TRACE_CONTROL_STOP = 1
TRACE_LEVEL_VERBOSE = 5
KEYWORD_IPV4 = 0x10
KEYWORD_IPV6 = 0x20
ERROR_ALREADY_EXISTS = 183
INVALID_TRACEHANDLE = 0xFFFFFFFFFFFFFFFF
SESSION = "FluxNetProbe"

SEND_IDS = {10, 26, 42, 58}
RECV_IDS = {11, 27, 43, 59}

lock = threading.Lock()
by_pid = {}                       # pid -> [sent, recv]
raw_dump = []


def _props():
    size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + (len(SESSION) + 1) * 2 + 8
    buf = (ctypes.c_byte * size)()
    p = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES))
    p.contents.Wnode.BufferSize = size
    p.contents.Wnode.Flags = WNODE_FLAG_TRACED_GUID
    p.contents.Wnode.ClientContext = 1
    p.contents.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
    p.contents.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
    return buf, p


@EVENT_RECORD_CALLBACK
def _on_event(rec):
    r = rec.contents
    eid = r.EventHeader.EventDescriptor.Id
    n = r.UserDataLength
    if not r.UserData or n < 8:
        return
    data = ctypes.string_at(r.UserData, n)
    pid, size = struct.unpack_from("<II", data, 0)
    with lock:
        if len(raw_dump) < 8:
            raw_dump.append((eid, pid, size, data[:16].hex()))
        slot = by_pid.setdefault(pid, [0, 0])
        if eid in SEND_IDS:
            slot[0] += size
        elif eid in RECV_IDS:
            slot[1] += size


def proc_names():
    import subprocess
    names = {}
    try:
        # cheap PID->name without extra deps
        TH32 = 0x2

        class PE(ctypes.Structure):
            _fields_ = [("dwSize", ULONG), ("cntUsage", ULONG),
                        ("th32ProcessID", ULONG), ("th32DefaultHeapID", ctypes.c_size_t),
                        ("th32ModuleID", ULONG), ("cntThreads", ULONG),
                        ("th32ParentProcessID", ULONG), ("pcPriClassBase", LONG),
                        ("dwFlags", ULONG), ("szExeFile", ctypes.c_wchar * 260)]
        k = ctypes.WinDLL("kernel32.dll")
        k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        snap = k.CreateToolhelp32Snapshot(TH32, 0)
        e = PE(); e.dwSize = ctypes.sizeof(PE)
        if k.Process32FirstW(snap, ctypes.byref(e)):
            while True:
                names[e.th32ProcessID] = e.szExeFile
                if not k.Process32NextW(snap, ctypes.byref(e)):
                    break
        k.CloseHandle(snap)
    except Exception:
        pass
    return names


def run_trace(seconds=6):
    lines = []
    buf, p = _props()
    h = TRACEHANDLE(0)
    st = advapi32.StartTraceW(ctypes.byref(h), SESSION, p)
    if st == ERROR_ALREADY_EXISTS:
        advapi32.ControlTraceW(0, SESSION, p, EVENT_TRACE_CONTROL_STOP)
        buf, p = _props()
        st = advapi32.StartTraceW(ctypes.byref(h), SESSION, p)
    if st != 0:
        return [f"StartTrace failed: error {st} "
                f"({'ACCESS DENIED — not elevated' if st == 5 else st})"]
    lines.append(f"session started (handle ok), enabling provider…")
    en = advapi32.EnableTraceEx2(
        h, ctypes.byref(KERNEL_NET), EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE, KEYWORD_IPV4 | KEYWORD_IPV6, 0, 0, None)
    lines.append(f"EnableTraceEx2 -> {en}")
    if en != 0:
        advapi32.ControlTraceW(h, SESSION, p, EVENT_TRACE_CONTROL_STOP)
        return lines + [f"provider enable failed: error {en} "
                        f"({'ACCESS DENIED — needs admin' if en == 5 else en})"]

    logfile = EVENT_TRACE_LOGFILE()
    logfile.LoggerName = SESSION
    logfile.ProcessTraceMode = (PROCESS_TRACE_MODE_REAL_TIME |
                                PROCESS_TRACE_MODE_EVENT_RECORD)
    logfile.EventRecordCallback = _on_event
    th = advapi32.OpenTraceW(ctypes.byref(logfile))
    if th == INVALID_TRACEHANDLE:
        advapi32.ControlTraceW(h, SESSION, p, EVENT_TRACE_CONTROL_STOP)
        return lines + [f"OpenTrace failed: {ctypes.get_last_error()}"]
    lines.append("trace opened, capturing…")

    def pump():
        harr = (TRACEHANDLE * 1)(th)
        advapi32.ProcessTrace(harr, 1, None, None)
    t = threading.Thread(target=pump, daemon=True)
    t.start()
    time.sleep(seconds)
    advapi32.ControlTraceW(h, SESSION, p, EVENT_TRACE_CONTROL_STOP)
    advapi32.CloseTrace(th)
    t.join(timeout=2)

    names = proc_names()
    lines.append(f"\ncaptured {sum(s+r for s, r in by_pid.values())} bytes "
                 f"across {len(by_pid)} pids in {seconds}s\n")
    lines.append("raw sample events (eid, pid, size, first16hex):")
    for eid, pid, size, hx in raw_dump:
        lines.append(f"  eid={eid:3} pid={pid:<7} size={size:<7} {hx}")
    lines.append("\ntop processes by total bytes (name: sent / recv):")
    ranked = sorted(by_pid.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))
    for pid, (s, r) in ranked[:15]:
        nm = names.get(pid, f"pid {pid}")
        lines.append(f"  {nm:28} {s/seconds/1e6*8:7.2f} Mbps up  "
                     f"{r/seconds/1e6*8:7.2f} Mbps down")
    return lines


def main():
    admin = False
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass
    if not admin:
        try:
            os.remove(OUT)
        except OSError:
            pass
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            f'"{os.path.abspath(__file__)}"', None, 1)
        print(f"Not elevated — requested UAC elevation (ShellExecute={rc}).")
        print(f"Approve the prompt; results will be written to:\n  {OUT}")
        return
    out = run_trace()
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n=== DONE ===\n")
    print("\n".join(out))
    print("wrote", OUT)


if __name__ == "__main__":
    main()
