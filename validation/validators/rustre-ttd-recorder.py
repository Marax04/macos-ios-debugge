"""Independent validator for rustre-ttd-recorder crate.

Reimplements pure-logic primitives described in
validation/reports/rustre-ttd-recorder.md using only Python stdlib,
and emits expected results that can be compared against the crate.
"""

import json
import os
import struct
from collections import deque
from typing import Optional


# ---------- TtdPosition ----------
class TtdPosition:
    def __init__(self, major: int, minor: int):
        self.major = major & 0xFFFFFFFFFFFFFFFF
        self.minor = minor & 0xFFFFFFFFFFFFFFFF

    @classmethod
    def new(cls, major, minor):
        return cls(major, minor)

    @classmethod
    def start(cls):
        return cls(0, 0)

    @classmethod
    def earliest(cls):
        return cls(0, 0)

    def is_before(self, other: "TtdPosition") -> bool:
        if self.major != other.major:
            return self.major < other.major
        return self.minor < other.minor

    def __str__(self):
        return f"{self.major}:{self.minor}"


# ---------- CompressionLevel ----------
COMPRESSION_LEVELS = ["None", "Fast", "Default", "Best"]


# ---------- TtdRecordConfig.validate ----------
def validate_config(cfg: dict) -> Optional[str]:
    if cfg.get("max_recording_size_mb", 0) == 0:
        return "max_recording_size_mb must be > 0"
    if cfg.get("ring_buffer_mb", 0) == 0:
        return "ring_buffer_mb must be > 0"
    out = cfg.get("output_dir", "")
    if not out:
        return "output_dir must not be empty"
    return None


def for_pid(pid: int, output_dir: str) -> dict:
    return {
        "target_process": {"ProcessId": pid},
        "output_dir": output_dir,
        "max_recording_size_mb": 1024,
        "compression": "Default",
        "encrypt": False,
        "ring_buffer_mb": 256,
        "timeout_secs": 0,
        "follow_children": False,
        "record_heap": False,
        "full_heap": False,
    }


# ---------- TtdRecordFilter ----------
class TtdRecordFilter:
    def __init__(self):
        self.include_modules = []
        self.exclude_modules = []
        self.include_threads = []
        self.exclude_threads = []
        self.record_only_from_address = None
        self.stop_at_address = None

    @classmethod
    def pass_all(cls):
        return cls()

    def thread_allowed(self, tid: int) -> bool:
        if self.include_threads and tid not in self.include_threads:
            return False
        if tid in self.exclude_threads:
            return False
        return True

    def module_allowed(self, name: str) -> bool:
        if self.include_modules and name not in self.include_modules:
            return False
        if name in self.exclude_modules:
            return False
        return True


# ---------- RingBufferRecorder ----------
class RingBufferRecorder:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.events = deque(maxlen=capacity)

    def push(self, ev):
        self.events.append(ev)

    def snapshot(self):
        return list(self.events)

    def len(self):
        return len(self.events)

    def is_empty(self):
        return len(self.events) == 0

    def clear(self):
        self.events.clear()


# ---------- RecordingSchedule ----------
class RecordingSchedule:
    def __init__(self, start_address=None, stop_address=None,
                 start_position=None, stop_position=None, max_duration=None):
        self.start_address = start_address
        self.stop_address = stop_address
        self.start_position = start_position
        self.stop_position = stop_position
        self.max_duration = max_duration

    @classmethod
    def record_all(cls):
        return cls()

    @classmethod
    def for_duration(cls, secs: int):
        return cls(max_duration=secs)

    def should_stop(self, elapsed_secs: int, position: Optional[TtdPosition] = None) -> bool:
        if self.max_duration is not None and elapsed_secs >= self.max_duration:
            return True
        if self.stop_position is not None and position is not None:
            if not position.is_before(self.stop_position):
                return True
        return False


# ---------- TtdTraceValidation.is_valid_extension ----------
def is_valid_extension(path: str) -> bool:
    p = path.lower()
    return p.endswith(".run") or p.endswith(".ttd")


# ---------- ChaCha20Poly1305 nonce layout (96-bit = salt(8) || counter(4)) ----------
def build_nonce(salt: bytes, counter: int) -> bytes:
    assert len(salt) == 8
    return salt + struct.pack("<I", counter & 0xFFFFFFFF)


# ---------- RecordingMetrics.summary ----------
def metrics_summary(m: dict) -> str:
    return (
        f"events={m['events_recorded']} "
        f"size={m['file_size_bytes']}B "
        f"compressed={m['compressed_size_bytes']}B "
        f"elapsed={m['elapsed_secs']}s "
        f"insns={m['instructions_recorded']} "
        f"mem_events={m['memory_events']} "
        f"threads={m['thread_count']}"
    )


# ---------- validation functions ----------
def fn_position_ordering():
    a = TtdPosition.new(1, 5)
    b = TtdPosition.new(1, 6)
    c = TtdPosition.new(2, 0)
    s = TtdPosition.start()
    return {
        "start": str(s),
        "a_before_b": a.is_before(b),
        "b_before_a": b.is_before(a),
        "a_before_c": a.is_before(c),
        "equal_before": a.is_before(a),
        "earliest": str(TtdPosition.earliest()),
    }


def fn_compression_levels():
    return {"levels": COMPRESSION_LEVELS, "count": len(COMPRESSION_LEVELS)}


def fn_config_for_pid_and_validate():
    cfg = for_pid(1234, "C:/traces")
    return {
        "config": cfg,
        "validate_ok": validate_config(cfg) is None,
        "validate_no_outdir": validate_config({**cfg, "output_dir": ""}),
        "validate_zero_size": validate_config({**cfg, "max_recording_size_mb": 0}),
        "validate_zero_ring": validate_config({**cfg, "ring_buffer_mb": 0}),
    }


def fn_filter_pass_all():
    f = TtdRecordFilter.pass_all()
    return {
        "thread_42": f.thread_allowed(42),
        "module_kernel32": f.module_allowed("kernel32.dll"),
    }


def fn_filter_include_exclude():
    f = TtdRecordFilter()
    f.include_threads = [1, 2, 3]
    f.exclude_threads = [2]
    f.include_modules = ["a.dll", "b.dll"]
    f.exclude_modules = ["b.dll"]
    return {
        "tid_1": f.thread_allowed(1),
        "tid_2": f.thread_allowed(2),
        "tid_4": f.thread_allowed(4),
        "mod_a": f.module_allowed("a.dll"),
        "mod_b": f.module_allowed("b.dll"),
        "mod_c": f.module_allowed("c.dll"),
    }


def fn_ring_buffer():
    rb = RingBufferRecorder(3)
    assert rb.is_empty()
    rb.push("e1"); rb.push("e2"); rb.push("e3"); rb.push("e4")
    snap = rb.snapshot()
    out = {"len": rb.len(), "snapshot": snap, "capacity": rb.capacity}
    rb.clear()
    out["cleared_empty"] = rb.is_empty()
    return out


def fn_schedule():
    s_all = RecordingSchedule.record_all()
    s_dur = RecordingSchedule.for_duration(10)
    s_pos = RecordingSchedule(stop_position=TtdPosition.new(5, 0))
    return {
        "all_should_stop_at_100s": s_all.should_stop(100),
        "dur_stop_at_9": s_dur.should_stop(9),
        "dur_stop_at_10": s_dur.should_stop(10),
        "dur_stop_at_11": s_dur.should_stop(11),
        "pos_before": s_pos.should_stop(0, TtdPosition.new(4, 999)),
        "pos_equal": s_pos.should_stop(0, TtdPosition.new(5, 0)),
        "pos_after": s_pos.should_stop(0, TtdPosition.new(5, 1)),
    }


def fn_trace_extension():
    return {
        "ok_run": is_valid_extension("a.run"),
        "ok_ttd": is_valid_extension("X.TTD"),
        "bad_txt": is_valid_extension("a.txt"),
        "bad_none": is_valid_extension("a"),
    }


def fn_nonce_layout():
    salt = bytes([0xAA] * 8)
    n0 = build_nonce(salt, 0)
    n1 = build_nonce(salt, 1)
    n_big = build_nonce(salt, 0x01020304)
    return {
        "nonce_len": len(n0),
        "n0_hex": n0.hex(),
        "n1_hex": n1.hex(),
        "n_big_hex": n_big.hex(),  # salt + 04030201 (LE)
    }


def fn_metrics_summary():
    m = {
        "events_recorded": 100,
        "file_size_bytes": 4096,
        "compressed_size_bytes": 1024,
        "elapsed_secs": 5,
        "instructions_recorded": 9999,
        "memory_events": 42,
        "thread_count": 3,
    }
    return {"summary": metrics_summary(m)}


def fn_recording_status_variants():
    return {
        "variants": [
            "Initializing", "Injecting", "Recording",
            "Paused", "Stopping", "Stopped", "Error",
        ]
    }


def fn_error_variants():
    return {
        "TtdRecordError": [
            "NotAvailable", "ProcessNotFound", "InsufficientPrivileges",
            "OutputPathError", "CompressionError", "RecordingFailed", "Io",
        ],
        "RecorderError": [
            "AlreadyRecording", "NotRecording", "SpawnError",
            "TraceWriteError", "Io", "InvalidConfig", "Serde",
        ],
    }


FUNCTIONS = [
    ("position_ordering", fn_position_ordering),
    ("compression_levels", fn_compression_levels),
    ("config_for_pid_and_validate", fn_config_for_pid_and_validate),
    ("filter_pass_all", fn_filter_pass_all),
    ("filter_include_exclude", fn_filter_include_exclude),
    ("ring_buffer", fn_ring_buffer),
    ("schedule", fn_schedule),
    ("trace_extension", fn_trace_extension),
    ("nonce_layout", fn_nonce_layout),
    ("metrics_summary", fn_metrics_summary),
    ("recording_status_variants", fn_recording_status_variants),
    ("error_variants", fn_error_variants),
]


def main():
    results = []
    for name, fn in FUNCTIONS:
        try:
            results.append({"name": name, "ok": True, "result": fn()})
        except Exception as e:
            results.append({"name": name, "ok": False, "error": str(e)})
    out = {"crate": "rustre-ttd-recorder", "saved": True, "functions": results}
    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "rustre-ttd-recorder.result.json",
    )
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, default=str)
    except Exception:
        out["saved"] = False
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
