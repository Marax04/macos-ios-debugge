#!/usr/bin/env python3
"""Wrapper: run agent-suggested edits with SIZE CHECK — restore if wire_tools.rs shrinks."""
import os, shutil, subprocess, sys, json

WT = r"C:\Users\Fra\Desktop\RustRE\crates\rustre-mcp-tools\src\wire_tools.rs"
BACKUP = r"C:\Users\Fra\Desktop\RustRE\validation\wire_tools_SAFE_71tools.bak"

def size():
    return os.path.getsize(WT)

def check_and_restore(min_bytes_expected):
    s = size()
    if s < min_bytes_expected * 0.7:  # if shrank by >30%, restore
        print(f"REGRESSION DETECTED: {s} < {min_bytes_expected*0.7} — RESTORING")
        shutil.copy(BACKUP, WT)
        return True
    return False

if __name__ == "__main__":
    baseline = os.path.getsize(BACKUP)
    print(f"Baseline: {baseline} bytes")
    print(f"Current:  {size()} bytes")
    if check_and_restore(baseline):
        print("Restored from backup")
