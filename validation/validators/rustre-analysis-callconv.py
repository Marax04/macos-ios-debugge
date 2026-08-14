"""Independent validator for rustre-analysis-callconv.

Implements minimal calling-convention pattern factories and an observed-pattern
extractor in pure Python stdlib, then exercises them against synthetic
instruction streams. Output: JSON { crate, saved, functions }.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple, Dict


# --------------------------------------------------------------------------
# Calling convention patterns (subset, derived from the report's ABI summary)
# --------------------------------------------------------------------------

@dataclass
class CCPattern:
    name: str
    arg_registers: List[str]
    retval_registers: List[str]
    callee_saved: List[str]
    caller_cleanup: bool = True
    shadow_space_bytes: int = 0
    hidden_this_ptr: bool = False
    stack_alignment: int = 16

    def is_arg_register(self, reg: str) -> bool:
        return reg.lower() in (r.lower() for r in self.arg_registers)

    def is_callee_saved(self, reg: str) -> bool:
        return reg.lower() in (r.lower() for r in self.callee_saved)

    def is_retval_register(self, reg: str) -> bool:
        return reg.lower() in (r.lower() for r in self.retval_registers)

    def arg_register_at(self, n: int) -> Optional[str]:
        return self.arg_registers[n] if 0 <= n < len(self.arg_registers) else None

    def arg_register_count(self) -> int:
        return len(self.arg_registers)


def sysv_x64() -> CCPattern:
    return CCPattern(
        name="sysv_x64",
        arg_registers=["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        retval_registers=["rax", "rdx"],
        callee_saved=["rbx", "rbp", "r12", "r13", "r14", "r15"],
        caller_cleanup=True,
        shadow_space_bytes=0,
    )


def msvc_x64() -> CCPattern:
    return CCPattern(
        name="msvc_x64",
        arg_registers=["rcx", "rdx", "r8", "r9"],
        retval_registers=["rax"],
        callee_saved=["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"],
        caller_cleanup=True,
        shadow_space_bytes=32,
    )


def cdecl_x86() -> CCPattern:
    return CCPattern(
        name="cdecl_x86",
        arg_registers=[],
        retval_registers=["eax", "edx"],
        callee_saved=["ebx", "esi", "edi", "ebp"],
        caller_cleanup=True,
        stack_alignment=4,
    )


def stdcall_x86() -> CCPattern:
    return CCPattern(
        name="stdcall_x86",
        arg_registers=[],
        retval_registers=["eax", "edx"],
        callee_saved=["ebx", "esi", "edi", "ebp"],
        caller_cleanup=False,
        stack_alignment=4,
    )


def fastcall_x86() -> CCPattern:
    return CCPattern(
        name="fastcall_x86",
        arg_registers=["ecx", "edx"],
        retval_registers=["eax"],
        callee_saved=["ebx", "esi", "edi", "ebp"],
        caller_cleanup=False,
        stack_alignment=4,
    )


def thiscall_x86() -> CCPattern:
    return CCPattern(
        name="thiscall_x86",
        arg_registers=["ecx"],
        retval_registers=["eax"],
        callee_saved=["ebx", "esi", "edi", "ebp"],
        caller_cleanup=False,
        hidden_this_ptr=True,
        stack_alignment=4,
    )


def aapcs64() -> CCPattern:
    return CCPattern(
        name="aapcs64",
        arg_registers=["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        retval_registers=["x0", "x1"],
        callee_saved=[f"x{i}" for i in range(19, 29)],
        caller_cleanup=True,
    )


def aapcs32() -> CCPattern:
    return CCPattern(
        name="aapcs32",
        arg_registers=["r0", "r1", "r2", "r3"],
        retval_registers=["r0", "r1"],
        callee_saved=[f"r{i}" for i in range(4, 12)],
        caller_cleanup=True,
        stack_alignment=8,
    )


def mips_o32() -> CCPattern:
    return CCPattern(
        name="mips_o32",
        arg_registers=["a0", "a1", "a2", "a3"],
        retval_registers=["v0", "v1"],
        callee_saved=[f"s{i}" for i in range(0, 8)],
        caller_cleanup=True,
        shadow_space_bytes=16,
    )


def riscv64_lp64d() -> CCPattern:
    return CCPattern(
        name="riscv64_lp64d",
        arg_registers=["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
        retval_registers=["a0", "a1"],
        callee_saved=[f"s{i}" for i in range(0, 12)],
        caller_cleanup=True,
    )


# --------------------------------------------------------------------------
# Observed pattern + extractor
# --------------------------------------------------------------------------

@dataclass
class Observed:
    read_before_write: List[str] = field(default_factory=list)
    saved_registers: List[str] = field(default_factory=list)
    written_before_return: List[str] = field(default_factory=list)
    callee_pops_stack: bool = False
    this_ptr_hint: bool = False
    shadow_space_observed: int = 0
    stack_arg_count: int = 0

    def has_arg_evidence(self) -> bool:
        return bool(self.read_before_write) or self.stack_arg_count > 0


def extract_pattern(instrs: List[Tuple[str, str]], pointer_width: int) -> Observed:
    """instrs: list of (op, operand). op in {RegRead, RegWrite, Push, Pop, Ret,
    ThisPtrUse, StackArgAccess, Other}."""
    obs = Observed()
    written = set()
    push_stack: List[str] = []
    for op, arg in instrs:
        if op == "RegRead":
            r = arg.lower()
            if r not in written and r not in obs.read_before_write:
                obs.read_before_write.append(r)
        elif op == "RegWrite":
            written.add(arg.lower())
        elif op == "Push":
            push_stack.append(arg.lower())
        elif op == "Pop":
            if push_stack and push_stack[-1] == arg.lower():
                r = push_stack.pop()
                if r not in obs.saved_registers:
                    obs.saved_registers.append(r)
        elif op == "Ret":
            try:
                n = int(arg)
            except (TypeError, ValueError):
                n = 0
            if n > 0:
                obs.callee_pops_stack = True
        elif op == "ThisPtrUse":
            obs.this_ptr_hint = True
        elif op == "StackArgAccess":
            obs.stack_arg_count += 1
    obs.written_before_return = sorted(written)
    return obs


# --------------------------------------------------------------------------
# Scoring + detection
# --------------------------------------------------------------------------

def score(pattern: CCPattern, observed: Observed) -> int:
    s = 0
    # Args matched against arg_registers in order
    for i, r in enumerate(observed.read_before_write):
        if pattern.is_arg_register(r):
            s += 20 if i < pattern.arg_register_count() else 5
        elif r in {"rsp", "esp", "sp"}:
            continue
    # Callee-saved
    for r in observed.saved_registers:
        if pattern.is_callee_saved(r):
            s += 10
        else:
            s -= 5
    # Stack cleanup
    if observed.callee_pops_stack and not pattern.caller_cleanup:
        s += 15
    if observed.callee_pops_stack and pattern.caller_cleanup:
        s -= 10
    # Shadow space
    if pattern.shadow_space_bytes > 0 and observed.shadow_space_observed >= pattern.shadow_space_bytes:
        s += 10
    # this ptr
    if observed.this_ptr_hint and pattern.hidden_this_ptr:
        s += 15
    # Stack-only ABI bonus when no reg args read
    if not observed.read_before_write and pattern.arg_register_count() == 0 and observed.stack_arg_count > 0:
        s += 15
    return max(0, min(100, s))


def detect(observed: Observed, candidates: List[CCPattern]) -> Tuple[Optional[CCPattern], int, List[Tuple[str, int]]]:
    ranked = sorted(((c, score(c, observed)) for c in candidates), key=lambda x: -x[1])
    ranking = [(c.name, sc) for c, sc in ranked]
    if not ranked:
        return None, 0, ranking
    best, best_score = ranked[0]
    if len(ranked) > 1 and ranked[1][1] == best_score:
        # ambiguous, still return best with lower confidence
        pass
    return best, best_score, ranking


# --------------------------------------------------------------------------
# Test scenarios
# --------------------------------------------------------------------------

X64_CANDIDATES = [sysv_x64(), msvc_x64()]
X86_CANDIDATES = [cdecl_x86(), stdcall_x86(), fastcall_x86(), thiscall_x86()]
ARM_CANDIDATES = [aapcs64(), aapcs32()]
ALL_CANDIDATES = X64_CANDIDATES + X86_CANDIDATES + ARM_CANDIDATES + [mips_o32(), riscv64_lp64d()]


def run_scenarios() -> List[Dict]:
    results = []

    # 1. SysV x64: reads rdi, rsi, rdx; saves rbx
    instrs = [
        ("Push", "rbx"),
        ("RegRead", "rdi"),
        ("RegRead", "rsi"),
        ("RegRead", "rdx"),
        ("RegWrite", "rax"),
        ("Pop", "rbx"),
        ("Ret", "0"),
    ]
    obs = extract_pattern(instrs, 64)
    best, sc, ranking = detect(obs, X64_CANDIDATES)
    results.append({
        "name": "sysv_x64_three_args",
        "expected": "sysv_x64",
        "detected": best.name if best else None,
        "score": sc,
        "ranking": ranking,
        "pass": best is not None and best.name == "sysv_x64",
    })

    # 2. MSVC x64: reads rcx, rdx, r8; saves rsi
    instrs = [
        ("Push", "rsi"),
        ("RegRead", "rcx"),
        ("RegRead", "rdx"),
        ("RegRead", "r8"),
        ("RegWrite", "rax"),
        ("Pop", "rsi"),
        ("Ret", "0"),
    ]
    obs = extract_pattern(instrs, 64)
    obs.shadow_space_observed = 32
    best, sc, ranking = detect(obs, X64_CANDIDATES)
    results.append({
        "name": "msvc_x64_three_args",
        "expected": "msvc_x64",
        "detected": best.name if best else None,
        "score": sc,
        "ranking": ranking,
        "pass": best is not None and best.name == "msvc_x64",
    })

    # 3. stdcall x86: stack-only, callee pops
    instrs = [
        ("Push", "ebp"),
        ("StackArgAccess", "8"),
        ("StackArgAccess", "12"),
        ("RegWrite", "eax"),
        ("Pop", "ebp"),
        ("Ret", "8"),
    ]
    obs = extract_pattern(instrs, 32)
    best, sc, ranking = detect(obs, X86_CANDIDATES)
    results.append({
        "name": "stdcall_x86_two_stack_args",
        "expected": "stdcall_x86",
        "detected": best.name if best else None,
        "score": sc,
        "ranking": ranking,
        "pass": best is not None and best.name == "stdcall_x86",
    })

    # 4. fastcall x86: ecx, edx
    instrs = [
        ("RegRead", "ecx"),
        ("RegRead", "edx"),
        ("RegWrite", "eax"),
        ("Ret", "0"),
    ]
    obs = extract_pattern(instrs, 32)
    best, sc, ranking = detect(obs, X86_CANDIDATES)
    results.append({
        "name": "fastcall_x86_two_args",
        "expected": "fastcall_x86",
        "detected": best.name if best else None,
        "score": sc,
        "ranking": ranking,
        "pass": best is not None and best.name == "fastcall_x86",
    })

    # 5. thiscall x86: ecx (this) + this_ptr_hint
    instrs = [
        ("RegRead", "ecx"),
        ("ThisPtrUse", "ecx"),
        ("RegWrite", "eax"),
        ("Ret", "4"),
    ]
    obs = extract_pattern(instrs, 32)
    best, sc, ranking = detect(obs, X86_CANDIDATES)
    results.append({
        "name": "thiscall_x86_method",
        "expected": "thiscall_x86",
        "detected": best.name if best else None,
        "score": sc,
        "ranking": ranking,
        "pass": best is not None and best.name == "thiscall_x86",
    })

    # 6. AAPCS64: x0..x3
    instrs = [
        ("RegRead", "x0"),
        ("RegRead", "x1"),
        ("RegRead", "x2"),
        ("RegRead", "x3"),
        ("RegWrite", "x0"),
        ("Ret", "0"),
    ]
    obs = extract_pattern(instrs, 64)
    best, sc, ranking = detect(obs, ARM_CANDIDATES)
    results.append({
        "name": "aapcs64_four_args",
        "expected": "aapcs64",
        "detected": best.name if best else None,
        "score": sc,
        "ranking": ranking,
        "pass": best is not None and best.name == "aapcs64",
    })

    # 7. ABI factory sanity (sysv_x64 register set)
    p = sysv_x64()
    factory_ok = (
        p.arg_register_at(0) == "rdi"
        and p.arg_register_at(5) == "r9"
        and p.is_callee_saved("rbx")
        and p.is_retval_register("rax")
        and not p.is_arg_register("rax")
    )
    results.append({
        "name": "sysv_x64_factory_invariants",
        "expected": True,
        "detected": factory_ok,
        "score": 100 if factory_ok else 0,
        "ranking": [],
        "pass": factory_ok,
    })

    # 8. msvc_x64 shadow space invariant
    p = msvc_x64()
    msvc_ok = p.shadow_space_bytes == 32 and p.arg_register_at(0) == "rcx"
    results.append({
        "name": "msvc_x64_factory_invariants",
        "expected": True,
        "detected": msvc_ok,
        "score": 100 if msvc_ok else 0,
        "ranking": [],
        "pass": msvc_ok,
    })

    return results


def main() -> None:
    crate = "rustre-analysis-callconv"
    out_dir = r"C:\Users\Fra\Desktop\RustRE\validation\results"
    results = run_scenarios()
    payload = {
        "crate": crate,
        "saved": False,
        "functions": results,
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r["pass"]),
            "failed": sum(1 for r in results if not r["pass"]),
        },
    }
    try:
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, f"{crate}.json"), "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        payload["saved"] = True
    except Exception as e:
        payload["save_error"] = str(e)

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
