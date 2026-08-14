"""Independent Python validator for rustre-deobf-vm crate.

Reimplements key primitives and analyses described in the report using only
stdlib, to cross-check the Rust crate's behaviour.
"""

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# ---------- primitives ----------

def read_u64_le(b: bytes) -> int:
    if len(b) < 8:
        return 0
    return struct.unpack_from("<Q", b, 0)[0]


def read_u32_le(b: bytes) -> int:
    if len(b) < 4:
        return 0
    return struct.unpack_from("<I", b, 0)[0]


def read_u16_le(b: bytes) -> int:
    if len(b) < 2:
        return 0
    return struct.unpack_from("<H", b, 0)[0]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


# ---------- VirtualMachineState ----------

class VirtualMachineState:
    def __init__(self):
        self.regs = [0] * 8
        self.pc = 0
        self.stack: List[int] = []
        self.flags = 0
        self.memory: Dict[int, int] = {}

    def reset(self):
        self.__init__()

    def push(self, v: int):
        self.stack.append(v & 0xFFFFFFFF)

    def pop(self) -> Optional[int]:
        if not self.stack:
            return None
        return self.stack.pop()

    def mem_read_byte(self, addr: int) -> int:
        return self.memory.get(addr, 0)

    def mem_write_byte(self, addr: int, v: int):
        self.memory[addr] = v & 0xFF

    def mem_read_u32(self, addr: int) -> int:
        return (
            self.mem_read_byte(addr)
            | (self.mem_read_byte(addr + 1) << 8)
            | (self.mem_read_byte(addr + 2) << 16)
            | (self.mem_read_byte(addr + 3) << 24)
        )

    def mem_write_u32(self, addr: int, v: int):
        for i in range(4):
            self.mem_write_byte(addr + i, (v >> (8 * i)) & 0xFF)

    def zero_flag(self) -> bool:
        return (self.flags & 1) != 0

    def carry_flag(self) -> bool:
        return (self.flags & 2) != 0

    def set_zero_flag(self, result: int):
        if (result & 0xFFFFFFFF) == 0:
            self.flags |= 1
        else:
            self.flags &= ~1


# ---------- VmDispatcherDetector ----------

SIG1 = bytes([0x31, 0xC0, 0xFF, 0x24])
SIG2 = bytes([0x48, 0x81, 0xC3, 0xFF])


@dataclass
class VmDispatcher:
    entry: int
    handler_table: int
    handler_count: int
    signature_index: int


class VmDispatcherDetector:
    def detect_dispatcher(self, blocks: List[bytes]) -> Optional[VmDispatcher]:
        for block in blocks:
            for sig_idx, sig in enumerate((SIG1, SIG2)):
                idx = block.find(sig)
                if idx < 0:
                    continue
                # next bytes interpreted as three little-endian u64
                base = idx + len(sig)
                entry = read_u64_le(block[base : base + 8])
                table = read_u64_le(block[base + 8 : base + 16])
                count = read_u64_le(block[base + 16 : base + 24])
                if count > 65536:
                    count = 65536
                return VmDispatcher(entry, table, count, sig_idx)
        return None

    def detect(self, blocks: List[bytes]) -> Optional[VmDispatcher]:
        return self.detect_dispatcher(blocks)


# ---------- VmHandler ----------

class HandlerKind(Enum):
    Arithmetic = "Arithmetic"
    Logic = "Logic"
    Load = "Load"
    Store = "Store"
    ControlFlow = "ControlFlow"
    StackOp = "StackOp"
    Compare = "Compare"
    Unknown = "Unknown"


@dataclass
class VmHandler:
    index: int
    address: int
    prologue: bytes
    kind: HandlerKind
    description: str
    stack_inputs: int
    stack_outputs: int

    def is_arithmetic(self) -> bool:
        return self.kind in (HandlerKind.Arithmetic, HandlerKind.Logic)

    def is_control_flow(self) -> bool:
        return self.kind == HandlerKind.ControlFlow

    def prologue_entropy(self) -> float:
        return shannon_entropy(self.prologue)


# ---------- VmDetector ----------

class VmConfidence(Enum):
    NoneC = 0
    Low = 1
    Medium = 2
    High = 3
    Definitive = 4


@dataclass
class VmDetectionResult:
    confidence: VmConfidence
    dispatcher_count: int
    handler_count: int
    arch_hints: List[str] = field(default_factory=list)
    dispatcher_offset: Optional[int] = None


INDIRECT_JMP_BYTES = {0x24, 0xE0, 0xE1, 0xE2, 0xE3, 0xD0}


class VmDetector:
    def detect(self, data: bytes) -> VmDetectionResult:
        hints: List[str] = []
        for marker, name in (
            (b"VMProtect", "VMProtect"),
            (b"Themida", "Themida"),
            (b"Enigma", "Enigma"),
            (b"cpuid", "CPUID"),
            (b"rdtsc", "RDTSC"),
        ):
            if marker.lower() in data.lower():
                hints.append(name)

        dispatcher_count = 0
        dispatcher_offset: Optional[int] = None
        i = 0
        while i + 1 < len(data):
            if data[i] == 0xFF and data[i + 1] in INDIRECT_JMP_BYTES:
                if dispatcher_offset is None:
                    dispatcher_offset = i
                dispatcher_count += 1
                i += 2
            else:
                i += 1

        # PUSH-reg handler entries: 0x50..0x57
        handler_count = sum(1 for b in data if 0x50 <= b <= 0x57)

        if dispatcher_count == 0 and not hints:
            conf = VmConfidence.NoneC
        elif dispatcher_count > 0 and hints:
            conf = VmConfidence.Definitive
        elif dispatcher_count > 5:
            conf = VmConfidence.High
        elif dispatcher_count > 0:
            conf = VmConfidence.Medium
        else:
            conf = VmConfidence.Low

        return VmDetectionResult(
            confidence=conf,
            dispatcher_count=dispatcher_count,
            handler_count=handler_count,
            arch_hints=hints,
            dispatcher_offset=dispatcher_offset,
        )


# ---------- VmBytecode ----------

@dataclass
class VmBytecode:
    bytes_: bytes
    start_address: int
    opcode_width: int
    distinct_opcodes: int = 0
    entropy: float = 0.0

    @classmethod
    def new(cls, data: bytes, start_address: int, opcode_width: int) -> "VmBytecode":
        step = max(opcode_width, 1)
        opcodes = set(data[i] for i in range(0, len(data), step))
        return cls(
            bytes_=data,
            start_address=start_address,
            opcode_width=opcode_width,
            distinct_opcodes=len(opcodes),
            entropy=shannon_entropy(data),
        )

    def looks_encrypted(self) -> bool:
        return self.entropy > 7.0

    def len(self) -> int:
        return len(self.bytes_)

    def is_empty(self) -> bool:
        return len(self.bytes_) == 0

    def is_non_empty(self) -> bool:
        return not self.is_empty()


# ---------- VmSemanticOp & VmLifter ----------

class VmSemanticOp:
    def __init__(self, kind: str, operand: Optional[int] = None):
        self.kind = kind
        self.operand = operand

    def __repr__(self):
        return f"Op({self.kind}, {self.operand})"

    def is_control_flow(self) -> bool:
        return self.kind in ("Jmp", "Jz", "Call", "Ret")

    def is_alu(self) -> bool:
        return self.kind in (
            "Add", "Sub", "Mul", "And", "Or", "Xor", "Not", "Neg", "Shl", "Shr"
        )

    def stack_delta(self) -> int:
        deltas = {
            "PushImm": 1, "PushReg": 1, "PopReg": -1,
            "Add": -1, "Sub": -1, "Mul": -1, "And": -1, "Or": -1,
            "Xor": -1, "Shl": -1, "Shr": -1,
            "Not": 0, "Neg": 0,
            "Load32": 0, "Store32": -2,
            "Jmp": 0, "Jz": -1, "Call": 0, "Ret": 0,
            "Nop": 0, "Halt": 0,
        }
        return deltas.get(self.kind, 0)


ALU_MAP = {
    0x10: "Add", 0x11: "Sub", 0x12: "Mul",
    0x13: "And", 0x14: "Or", 0x15: "Xor",
    0x16: "Not", 0x17: "Neg",
    0x18: "Shl", 0x19: "Shr",
}


@dataclass
class VmLifterConfig:
    opcode_width: int = 1
    little_endian: bool = True
    max_instructions: int = 65536


class VmLifter:
    def __init__(self):
        self.config = VmLifterConfig()
        self.opcode_map: Dict[int, int] = {}

    def with_opcode_map(self, m: Dict[int, int]) -> "VmLifter":
        self.opcode_map = dict(m)
        return self

    def remap(self, opcode: int) -> int:
        return self.opcode_map.get(opcode, opcode)

    def lift(self, data: bytes) -> List[VmSemanticOp]:
        ops: List[VmSemanticOp] = []
        i = 0
        while i < len(data) and len(ops) < self.config.max_instructions:
            op = self.remap(data[i])
            i += 1
            if op == 0x00:
                ops.append(VmSemanticOp("Nop"))
            elif op == 0x01:
                if i + 4 > len(data):
                    raise ValueError("truncated PushImm operand")
                imm = struct.unpack_from("<i", data, i)[0]
                i += 4
                ops.append(VmSemanticOp("PushImm", imm))
            elif op == 0x02:
                ops.append(VmSemanticOp("PushReg"))
            elif op == 0x03:
                ops.append(VmSemanticOp("PopReg"))
            elif op in ALU_MAP:
                ops.append(VmSemanticOp(ALU_MAP[op]))
            elif op == 0x20:
                ops.append(VmSemanticOp("Load32"))
            elif op == 0x21:
                ops.append(VmSemanticOp("Store32"))
            elif op == 0x30:
                ops.append(VmSemanticOp("Jmp"))
            elif op == 0x31:
                ops.append(VmSemanticOp("Jz"))
            elif op == 0x32:
                ops.append(VmSemanticOp("Call"))
            elif op == 0x33:
                ops.append(VmSemanticOp("Ret"))
            elif op == 0xFF:
                ops.append(VmSemanticOp("Halt"))
            else:
                ops.append(VmSemanticOp("Unknown", op))
        return ops

    def simulate(self, ops: List[VmSemanticOp], state: VirtualMachineState) -> VirtualMachineState:
        for op in ops:
            k = op.kind
            if k == "Nop":
                pass
            elif k == "PushImm":
                state.push(op.operand & 0xFFFFFFFF)
            elif k == "PushReg":
                state.push(state.regs[0])
            elif k == "PopReg":
                v = state.pop()
                if v is None:
                    raise ValueError("stack underflow")
                state.regs[0] = v
            elif k in ("Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr"):
                b = state.pop()
                a = state.pop()
                if a is None or b is None:
                    raise ValueError("stack underflow")
                if k == "Add":
                    r = (a + b) & 0xFFFFFFFF
                elif k == "Sub":
                    r = (a - b) & 0xFFFFFFFF
                elif k == "Mul":
                    r = (a * b) & 0xFFFFFFFF
                elif k == "And":
                    r = a & b
                elif k == "Or":
                    r = a | b
                elif k == "Xor":
                    r = a ^ b
                elif k == "Shl":
                    r = (a << (b & 31)) & 0xFFFFFFFF
                else:
                    r = (a >> (b & 31)) & 0xFFFFFFFF
                state.push(r)
                state.set_zero_flag(r)
            elif k in ("Not", "Neg"):
                a = state.pop()
                if a is None:
                    raise ValueError("stack underflow")
                if k == "Not":
                    r = (~a) & 0xFFFFFFFF
                else:
                    r = (-a) & 0xFFFFFFFF
                state.push(r)
                state.set_zero_flag(r)
            elif k == "Load32":
                addr = state.pop()
                if addr is None:
                    raise ValueError("stack underflow")
                state.push(state.mem_read_u32(addr))
            elif k == "Store32":
                v = state.pop()
                addr = state.pop()
                if v is None or addr is None:
                    raise ValueError("stack underflow")
                state.mem_write_u32(addr, v)
            elif k in ("Jmp", "Ret", "Halt", "Unknown"):
                break
            elif k == "Jz":
                v = state.pop()
                if v is None:
                    raise ValueError("stack underflow")
            elif k == "Call":
                pass
        return state


# ---------- HandlerClusterer ----------

@dataclass
class HandlerCluster:
    label: str
    handler_count: int
    avg_prologue_entropy: float


class HandlerClusterer:
    def cluster(self, handlers: List[VmHandler]) -> List[HandlerCluster]:
        groups: Dict[HandlerKind, List[VmHandler]] = {}
        for h in handlers:
            groups.setdefault(h.kind, []).append(h)
        out: List[HandlerCluster] = []
        for kind, hs in groups.items():
            avg = sum(h.prologue_entropy() for h in hs) / len(hs) if hs else 0.0
            out.append(HandlerCluster(kind.value, len(hs), avg))
        out.sort(key=lambda c: c.label)
        return out


# ---------- VmArch ----------

@dataclass
class VmArch:
    kind: str
    register_count: int
    opcode_count: int
    complexity_score: float

    @classmethod
    def stack_machine(cls, opcode_count: int) -> "VmArch":
        return cls("stack", 0, opcode_count, float(opcode_count))

    @classmethod
    def register_machine(cls, register_count: int, opcode_count: int) -> "VmArch":
        return cls("register", register_count, opcode_count,
                   float(register_count) * 1.5 + float(opcode_count))

    def summary(self) -> str:
        return f"{self.kind} machine: {self.register_count} regs, {self.opcode_count} opcodes"


# ---------- self-test ----------

if __name__ == "__main__":
    # quick smoke test
    assert read_u32_le(b"\x01\x00\x00\x00") == 1
    assert read_u64_le(b"\x00" * 3) == 0
    assert abs(shannon_entropy(b"AAAA") - 0.0) < 1e-9

    bc = VmBytecode.new(b"\x00\x01\x02\x03\x04", 0x1000, 1)
    assert bc.distinct_opcodes == 5
    assert not bc.looks_encrypted()

    lifter = VmLifter()
    prog = bytes([0x01, 0x05, 0x00, 0x00, 0x00,  # PushImm 5
                  0x01, 0x07, 0x00, 0x00, 0x00,  # PushImm 7
                  0x10,                          # Add
                  0xFF])                         # Halt
    ops = lifter.lift(prog)
    assert [o.kind for o in ops] == ["PushImm", "PushImm", "Add", "Halt"]
    st = lifter.simulate(ops, VirtualMachineState())
    assert st.stack[-1] == 12

    dis = VmDispatcherDetector()
    # build a fake block with SIG1 + three u64
    blk = (b"\x90\x90"
           + bytes([0x31, 0xC0, 0xFF, 0x24])
           + struct.pack("<QQQ", 0xDEADBEEF, 0xCAFEBABE, 16))
    d = dis.detect_dispatcher([blk])
    assert d is not None and d.entry == 0xDEADBEEF and d.handler_count == 16

    det = VmDetector()
    res = det.detect(b"hello VMProtect world \xff\x24 garbage")
    assert "VMProtect" in res.arch_hints
    assert res.dispatcher_count >= 1

    print("rustre-deobf-vm.py: self-tests passed")
