"""
rustre-fuzz-net validator — Python reproduction of the public API documented in
validation/reports/rustre-fuzz-net.md.

Pure stdlib (struct, hashlib, json, re, random, socket-free). Each Rust public
function maps to a Python function/method with equivalent inputs and output
types. This is a behavioural reference implementation, not a full fuzzer.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Errors / enums
# ---------------------------------------------------------------------------

class FuzzNetError(Exception):
    pass


class HarnessError(Exception):
    pass


class ReplayError(Exception):
    pass


# ---------------------------------------------------------------------------
# lib.rs — Core API
# ---------------------------------------------------------------------------

class FieldType:
    STATIC = "static"
    BLOB = "blob"
    U8 = "u8"
    U16 = "u16"
    U32 = "u32"
    RANDOM = "random"
    STRING = "string"
    SIZE_OF = "size_of"


@dataclass
class FieldDef:
    name: str
    field_type: str
    fuzz: bool
    data: bytes = b""
    value: int = 0
    min_len: int = 0
    max_len: int = 0
    target_field: str = ""

    @staticmethod
    def new(name: str, field_type: str, fuzz: bool) -> "FieldDef":
        return FieldDef(name=str(name), field_type=field_type, fuzz=bool(fuzz))


@dataclass
class MessageDef:
    name: str
    fields: List[FieldDef] = field(default_factory=list)

    @staticmethod
    def new(name: str, fields: List[FieldDef]) -> "MessageDef":
        return MessageDef(name=str(name), fields=list(fields))

    def serialise(self) -> bytes:
        out = bytearray()
        for f in self.fields:
            if f.field_type == FieldType.STATIC or f.field_type == FieldType.BLOB:
                out += f.data
            elif f.field_type == FieldType.U8:
                out += struct.pack("<B", f.value & 0xFF)
            elif f.field_type == FieldType.U16:
                out += struct.pack("<H", f.value & 0xFFFF)
            elif f.field_type == FieldType.U32:
                out += struct.pack("<I", f.value & 0xFFFFFFFF)
            elif f.field_type == FieldType.STRING:
                out += f.data
            elif f.field_type == FieldType.RANDOM:
                out += f.data
            elif f.field_type == FieldType.SIZE_OF:
                target = self.field(f.target_field)
                size = len(target.data) if target else 0
                out += struct.pack("<I", size)
            else:
                raise FuzzNetError(f"unknown field type {f.field_type}")
        return bytes(out)

    def mutate(self, rng: random.Random) -> None:
        for f in self.fields:
            if not f.fuzz:
                continue
            if f.field_type in (FieldType.BLOB, FieldType.STRING, FieldType.RANDOM):
                if f.data:
                    idx = rng.randrange(len(f.data))
                    data = bytearray(f.data)
                    data[idx] ^= 1 << rng.randrange(8)
                    f.data = bytes(data)
            elif f.field_type == FieldType.U8:
                f.value = rng.randrange(0, 1 << 8)
            elif f.field_type == FieldType.U16:
                f.value = rng.randrange(0, 1 << 16)
            elif f.field_type == FieldType.U32:
                f.value = rng.randrange(0, 1 << 32)

    def estimated_len(self) -> int:
        total = 0
        for f in self.fields:
            if f.field_type == FieldType.U8:
                total += 1
            elif f.field_type == FieldType.U16:
                total += 2
            elif f.field_type in (FieldType.U32, FieldType.SIZE_OF):
                total += 4
            else:
                total += len(f.data)
        return total

    def fuzz_field_count(self) -> int:
        return sum(1 for f in self.fields if f.fuzz)

    def field(self, name: str) -> Optional[FieldDef]:
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def field_mut(self, name: str) -> Optional[FieldDef]:
        return self.field(name)


@dataclass
class ProtocolState:
    name: str
    transitions: List[Tuple[str, str]] = field(default_factory=list)  # (message, dest)
    terminal: bool = False


@dataclass
class ProtocolDef:
    initial_state: str
    states: Dict[str, ProtocolState]

    @staticmethod
    def new(initial_state: str, states: Dict[str, ProtocolState]) -> "ProtocolDef":
        return ProtocolDef(initial_state=str(initial_state), states=dict(states))

    def state_names(self) -> List[str]:
        return list(self.states.keys())

    def state_count(self) -> int:
        return len(self.states)

    def edges(self) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        for sname, s in self.states.items():
            for _, dest in s.transitions:
                out.append((sname, dest))
        return out

    def validate(self) -> List[str]:
        errs: List[str] = []
        if self.initial_state not in self.states:
            errs.append(f"missing initial state '{self.initial_state}'")
        for sname, s in self.states.items():
            for _, dest in s.transitions:
                if dest not in self.states:
                    errs.append(f"state '{sname}' -> unknown '{dest}'")
        return errs

    @staticmethod
    def load_from_yaml(yaml_text: str) -> "ProtocolDef":
        # Minimal YAML-ish parser: initial: X / states: name -> [dest, ...]
        initial = ""
        states: Dict[str, ProtocolState] = {}
        current: Optional[str] = None
        for raw in yaml_text.splitlines():
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            m = re.match(r"^initial:\s*(\S+)", line)
            if m:
                initial = m.group(1)
                continue
            m = re.match(r"^\s{2}(\w+):\s*$", line)
            if m:
                current = m.group(1)
                states[current] = ProtocolState(name=current)
                continue
            m = re.match(r"^\s{4}-\s*(\w+)\s*->\s*(\w+)\s*$", line)
            if m and current:
                states[current].transitions.append((m.group(1), m.group(2)))
        if not initial:
            raise FuzzNetError("YAML missing initial state")
        return ProtocolDef.new(initial, states)

    @staticmethod
    def load_from_file(path: str) -> "ProtocolDef":
        with open(path, "r", encoding="utf-8") as f:
            return ProtocolDef.load_from_yaml(f.read())


class Transport:
    def send(self, data: bytes) -> bytes:
        raise NotImplementedError


@dataclass
class TcpTransport(Transport):
    addr: str

    @staticmethod
    def new(addr: str) -> "TcpTransport":
        return TcpTransport(addr=str(addr))

    def send(self, data: bytes) -> bytes:
        return b""  # stub


@dataclass
class UdpTransport(Transport):
    addr: str

    @staticmethod
    def new(addr: str) -> "UdpTransport":
        return UdpTransport(addr=str(addr))

    def send(self, data: bytes) -> bytes:
        return b""


@dataclass
class CrashEntry:
    input: bytes
    reason: str
    state: str


@dataclass
class CrashLog:
    entries: List[CrashEntry] = field(default_factory=list)

    @staticmethod
    def new() -> "CrashLog":
        return CrashLog()

    def log(self, input_: bytes, reason: str, state: str) -> None:
        self.entries.append(CrashEntry(bytes(input_), str(reason), str(state)))

    def unique_reasons(self) -> List[str]:
        seen: List[str] = []
        for e in self.entries:
            if e.reason not in seen:
                seen.append(e.reason)
        return seen

    def by_reason(self, reason: str) -> List[CrashEntry]:
        return [e for e in self.entries if e.reason == reason]

    def by_state(self, state: str) -> List[CrashEntry]:
        return [e for e in self.entries if e.state == state]

    def clear(self) -> None:
        self.entries.clear()

    def dedup(self) -> None:
        seen = set()
        out: List[CrashEntry] = []
        for e in self.entries:
            key = (e.reason, e.state, e.input)
            if key not in seen:
                seen.add(key)
                out.append(e)
        self.entries = out

    def summary(self) -> str:
        return f"crashes={len(self.entries)} unique_reasons={len(self.unique_reasons())}"


@dataclass
class SessionStats:
    iterations: int = 0
    crashes: int = 0
    state_visits: Dict[str, int] = field(default_factory=dict)


@dataclass
class FuzzSession:
    protocol: ProtocolDef
    transport: Transport
    state: str = ""
    _stats: SessionStats = field(default_factory=SessionStats)

    @staticmethod
    def new(protocol: ProtocolDef, transport: Transport) -> "FuzzSession":
        s = FuzzSession(protocol=protocol, transport=transport,
                        state=protocol.initial_state)
        return s

    def reset(self) -> None:
        self.state = self.protocol.initial_state

    def current_state(self) -> str:
        return self.state

    def run_once(self) -> None:
        self._stats.iterations += 1
        self._stats.state_visits[self.state] = self._stats.state_visits.get(self.state, 0) + 1
        st = self.protocol.states.get(self.state)
        if st and st.transitions:
            self.state = st.transitions[0][1]

    def run(self, count: int) -> None:
        for _ in range(int(count)):
            self.run_once()

    def stats(self) -> SessionStats:
        return self._stats

    def most_visited_state(self) -> Optional[str]:
        if not self._stats.state_visits:
            return None
        return max(self._stats.state_visits.items(), key=lambda kv: kv[1])[0]


@dataclass
class NetFuzzer:
    session: FuzzSession

    @staticmethod
    def new(protocol: ProtocolDef, transport: Transport) -> "NetFuzzer":
        return NetFuzzer(session=FuzzSession.new(protocol, transport))

    def fuzz(self, count: int) -> None:
        self.session.run(count)

    def stats(self) -> SessionStats:
        return self.session.stats()


@dataclass
class ProtocolBuilder:
    initial_state: str
    states: Dict[str, ProtocolState] = field(default_factory=dict)

    @staticmethod
    def new(initial_state: str) -> "ProtocolBuilder":
        b = ProtocolBuilder(initial_state=str(initial_state))
        b.states[b.initial_state] = ProtocolState(name=b.initial_state)
        return b

    def add_terminal(self, name: str) -> "ProtocolBuilder":
        self.states[name] = ProtocolState(name=name, terminal=True)
        return self

    def add_transition(self, from_: str, to: str, message: str) -> "ProtocolBuilder":
        self.states.setdefault(from_, ProtocolState(name=from_))
        self.states.setdefault(to, ProtocolState(name=to))
        self.states[from_].transitions.append((message, to))
        return self

    def add_transition_with_expect(self, from_: str, to: str, message: str, expect: bytes) -> "ProtocolBuilder":
        return self.add_transition(from_, to, message)

    def build(self) -> ProtocolDef:
        return ProtocolDef.new(self.initial_state, self.states)


@dataclass
class MessageBuilder:
    name: str
    fields: List[FieldDef] = field(default_factory=list)

    @staticmethod
    def new(name: str) -> "MessageBuilder":
        return MessageBuilder(name=str(name))

    def static_bytes(self, name: str, data: bytes) -> "MessageBuilder":
        f = FieldDef.new(name, FieldType.STATIC, False)
        f.data = bytes(data)
        self.fields.append(f)
        return self

    def fuzz_blob(self, name: str, data: bytes) -> "MessageBuilder":
        f = FieldDef.new(name, FieldType.BLOB, True)
        f.data = bytes(data)
        self.fields.append(f)
        return self

    def fuzz_u8(self, name: str, value: int) -> "MessageBuilder":
        f = FieldDef.new(name, FieldType.U8, True)
        f.value = int(value) & 0xFF
        self.fields.append(f)
        return self

    def fuzz_u16(self, name: str, value: int) -> "MessageBuilder":
        f = FieldDef.new(name, FieldType.U16, True)
        f.value = int(value) & 0xFFFF
        self.fields.append(f)
        return self

    def fuzz_u32(self, name: str, value: int) -> "MessageBuilder":
        f = FieldDef.new(name, FieldType.U32, True)
        f.value = int(value) & 0xFFFFFFFF
        self.fields.append(f)
        return self

    def fuzz_random(self, name: str, min_: int, max_: int) -> "MessageBuilder":
        f = FieldDef.new(name, FieldType.RANDOM, True)
        f.min_len = int(min_)
        f.max_len = int(max_)
        f.data = b"\x00" * f.min_len
        self.fields.append(f)
        return self

    def fuzz_string(self, name: str, max_len: int) -> "MessageBuilder":
        f = FieldDef.new(name, FieldType.STRING, True)
        f.max_len = int(max_len)
        self.fields.append(f)
        return self

    def size_of(self, name: str, target_field: str) -> "MessageBuilder":
        f = FieldDef.new(name, FieldType.SIZE_OF, False)
        f.target_field = str(target_field)
        self.fields.append(f)
        return self

    def build(self) -> MessageDef:
        return MessageDef.new(self.name, self.fields)


# Mutation strategies
class MutationStrategy:
    BITFLIP = "bitflip"
    BYTEFLIP = "byteflip"
    INTERESTING = "interesting"
    RANDOM = "random"


def apply_strategy(msg: MessageDef, strategy: str, rng: random.Random) -> None:
    if strategy == MutationStrategy.RANDOM:
        msg.mutate(rng)
        return
    for f in msg.fields:
        if not f.fuzz or not f.data:
            continue
        data = bytearray(f.data)
        if strategy == MutationStrategy.BITFLIP and data:
            i = rng.randrange(len(data))
            data[i] ^= 1 << rng.randrange(8)
        elif strategy == MutationStrategy.BYTEFLIP and data:
            i = rng.randrange(len(data))
            data[i] = rng.randrange(256)
        elif strategy == MutationStrategy.INTERESTING and data:
            interesting = [0, 1, 0x7F, 0x80, 0xFF]
            i = rng.randrange(len(data))
            data[i] = interesting[rng.randrange(len(interesting))]
        f.data = bytes(data)


def frame_u32_le(payload: bytes) -> bytes:
    if len(payload) > 0xFFFFFFFF:
        raise FuzzNetError("payload too large")
    return struct.pack("<I", len(payload)) + bytes(payload)


def frame_u32_be(payload: bytes) -> bytes:
    if len(payload) > 0xFFFFFFFF:
        raise FuzzNetError("payload too large")
    return struct.pack(">I", len(payload)) + bytes(payload)


def decode_frame_u32_le(buf: bytes) -> Optional[Tuple[int, bytes]]:
    if len(buf) < 4:
        return None
    (length,) = struct.unpack("<I", buf[:4])
    if len(buf) < 4 + length:
        return None
    return (length, bytes(buf[4:4 + length]))


def decode_frame_u32_be(buf: bytes) -> Optional[Tuple[int, bytes]]:
    if len(buf) < 4:
        return None
    (length,) = struct.unpack(">I", buf[:4])
    if len(buf) < 4 + length:
        return None
    return (length, bytes(buf[4:4 + length]))


def xor_checksum(data: bytes) -> int:
    out = 0
    for b in data:
        out ^= b
    return out & 0xFF


def add_checksum(data: bytes) -> int:
    return sum(data) & 0xFF


def interesting_int_mutation(current: int, size_bytes: int, rng: random.Random) -> int:
    if size_bytes == 1:
        candidates = [0, 1, 0x7F, -1, -0x80]
    elif size_bytes == 2:
        candidates = [0, 1, 0x7FFF, -1, -0x8000, 0xFF, 0x100]
    else:
        candidates = [0, 1, 0x7FFFFFFF, -1, -0x80000000, 0xFFFF, 0x10000]
    return candidates[rng.randrange(len(candidates))]


# CoverageMap
@dataclass
class CoverageMap:
    covered: Dict[str, set] = field(default_factory=dict)

    @staticmethod
    def new() -> "CoverageMap":
        return CoverageMap()

    def record(self, state: str, transition_idx: int) -> None:
        self.covered.setdefault(state, set()).add(int(transition_idx))

    def coverage_pct(self, total_transitions: int) -> float:
        if total_transitions <= 0:
            return 0.0
        seen = sum(len(s) for s in self.covered.values())
        return 100.0 * seen / total_transitions

    def is_covered(self, state: str, transition_idx: int) -> bool:
        return transition_idx in self.covered.get(state, set())


# Pattern matching
@dataclass
class Pattern:
    needle: bytes

    def matches(self, buf: bytes) -> bool:
        return self.needle in buf

    def find(self, buf: bytes) -> Optional[int]:
        idx = buf.find(self.needle)
        return idx if idx >= 0 else None


# Corpus
@dataclass
class CorpusEntry:
    data: bytes
    tag: str
    state: str


@dataclass
class Corpus:
    entries: List[CorpusEntry] = field(default_factory=list)

    @staticmethod
    def new() -> "Corpus":
        return Corpus()

    def add(self, data: bytes, tag: str, state: str) -> None:
        self.entries.append(CorpusEntry(bytes(data), str(tag), str(state)))

    def pick(self, rng: random.Random) -> Optional[CorpusEntry]:
        if not self.entries:
            return None
        return self.entries[rng.randrange(len(self.entries))]

    def by_tag(self, tag: str) -> List[CorpusEntry]:
        return [e for e in self.entries if e.tag == tag]

    def dedup(self) -> None:
        seen = set()
        out = []
        for e in self.entries:
            key = (e.tag, e.state, e.data)
            if key not in seen:
                seen.add(key)
                out.append(e)
        self.entries = out


# Replay
@dataclass
class ReplayResult:
    sent: int
    received: int


@dataclass
class ReplaySession:
    inputs: List[bytes]
    transport: Transport

    @staticmethod
    def new(inputs: List[bytes], transport: Transport) -> "ReplaySession":
        return ReplaySession(inputs=[bytes(x) for x in inputs], transport=transport)

    def run(self) -> ReplayResult:
        return ReplayResult(sent=len(self.inputs), received=0)


# Stack/queue
@dataclass
class MessageStack:
    max_depth: int
    stack: List[MessageDef] = field(default_factory=list)

    @staticmethod
    def new(max_depth: int) -> "MessageStack":
        return MessageStack(max_depth=int(max_depth))

    def push(self, msg: MessageDef) -> None:
        if len(self.stack) >= self.max_depth:
            return
        self.stack.append(msg)

    def pop(self) -> Optional[MessageDef]:
        return self.stack.pop() if self.stack else None


# StateMachineDriver
@dataclass
class StateMachineDriver:
    protocol: ProtocolDef
    state: str = ""
    history: List[str] = field(default_factory=list)

    @staticmethod
    def new(protocol: ProtocolDef) -> "StateMachineDriver":
        return StateMachineDriver(protocol=protocol, state=protocol.initial_state)

    def current_state(self) -> str:
        return self.state

    def transition_history(self) -> List[str]:
        return list(self.history)

    def drive_to_state(self, target: str) -> None:
        if target not in self.protocol.states:
            raise FuzzNetError(f"unknown state {target}")
        # BFS
        from collections import deque
        prev: Dict[str, Tuple[str, str]] = {}
        q = deque([self.state])
        visited = {self.state}
        while q:
            cur = q.popleft()
            if cur == target:
                break
            for msg, dest in self.protocol.states[cur].transitions:
                if dest not in visited:
                    visited.add(dest)
                    prev[dest] = (cur, msg)
                    q.append(dest)
        if target not in visited:
            raise FuzzNetError("unreachable")
        # walk
        path = []
        cur = target
        while cur in prev:
            p, msg = prev[cur]
            path.append(msg)
            cur = p
        for m in reversed(path):
            self.history.append(m)
        self.state = target

    def reset(self) -> None:
        self.state = self.protocol.initial_state
        self.history.clear()

    def can_advance(self) -> bool:
        st = self.protocol.states.get(self.state)
        return bool(st and st.transitions)


# Crash classifier
class CrashKind:
    NORMAL = "normal"
    CONNECTION_RESET = "connection_reset"
    TIMEOUT = "timeout"
    INVALID_RESPONSE = "invalid_response"
    SEGFAULT = "segfault"
    ASSERTION = "assertion"
    UNKNOWN = "unknown"


def classify(response: bytes, expected: bytes) -> str:
    if response == expected:
        return CrashKind.NORMAL
    if not response:
        return CrashKind.CONNECTION_RESET
    return CrashKind.INVALID_RESPONSE


def classify_reason(reason: str) -> str:
    r = reason.lower()
    if "timeout" in r:
        return CrashKind.TIMEOUT
    if "reset" in r or "closed" in r:
        return CrashKind.CONNECTION_RESET
    if "segfault" in r or "sigsegv" in r:
        return CrashKind.SEGFAULT
    if "assert" in r:
        return CrashKind.ASSERTION
    if "invalid" in r:
        return CrashKind.INVALID_RESPONSE
    return CrashKind.UNKNOWN


def is_interesting(kind: str) -> bool:
    return kind not in (CrashKind.NORMAL, CrashKind.UNKNOWN)


# ---------------------------------------------------------------------------
# protocol_model.rs
# ---------------------------------------------------------------------------

@dataclass
class MessageField:
    _name: str
    _is_fuzz_target: bool
    _default_bytes: bytes

    def name(self) -> str:
        return self._name

    def is_fuzz_target(self) -> bool:
        return self._is_fuzz_target

    def default_bytes(self) -> bytes:
        return self._default_bytes


@dataclass
class MessageType:
    _name: str
    _fields: List[MessageField]
    _magic: bytes = b""

    @staticmethod
    def new(name: str, fields: List[MessageField]) -> "MessageType":
        return MessageType(_name=str(name), _fields=list(fields))

    def with_magic(self, magic: bytes) -> "MessageType":
        self._magic = bytes(magic)
        return self

    def field_count(self) -> int:
        return len(self._fields)

    def fuzz_field_count(self) -> int:
        return sum(1 for f in self._fields if f._is_fuzz_target)

    def get_field(self, name: str) -> Optional[MessageField]:
        for f in self._fields:
            if f._name == name:
                return f
        return None

    def validate(self, data: bytes) -> bool:
        return data.startswith(self._magic)

    def default_bytes(self) -> bytes:
        out = bytearray(self._magic)
        for f in self._fields:
            out += f._default_bytes
        return bytes(out)


@dataclass
class ProtocolConstraint:
    kind: str  # "min_len" | "max_len" | "magic"
    value: Any

    def check(self, data: bytes) -> bool:
        if self.kind == "min_len":
            return len(data) >= int(self.value)
        if self.kind == "max_len":
            return len(data) <= int(self.value)
        if self.kind == "magic":
            return data.startswith(bytes(self.value))
        return True

    def enforce(self, data: bytearray) -> bool:
        if self.check(bytes(data)):
            return True
        if self.kind == "min_len":
            need = int(self.value) - len(data)
            data.extend(b"\x00" * need)
            return True
        if self.kind == "max_len":
            del data[int(self.value):]
            return True
        if self.kind == "magic":
            data[:0] = bytes(self.value)
            return True
        return False


@dataclass
class ProtocolGenerator:
    seed: int

    @staticmethod
    def new(seed: int) -> "ProtocolGenerator":
        g = ProtocolGenerator(seed=int(seed))
        g._rng = random.Random(seed)
        return g

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    def generate(self, msg_type: MessageType) -> bytes:
        return msg_type.default_bytes()

    def generate_many(self, msg_type: MessageType, count: int) -> List[bytes]:
        return [self.generate(msg_type) for _ in range(int(count))]

    def mutate(self, data: bytes, msg_type: MessageType) -> bytes:
        if not data:
            return data
        out = bytearray(data)
        idx = self._rng.randrange(len(out))
        out[idx] ^= 1 << self._rng.randrange(8)
        return bytes(out)


@dataclass
class ConstraintValidator:
    constraints: List[ProtocolConstraint]
    auto_fix_flag: bool = False

    @staticmethod
    def new(constraints: List[ProtocolConstraint]) -> "ConstraintValidator":
        return ConstraintValidator(constraints=list(constraints))

    def auto_fix(self, enabled: bool = True) -> "ConstraintValidator":
        self.auto_fix_flag = bool(enabled)
        return self

    def is_valid(self, data: bytes) -> bool:
        return all(c.check(data) for c in self.constraints)

    def fix_or_check(self, data: bytearray) -> bool:
        if self.is_valid(bytes(data)):
            return True
        if not self.auto_fix_flag:
            return False
        for c in self.constraints:
            c.enforce(data)
        return self.is_valid(bytes(data))

    def filter(self, messages: List[bytes]) -> List[bytes]:
        return [m for m in messages if self.is_valid(m)]

    def filter_and_fix(self, messages: List[bytes]) -> List[bytes]:
        out: List[bytes] = []
        for m in messages:
            ba = bytearray(m)
            if self.fix_or_check(ba):
                out.append(bytes(ba))
        return out


@dataclass
class ProtocolModel:
    name: str
    types: Dict[str, MessageType] = field(default_factory=dict)

    @staticmethod
    def new(name: str) -> "ProtocolModel":
        return ProtocolModel(name=str(name))

    def add_type(self, msg: MessageType) -> None:
        self.types[msg._name] = msg

    def get_type(self, name: str) -> Optional[MessageType]:
        return self.types.get(name)

    def type_count(self) -> int:
        return len(self.types)

    def to_json(self) -> str:
        obj = {
            "name": self.name,
            "types": {
                k: {"magic": list(v._magic),
                    "fields": [{"name": f._name, "fuzz": f._is_fuzz_target,
                                "default": list(f._default_bytes)} for f in v._fields]}
                for k, v in self.types.items()
            },
        }
        return json.dumps(obj)

    @staticmethod
    def from_json(s: str) -> "ProtocolModel":
        obj = json.loads(s)
        m = ProtocolModel.new(obj["name"])
        for k, v in obj.get("types", {}).items():
            fields = [MessageField(_name=f["name"], _is_fuzz_target=f["fuzz"],
                                   _default_bytes=bytes(f["default"]))
                      for f in v.get("fields", [])]
            mt = MessageType.new(k, fields).with_magic(bytes(v.get("magic", [])))
            m.add_type(mt)
        return m

    def save_to_file(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    @staticmethod
    def load_from_file(path: str) -> "ProtocolModel":
        with open(path, "r", encoding="utf-8") as f:
            return ProtocolModel.from_json(f.read())

    def type_names(self) -> List[str]:
        return list(self.types.keys())

    def validate(self) -> List[str]:
        errs: List[str] = []
        for n, t in self.types.items():
            if t.field_count() == 0:
                errs.append(f"type {n} has no fields")
        return errs


@dataclass
class ModelFuzzer:
    model: ProtocolModel
    seed: int
    constraints: Optional[ConstraintValidator] = None
    _generated: int = 0
    _valid: int = 0

    @staticmethod
    def new(model: ProtocolModel, seed: int) -> "ModelFuzzer":
        f = ModelFuzzer(model=model, seed=int(seed))
        f._gen = ProtocolGenerator.new(seed)
        return f

    def __post_init__(self) -> None:
        self._gen = ProtocolGenerator.new(self.seed)

    def set_constraints(self, cv: ConstraintValidator) -> None:
        self.constraints = cv

    def generate(self, type_name: str, count: int) -> List[bytes]:
        t = self.model.get_type(type_name)
        if t is None:
            return []
        out = []
        for _ in range(int(count)):
            b = self._gen.generate(t)
            self._generated += 1
            if not self.constraints or self.constraints.is_valid(b):
                self._valid += 1
            out.append(b)
        return out

    def mutate(self, type_name: str, data: bytes) -> bytes:
        t = self.model.get_type(type_name)
        if t is None:
            return data
        return self._gen.mutate(data, t)

    def validity_ratio(self) -> float:
        if self._generated == 0:
            return 0.0
        return self._valid / self._generated


# ---------------------------------------------------------------------------
# mutation_engine.rs
# ---------------------------------------------------------------------------

@dataclass
class ProtocolMutation:
    kind: str
    offset: int = 0
    value: int = 0

    def apply(self, data: bytearray, rng: random.Random) -> None:
        if not data:
            return
        off = self.offset % len(data)
        if self.kind == "bitflip":
            data[off] ^= 1 << (self.value & 7)
        elif self.kind == "byteset":
            data[off] = self.value & 0xFF
        elif self.kind == "rand":
            data[off] = rng.randrange(256)

    def dedup_key(self) -> str:
        return f"{self.kind}:{self.offset}:{self.value}"


@dataclass
class MutationRecord:
    mutation: ProtocolMutation
    before: bytes
    after: bytes


@dataclass
class MutationHistory:
    max_records: int
    records: List[MutationRecord] = field(default_factory=list)
    _keys: set = field(default_factory=set)

    @staticmethod
    def new(max_records: int) -> "MutationHistory":
        return MutationHistory(max_records=int(max_records))

    def record(self, mut: ProtocolMutation, before: bytes, after: bytes) -> bool:
        key = mut.dedup_key()
        novel = key not in self._keys
        self._keys.add(key)
        if len(self.records) >= self.max_records:
            self.records.pop(0)
        self.records.append(MutationRecord(mut, bytes(before), bytes(after)))
        return novel

    def unique_count(self) -> int:
        return len(self._keys)

    def clear(self) -> None:
        self.records.clear()
        self._keys.clear()

    def novel_records(self) -> List[MutationRecord]:
        seen = set()
        out = []
        for r in self.records:
            k = r.mutation.dedup_key()
            if k not in seen:
                seen.add(k)
                out.append(r)
        return out


@dataclass
class MutationEngine:
    strategy: str
    _bytes: int = 0
    _rng: random.Random = field(default_factory=lambda: random.Random(0))

    @staticmethod
    def new(strategy: str) -> "MutationEngine":
        return MutationEngine(strategy=str(strategy))

    def generate_mutation(self, data: bytes) -> Optional[ProtocolMutation]:
        if not data:
            return None
        return ProtocolMutation(kind="bitflip",
                                offset=self._rng.randrange(len(data)),
                                value=self._rng.randrange(8))

    def mutate(self, data: bytearray) -> Optional[bool]:
        m = self.generate_mutation(bytes(data))
        if m is None:
            return None
        m.apply(data, self._rng)
        self._bytes += 1
        return True

    def mutate_n(self, data: bytearray, n: int) -> None:
        for _ in range(int(n)):
            self.mutate(data)

    def total_bytes_mutated(self) -> int:
        return self._bytes


# ---------------------------------------------------------------------------
# crash_detector.rs
# ---------------------------------------------------------------------------

class CrashSignal:
    SIGSEGV = "SIGSEGV"
    SIGABRT = "SIGABRT"
    SIGFPE = "SIGFPE"
    SIGILL = "SIGILL"
    SIGBUS = "SIGBUS"
    TIMEOUT = "TIMEOUT"

    @staticmethod
    def severity(sig: str) -> int:
        return {"SIGSEGV": 9, "SIGABRT": 8, "SIGBUS": 8,
                "SIGFPE": 6, "SIGILL": 7, "TIMEOUT": 3}.get(sig, 1)

    @staticmethod
    def name(sig: str) -> str:
        return sig


@dataclass
class CrashReport:
    signal: str
    input: bytes
    bucket: int
    text: str = ""

    @staticmethod
    def new(signal: str, input_: bytes, bucket: int, text: str = "") -> "CrashReport":
        return CrashReport(signal=signal, input=bytes(input_), bucket=int(bucket), text=text)

    def severity(self) -> int:
        return CrashSignal.severity(self.signal)


def bucket_hash(signal: str, input_: bytes) -> int:
    h = hashlib.sha256()
    h.update(signal.encode("utf-8"))
    h.update(bytes(input_))
    return int.from_bytes(h.digest()[:8], "little")


def detect_sanitizer_output(text: str) -> Optional[str]:
    pats = ["AddressSanitizer", "UndefinedBehaviorSanitizer",
            "ThreadSanitizer", "LeakSanitizer", "MemorySanitizer"]
    for p in pats:
        if p in text:
            return p
    return None


def detect_crash_string(data: bytes) -> Optional[Tuple[str, int]]:
    needles = [b"panic", b"segmentation fault", b"abort", b"assertion failed"]
    low = bytes(data).lower()
    for n in needles:
        i = low.find(n)
        if i >= 0:
            return (n.decode("ascii"), i)
    return None


@dataclass
class CrashDetectorConfig:
    dedup: bool = True


@dataclass
class CrashDetector:
    config: CrashDetectorConfig
    _reports: List[CrashReport] = field(default_factory=list)
    _buckets: set = field(default_factory=set)
    _total_inputs: int = 0

    @staticmethod
    def new(config: CrashDetectorConfig) -> "CrashDetector":
        return CrashDetector(config=config)

    @staticmethod
    def with_default_config() -> "CrashDetector":
        return CrashDetector.new(CrashDetectorConfig())

    def analyse(self, signal: str, input_: bytes, text: str = "") -> CrashReport:
        self._total_inputs += 1
        b = bucket_hash(signal, input_)
        rep = CrashReport.new(signal, input_, b, text)
        if not self.config.dedup or b not in self._buckets:
            self._buckets.add(b)
            self._reports.append(rep)
        return rep

    def unique_crashes(self) -> int:
        return len(self._buckets)

    def total_crashes(self) -> int:
        return len(self._reports)

    def total_inputs(self) -> int:
        return self._total_inputs

    def crash_rate(self) -> float:
        if self._total_inputs == 0:
            return 0.0
        return self.total_crashes() / self._total_inputs

    def reports(self) -> Iterator[CrashReport]:
        return iter(self._reports)

    def reports_by_severity(self) -> List[CrashReport]:
        return sorted(self._reports, key=lambda r: -r.severity())

    def clear(self) -> None:
        self._reports.clear()
        self._buckets.clear()
        self._total_inputs = 0


@dataclass
class HangDetector:
    timeout_ms: int
    _pending: Dict[int, int] = field(default_factory=dict)
    _next_id: int = 0
    _ticks: int = 0
    _hangs: List[int] = field(default_factory=list)

    @staticmethod
    def new(timeout_ms: int) -> "HangDetector":
        return HangDetector(timeout_ms=int(timeout_ms))

    def register(self) -> int:
        self._next_id += 1
        self._pending[self._next_id] = self._ticks
        return self._next_id

    def complete(self, id_: int) -> None:
        self._pending.pop(id_, None)

    def tick(self) -> None:
        self._ticks += 1
        for pid, start in list(self._pending.items()):
            if self._ticks - start > self.timeout_ms:
                self._hangs.append(pid)
                self._pending.pop(pid, None)

    def hang_count(self) -> int:
        return len(self._hangs)

    def hangs(self) -> List[int]:
        return list(self._hangs)


@dataclass
class ReproductionResult:
    confirmed: bool
    detail: str = ""

    @staticmethod
    def reproduced(detail: str = "") -> "ReproductionResult":
        return ReproductionResult(confirmed=True, detail=detail)

    @staticmethod
    def not_reproduced(detail: str = "") -> "ReproductionResult":
        return ReproductionResult(confirmed=False, detail=detail)

    def is_confirmed(self) -> bool:
        return self.confirmed


@dataclass
class Minimiser:
    max_iterations: int

    @staticmethod
    def new(max_iterations: int) -> "Minimiser":
        return Minimiser(max_iterations=int(max_iterations))

    def minimise(self, input_: bytes, predicate: Callable[[bytes], bool]) -> bytes:
        cur = bytes(input_)
        for _ in range(self.max_iterations):
            if len(cur) <= 1:
                break
            half = cur[: len(cur) // 2]
            if predicate(half):
                cur = half
            else:
                tail = cur[len(cur) // 2:]
                if predicate(tail):
                    cur = tail
                else:
                    break
        return cur


@dataclass
class CrashSummary:
    total: int
    unique: int
    by_signal: Dict[str, int]

    @staticmethod
    def from_reports(reports: Iterable[CrashReport]) -> "CrashSummary":
        reports = list(reports)
        by_sig: Dict[str, int] = {}
        buckets = set()
        for r in reports:
            by_sig[r.signal] = by_sig.get(r.signal, 0) + 1
            buckets.add(r.bucket)
        return CrashSummary(total=len(reports), unique=len(buckets), by_signal=by_sig)


# ---------------------------------------------------------------------------
# crash_analyzer.rs
# ---------------------------------------------------------------------------

class CrashType:
    MEMORY = "memory"
    LOGIC = "logic"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"
    CRITICAL = "critical"

    @staticmethod
    def from_reason(reason: str) -> str:
        r = reason.lower()
        if "segfault" in r or "heap" in r or "uaf" in r or "overflow" in r:
            return CrashType.MEMORY
        if "timeout" in r or "hang" in r:
            return CrashType.TIMEOUT
        if "assert" in r or "panic" in r:
            return CrashType.LOGIC
        return CrashType.UNKNOWN


@dataclass
class CrashRecord:
    reason: str
    input: bytes
    type_: str

    @staticmethod
    def from_reason(reason: str, input_: bytes) -> "CrashRecord":
        return CrashRecord(reason=str(reason), input=bytes(input_),
                           type_=CrashType.from_reason(reason))

    def is_critical(self) -> bool:
        return self.type_ == CrashType.MEMORY


@dataclass
class CrashDeduplicator:
    seen: set = field(default_factory=set)
    records: List[CrashRecord] = field(default_factory=list)

    @staticmethod
    def new() -> "CrashDeduplicator":
        return CrashDeduplicator()

    def submit(self, record: CrashRecord) -> bool:
        key = (record.reason, record.input)
        if key in self.seen:
            return False
        self.seen.add(key)
        self.records.append(record)
        return True

    def iter(self) -> Iterator[CrashRecord]:
        return iter(self.records)

    def clear(self) -> None:
        self.seen.clear()
        self.records.clear()

    def by_type(self, ct: str) -> List[CrashRecord]:
        return [r for r in self.records if r.type_ == ct]


@dataclass
class AnalyzerCrashReport:
    unique: int
    total: int
    counts: Dict[str, int]

    @staticmethod
    def from_deduplicator(dedup: CrashDeduplicator, total: int) -> "AnalyzerCrashReport":
        counts: Dict[str, int] = {}
        for r in dedup.records:
            counts[r.type_] = counts.get(r.type_, 0) + 1
        return AnalyzerCrashReport(unique=len(dedup.records), total=int(total), counts=counts)

    def has_critical(self) -> bool:
        return self.counts.get(CrashType.MEMORY, 0) > 0

    def count_for(self, type_name: str) -> int:
        return self.counts.get(type_name, 0)


@dataclass
class CrashAnalyzer:
    _dedup: CrashDeduplicator = field(default_factory=CrashDeduplicator.new)
    _total: int = 0

    @staticmethod
    def new() -> "CrashAnalyzer":
        return CrashAnalyzer()

    def submit_crash(self, reason: str, input_: bytes) -> None:
        self._total += 1
        self._dedup.submit(CrashRecord.from_reason(reason, input_))

    def classify(self, reason: str) -> str:
        return CrashType.from_reason(reason)

    def generate_report(self) -> AnalyzerCrashReport:
        return AnalyzerCrashReport.from_deduplicator(self._dedup, self._total)

    def crashes_of_type(self, ct: str) -> List[CrashRecord]:
        return self._dedup.by_type(ct)

    def reset(self) -> None:
        self._dedup.clear()
        self._total = 0


# ---------------------------------------------------------------------------
# network_harness.rs
# ---------------------------------------------------------------------------

@dataclass
class AttemptResult:
    crash: bool
    response: bytes = b""

    def is_crash(self) -> bool:
        return self.crash


@dataclass
class ResponseScorer:
    error_patterns: List[bytes] = field(default_factory=list)
    baseline: List[bytes] = field(default_factory=list)

    @staticmethod
    def new() -> "ResponseScorer":
        return ResponseScorer()

    def add_error_pattern(self, pat: bytes) -> None:
        self.error_patterns.append(bytes(pat))

    def feed_baseline(self, response: bytes) -> None:
        self.baseline.append(bytes(response))

    def score(self, response: bytes) -> int:
        score = 0
        for p in self.error_patterns:
            if p in response:
                score += 10
        if response not in self.baseline:
            score += 1
        return score

    def describe_anomaly(self, response: bytes) -> Optional[str]:
        for p in self.error_patterns:
            if p in response:
                return f"matched error pattern {p!r}"
        if response not in self.baseline:
            return "novel response"
        return None


@dataclass
class ConnectionPool:
    addr: str
    max_size: int
    connect_timeout_ms: int
    _pool: List[object] = field(default_factory=list)
    _reuse: int = 0

    @staticmethod
    def new(addr: str, max_size: int, connect_timeout_ms: int) -> "ConnectionPool":
        return ConnectionPool(addr=str(addr), max_size=int(max_size),
                              connect_timeout_ms=int(connect_timeout_ms))

    def acquire(self) -> object:
        if self._pool:
            self._reuse += 1
            return self._pool.pop()
        return object()

    def release(self, conn: object) -> None:
        if len(self._pool) < self.max_size:
            self._pool.append(conn)

    def pool_size(self) -> int:
        return len(self._pool)

    def reuse_count(self) -> int:
        return self._reuse


@dataclass
class HarnessConfig:
    addr: str = ""
    timeout_ms: int = 1000


@dataclass
class HarnessStats:
    attempts: int = 0
    crashes: int = 0
    successes: int = 0

    def crash_rate(self) -> float:
        return self.crashes / self.attempts if self.attempts else 0.0

    def success_rate(self) -> float:
        return self.successes / self.attempts if self.attempts else 0.0


@dataclass
class TcpFuzzHarness:
    config: HarnessConfig
    _stats: HarnessStats = field(default_factory=HarnessStats)
    _baseline: List[bytes] = field(default_factory=list)

    @staticmethod
    def new(config: HarnessConfig) -> "TcpFuzzHarness":
        return TcpFuzzHarness(config=config)

    def attempt(self, input_: bytes) -> AttemptResult:
        self._stats.attempts += 1
        self._stats.successes += 1
        return AttemptResult(crash=False)

    def run(self, count: int, generator: Callable[[int], bytes]) -> None:
        for i in range(int(count)):
            self.attempt(generator(i))

    def stats(self) -> HarnessStats:
        return self._stats

    def feed_baseline_response(self, response: bytes) -> None:
        self._baseline.append(bytes(response))


@dataclass
class UdpFuzzHarness:
    config: HarnessConfig
    _stats: HarnessStats = field(default_factory=HarnessStats)

    @staticmethod
    def new(config: HarnessConfig) -> "UdpFuzzHarness":
        return UdpFuzzHarness(config=config)

    def attempt(self, input_: bytes) -> AttemptResult:
        self._stats.attempts += 1
        self._stats.successes += 1
        return AttemptResult(crash=False)

    def run(self, count: int, generator: Callable[[int], bytes]) -> None:
        for i in range(int(count)):
            self.attempt(generator(i))

    def stats(self) -> HarnessStats:
        return self._stats


@dataclass
class HarnessCrashDeduplicator:
    seen: set = field(default_factory=set)

    @staticmethod
    def new() -> "HarnessCrashDeduplicator":
        return HarnessCrashDeduplicator()

    def is_new(self, result: AttemptResult) -> bool:
        if not result.is_crash():
            return False
        key = bytes(result.response)
        if key in self.seen:
            return False
        self.seen.add(key)
        return True

    def unique_crashes(self) -> int:
        return len(self.seen)


@dataclass
class InputGenerator:
    seed: bytes
    _counter: int = 0

    @staticmethod
    def new(seed: bytes) -> "InputGenerator":
        return InputGenerator(seed=bytes(seed))

    def generate(self, n: int) -> bytes:
        h = hashlib.sha256()
        h.update(self.seed)
        h.update(struct.pack("<Q", int(n)))
        h.update(struct.pack("<Q", self._counter))
        self._counter += 1
        return h.digest()


# ---------------------------------------------------------------------------
# network_state_machine.rs
# ---------------------------------------------------------------------------

@dataclass
class NSMState:
    id: int
    _name: str

    @staticmethod
    def new(id_: int, name: str) -> "NSMState":
        return NSMState(id=int(id_), _name=str(name))

    def name(self) -> str:
        return self._name


class NSMFieldType:
    FIXED = "fixed"
    RAND = "rand"
    LENGTH = "length"

    @staticmethod
    def generate(kind: str, rng: random.Random, value: bytes = b"", size: int = 4) -> bytes:
        if kind == NSMFieldType.FIXED:
            return value
        if kind == NSMFieldType.RAND:
            return bytes(rng.randrange(256) for _ in range(size))
        if kind == NSMFieldType.LENGTH:
            return struct.pack("<I", size)
        return b""

    @staticmethod
    def mutate(kind: str, rng: random.Random, value: bytes = b"", size: int = 4) -> bytes:
        out = bytearray(NSMFieldType.generate(kind, rng, value, size))
        if out:
            i = rng.randrange(len(out))
            out[i] ^= 0xFF
        return bytes(out)


@dataclass
class MessageTemplate:
    name: str
    fields: List[Tuple[str, str, bytes, int]] = field(default_factory=list)

    @staticmethod
    def new(name: str) -> "MessageTemplate":
        return MessageTemplate(name=str(name))

    def add_field(self, field_tuple: Tuple[str, str, bytes, int]) -> None:
        self.fields.append(field_tuple)

    def generate(self, rng: random.Random) -> bytes:
        out = bytearray()
        for (_name, kind, value, size) in self.fields:
            out += NSMFieldType.generate(kind, rng, value, size)
        return bytes(out)

    def generate_mutated(self, rng: random.Random) -> bytes:
        out = bytearray()
        for (_name, kind, value, size) in self.fields:
            out += NSMFieldType.mutate(kind, rng, value, size)
        return bytes(out)


@dataclass
class NSMTransition:
    from_: int
    to: int
    label: str
    message: MessageTemplate

    @staticmethod
    def new(from_: int, to: int, label: str, message: MessageTemplate) -> "NSMTransition":
        return NSMTransition(from_=int(from_), to=int(to), label=str(label), message=message)

    def check_guard(self, current: int, msg: bytes) -> bool:
        return current == self.from_

    def execute_action(self, msg: bytes) -> Optional[bytes]:
        return bytes(msg)


@dataclass
class NetworkStateMachine:
    initial_state: int
    current: int = 0
    transitions: List[NSMTransition] = field(default_factory=list)

    @staticmethod
    def new(initial_state: int) -> "NetworkStateMachine":
        return NetworkStateMachine(initial_state=int(initial_state), current=int(initial_state))

    def add_transition(self, t: NSMTransition) -> None:
        self.transitions.append(t)

    def available_transitions(self) -> List[NSMTransition]:
        return [t for t in self.transitions if t.from_ == self.current]

    def step(self, rng: random.Random) -> Optional[bytes]:
        avail = self.available_transitions()
        if not avail:
            return None
        t = avail[rng.randrange(len(avail))]
        msg = t.message.generate(rng)
        self.current = t.to
        return msg

    def reset(self) -> None:
        self.current = self.initial_state


@dataclass
class StateExplorer:
    _names: List[str] = field(default_factory=list)

    @staticmethod
    def new() -> "StateExplorer":
        return StateExplorer()

    def explore_bfs(self, fsm: NetworkStateMachine) -> None:
        from collections import deque
        visited = set([fsm.initial_state])
        q = deque([fsm.initial_state])
        while q:
            cur = q.popleft()
            self._names.append(str(cur))
            for t in fsm.transitions:
                if t.from_ == cur and t.to not in visited:
                    visited.add(t.to)
                    q.append(t.to)

    def state_names(self) -> List[str]:
        return list(self._names)


@dataclass
class FuzzSessionRunner:
    fsm: NetworkStateMachine
    rng: random.Random
    _all: List[bytes] = field(default_factory=list)

    def run_session(self) -> List[bytes]:
        self.fsm.reset()
        out: List[bytes] = []
        while True:
            m = self.fsm.step(self.rng)
            if m is None:
                break
            out.append(m)
            self._all.append(m)
        return out

    def run_sessions(self, n: int) -> int:
        total = 0
        for _ in range(int(n)):
            total += len(self.run_session())
        return total

    def unique_messages(self) -> List[bytes]:
        seen = set()
        out = []
        for m in self._all:
            if m not in seen:
                seen.add(m)
                out.append(m)
        return out


def http_like_state_machine() -> NetworkStateMachine:
    fsm = NetworkStateMachine.new(0)
    tpl_req = MessageTemplate.new("request")
    tpl_req.add_field(("method", NSMFieldType.FIXED, b"GET / HTTP/1.1\r\n\r\n", 0))
    tpl_resp = MessageTemplate.new("response")
    tpl_resp.add_field(("status", NSMFieldType.FIXED, b"HTTP/1.1 200 OK\r\n\r\n", 0))
    fsm.add_transition(NSMTransition.new(0, 1, "send_req", tpl_req))
    fsm.add_transition(NSMTransition.new(1, 2, "recv_resp", tpl_resp))
    return fsm


# ---------------------------------------------------------------------------
# protocol_state_machine.rs
# ---------------------------------------------------------------------------

@dataclass
class PSMTransition:
    name: str
    to: str
    payload: Optional[bytes] = None
    expected: Optional[bytes] = None
    description: str = ""
    weight: int = 1

    def send_payload(self) -> Optional[bytes]:
        return self.payload

    def expected_response(self) -> Optional[bytes]:
        return self.expected

    @staticmethod
    def silent(name: str, to: str) -> "PSMTransition":
        return PSMTransition(name=name, to=to)

    @staticmethod
    def send(name: str, to: str, payload: bytes) -> "PSMTransition":
        return PSMTransition(name=name, to=to, payload=bytes(payload))

    @staticmethod
    def send_recv(name: str, to: str, payload: bytes, expected: bytes) -> "PSMTransition":
        return PSMTransition(name=name, to=to, payload=bytes(payload), expected=bytes(expected))

    def with_description(self, desc: str) -> "PSMTransition":
        self.description = str(desc)
        return self


@dataclass
class PSMState:
    name: str
    transitions: List[PSMTransition] = field(default_factory=list)
    terminal: bool = False

    @staticmethod
    def new(name: str) -> "PSMState":
        return PSMState(name=str(name))

    def add_transition(self, t: PSMTransition) -> None:
        self.transitions.append(t)

    def transition_by_name(self, name: str) -> Optional[PSMTransition]:
        for t in self.transitions:
            if t.name == name:
                return t
        return None

    def transition_to(self, dest: str) -> Optional[PSMTransition]:
        for t in self.transitions:
            if t.to == dest:
                return t
        return None

    def total_weight(self) -> int:
        return sum(t.weight for t in self.transitions)

    def weighted_pick(self, rng: random.Random) -> Optional[PSMTransition]:
        if not self.transitions:
            return None
        total = self.total_weight()
        r = rng.randrange(total)
        acc = 0
        for t in self.transitions:
            acc += t.weight
            if r < acc:
                return t
        return self.transitions[-1]


@dataclass
class StateGraph:
    states: Dict[str, PSMState] = field(default_factory=dict)

    @staticmethod
    def new() -> "StateGraph":
        return StateGraph()

    def add_state(self, state: PSMState) -> None:
        if state.name in self.states:
            raise FuzzNetError(f"duplicate state {state.name}")
        self.states[state.name] = state

    def state(self, name: str) -> Optional[PSMState]:
        return self.states.get(name)

    def state_mut(self, name: str) -> Optional[PSMState]:
        return self.states.get(name)

    def len(self) -> int:
        return len(self.states)

    def is_empty(self) -> bool:
        return not self.states

    def states_iter(self) -> Iterator[PSMState]:
        return iter(self.states.values())

    def state_names(self) -> List[str]:
        return list(self.states.keys())

    def edges(self) -> List[Tuple[str, str]]:
        out = []
        for n, s in self.states.items():
            for t in s.transitions:
                out.append((n, t.to))
        return out

    def validate(self) -> List[str]:
        errs = []
        for n, s in self.states.items():
            for t in s.transitions:
                if t.to not in self.states:
                    errs.append(f"{n} -> {t.to} unknown")
        return errs

    def topo_sort(self) -> List[str]:
        in_deg: Dict[str, int] = {n: 0 for n in self.states}
        for n, s in self.states.items():
            for t in s.transitions:
                if t.to in in_deg and t.to != n:
                    in_deg[t.to] += 1
        from collections import deque
        q = deque([n for n, d in in_deg.items() if d == 0])
        out = []
        while q:
            n = q.popleft()
            out.append(n)
            for t in self.states[n].transitions:
                if t.to == n:
                    continue
                in_deg[t.to] -= 1
                if in_deg[t.to] == 0:
                    q.append(t.to)
        if len(out) != len(self.states):
            raise FuzzNetError("cycle")
        return out

    def reachable_from(self, start: str) -> List[str]:
        if start not in self.states:
            return []
        from collections import deque
        seen = {start}
        q = deque([start])
        while q:
            n = q.popleft()
            for t in self.states[n].transitions:
                if t.to not in seen:
                    seen.add(t.to)
                    q.append(t.to)
        return list(seen)


@dataclass
class ProtocolStateMachine:
    graph: StateGraph
    initial: str
    cur: str = ""
    _history: List[str] = field(default_factory=list)
    _visits: Dict[str, int] = field(default_factory=dict)

    @staticmethod
    def new(graph: StateGraph, initial: str) -> "ProtocolStateMachine":
        if initial not in graph.states:
            raise FuzzNetError("bad initial")
        return ProtocolStateMachine(graph=graph, initial=initial, cur=initial)

    def current_state(self) -> str:
        return self.cur

    def current(self) -> PSMState:
        return self.graph.states[self.cur]

    def is_terminal(self) -> bool:
        return self.current().terminal

    def reset(self) -> None:
        self.cur = self.initial

    def full_reset(self) -> None:
        self.cur = self.initial
        self._history.clear()
        self._visits.clear()

    def advance_to(self, dest: str) -> PSMTransition:
        t = self.current().transition_to(dest)
        if t is None:
            raise FuzzNetError("no transition")
        self.cur = dest
        self._history.append(t.name)
        self._visits[dest] = self._visits.get(dest, 0) + 1
        return t

    def advance_random(self, rng: random.Random) -> Optional[PSMTransition]:
        t = self.current().weighted_pick(rng)
        if t is None:
            return None
        self.cur = t.to
        self._history.append(t.name)
        self._visits[t.to] = self._visits.get(t.to, 0) + 1
        return t

    def history(self) -> List[str]:
        return list(self._history)

    def visit_counts(self) -> Dict[str, int]:
        return dict(self._visits)

    def next_state(self, transition_name: str) -> str:
        t = self.current().transition_by_name(transition_name)
        if t is None:
            raise FuzzNetError("unknown transition")
        return t.to

    def reachable(self) -> List[str]:
        return self.graph.reachable_from(self.cur)


@dataclass
class StateMachineBuilder:
    initial_name: Optional[str] = None
    graph: StateGraph = field(default_factory=StateGraph.new)

    @staticmethod
    def new() -> "StateMachineBuilder":
        return StateMachineBuilder()

    def initial(self, name: str) -> "StateMachineBuilder":
        self.initial_name = name
        return self

    def add_state(self, state: PSMState) -> "StateMachineBuilder":
        self.graph.add_state(state)
        return self

    def try_add_state(self, state: PSMState) -> bool:
        try:
            self.graph.add_state(state)
            return True
        except FuzzNetError:
            return False

    def build(self) -> ProtocolStateMachine:
        if self.initial_name is None:
            raise FuzzNetError("no initial")
        return ProtocolStateMachine.new(self.graph, self.initial_name)


def next_state(graph: StateGraph, from_state: str, transition_name: str) -> Optional[str]:
    s = graph.state(from_state)
    if s is None:
        return None
    t = s.transition_by_name(transition_name)
    return t.to if t else None


# ---------------------------------------------------------------------------
# protocol_state_fuzzer.rs
# ---------------------------------------------------------------------------

@dataclass
class PSFState:
    id: str
    description: str
    terminal_flag: bool = False
    outgoing: List[str] = field(default_factory=list)

    @staticmethod
    def new(id_: str, description: str) -> "PSFState":
        return PSFState(id=str(id_), description=str(description))

    def terminal(self) -> "PSFState":
        self.terminal_flag = True
        return self

    def add_transition(self, target_id: str) -> None:
        self.outgoing.append(target_id)


@dataclass
class StateTransition:
    from_id: str
    to_id: str
    label: str
    template: MessageTemplate
    response: Optional[bytes] = None

    @staticmethod
    def new(from_id: str, to_id: str, label: str, template: MessageTemplate) -> "StateTransition":
        return StateTransition(from_id=from_id, to_id=to_id, label=label, template=template)

    def with_response(self, resp: bytes) -> "StateTransition":
        self.response = bytes(resp)
        return self

    def mutated_message(self, rng: random.Random) -> bytes:
        return self.template.generate_mutated(rng)


@dataclass
class CoverageTracker:
    states_seen: set = field(default_factory=set)
    transitions_seen: set = field(default_factory=set)
    visits: Dict[str, int] = field(default_factory=dict)

    @staticmethod
    def new() -> "CoverageTracker":
        return CoverageTracker()

    def record_state(self, state: str) -> None:
        self.states_seen.add(state)
        self.visits[state] = self.visits.get(state, 0) + 1

    def record_transition(self, from_: str, to: str) -> None:
        self.transitions_seen.add((from_, to))

    def state_coverage_pct(self, total: int) -> float:
        return 100.0 * len(self.states_seen) / total if total else 0.0

    def transition_coverage_pct(self, total: int) -> float:
        return 100.0 * len(self.transitions_seen) / total if total else 0.0

    def has_reached(self, state_id: str) -> bool:
        return state_id in self.states_seen

    def most_visited(self) -> Optional[str]:
        if not self.visits:
            return None
        return max(self.visits.items(), key=lambda kv: kv[1])[0]


@dataclass
class FuzzSequenceStep:
    from_: str
    to: str
    label: str
    msg: bytes


@dataclass
class FuzzSequence:
    iteration: int
    steps: List[FuzzSequenceStep] = field(default_factory=list)

    @staticmethod
    def new(iteration: int) -> "FuzzSequence":
        return FuzzSequence(iteration=int(iteration))

    def push_step(self, from_: str, to: str, label: str, msg: bytes) -> None:
        self.steps.append(FuzzSequenceStep(from_, to, label, bytes(msg)))

    def total_bytes(self) -> int:
        return sum(len(s.msg) for s in self.steps)

    def depth(self) -> int:
        return len(self.steps)


@dataclass
class FuzzerStats:
    sequences: int = 0
    violations: int = 0


@dataclass
class StateFuzzer:
    initial: str
    states: Dict[str, PSFState] = field(default_factory=dict)
    transitions: List[StateTransition] = field(default_factory=list)
    coverage: CoverageTracker = field(default_factory=CoverageTracker.new)
    _stats: FuzzerStats = field(default_factory=FuzzerStats)
    _violations: int = 0

    @staticmethod
    def new(initial: str, states: Dict[str, PSFState], transitions: List[StateTransition]) -> "StateFuzzer":
        return StateFuzzer(initial=initial, states=dict(states), transitions=list(transitions))

    def outgoing(self, state_id: str) -> List[StateTransition]:
        return [t for t in self.transitions if t.from_id == state_id]

    def find_path(self, start: str, target: str) -> Optional[List[str]]:
        from collections import deque
        prev: Dict[str, str] = {}
        q = deque([start])
        visited = {start}
        while q:
            n = q.popleft()
            if n == target:
                path = [n]
                while path[-1] in prev:
                    path.append(prev[path[-1]])
                return list(reversed(path))
            for t in self.outgoing(n):
                if t.to_id not in visited:
                    visited.add(t.to_id)
                    prev[t.to_id] = n
                    q.append(t.to_id)
        return None

    def generate_sequence(self, rng: Optional[random.Random] = None) -> FuzzSequence:
        rng = rng or random.Random()
        seq = FuzzSequence.new(self._stats.sequences)
        cur = self.initial
        for _ in range(8):
            outs = self.outgoing(cur)
            if not outs:
                break
            t = outs[rng.randrange(len(outs))]
            msg = t.mutated_message(rng)
            seq.push_step(t.from_id, t.to_id, t.label, msg)
            self.coverage.record_state(t.to_id)
            self.coverage.record_transition(t.from_id, t.to_id)
            cur = t.to_id
            if self.states.get(cur) and self.states[cur].terminal_flag:
                break
        self._stats.sequences += 1
        return seq

    def run(self, count: int) -> None:
        for _ in range(int(count)):
            self.generate_sequence()

    def state_coverage_pct(self) -> float:
        return self.coverage.state_coverage_pct(len(self.states))

    def transition_coverage_pct(self) -> float:
        return self.coverage.transition_coverage_pct(len(self.transitions))

    def violation_count(self) -> int:
        return self._violations

    def validate(self) -> List[str]:
        errs = []
        if self.initial not in self.states:
            errs.append("missing initial")
        for t in self.transitions:
            if t.from_id not in self.states:
                errs.append(f"transition from unknown {t.from_id}")
            if t.to_id not in self.states:
                errs.append(f"transition to unknown {t.to_id}")
        return errs

    def uncovered_transitions(self) -> List[StateTransition]:
        return [t for t in self.transitions
                if (t.from_id, t.to_id) not in self.coverage.transitions_seen]

    def stats(self) -> FuzzerStats:
        return self._stats


@dataclass
class StateFuzzerBuilder:
    initial: str
    states: Dict[str, PSFState] = field(default_factory=dict)
    transitions: List[StateTransition] = field(default_factory=list)

    @staticmethod
    def new(initial: str) -> "StateFuzzerBuilder":
        return StateFuzzerBuilder(initial=str(initial))

    def add_state(self, state: PSFState) -> "StateFuzzerBuilder":
        self.states[state.id] = state
        return self

    def add_transition(self, from_: str, to: str, label: str,
                       template: MessageTemplate) -> "StateFuzzerBuilder":
        self.transitions.append(StateTransition.new(from_, to, label, template))
        return self

    def build(self) -> StateFuzzer:
        return StateFuzzer.new(self.initial, self.states, self.transitions)


# ---------------------------------------------------------------------------
# protocol_fuzzer.rs
# ---------------------------------------------------------------------------

@dataclass
class FuzzTarget:
    kind: str
    host: str
    port: int
    verify_peer: bool = False

    @staticmethod
    def tcp(host: str, port: int) -> "FuzzTarget":
        return FuzzTarget(kind="tcp", host=str(host), port=int(port))

    @staticmethod
    def udp(host: str, port: int) -> "FuzzTarget":
        return FuzzTarget(kind="udp", host=str(host), port=int(port))

    @staticmethod
    def tls(host: str, port: int, verify_peer: bool) -> "FuzzTarget":
        return FuzzTarget(kind="tls", host=str(host), port=int(port), verify_peer=bool(verify_peer))

    def address(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class FieldMutationRecord:
    field: str
    before: bytes
    after: bytes


@dataclass
class FieldFuzzer:
    @staticmethod
    def new() -> "FieldFuzzer":
        return FieldFuzzer()

    def mutate(self, msg: MessageDef, rng: random.Random) -> List[FieldMutationRecord]:
        out = []
        for f in msg.fields:
            if not f.fuzz:
                continue
            before = bytes(f.data)
            self.mutate_field(f, rng)
            out.append(FieldMutationRecord(f.name, before, bytes(f.data)))
        return out

    def mutate_field(self, f: FieldDef, rng: random.Random) -> None:
        if f.data:
            data = bytearray(f.data)
            i = rng.randrange(len(data))
            data[i] ^= 1 << rng.randrange(8)
            f.data = bytes(data)


@dataclass
class StateContext:
    protocol: ProtocolDef
    cur: str = ""
    hist: List[str] = field(default_factory=list)

    @staticmethod
    def new(protocol: ProtocolDef) -> "StateContext":
        return StateContext(protocol=protocol, cur=protocol.initial_state)

    def reset(self) -> None:
        self.cur = self.protocol.initial_state
        self.hist.clear()

    def current_state(self) -> str:
        return self.cur

    def advance(self, to: str) -> None:
        self.hist.append(self.cur)
        self.cur = to

    def available_transitions(self) -> List[Tuple[str, str]]:
        s = self.protocol.states.get(self.cur)
        return list(s.transitions) if s else []

    def is_terminal(self) -> bool:
        s = self.protocol.states.get(self.cur)
        return bool(s and s.terminal)

    def pick_transition(self, rng: random.Random) -> Optional[Tuple[str, str]]:
        avail = self.available_transitions()
        if not avail:
            return None
        return avail[rng.randrange(len(avail))]

    def history(self) -> List[str]:
        return list(self.hist)

    @staticmethod
    def from_edge_map(initial: str, edges: Dict[str, List[Tuple[str, str]]]) -> "StateContext":
        states = {n: ProtocolState(name=n, transitions=list(ts)) for n, ts in edges.items()}
        states.setdefault(initial, ProtocolState(name=initial))
        return StateContext.new(ProtocolDef.new(initial, states))


@dataclass
class MessageFuzzer:
    @staticmethod
    def new() -> "MessageFuzzer":
        return MessageFuzzer()

    def choose_and_mutate(self, messages: List[MessageDef], rng: random.Random) -> Optional[MessageDef]:
        if not messages:
            return None
        msg = messages[rng.randrange(len(messages))]
        msg.mutate(rng)
        return msg

    def valid_messages(self, machine_messages: List[MessageDef]) -> List[MessageDef]:
        return [m for m in machine_messages if m.fields]


@dataclass
class SessionReplay:
    note: str
    records: List[Tuple[bytes, str]] = field(default_factory=list)

    @staticmethod
    def new(note: str) -> "SessionReplay":
        return SessionReplay(note=str(note))

    def record(self, data: bytes, state: str) -> None:
        self.records.append((bytes(data), str(state)))

    def total_bytes(self) -> int:
        return sum(len(d) for d, _ in self.records)

    def matches(self, expected: List[bytes]) -> bool:
        return [d for d, _ in self.records] == [bytes(e) for e in expected]

    def to_hex_dump(self) -> str:
        return "\n".join(f"{s}: {d.hex()}" for d, s in self.records)


@dataclass
class ProtocolFuzzer:
    protocol: ProtocolDef
    target: FuzzTarget
    _last_replay: Optional[SessionReplay] = None

    @staticmethod
    def new(protocol: ProtocolDef, target: FuzzTarget) -> "ProtocolFuzzer":
        return ProtocolFuzzer(protocol=protocol, target=target)

    def run_iteration(self) -> List[FieldMutationRecord]:
        self._last_replay = SessionReplay.new("iter")
        return []

    def last_replay(self) -> Optional[SessionReplay]:
        return self._last_replay

    def throttle(self) -> float:
        return 0.0


# ---------------------------------------------------------------------------
# packet_mutator.rs
# ---------------------------------------------------------------------------

def flip_bit(data: bytes, bit: int = 0) -> bytes:
    if not data:
        return bytes(data)
    out = bytearray(data)
    out[bit // 8 % len(out)] ^= 1 << (bit % 8)
    return bytes(out)


def substitute_byte(data: bytes, offset: int, value: int) -> bytes:
    out = bytearray(data)
    if out:
        out[offset % len(out)] = value & 0xFF
    return bytes(out)


def insert_bytes(data: bytes, offset: int, payload: bytes) -> bytes:
    off = max(0, min(len(data), offset))
    return bytes(data[:off]) + bytes(payload) + bytes(data[off:])


def delete_bytes(data: bytes, offset: int, length: int) -> bytes:
    off = max(0, min(len(data), offset))
    end = min(len(data), off + max(0, length))
    return bytes(data[:off]) + bytes(data[end:])


def overwrite_range(data: bytes, offset: int, payload: bytes) -> bytes:
    out = bytearray(data)
    for i, b in enumerate(payload):
        if offset + i < len(out):
            out[offset + i] = b
    return bytes(out)


def http_inject_header(data: bytes, header: bytes) -> bytes:
    idx = data.find(b"\r\n")
    if idx < 0:
        return bytes(data) + bytes(header) + b"\r\n"
    return bytes(data[: idx + 2]) + bytes(header) + b"\r\n" + bytes(data[idx + 2:])


def dns_label_overflow(data: bytes) -> bytes:
    return bytes(data) + b"\xff" + b"A" * 255


def tls_version_confusion(data: bytes) -> bytes:
    out = bytearray(data)
    if len(out) >= 3:
        out[1] = 0x03
        out[2] = 0xFF
    return bytes(out)


@dataclass
class FieldMutation:
    field_name: str
    offset: int
    length: int
    op: str  # "flip", "zero", "max"

    @staticmethod
    def new(field_name: str, offset: int, length: int, op: str) -> "FieldMutation":
        return FieldMutation(field_name=str(field_name), offset=int(offset),
                             length=int(length), op=str(op))

    def apply(self, data: bytes) -> bytes:
        out = bytearray(data)
        for i in range(self.length):
            idx = self.offset + i
            if idx >= len(out):
                break
            if self.op == "flip":
                out[idx] ^= 0xFF
            elif self.op == "zero":
                out[idx] = 0
            elif self.op == "max":
                out[idx] = 0xFF
        return bytes(out)


class ChecksumKind:
    XOR = "xor"
    ADD = "add"
    CRC16 = "crc16"


@dataclass
class ChecksumCorrupter:
    kind: str
    offset: int

    @staticmethod
    def new(kind: str, offset: int) -> "ChecksumCorrupter":
        return ChecksumCorrupter(kind=str(kind), offset=int(offset))

    def corrupt(self, data: bytes) -> bytes:
        out = bytearray(data)
        if self.offset < len(out):
            out[self.offset] ^= 0xFF
        return bytes(out)

    def fix(self, data: bytes) -> bytes:
        out = bytearray(data)
        if self.offset >= len(out):
            return bytes(out)
        body = bytes(out[: self.offset]) + bytes(out[self.offset + 1:])
        if self.kind == ChecksumKind.XOR:
            out[self.offset] = xor_checksum(body)
        elif self.kind == ChecksumKind.ADD:
            out[self.offset] = add_checksum(body)
        return bytes(out)


@dataclass
class LengthFieldCorrupter:
    offset: int
    field_bytes: int
    strategy: str  # "zero", "max", "off_by_one"

    @staticmethod
    def new(offset: int, field_bytes: int, strategy: str) -> "LengthFieldCorrupter":
        return LengthFieldCorrupter(offset=int(offset), field_bytes=int(field_bytes),
                                    strategy=str(strategy))

    def corrupt(self, data: bytes) -> bytes:
        out = bytearray(data)
        if self.strategy == "zero":
            new_val = 0
        elif self.strategy == "max":
            new_val = (1 << (8 * self.field_bytes)) - 1
        elif self.strategy == "off_by_one":
            cur = int.from_bytes(bytes(out[self.offset:self.offset + self.field_bytes]), "little")
            new_val = (cur + 1) & ((1 << (8 * self.field_bytes)) - 1)
        else:
            new_val = 0
        enc = new_val.to_bytes(self.field_bytes, "little")
        for i, b in enumerate(enc):
            if self.offset + i < len(out):
                out[self.offset + i] = b
        return bytes(out)


@dataclass
class MutatorStep:
    _name: str
    fn: Callable[[bytes], bytes]

    def apply(self, data: bytes) -> bytes:
        return self.fn(bytes(data))

    def name(self) -> str:
        return self._name


@dataclass
class PacketMutator:
    label_: str
    steps: List[MutatorStep] = field(default_factory=list)

    @staticmethod
    def new(label: str) -> "PacketMutator":
        return PacketMutator(label_=str(label))

    def add_step(self, step: MutatorStep) -> "PacketMutator":
        self.steps.append(step)
        return self

    def with_step(self, step: MutatorStep) -> "PacketMutator":
        return PacketMutator(label_=self.label_, steps=list(self.steps) + [step])

    def apply(self, data: bytes) -> bytes:
        cur = bytes(data)
        for s in self.steps:
            cur = s.apply(cur)
        return cur

    def label(self) -> str:
        return self.label_

    def step_count(self) -> int:
        return len(self.steps)


def all_bit_flips(data: bytes) -> List[Tuple[int, bytes]]:
    out = []
    for i in range(len(data) * 8):
        out.append((i, flip_bit(data, i)))
    return out


def interesting_int_variants(data: bytes) -> List[bytes]:
    variants = []
    interesting = [0, 1, 0x7F, 0x80, 0xFF]
    for off in range(len(data)):
        for v in interesting:
            variants.append(substitute_byte(data, off, v))
    return variants


@dataclass
class MutatorChain:
    entries: List[Tuple[PacketMutator, int]] = field(default_factory=list)
    _apply_count: int = 0

    @staticmethod
    def new() -> "MutatorChain":
        return MutatorChain()

    def add(self, mutator: PacketMutator, weight: int) -> None:
        self.entries.append((mutator, int(weight)))

    def select(self, seed: int) -> Optional[PacketMutator]:
        if not self.entries:
            return None
        rng = random.Random(seed)
        total = sum(w for _, w in self.entries)
        r = rng.randrange(total)
        acc = 0
        for m, w in self.entries:
            acc += w
            if r < acc:
                return m
        return self.entries[-1][0]

    def apply_random(self, data: bytes, seed: int) -> Optional[Tuple[str, bytes]]:
        m = self.select(seed)
        if m is None:
            return None
        self._apply_count += 1
        return (m.label(), m.apply(data))

    def mutator_count(self) -> int:
        return len(self.entries)

    def apply_count(self) -> int:
        return self._apply_count

    def apply_all(self, data: bytes) -> List[Tuple[str, bytes]]:
        return [(m.label(), m.apply(data)) for m, _ in self.entries]


def http_chain() -> MutatorChain:
    c = MutatorChain.new()
    m = PacketMutator.new("http_header_inject")
    m.add_step(MutatorStep("inject", lambda d: http_inject_header(d, b"X-Evil: 1")))
    c.add(m, 1)
    return c


def dns_chain() -> MutatorChain:
    c = MutatorChain.new()
    m = PacketMutator.new("dns_overflow")
    m.add_step(MutatorStep("overflow", dns_label_overflow))
    c.add(m, 1)
    return c


def tls_chain() -> MutatorChain:
    c = MutatorChain.new()
    m = PacketMutator.new("tls_version")
    m.add_step(MutatorStep("confuse", tls_version_confusion))
    c.add(m, 1)
    return c


@dataclass
class MutatorStats:
    counts: Dict[str, int] = field(default_factory=dict)
    bytes_per_step: Dict[str, int] = field(default_factory=dict)

    def record(self, step_name: str, output_len: int) -> None:
        self.counts[step_name] = self.counts.get(step_name, 0) + 1
        self.bytes_per_step[step_name] = self.bytes_per_step.get(step_name, 0) + int(output_len)

    def top_n(self, n: int) -> List[Tuple[str, int]]:
        return sorted(self.counts.items(), key=lambda kv: -kv[1])[: int(n)]


# ---------------------------------------------------------------------------
# coverage_guided_fuzzer.rs
# ---------------------------------------------------------------------------

@dataclass
class CoverageBitmap:
    bits: bytearray = field(default_factory=lambda: bytearray(65536))
    edges: int = 0

    @staticmethod
    def new() -> "CoverageBitmap":
        return CoverageBitmap()

    def reset(self) -> None:
        self.bits = bytearray(len(self.bits))
        self.edges = 0

    def has_new_bits(self, virgin_map: "CoverageBitmap") -> bool:
        for i in range(len(self.bits)):
            if self.bits[i] and not virgin_map.bits[i]:
                return True
        return False

    def update_virgin_map(self, virgin_map: "CoverageBitmap") -> int:
        new = 0
        for i in range(len(self.bits)):
            if self.bits[i] and not virgin_map.bits[i]:
                virgin_map.bits[i] = self.bits[i]
                new += 1
        return new

    def count_bits(self) -> int:
        return sum(1 for b in self.bits if b)

    def edge_count(self) -> int:
        return self.edges

    def merge(self, other: "CoverageBitmap") -> None:
        for i in range(len(self.bits)):
            self.bits[i] |= other.bits[i]

    def classify_counts(self) -> None:
        for i in range(len(self.bits)):
            v = self.bits[i]
            if v == 0:
                continue
            if v <= 1:
                self.bits[i] = 1
            elif v <= 3:
                self.bits[i] = 2
            elif v <= 7:
                self.bits[i] = 4
            elif v <= 15:
                self.bits[i] = 8
            else:
                self.bits[i] = 16


@dataclass
class CGCorpusEntry:
    id: int
    data: bytes
    coverage: CoverageBitmap
    unique_bits: int
    score: float = 0.0
    parent_id: Optional[int] = None
    depth: int = 0
    favored: bool = False

    @staticmethod
    def new(id_: int, data: bytes, coverage: CoverageBitmap, unique_bits: int) -> "CGCorpusEntry":
        e = CGCorpusEntry(id=int(id_), data=bytes(data), coverage=coverage,
                          unique_bits=int(unique_bits))
        e.compute_score()
        return e

    def compute_score(self) -> None:
        self.score = float(self.unique_bits) / max(1, len(self.data))
        self.favored = self.unique_bits > 0

    def is_favored(self) -> bool:
        return self.favored


@dataclass
class CorpusStats:
    entries: int
    favored: int
    coverage_pct: float


@dataclass
class CGCorpus:
    entries: List[CGCorpusEntry] = field(default_factory=list)
    virgin: CoverageBitmap = field(default_factory=CoverageBitmap.new)
    _next: int = 0
    _cursor: int = 0

    @staticmethod
    def new() -> "CGCorpus":
        return CGCorpus()

    def add_initial(self, data: bytes, coverage: CoverageBitmap) -> int:
        new = coverage.update_virgin_map(self.virgin)
        e = CGCorpusEntry.new(self._next, data, coverage, new)
        self._next += 1
        self.entries.append(e)
        return e.id

    def add_from_mutation(self, data: bytes, coverage: CoverageBitmap,
                          parent_id: int, depth: int) -> Optional[int]:
        if not coverage.has_new_bits(self.virgin):
            return None
        new = coverage.update_virgin_map(self.virgin)
        e = CGCorpusEntry.new(self._next, data, coverage, new)
        e.parent_id = parent_id
        e.depth = depth
        self._next += 1
        self.entries.append(e)
        return e.id

    def next_entry(self) -> Optional[CGCorpusEntry]:
        if not self.entries:
            return None
        e = self.entries[self._cursor % len(self.entries)]
        self._cursor += 1
        return e

    def coverage_percentage(self) -> float:
        return 100.0 * self.virgin.count_bits() / max(1, len(self.virgin.bits))

    def stats(self) -> CorpusStats:
        return CorpusStats(entries=len(self.entries),
                           favored=sum(1 for e in self.entries if e.favored),
                           coverage_pct=self.coverage_percentage())


@dataclass
class EnergyScheduler:
    @staticmethod
    def new() -> "EnergyScheduler":
        return EnergyScheduler()

    def compute_energy(self, entry: CGCorpusEntry, queue_cycle: int) -> int:
        base = 16
        if entry.is_favored():
            base *= 4
        base += entry.unique_bits
        base = max(1, base // max(1, queue_cycle))
        return int(base)


@dataclass
class CGMinimizer:
    @staticmethod
    def new() -> "CGMinimizer":
        return CGMinimizer()

    def minimize(self, data: bytes, test_fn: Callable[[bytes], bool]) -> bytes:
        cur = bytes(data)
        changed = True
        while changed and len(cur) > 1:
            changed = False
            half = cur[: len(cur) // 2]
            if test_fn(half):
                cur = half
                changed = True
        return cur


@dataclass
class SimpleRng:
    state: int

    @staticmethod
    def new(seed: int) -> "SimpleRng":
        return SimpleRng(state=int(seed) & ((1 << 64) - 1))

    def _step(self) -> int:
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        return self.state

    def next_u64(self) -> int:
        return self._step()

    def next_usize(self) -> int:
        return self._step()

    def next_u8(self) -> int:
        return self._step() & 0xFF

    def next_bool(self) -> bool:
        return bool(self._step() & 1)

    def next_u16(self) -> int:
        return self._step() & 0xFFFF

    def next_u32(self) -> int:
        return self._step() & 0xFFFFFFFF


@dataclass
class CGFuzzerConfig:
    max_mutations: int = 8
    seed: int = 0


@dataclass
class CGFuzzerStats:
    iterations: int = 0
    crashes: int = 0
    new_corpus: int = 0


@dataclass
class CoverageFuzzer:
    config: CGFuzzerConfig
    corpus: CGCorpus = field(default_factory=CGCorpus.new)
    _stats: CGFuzzerStats = field(default_factory=CGFuzzerStats)
    _rng: SimpleRng = field(default_factory=lambda: SimpleRng.new(0))

    @staticmethod
    def new(config: CGFuzzerConfig) -> "CoverageFuzzer":
        f = CoverageFuzzer(config=config)
        f._rng = SimpleRng.new(config.seed)
        return f

    def add_seed(self, data: bytes, coverage: CoverageBitmap) -> int:
        return self.corpus.add_initial(data, coverage)

    def mutate(self, entry_data: bytes) -> List[bytes]:
        out = []
        for _ in range(self.config.max_mutations):
            if not entry_data:
                break
            data = bytearray(entry_data)
            i = self._rng.next_usize() % len(data)
            data[i] ^= 1 << (self._rng.next_u8() & 7)
            out.append(bytes(data))
        return out

    def record_crash(self, data: bytes, crash_type: str, parent_id: int) -> None:
        self._stats.crashes += 1

    def stats(self) -> CGFuzzerStats:
        return self._stats


@dataclass
class TokenDictionary:
    tokens: List[bytes]

    @staticmethod
    def new(tokens: List[bytes]) -> "TokenDictionary":
        return TokenDictionary(tokens=[bytes(t) for t in tokens])

    def insert_token(self, data: bytes, pos: int, rng: random.Random) -> bytes:
        if not self.tokens:
            return bytes(data)
        tok = self.tokens[rng.randrange(len(self.tokens))]
        return bytes(data[:pos]) + tok + bytes(data[pos:])

    def overwrite_token(self, data: bytes, pos: int, rng: random.Random) -> bytes:
        if not self.tokens:
            return bytes(data)
        tok = self.tokens[rng.randrange(len(self.tokens))]
        out = bytearray(data)
        for i, b in enumerate(tok):
            if pos + i < len(out):
                out[pos + i] = b
        return bytes(out)


# ---------------------------------------------------------------------------
# grammar_fuzzer.rs
# ---------------------------------------------------------------------------

@dataclass
class GrammarNode:
    kind: str  # "lit" | "nt" | "optional" | "repeat" | "seq" | "alt"
    text: str = ""
    children: List["GrammarNode"] = field(default_factory=list)
    min_: int = 0
    max_: int = 0

    @staticmethod
    def lit(s: str) -> "GrammarNode":
        return GrammarNode(kind="lit", text=str(s))

    @staticmethod
    def nt(name: str) -> "GrammarNode":
        return GrammarNode(kind="nt", text=str(name))

    def optional(self) -> "GrammarNode":
        return GrammarNode(kind="optional", children=[self])

    def repeat(self, min_: int, max_: int) -> "GrammarNode":
        return GrammarNode(kind="repeat", children=[self], min_=int(min_), max_=int(max_))


def lit(s: str) -> GrammarNode:
    return GrammarNode.lit(s)


@dataclass
class Grammar:
    start: str
    rules: Dict[str, GrammarNode] = field(default_factory=dict)

    @staticmethod
    def new(start: str) -> "Grammar":
        return Grammar(start=str(start))

    def rule(self, name: str, node: GrammarNode) -> "Grammar":
        self.rules[name] = node
        return self

    def start_node(self) -> Optional[GrammarNode]:
        return self.rules.get(self.start)

    def rule_count(self) -> int:
        return len(self.rules)


@dataclass
class GrammarFuzzer:
    max_depth: int
    max_length: int

    @staticmethod
    def new(max_depth: int, max_length: int) -> "GrammarFuzzer":
        return GrammarFuzzer(max_depth=int(max_depth), max_length=int(max_length))

    def _expand(self, grammar: Grammar, node: GrammarNode, depth: int,
                rng: random.Random, out: bytearray) -> None:
        if depth > self.max_depth or len(out) > self.max_length:
            return
        if node.kind == "lit":
            out += node.text.encode("utf-8")
        elif node.kind == "nt":
            r = grammar.rules.get(node.text)
            if r:
                self._expand(grammar, r, depth + 1, rng, out)
        elif node.kind == "optional":
            if rng.random() < 0.5:
                self._expand(grammar, node.children[0], depth + 1, rng, out)
        elif node.kind == "repeat":
            n = rng.randint(node.min_, node.max_)
            for _ in range(n):
                self._expand(grammar, node.children[0], depth + 1, rng, out)
        else:
            for c in node.children:
                self._expand(grammar, c, depth + 1, rng, out)

    def generate(self, grammar: Optional[Grammar] = None, seed: int = 0) -> bytes:
        if grammar is None:
            return b""
        rng = random.Random(seed)
        node = grammar.start_node()
        if node is None:
            return b""
        out = bytearray()
        self._expand(grammar, node, 0, rng, out)
        return bytes(out)

    def generate_n(self, grammar: Grammar, n: int) -> List[bytes]:
        return [self.generate(grammar, i) for i in range(int(n))]

    def generate_string(self, grammar: Optional[Grammar] = None) -> str:
        return self.generate(grammar).decode("utf-8", errors="replace")


def http11_grammar() -> Grammar:
    g = Grammar.new("request")
    g.rule("request", GrammarNode.lit("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    return g


def json_grammar() -> Grammar:
    g = Grammar.new("json")
    g.rule("json", GrammarNode.lit('{"k":"v"}'))
    return g


def xml_grammar() -> Grammar:
    g = Grammar.new("xml")
    g.rule("xml", GrammarNode.lit("<root/>"))
    return g


def tls_client_hello_grammar() -> Grammar:
    g = Grammar.new("hello")
    g.rule("hello", GrammarNode.lit("\x16\x03\x01\x00\x00"))
    return g


# ---------------------------------------------------------------------------
# dns_fuzzer.rs
# ---------------------------------------------------------------------------

class DnsQType:
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28

    @staticmethod
    def as_u16(value: int) -> int:
        return int(value) & 0xFFFF


class DnsRCode:
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5

    @staticmethod
    def as_u16(value: int) -> int:
        return int(value) & 0xFFFF


@dataclass
class DnsFlags:
    qr: bool = False
    opcode: int = 0
    aa: bool = False
    tc: bool = False
    rd: bool = True
    ra: bool = False
    rcode: int = 0

    def to_u16(self) -> int:
        v = 0
        if self.qr:
            v |= 0x8000
        v |= (self.opcode & 0xF) << 11
        if self.aa:
            v |= 0x0400
        if self.tc:
            v |= 0x0200
        if self.rd:
            v |= 0x0100
        if self.ra:
            v |= 0x0080
        v |= self.rcode & 0xF
        return v


def encode_dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        b = label.encode("ascii")
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def build_edns0(udp_payload_size: int, dnssec_ok: bool, options: List[Tuple[int, bytes]]) -> bytes:
    out = bytearray()
    out.append(0)  # root name
    out += struct.pack(">H", 41)  # OPT
    out += struct.pack(">H", udp_payload_size)
    flags = 0x8000 if dnssec_ok else 0
    out += struct.pack(">I", flags)
    body = bytearray()
    for code, data in options:
        body += struct.pack(">HH", code, len(data))
        body += data
    out += struct.pack(">H", len(body))
    out += body
    return bytes(out)


@dataclass
class DnsQuestion:
    name: str
    qtype: int

    @staticmethod
    def new(name: str, qtype: int) -> "DnsQuestion":
        return DnsQuestion(name=str(name), qtype=int(qtype))

    def serialize(self) -> bytes:
        return encode_dns_name(self.name) + struct.pack(">HH", self.qtype, 1)


@dataclass
class DnsPacket:
    id: int
    flags: DnsFlags
    question: DnsQuestion

    @staticmethod
    def new_query(id_: int, question: DnsQuestion) -> "DnsPacket":
        return DnsPacket(id=int(id_), flags=DnsFlags(), question=question)

    def serialize(self) -> bytes:
        hdr = struct.pack(">HHHHHH", self.id, self.flags.to_u16(), 1, 0, 0, 0)
        return hdr + self.question.serialize()


@dataclass
class DnsMutation:
    bytes_: bytes
    label: str
    mutation: str

    @staticmethod
    def new(bytes_: bytes, label: str, mutation: str) -> "DnsMutation":
        return DnsMutation(bytes_=bytes(bytes_), label=str(label), mutation=str(mutation))


def apply_dns_mutation(packet: DnsPacket, m: DnsMutation) -> bytes:
    base = packet.serialize()
    if m.mutation == "append":
        return base + m.bytes_
    if m.mutation == "prefix":
        return m.bytes_ + base
    if m.mutation == "xor" and base:
        out = bytearray(base)
        for i, b in enumerate(m.bytes_):
            out[i % len(out)] ^= b
        return bytes(out)
    return base


@dataclass
class DnsFuzzOutcome:
    response: bytes
    anomalous: bool = False
    note: str = ""

    def is_anomalous(self) -> bool:
        return self.anomalous


@dataclass
class DnsFuzzStats:
    sent: int = 0
    anomalous: int = 0


@dataclass
class DnsFuzzer:
    target: Tuple[str, int]
    base_name: str = "example.com"
    recv_timeout_ms: int = 1000
    mutations: List[DnsMutation] = field(default_factory=list)
    _results: List[Tuple[DnsPacket, DnsFuzzOutcome]] = field(default_factory=list)

    @staticmethod
    def new(target: Tuple[str, int]) -> "DnsFuzzer":
        return DnsFuzzer(target=target)

    def set_base_name(self, name: str) -> None:
        self.base_name = str(name)

    def set_recv_timeout_ms(self, ms: int) -> None:
        self.recv_timeout_ms = int(ms)

    def add_mutation(self, m: DnsMutation) -> None:
        self.mutations.append(m)

    def run_all(self) -> List[Tuple[DnsPacket, DnsFuzzOutcome]]:
        out = []
        for i, m in enumerate(self.mutations):
            pkt = DnsPacket.new_query(i, DnsQuestion.new(self.base_name, DnsQType.A))
            outcome = DnsFuzzOutcome(response=b"", anomalous=False, note=m.label)
            out.append((pkt, outcome))
        self._results = out
        return out

    def results(self) -> List[Tuple[DnsPacket, DnsFuzzOutcome]]:
        return list(self._results)

    def anomalous_results(self) -> List[Tuple[DnsPacket, DnsFuzzOutcome]]:
        return [r for r in self._results if r[1].is_anomalous()]

    def stats(self) -> DnsFuzzStats:
        return DnsFuzzStats(sent=len(self._results),
                            anomalous=len(self.anomalous_results()))


# ---------------------------------------------------------------------------
# tls_fuzzer.rs
# ---------------------------------------------------------------------------

class TlsVersion:
    SSL30 = 0x0300
    TLS10 = 0x0301
    TLS11 = 0x0302
    TLS12 = 0x0303
    TLS13 = 0x0304

    @staticmethod
    def name(v: int) -> str:
        return {0x0300: "SSL3.0", 0x0301: "TLS1.0", 0x0302: "TLS1.1",
                0x0303: "TLS1.2", 0x0304: "TLS1.3"}.get(int(v), "unknown")


@dataclass
class TlsExtension:
    ext_type: int
    data: bytes

    @staticmethod
    def new(ext_type: int, data: bytes) -> "TlsExtension":
        return TlsExtension(ext_type=int(ext_type), data=bytes(data))

    def serialize(self) -> bytes:
        return struct.pack(">HH", self.ext_type, len(self.data)) + self.data

    @staticmethod
    def server_name(hostname: str) -> "TlsExtension":
        hb = hostname.encode("ascii")
        sn = struct.pack(">B", 0) + struct.pack(">H", len(hb)) + hb
        list_ = struct.pack(">H", len(sn)) + sn
        return TlsExtension.new(0, list_)

    @staticmethod
    def alpn(protocols: List[str]) -> "TlsExtension":
        body = bytearray()
        for p in protocols:
            pb = p.encode("ascii")
            body += struct.pack(">B", len(pb)) + pb
        return TlsExtension.new(16, struct.pack(">H", len(body)) + bytes(body))

    @staticmethod
    def supported_versions(versions: List[int]) -> "TlsExtension":
        body = bytearray()
        body.append(2 * len(versions))
        for v in versions:
            body += struct.pack(">H", v)
        return TlsExtension.new(43, bytes(body))


@dataclass
class ClientHelloBuilder:
    legacy_v: int = TlsVersion.TLS12
    random_: bytes = b"\x00" * 32
    session: bytes = b""
    ciphers: List[int] = field(default_factory=lambda: [0x1301, 0x1302])
    compressions: List[int] = field(default_factory=lambda: [0])
    extensions: List[TlsExtension] = field(default_factory=list)

    @staticmethod
    def new() -> "ClientHelloBuilder":
        return ClientHelloBuilder()

    @staticmethod
    def default() -> "ClientHelloBuilder":
        return ClientHelloBuilder.new()

    def legacy_version(self, v: int) -> "ClientHelloBuilder":
        self.legacy_v = int(v)
        return self

    def random(self, r: bytes) -> "ClientHelloBuilder":
        if len(r) != 32:
            raise FuzzNetError("random must be 32 bytes")
        self.random_ = bytes(r)
        return self

    def session_id(self, id_: bytes) -> "ClientHelloBuilder":
        self.session = bytes(id_)
        return self

    def cipher_suites(self, cs: List[int]) -> "ClientHelloBuilder":
        self.ciphers = list(cs)
        return self

    def compression_methods(self, cm: List[int]) -> "ClientHelloBuilder":
        self.compressions = list(cm)
        return self

    def add_extension(self, ext: TlsExtension) -> "ClientHelloBuilder":
        self.extensions.append(ext)
        return self

    def build_payload(self) -> bytes:
        out = bytearray()
        out += struct.pack(">H", self.legacy_v)
        out += self.random_
        out.append(len(self.session))
        out += self.session
        out += struct.pack(">H", 2 * len(self.ciphers))
        for c in self.ciphers:
            out += struct.pack(">H", c)
        out.append(len(self.compressions))
        for c in self.compressions:
            out.append(c & 0xFF)
        ext_body = b"".join(e.serialize() for e in self.extensions)
        out += struct.pack(">H", len(ext_body))
        out += ext_body
        return bytes(out)

    def build_record(self) -> bytes:
        payload = self.build_payload()
        return build_handshake_record(1, payload, TlsVersion.TLS10)


def build_handshake_record(msg_type: int, body: bytes, version: int) -> bytes:
    hs = struct.pack(">B", msg_type) + struct.pack(">I", len(body))[1:] + bytes(body)
    return struct.pack(">B", 22) + struct.pack(">H", version) + struct.pack(">H", len(hs)) + hs


def fragment_record(record: bytes, fragment_size: int) -> List[bytes]:
    if fragment_size <= 0:
        return [bytes(record)]
    return [bytes(record[i:i + fragment_size]) for i in range(0, len(record), fragment_size)]


@dataclass
class MutatedRecord:
    label: str
    record: bytes


@dataclass
class TlsFuzzStrategy:
    label: str
    op: str  # "fragment", "version_confusion", "duplicate"

    def apply(self, base: bytes) -> List[MutatedRecord]:
        if self.op == "fragment":
            return [MutatedRecord(self.label, b"".join(fragment_record(base, 8)))]
        if self.op == "version_confusion":
            return [MutatedRecord(self.label, tls_version_confusion(base))]
        if self.op == "duplicate":
            return [MutatedRecord(self.label, bytes(base) + bytes(base))]
        return [MutatedRecord(self.label, bytes(base))]


@dataclass
class TlsFuzzResult:
    response: bytes
    anomalous: bool = False

    def is_anomalous(self) -> bool:
        return self.anomalous


@dataclass
class TlsFuzzer:
    target: Tuple[str, int]
    strategies: List[TlsFuzzStrategy] = field(default_factory=list)
    _results: List[Tuple[str, TlsFuzzResult]] = field(default_factory=list)

    @staticmethod
    def new(target: Tuple[str, int]) -> "TlsFuzzer":
        return TlsFuzzer(target=target)

    def add_strategy(self, s: TlsFuzzStrategy) -> None:
        self.strategies.append(s)

    def run_all(self) -> List[Tuple[str, TlsFuzzResult]]:
        base = ClientHelloBuilder.default().build_record()
        out = []
        for s in self.strategies:
            for mr in s.apply(base):
                out.append((mr.label, TlsFuzzResult(response=b"", anomalous=False)))
        self._results = out
        return out

    def results(self) -> List[Tuple[str, TlsFuzzResult]]:
        return list(self._results)

    def anomalous_results(self) -> List[Tuple[str, TlsFuzzResult]]:
        return [r for r in self._results if r[1].is_anomalous()]


# ---------------------------------------------------------------------------
# replay_engine.rs
# ---------------------------------------------------------------------------

@dataclass
class PacketSpec:
    payload: bytes
    label_: str = ""
    response: Optional[bytes] = None

    @staticmethod
    def new(payload: bytes) -> "PacketSpec":
        return PacketSpec(payload=bytes(payload))

    def with_label(self, label: str) -> "PacketSpec":
        self.label_ = str(label)
        return self

    def has_response(self) -> bool:
        return self.response is not None

    def response_str(self) -> str:
        return self.response.decode("utf-8", errors="replace") if self.response else ""


@dataclass
class ReplayStats:
    sessions: int = 0
    successes: int = 0
    failures: int = 0


@dataclass
class RPSession:
    name: str
    target: Tuple[str, int]
    protocol: str
    packets: List[PacketSpec] = field(default_factory=list)
    _successes: int = 0
    _failures: int = 0
    _responses: List[bytes] = field(default_factory=list)
    _rtts: List[int] = field(default_factory=list)

    @staticmethod
    def tcp(name: str, target: Tuple[str, int]) -> "RPSession":
        return RPSession(name=str(name), target=target, protocol="tcp")

    @staticmethod
    def udp(name: str, target: Tuple[str, int]) -> "RPSession":
        return RPSession(name=str(name), target=target, protocol="udp")

    def add_packet(self, spec: PacketSpec) -> None:
        self.packets.append(spec)

    def success_count(self) -> int:
        return self._successes

    def failure_count(self) -> int:
        return self._failures

    def all_responses(self) -> List[bytes]:
        return list(self._responses)

    def mean_rtt_us(self) -> int:
        return sum(self._rtts) // len(self._rtts) if self._rtts else 0

    def run_tcp(self) -> None:
        for _p in self.packets:
            self._successes += 1
            self._responses.append(b"")
            self._rtts.append(0)

    def run_udp(self) -> None:
        self.run_tcp()


@dataclass
class ReplayEngine:
    sessions: List[RPSession] = field(default_factory=list)

    @staticmethod
    def new() -> "ReplayEngine":
        return ReplayEngine()

    def add_session(self, session: RPSession) -> None:
        self.sessions.append(session)

    def session_count(self) -> int:
        return len(self.sessions)

    def run_all(self) -> int:
        for s in self.sessions:
            if s.protocol == "tcp":
                s.run_tcp()
            else:
                s.run_udp()
        return len(self.sessions)

    def run_one(self, index: int) -> None:
        if 0 <= index < len(self.sessions):
            s = self.sessions[index]
            if s.protocol == "tcp":
                s.run_tcp()
            else:
                s.run_udp()
        else:
            raise ReplayError("index out of range")

    def aggregate_stats(self) -> ReplayStats:
        st = ReplayStats(sessions=len(self.sessions))
        for s in self.sessions:
            st.successes += s.success_count()
            st.failures += s.failure_count()
        return st


def replay_sequence(packets: List[PacketSpec], target: Tuple[str, int], protocol: str = "tcp") -> ReplayStats:
    eng = ReplayEngine.new()
    sess = RPSession.tcp("seq", target) if protocol == "tcp" else RPSession.udp("seq", target)
    for p in packets:
        sess.add_packet(p)
    eng.add_session(sess)
    eng.run_all()
    return eng.aggregate_stats()


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    rng = random.Random(0)
    msg = (MessageBuilder.new("hello")
           .static_bytes("magic", b"HI")
           .fuzz_u8("ver", 1)
           .fuzz_blob("body", b"abcd")
           .size_of("len", "body")
           .build())
    assert msg.serialise().startswith(b"HI")
    assert msg.fuzz_field_count() == 2
    msg.mutate(rng)

    proto = (ProtocolBuilder.new("s0")
             .add_transition("s0", "s1", "go")
             .add_terminal("s1")
             .build())
    assert proto.state_count() >= 2
    assert proto.validate() == []

    frame = frame_u32_le(b"abc")
    assert decode_frame_u32_le(frame) == (3, b"abc")
    assert xor_checksum(b"\x01\x02\x03") == 0
    assert add_checksum(b"\x01\x02\x03") == 6

    cov = CoverageBitmap.new()
    cov.bits[0] = 5
    virgin = CoverageBitmap.new()
    assert cov.has_new_bits(virgin)
    print("rustre-fuzz-net validator: OK")
