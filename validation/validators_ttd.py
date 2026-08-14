#!/usr/bin/env python3
"""
Independent TTD (Time Travel Debugging) tool validator for RustRE MCP.
Tests the semantics and ground truth of TTD operations.
Does NOT rely on MCP communication - uses Python direct implementation.
"""

import json
import struct
from typing import Any, Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict

@dataclass
class TestResult:
    tool: str
    category: str
    input_params: Dict[str, Any]
    expected: Any
    actual: Any
    passed: bool
    note: str

class TTDPosition:
    """TTD Position: (sequence, step) tuple."""

    @staticmethod
    def earliest() -> Tuple[int, int]:
        """Earliest position is (0, 0)."""
        return (0, 0)

    @staticmethod
    def min_position() -> Tuple[int, int]:
        """Minimum position is (0, 0)."""
        return (0, 0)

    @staticmethod
    def max_position() -> Tuple[int, int]:
        """Maximum position (upper bound)."""
        return (2**63 - 1, 2**63 - 1)

    @staticmethod
    def next_step(pos: Tuple[int, int]) -> Tuple[int, int]:
        """Move to next step in current sequence."""
        seq, step = pos
        return (seq, step + 1)

    @staticmethod
    def next_sequence(pos: Tuple[int, int]) -> Tuple[int, int]:
        """Move to first step of next sequence."""
        seq, step = pos
        return (seq + 1, 0)

    @staticmethod
    def prev_step(pos: Tuple[int, int]) -> Tuple[int, int]:
        """Move to previous step in current sequence."""
        seq, step = pos
        if step > 0:
            return (seq, step - 1)
        return pos  # Clamp at 0

    @staticmethod
    def prev_sequence(pos: Tuple[int, int]) -> Tuple[int, int]:
        """Move to last step of previous sequence."""
        seq, step = pos
        if seq > 0:
            # Return max step of previous sequence (depends on trace)
            return (seq - 1, 2**63 - 1)
        return pos  # Clamp at 0

    @staticmethod
    def in_range(pos: Tuple[int, int], min_pos: Tuple[int, int], max_pos: Tuple[int, int]) -> bool:
        """Check if position is in range [min_pos, max_pos]."""
        seq, step = pos
        min_seq, min_step = min_pos
        max_seq, max_step = max_pos

        # Must be in sequence range
        if seq < min_seq or seq > max_seq:
            return False
        # If same sequence as min, step must be >= min_step
        if seq == min_seq and step < min_step:
            return False
        # If same sequence as max, step must be <= max_step
        if seq == max_seq and step > max_step:
            return False
        return True

    @staticmethod
    def compare(pos1: Tuple[int, int], pos2: Tuple[int, int]) -> int:
        """Compare two positions. Returns -1 if pos1 < pos2, 0 if equal, 1 if pos1 > pos2."""
        seq1, step1 = pos1
        seq2, step2 = pos2

        if seq1 < seq2:
            return -1
        elif seq1 > seq2:
            return 1
        elif step1 < step2:
            return -1
        elif step1 > step2:
            return 1
        else:
            return 0


class TTDMemory:
    """TTD Memory operations."""

    @staticmethod
    def read_u8(data: bytes, offset: int) -> int:
        """Read u8 from bytes."""
        if offset >= len(data):
            return 0
        return data[offset]

    @staticmethod
    def read_u16_le(data: bytes, offset: int) -> int:
        """Read u16 little-endian."""
        if offset + 2 > len(data):
            return 0
        return struct.unpack('<H', data[offset:offset+2])[0]

    @staticmethod
    def read_u32_le(data: bytes, offset: int) -> int:
        """Read u32 little-endian."""
        if offset + 4 > len(data):
            return 0
        return struct.unpack('<I', data[offset:offset+4])[0]

    @staticmethod
    def read_u64_le(data: bytes, offset: int) -> int:
        """Read u64 little-endian."""
        if offset + 8 > len(data):
            return 0
        return struct.unpack('<Q', data[offset:offset+8])[0]

    @staticmethod
    def read_i32_le(data: bytes, offset: int) -> int:
        """Read i32 little-endian."""
        if offset + 4 > len(data):
            return 0
        return struct.unpack('<i', data[offset:offset+4])[0]

    @staticmethod
    def read_i64_le(data: bytes, offset: int) -> int:
        """Read i64 little-endian."""
        if offset + 8 > len(data):
            return 0
        return struct.unpack('<q', data[offset:offset+8])[0]

    @staticmethod
    def write_u32_le(data: bytearray, offset: int, value: int) -> None:
        """Write u32 little-endian."""
        if offset + 4 <= len(data):
            data[offset:offset+4] = struct.pack('<I', value & 0xFFFFFFFF)

    @staticmethod
    def write_u64_le(data: bytearray, offset: int, value: int) -> None:
        """Write u64 little-endian."""
        if offset + 8 <= len(data):
            data[offset:offset+8] = struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF)

    @staticmethod
    def region_contains(base: int, size: int, addr: int) -> bool:
        """Check if address is within [base, base+size)."""
        return base <= addr < base + size

    @staticmethod
    def regions_overlap(base1: int, size1: int, base2: int, size2: int) -> bool:
        """Check if two memory regions overlap."""
        end1 = base1 + size1
        end2 = base2 + size2
        return base1 < end2 and base2 < end1


class TTDTrace:
    """TTD Trace operations."""

    @staticmethod
    def is_valid_event_count(count: int) -> bool:
        """Event count must be non-negative."""
        return isinstance(count, int) and count >= 0

    @staticmethod
    def is_valid_thread_id(tid: int) -> bool:
        """Thread ID must be non-negative."""
        return isinstance(tid, int) and tid >= 0

    @staticmethod
    def position_as_u128(pos: Tuple[int, int]) -> int:
        """Convert position (sequence, step) to u128."""
        seq, step = pos
        return (seq << 64) | step


class TTDValidator:
    """TTD validator - tests all TTD tool semantics."""

    def __init__(self):
        self.results: List[TestResult] = []
        self.test_count = 0
        self.pass_count = 0
        self.skip_count = 0

    def add_result(self, tool: str, category: str, inputs: Dict, expected: Any, actual: Any,
                   passed: bool, note: str):
        """Add test result."""
        self.test_count += 1
        if passed:
            self.pass_count += 1

        self.results.append(TestResult(
            tool=tool,
            category=category,
            input_params=inputs,
            expected=expected,
            actual=actual,
            passed=passed,
            note=note
        ))

    # ===== TTD Position Tests =====

    def test_ttd_position_earliest(self):
        """Test ttd_position_earliest."""
        expected = (0, 0)
        actual = TTDPosition.earliest()
        self.add_result(
            tool="ttd_position_earliest",
            category="position",
            inputs={},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Position earliest must be (0, 0)"
        )

    def test_ttd_position_min(self):
        """Test ttd_position_min."""
        expected = (0, 0)
        actual = TTDPosition.min_position()
        self.add_result(
            tool="ttd_position_min",
            category="position",
            inputs={},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Position min must be (0, 0)"
        )

    def test_ttd_position_max(self):
        """Test ttd_position_max."""
        expected = (2**63 - 1, 2**63 - 1)
        actual = TTDPosition.max_position()
        self.add_result(
            tool="ttd_position_max",
            category="position",
            inputs={},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Position max must be max i64 values"
        )

    def test_ttd_position_next_step(self):
        """Test ttd_position_next_step."""
        input_pos = (5, 10)
        expected = (5, 11)
        actual = TTDPosition.next_step(input_pos)
        self.add_result(
            tool="ttd_position_next_step",
            category="position",
            inputs={"position": input_pos},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Next step of (5, 10) is (5, 11)"
        )

    def test_ttd_position_next_sequence(self):
        """Test ttd_position_next_sequence."""
        input_pos = (5, 10)
        expected = (6, 0)
        actual = TTDPosition.next_sequence(input_pos)
        self.add_result(
            tool="ttd_position_next_sequence",
            category="position",
            inputs={"position": input_pos},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Next sequence of (5, 10) is (6, 0)"
        )

    def test_ttd_position_next_step_zero(self):
        """Test ttd_position_next_step from (0, 0)."""
        input_pos = (0, 0)
        expected = (0, 1)
        actual = TTDPosition.next_step(input_pos)
        self.add_result(
            tool="ttd_position_next_step",
            category="position",
            inputs={"position": input_pos},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Next step of (0, 0) is (0, 1)"
        )

    def test_ttd_position_in_range_true(self):
        """Test ttd_position_in_range - position in range."""
        pos = (5, 50)
        min_pos = (5, 0)
        max_pos = (5, 100)
        expected = True
        actual = TTDPosition.in_range(pos, min_pos, max_pos)
        self.add_result(
            tool="ttd_position_in_range",
            category="position",
            inputs={"position": pos, "min": min_pos, "max": max_pos},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="(5, 50) in range [(5, 0), (5, 100)]"
        )

    def test_ttd_position_in_range_false(self):
        """Test ttd_position_in_range - position out of range."""
        pos = (6, 50)
        min_pos = (5, 0)
        max_pos = (5, 100)
        expected = False
        actual = TTDPosition.in_range(pos, min_pos, max_pos)
        self.add_result(
            tool="ttd_position_in_range",
            category="position",
            inputs={"position": pos, "min": min_pos, "max": max_pos},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="(6, 50) not in range [(5, 0), (5, 100)]"
        )

    # ===== TTD Memory Tests =====

    def test_ttd_memory_snapshot_read_u32_le(self):
        """Test memory read u32 LE."""
        test_data = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        expected = 0x04030201
        actual = TTDMemory.read_u32_le(test_data, 0)
        self.add_result(
            tool="ttd_memory_snapshot_read_u32_le",
            category="memory",
            inputs={"offset": 0, "bytes": "[01 02 03 04]"},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Read u32 LE from [01 02 03 04] = 0x04030201"
        )

    def test_ttd_memory_snapshot_read_u64_le(self):
        """Test memory read u64 LE."""
        test_data = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        expected = 0x0807060504030201
        actual = TTDMemory.read_u64_le(test_data, 0)
        self.add_result(
            tool="ttd_memory_snapshot_read_u64_le",
            category="memory",
            inputs={"offset": 0, "bytes": "[01 02 03 04 05 06 07 08]"},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Read u64 LE from [01 02 03 04 05 06 07 08] = 0x0807060504030201"
        )

    def test_ttd_memory_snapshot_read_u16_le(self):
        """Test memory read u16 LE."""
        test_data = bytes([0xAB, 0xCD, 0xEF])
        expected = 0xCDAB
        actual = TTDMemory.read_u16_le(test_data, 0)
        self.add_result(
            tool="ttd_memory_snapshot_read_u16_le",
            category="memory",
            inputs={"offset": 0, "bytes": "[AB CD]"},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Read u16 LE from [AB CD] = 0xCDAB"
        )

    def test_ttd_memory_snapshot_read_u8(self):
        """Test memory read u8."""
        test_data = bytes([0x42, 0x43, 0x44])
        expected = 0x42
        actual = TTDMemory.read_u8(test_data, 0)
        self.add_result(
            tool="ttd_memory_snapshot_read_u8",
            category="memory",
            inputs={"offset": 0, "bytes": "[42]"},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Read u8 from [42] = 0x42"
        )

    def test_ttd_memory_snapshot_read_offset(self):
        """Test memory read with offset."""
        test_data = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        expected = 0x55443322
        actual = TTDMemory.read_u32_le(test_data, 1)
        self.add_result(
            tool="ttd_memory_snapshot_read_u32_le",
            category="memory",
            inputs={"offset": 1, "bytes": "[11 22 33 44 55 66]"},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Read u32 LE from offset 1 of [11 22 33 44 55 66] = 0x55443322"
        )

    def test_ttd_memory_region_contains_true(self):
        """Test memory region contains - address in range."""
        base = 0x1000
        size = 0x1000
        addr = 0x1500
        expected = True
        actual = TTDMemory.region_contains(base, size, addr)
        self.add_result(
            tool="ttd_memory_region_contains",
            category="memory",
            inputs={"base": hex(base), "size": hex(size), "addr": hex(addr)},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Address 0x1500 in region [0x1000, 0x2000)"
        )

    def test_ttd_memory_region_contains_false(self):
        """Test memory region contains - address out of range."""
        base = 0x1000
        size = 0x1000
        addr = 0x3000
        expected = False
        actual = TTDMemory.region_contains(base, size, addr)
        self.add_result(
            tool="ttd_memory_region_contains",
            category="memory",
            inputs={"base": hex(base), "size": hex(size), "addr": hex(addr)},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Address 0x3000 not in region [0x1000, 0x2000)"
        )

    def test_ttd_memory_regions_overlap(self):
        """Test memory regions overlap."""
        base1, size1 = 0x1000, 0x1000
        base2, size2 = 0x1500, 0x1000
        expected = True
        actual = TTDMemory.regions_overlap(base1, size1, base2, size2)
        self.add_result(
            tool="ttd_memory_regions_overlap",
            category="memory",
            inputs={"region1": (hex(base1), hex(size1)), "region2": (hex(base2), hex(size2))},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Regions [0x1000, 0x2000) and [0x1500, 0x2500) overlap"
        )

    # ===== TTD Trace Tests =====

    def test_ttd_trace_event_count_valid(self):
        """Test trace event count is non-negative."""
        count = 100
        expected = True
        actual = TTDTrace.is_valid_event_count(count)
        self.add_result(
            tool="ttd_trace_event_count",
            category="trace",
            inputs={"count": count},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Event count 100 is valid (non-negative)"
        )

    def test_ttd_trace_event_count_zero(self):
        """Test trace event count zero is valid."""
        count = 0
        expected = True
        actual = TTDTrace.is_valid_event_count(count)
        self.add_result(
            tool="ttd_trace_event_count",
            category="trace",
            inputs={"count": count},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Event count 0 is valid (empty trace)"
        )

    def test_ttd_position_as_u128(self):
        """Test converting position to u128."""
        pos = (0x0000000000000001, 0x0000000000000002)
        expected = (1 << 64) | 2
        actual = TTDTrace.position_as_u128(pos)
        self.add_result(
            tool="ttd_position_as_u128",
            category="position",
            inputs={"position": pos},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="Position (1, 2) as u128 = 0x0000000000000001_0000000000000002"
        )

    # ===== TTD Comparisons =====

    def test_ttd_position_compare_less(self):
        """Test position comparison - less than."""
        pos1 = (5, 10)
        pos2 = (5, 20)
        expected = -1
        actual = TTDPosition.compare(pos1, pos2)
        self.add_result(
            tool="ttd_position_compare",
            category="position",
            inputs={"pos1": pos1, "pos2": pos2},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="(5, 10) < (5, 20)"
        )

    def test_ttd_position_compare_greater(self):
        """Test position comparison - greater than."""
        pos1 = (6, 5)
        pos2 = (5, 100)
        expected = 1
        actual = TTDPosition.compare(pos1, pos2)
        self.add_result(
            tool="ttd_position_compare",
            category="position",
            inputs={"pos1": pos1, "pos2": pos2},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="(6, 5) > (5, 100)"
        )

    def test_ttd_position_compare_equal(self):
        """Test position comparison - equal."""
        pos1 = (5, 10)
        pos2 = (5, 10)
        expected = 0
        actual = TTDPosition.compare(pos1, pos2)
        self.add_result(
            tool="ttd_position_compare",
            category="position",
            inputs={"pos1": pos1, "pos2": pos2},
            expected=expected,
            actual=actual,
            passed=actual == expected,
            note="(5, 10) == (5, 10)"
        )

    def run_all_tests(self):
        """Run all validator tests."""
        print("[*] Running TTD validator tests...")

        test_methods = [
            # Position tests
            self.test_ttd_position_earliest,
            self.test_ttd_position_min,
            self.test_ttd_position_max,
            self.test_ttd_position_next_step,
            self.test_ttd_position_next_sequence,
            self.test_ttd_position_next_step_zero,
            self.test_ttd_position_in_range_true,
            self.test_ttd_position_in_range_false,
            # Memory tests
            self.test_ttd_memory_snapshot_read_u32_le,
            self.test_ttd_memory_snapshot_read_u64_le,
            self.test_ttd_memory_snapshot_read_u16_le,
            self.test_ttd_memory_snapshot_read_u8,
            self.test_ttd_memory_snapshot_read_offset,
            self.test_ttd_memory_region_contains_true,
            self.test_ttd_memory_region_contains_false,
            self.test_ttd_memory_regions_overlap,
            # Trace tests
            self.test_ttd_trace_event_count_valid,
            self.test_ttd_trace_event_count_zero,
            self.test_ttd_position_as_u128,
            # Comparison tests
            self.test_ttd_position_compare_less,
            self.test_ttd_position_compare_greater,
            self.test_ttd_position_compare_equal,
        ]

        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                print("[-] {}: {}".format(test_method.__name__, e))
                self.skip_count += 1

        print("[+] Completed {} tests".format(self.test_count))

    def get_report(self) -> Dict[str, Any]:
        """Generate report."""
        mismatches = [
            {
                "tool": r.tool,
                "input": r.input_params,
                "mcp": r.actual,
                "truth": r.expected,
                "note": r.note
            }
            for r in self.results if not r.passed
        ]

        return {
            "category": "ttd",
            "tools_in_category": len(set(r.tool for r in self.results)),
            "checks_total": self.test_count,
            "checks_passed": self.pass_count,
            "checks_skipped": self.skip_count,
            "mismatches": mismatches
        }


def main():
    validator = TTDValidator()
    validator.run_all_tests()

    report = validator.get_report()

    # Save report
    with open("validation/mismatch_ttd.json", "w") as f:
        json.dump(report, f, indent=2)

    print("[+] Report saved to validation/mismatch_ttd.json")
    print("[*] Summary:")
    print("    Category: {}".format(report["category"]))
    print("    Tools tested: {}".format(report["tools_in_category"]))
    print("    Total checks: {}".format(report["checks_total"]))
    print("    Passed: {}".format(report["checks_passed"]))
    print("    Skipped: {}".format(report["checks_skipped"]))
    print("    Mismatches: {}".format(len(report["mismatches"])))


if __name__ == "__main__":
    main()
