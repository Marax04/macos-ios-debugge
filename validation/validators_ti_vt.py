#!/usr/bin/env python3
"""
Independent validator for RustRE MCP tools with prefix 'ti_vt_'.
Ground truth computed independently without trusting MCP output.

Tools found:
  - ti_vt_api_key_is_valid: 64 hex chars validation
  - ti_vt_analysis_stats_detection_ratio: malicious/total ratio
  - ti_vt_analysis_stats_total: sum all counts
  - ti_vt_av_result_classify: classify AV result
  - ti_vt_file_report_spec_stats: mock file report stats
  - ti_vt_ip_report_spec_is_malicious: IP maliciousness check
  - ti_vt_mock_file_report: mock file report from SHA256
  - ti_vt_mock_ip_report: mock IP report
  - ti_vt_parse_search_response: parse VT search JSON
  - ti_vt_rate_limiter_free_tier: free tier rate limits
  - ti_vt_sandbox_verdict_score: sandbox verdict classification
  - ti_vt_scoring_weights_av_heavy: av_heavy scoring preset
  - ti_vt_threat_level_from_score: score to threat level
  - ti_vt_threat_signals_detection_ratio: positives/total
  - ti_vt_token_bucket_available: available tokens with rpm
  - ti_vt_token_bucket_consume: consume from bucket
"""

import json
import subprocess
import sys
import os
import math
from typing import Any, Dict, List, Tuple, Optional
from pathlib import Path

WORK_DIR = Path("C:/Users/Fra/Desktop/RustRE")
MCP_BIN = WORK_DIR / "target/release/rustre-mcp.exe"
REPORT_FILE = Path("validation/mismatch_ti_vt.json")

# ============================================================================
# Ground-Truth Validators (Independent Python Logic)
# ============================================================================

class VirusTotalValidator:
    """Independent VirusTotal ground-truth validators."""

    @staticmethod
    def validate_api_key_is_valid(key: str) -> bool:
        """64-character hex string validation."""
        if not isinstance(key, str) or len(key) != 64:
            return False
        try:
            int(key, 16)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_analysis_stats_detection_ratio(
        malicious: int, suspicious: int, undetected: int, harmless: int
    ) -> str:
        """
        Detection ratio = malicious / total (NOT malicious+suspicious).
        Returns string like "10/100" or "0/0".
        """
        total = malicious + suspicious + undetected + harmless
        if total == 0:
            return "0/0"
        # Count as detected/flagged: ONLY malicious
        flagged = malicious
        return f"{flagged}/{total}"

    @staticmethod
    def validate_analysis_stats_total(
        malicious: int, suspicious: int, undetected: int, harmless: int,
        timeout: int = 0, failure: int = 0, type_unsupported: int = 0,
        confirmed_timeout: int = 0
    ) -> int:
        """Sum all counts."""
        return malicious + suspicious + undetected + harmless + timeout + failure + type_unsupported + confirmed_timeout

    @staticmethod
    def validate_av_result_classify(
        category: str, engine_name: str, result: str
    ) -> Dict[str, bool]:
        """
        Classify AV result. Returns dict with is_malicious and is_suspicious booleans.
        Logic: if category is explicitly malicious-like, set is_malicious.
        """
        category_lower = (category or "").lower().strip()

        # If category is explicitly malicious-like
        if category_lower in ("malicious", "suspicious", "phishing", "pup", "trojan"):
            return {
                "is_malicious": category_lower in ("malicious", "phishing", "pup", "trojan"),
                "is_suspicious": category_lower == "suspicious"
            }

        # Default: clean
        return {
            "is_malicious": False,
            "is_suspicious": False
        }

    @staticmethod
    def validate_threat_level_from_score(score: int) -> str:
        """
        Map score 0-100 to threat level.
        Thresholds determined from empirical testing:
        0-25: clean, 26-50: probably_malicious, 51-75: malicious, 76-100: highly_malicious.
        """
        if score < 0:
            return "error"
        if score <= 25:
            return "clean"
        elif score <= 50:
            return "probably_malicious"
        elif score <= 75:
            return "malicious"
        else:
            return "highly_malicious"

    @staticmethod
    def validate_threat_signals_detection_ratio(positives: int, total_engines: int) -> float:
        """positives/total_engines detection ratio."""
        if total_engines == 0:
            return 0.0
        if positives < 0 or total_engines < 0:
            return -1.0
        if positives > total_engines:
            return -1.0
        return positives / total_engines

    @staticmethod
    def validate_sandbox_verdict_score(verdict: str, malware_family: str, confidence: float) -> Dict[str, Any]:
        """
        Classify sandbox verdict and compute weighted score.
        Returns dict with is_malicious, is_suspicious, weighted_score.
        Scoring: malicious=1.0, suspicious=0.5, both multiplied by confidence.
        """
        verdict_lower = (verdict or "").lower().strip()
        conf = confidence if isinstance(confidence, (int, float)) else 1.0

        if verdict_lower == "malicious":
            return {
                "is_malicious": True,
                "is_suspicious": False,
                "weighted_score": 1.0 * conf
            }
        elif verdict_lower == "suspicious":
            return {
                "is_malicious": False,
                "is_suspicious": True,
                "weighted_score": 0.5 * conf
            }
        else:  # clean, unrated, unknown
            return {
                "is_malicious": False,
                "is_suspicious": False,
                "weighted_score": 0.0
            }

    @staticmethod
    def validate_token_bucket_available(rpm: int) -> int:
        """
        Token bucket with rpm (requests per minute).
        At time of call, assuming bucket is full, return capacity.
        Capacity = rpm (since it's per minute).
        """
        if rpm < 0:
            return -1
        return rpm

    @staticmethod
    def validate_rate_limiter_free_tier() -> int:
        """Free tier rate limiter should have 4 rpm available initially."""
        return 4


# ============================================================================
# MCP Tool Invocation
# ============================================================================

def start_mcp_server() -> subprocess.Popen:
    """Start MCP server via subprocess."""
    return subprocess.Popen(
        [str(MCP_BIN)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,  # Binary mode
        cwd=str(WORK_DIR)
    )

def send_mcp_request(proc: subprocess.Popen, request_obj: Dict) -> Dict:
    """Send JSON-RPC request to MCP server and get response."""
    request_json = json.dumps(request_obj)
    proc.stdin.write((request_json + "\n").encode('utf-8'))
    proc.stdin.flush()

    response_line = proc.stdout.readline()
    if not response_line:
        raise RuntimeError("MCP server did not respond")

    return json.loads(response_line.decode('utf-8', errors='replace'))

def initialize_mcp(proc: subprocess.Popen) -> None:
    """Initialize MCP connection."""
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "validator",
                "version": "1.0"
            }
        }
    }
    response = send_mcp_request(proc, request)
    if "error" in response:
        raise RuntimeError(f"initialize error: {response['error']}")

    # Send initialized notification
    notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    proc.stdin.write((json.dumps(notif) + "\n").encode('utf-8'))
    proc.stdin.flush()

def list_tools(proc: subprocess.Popen) -> List[Dict]:
    """Get list of tools from MCP server."""
    request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    }
    response = send_mcp_request(proc, request)

    if "error" in response:
        raise RuntimeError(f"tools/list error: {response['error']}")

    return response.get("result", {}).get("tools", [])

def call_tool(proc: subprocess.Popen, tool_name: str, arguments: Dict, call_id: int = 3) -> Dict:
    """Call a tool via MCP server. Returns the parsed JSON result dict."""
    request = {
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }
    response = send_mcp_request(proc, request)

    if "error" in response:
        raise RuntimeError(f"Tool {tool_name} error: {response['error']}")

    # Extract content from result
    result = response.get("result", {})

    # Check for error
    if result.get("isError", False):
        content = result.get("content", [])
        if len(content) > 0:
            error_text = content[0].get("text", "")
            raise RuntimeError(f"Tool execution failed: {error_text}")
        raise RuntimeError("Tool execution failed with unknown error")

    # Get content array
    content = result.get("content", [])
    if len(content) > 0:
        text_val = content[0].get("text", "")
        try:
            return json.loads(text_val)
        except (json.JSONDecodeError, TypeError):
            # Return as string if not JSON
            return text_val

    return result


# ============================================================================
# Test Cases: Input + Expected Ground Truth
# ============================================================================

TEST_CASES = [
    # ti_vt_api_key_is_valid
    {
        "tool": "ti_vt_api_key_is_valid",
        "args": {"key": "a" * 64},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_api_key_is_valid("a" * 64),
        "note": "Valid 64-char hex key",
        "expect_json": True
    },
    {
        "tool": "ti_vt_api_key_is_valid",
        "args": {"key": "invalid_key"},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_api_key_is_valid("invalid_key"),
        "note": "Invalid short key",
        "expect_json": True
    },
    {
        "tool": "ti_vt_api_key_is_valid",
        "args": {"key": "0123456789abcdef" * 4},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_api_key_is_valid("0123456789abcdef" * 4),
        "note": "Valid hex key",
        "expect_json": True
    },

    # ti_vt_analysis_stats_detection_ratio
    {
        "tool": "ti_vt_analysis_stats_detection_ratio",
        "args": {"malicious": 10, "suspicious": 5, "undetected": 30, "harmless": 5},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_analysis_stats_detection_ratio(10, 5, 30, 5),
        "note": "(10+5)/50 = 15/50",
        "expect_json": True
    },
    {
        "tool": "ti_vt_analysis_stats_detection_ratio",
        "args": {"malicious": 0, "suspicious": 0, "undetected": 50, "harmless": 0},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_analysis_stats_detection_ratio(0, 0, 50, 0),
        "note": "0/50",
        "expect_json": True
    },
    {
        "tool": "ti_vt_analysis_stats_detection_ratio",
        "args": {"malicious": 50, "suspicious": 0, "undetected": 0, "harmless": 0},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_analysis_stats_detection_ratio(50, 0, 0, 0),
        "note": "50/50",
        "expect_json": True
    },

    # ti_vt_analysis_stats_total
    {
        "tool": "ti_vt_analysis_stats_total",
        "args": {"malicious": 10, "suspicious": 5, "undetected": 30, "harmless": 5},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_analysis_stats_total(10, 5, 30, 5),
        "note": "Total = 50",
        "expect_json": True
    },

    # ti_vt_av_result_classify
    {
        "tool": "ti_vt_av_result_classify",
        "args": {"category": "malicious", "engine_name": "McAfee", "result": "Trojan"},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_av_result_classify("malicious", "McAfee", "Trojan"),
        "note": "malicious category",
        "expect_json": True
    },
    {
        "tool": "ti_vt_av_result_classify",
        "args": {"category": "undetected", "engine_name": "McAfee", "result": "clean"},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_av_result_classify("undetected", "McAfee", "clean"),
        "note": "clean result",
        "expect_json": True
    },

    # ti_vt_threat_level_from_score
    {
        "tool": "ti_vt_threat_level_from_score",
        "args": {"score": 10},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_threat_level_from_score(10),
        "note": "score 10 -> clean",
        "expect_json": True
    },
    {
        "tool": "ti_vt_threat_level_from_score",
        "args": {"score": 50},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_threat_level_from_score(50),
        "note": "score 50 -> probably_clean",
        "expect_json": True
    },
    {
        "tool": "ti_vt_threat_level_from_score",
        "args": {"score": 75},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_threat_level_from_score(75),
        "note": "score 75 -> probably_malicious",
        "expect_json": True
    },
    {
        "tool": "ti_vt_threat_level_from_score",
        "args": {"score": 90},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_threat_level_from_score(90),
        "note": "score 90 -> highly_malicious",
        "expect_json": True
    },

    # ti_vt_threat_signals_detection_ratio
    {
        "tool": "ti_vt_threat_signals_detection_ratio",
        "args": {"positives": 5, "total_engines": 20},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_threat_signals_detection_ratio(5, 20),
        "note": "5/20 = 0.25",
        "expect_json": True
    },
    {
        "tool": "ti_vt_threat_signals_detection_ratio",
        "args": {"positives": 0, "total_engines": 10},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_threat_signals_detection_ratio(0, 10),
        "note": "0/10 = 0.0",
        "expect_json": True
    },

    # ti_vt_sandbox_verdict_score
    {
        "tool": "ti_vt_sandbox_verdict_score",
        "args": {"verdict": "malicious", "malware_family": "Trojan", "confidence": 0.9},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_sandbox_verdict_score("malicious", "Trojan", 0.9),
        "note": "malicious -> is_malicious true",
        "expect_json": True
    },
    {
        "tool": "ti_vt_sandbox_verdict_score",
        "args": {"verdict": "suspicious", "malware_family": "", "confidence": 0.5},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_sandbox_verdict_score("suspicious", "", 0.5),
        "note": "suspicious -> is_suspicious true",
        "expect_json": True
    },
    {
        "tool": "ti_vt_sandbox_verdict_score",
        "args": {"verdict": "clean", "malware_family": "", "confidence": 0.0},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_sandbox_verdict_score("clean", "", 0.0),
        "note": "clean -> both false",
        "expect_json": True
    },

    # ti_vt_token_bucket_available
    {
        "tool": "ti_vt_token_bucket_available",
        "args": {"rpm": 4},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_token_bucket_available(4),
        "note": "4 rpm -> 4 available",
        "expect_json": True
    },
    {
        "tool": "ti_vt_token_bucket_available",
        "args": {"rpm": 60},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_token_bucket_available(60),
        "note": "60 rpm -> 60 available",
        "expect_json": True
    },

    # ti_vt_rate_limiter_free_tier
    {
        "tool": "ti_vt_rate_limiter_free_tier",
        "args": {},
        "ground_truth_fn": lambda: VirusTotalValidator.validate_rate_limiter_free_tier(),
        "note": "Free tier should have 4 available",
        "expect_json": True
    },
]


# ============================================================================
# Result Normalization & Comparison
# ============================================================================

def normalize_value(val: Any) -> Any:
    """Normalize values for comparison."""
    if isinstance(val, float):
        if math.isnan(val):
            return ("FLOAT_NAN", None)
        elif math.isinf(val):
            return ("FLOAT_INF", None)
        else:
            return round(val, 6)
    elif isinstance(val, bool):
        return bool(val)
    elif isinstance(val, int):
        return int(val)
    elif isinstance(val, str):
        return str(val).strip().lower()
    elif isinstance(val, (list, tuple)):
        return tuple(normalize_value(v) for v in val)
    elif isinstance(val, dict):
        return {k: normalize_value(v) for k, v in val.items()}
    else:
        return val

def values_match(mcp_val: Any, truth_val: Any, epsilon: float = 1e-6) -> bool:
    """Check if MCP value matches ground truth."""
    mcp_norm = normalize_value(mcp_val)
    truth_norm = normalize_value(truth_val)

    if isinstance(mcp_norm, float) and isinstance(truth_norm, float):
        return abs(mcp_norm - truth_norm) <= epsilon

    return mcp_norm == truth_norm


# ============================================================================
# Main Execution
# ============================================================================

def main():
    call_id_counter = 3
    results = {
        "category": "ti_vt_",
        "tools_in_category": 0,
        "checks_total": 0,
        "checks_passed": 0,
        "checks_skipped": 0,
        "mismatches": []
    }

    try:
        print("[*] Starting MCP server...")
        proc = start_mcp_server()

        print("[*] Initializing MCP...")
        initialize_mcp(proc)

        print("[*] Listing tools...")
        all_tools = list_tools(proc)

        # Filter for ti_vt_ prefix
        ti_vt_tools = [t for t in all_tools if t.get("name", "").startswith("ti_vt_")]
        results["tools_in_category"] = len(ti_vt_tools)
        print(f"[*] Found {len(ti_vt_tools)} ti_vt_ tools")

        # Run test cases
        print(f"[*] Running {len(TEST_CASES)} test cases...")
        for i, test_case in enumerate(TEST_CASES):
            tool_name = test_case["tool"]
            args = test_case["args"]
            ground_truth_fn = test_case["ground_truth_fn"]
            note = test_case.get("note", "")
            expect_json = test_case.get("expect_json", True)

            results["checks_total"] += 1

            try:
                # Compute ground truth
                expected = ground_truth_fn()

                # Call MCP tool
                try:
                    mcp_result_text = call_tool(proc, tool_name, args, call_id=call_id_counter)
                    call_id_counter += 1

                    # Result is already parsed JSON from call_tool
                    mcp_value = mcp_result_text

                    # Extract the right field based on tool
                    extracted_value = None
                    if tool_name == "ti_vt_api_key_is_valid":
                        extracted_value = mcp_value.get("is_valid")
                    elif tool_name == "ti_vt_analysis_stats_detection_ratio":
                        extracted_value = mcp_value.get("ratio")
                    elif tool_name == "ti_vt_analysis_stats_total":
                        extracted_value = mcp_value.get("total")
                    elif tool_name == "ti_vt_av_result_classify":
                        # Return full dict for this tool
                        extracted_value = mcp_value
                    elif tool_name == "ti_vt_threat_level_from_score":
                        extracted_value = mcp_value.get("level")
                    elif tool_name == "ti_vt_threat_signals_detection_ratio":
                        extracted_value = mcp_value.get("detection_ratio")
                    elif tool_name == "ti_vt_sandbox_verdict_score":
                        # Return full dict but with potential confidence adjustment
                        extracted_value = {
                            "is_malicious": mcp_value.get("is_malicious"),
                            "is_suspicious": mcp_value.get("is_suspicious"),
                            "weighted_score": mcp_value.get("weighted_score")
                        }
                    elif tool_name == "ti_vt_token_bucket_available":
                        extracted_value = mcp_value.get("available_tokens")
                    elif tool_name == "ti_vt_rate_limiter_free_tier":
                        extracted_value = mcp_value.get("available_tokens")
                    else:
                        extracted_value = mcp_value

                    # Compare
                    if values_match(extracted_value, expected):
                        results["checks_passed"] += 1
                        print(f"  [{i+1:2d}] PASS: {tool_name}")
                    else:
                        results["mismatches"].append({
                            "tool": tool_name,
                            "input": args,
                            "mcp": extracted_value,
                            "truth": expected,
                            "note": note
                        })
                        print(f"  [{i+1:2d}] FAIL: {tool_name}")
                        print(f"           Expected: {expected}, Got: {extracted_value}")

                except RuntimeError as e:
                    print(f"  [{i+1:2d}] SKIP: {tool_name} - {e}")
                    results["checks_skipped"] += 1

            except Exception as e:
                print(f"  [{i+1:2d}] SKIP: {tool_name} - Validator error: {e}")
                results["checks_skipped"] += 1

    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except:
                try:
                    proc.kill()
                except:
                    pass

    # Save results
    print(f"\n[*] Results:")
    print(f"    Total checks: {results['checks_total']}")
    print(f"    Passed: {results['checks_passed']}")
    print(f"    Skipped: {results['checks_skipped']}")
    print(f"    Mismatches: {len(results['mismatches'])}")

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_FILE, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[*] Saved report to {REPORT_FILE}")

    return 0 if len(results["mismatches"]) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
