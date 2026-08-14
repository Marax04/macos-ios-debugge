#!/usr/bin/env python3
"""
Rigorous ground-truth validator for all MCP tools prefixed with ti_.
Compares live MCP output against independent Python reference implementations.
Writes results to rigorous_ti_v2.json and skip_ti.json.
"""
import json
import subprocess
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_PASS = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_ti_v2.json"
OUT_SKIP = r"C:\Users\Fra\Desktop\RustRE\validation\skip_ti.json"

# ---------------------------------------------------------------------------
# MCP subprocess helpers
# ---------------------------------------------------------------------------

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    return json.loads(line)

def mcp_call(tool_name, args, rid):
    send({"jsonrpc":"2.0","id":rid,"method":"tools/call",
          "params":{"name":tool_name,"arguments":args}})
    resp = recv()
    if "error" in resp:
        raise RuntimeError(f"JSONRPC error: {resp['error']}")
    result = resp.get("result", {})
    if result.get("isError"):
        content = result.get("content", [])
        txt = content[0].get("text", "") if content else ""
        raise RuntimeError(f"TOOL_ERROR: {txt[:300]}")
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    return json.loads(txt)

# Initialize
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous_ti","version":"1"}
}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project (required)
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
    "name":"project.open","arguments":{"path":TARGET}
}})
recv()

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

RID = 100
results = []
skipped = []
mismatches = []

def call_tool(tool_name, args):
    global RID
    RID += 1
    return mcp_call(tool_name, args, RID)

def check(tool_name, args, key_checks):
    """
    Call tool with args, then verify each key in key_checks matches expected value.
    key_checks: dict of {output_key: expected_value}
    Float values use 1e-9 tolerance.
    """
    try:
        actual = call_tool(tool_name, args)
    except Exception as e:
        results.append({"tool": tool_name, "status": "FAIL", "reason": str(e), "args": args})
        mismatches.append({"tool": tool_name, "expected": key_checks, "actual": str(e)})
        return

    all_ok = True
    for k, exp_val in key_checks.items():
        act_val = actual.get(k)
        if isinstance(exp_val, float) and exp_val != 0.0:
            ok = isinstance(act_val, (int, float)) and abs(float(act_val) - exp_val) < 1e-9
        else:
            ok = act_val == exp_val
        if not ok:
            all_ok = False
            mismatches.append({
                "tool": tool_name, "key": k,
                "expected": exp_val, "actual": act_val,
                "args": args,
            })

    results.append({
        "tool": tool_name,
        "status": "PASS" if all_ok else "FAIL",
        "args": args,
        "actual": actual,
        "expected_checks": key_checks,
    })

def skip(tool_name, reason):
    skipped.append({"tool": tool_name, "reason": reason})

# ===========================================================================
# 1. ti_opencti_graphql_url
#    cfg.graphql_url() = base_url.trim_end_matches('/') + "/graphql"
# ===========================================================================
for base_url, expected_url in [
    ("https://opencti.example.com",  "https://opencti.example.com/graphql"),
    ("https://opencti.example.com/", "https://opencti.example.com/graphql"),
    ("http://localhost:8080",         "http://localhost:8080/graphql"),
]:
    check("ti_opencti_graphql_url", {"base_url": base_url},
          {"graphql_url": expected_url})

# ===========================================================================
# 2. ti_opencti_confidence_clamp
#    Confidence::new(v.min(255) as u8) where new() clamps at 100
#    Returns {"value": clamped, "is_high": clamped >= 75}
# ===========================================================================
for v, exp_val, exp_high in [
    (0,   0,   False),
    (50,  50,  False),
    (74,  74,  False),
    (75,  75,  True),
    (100, 100, True),
    (150, 100, True),   # clamped to 100
    (255, 100, True),   # u8 max, clamped to 100
]:
    check("ti_opencti_confidence_clamp", {"value": v},
          {"value": exp_val, "is_high": exp_high})

# ===========================================================================
# 3. ti_opencti_confidence_is_high  (same logic, separate tool)
# ===========================================================================
for v, exp_high in [(0, False), (74, False), (75, True), (100, True), (200, True)]:
    clamped = min(min(v, 255), 100)
    check("ti_opencti_confidence_is_high", {"value": v},
          {"value": clamped, "is_high": exp_high})

# ===========================================================================
# 4. ti_otx_threat_level
#    ThreatLevel::from_int(v_u8) via Display + severity()
#    Returns {"input": v_u8, "level": str, "severity": u8}
# ===========================================================================
otx_level_map = {0:"unknown",1:"low",2:"medium",3:"high",4:"critical",5:"unknown"}
otx_sev_map   = {"unknown":0,"low":1,"medium":2,"high":3,"critical":4}
for v in [0, 1, 2, 3, 4, 5]:
    lvl = otx_level_map[v]
    check("ti_otx_threat_level", {"value": v},
          {"level": lvl, "severity": otx_sev_map[lvl]})

# ===========================================================================
# 5. ti_vt_api_key_is_valid
#    VtApiKey::is_valid: len==64 AND all chars are ASCII hex
#    Returns {"is_valid": bool}
# ===========================================================================
check("ti_vt_api_key_is_valid", {"key": "a" * 64},   {"is_valid": True})
check("ti_vt_api_key_is_valid", {"key": "deadbeef"},  {"is_valid": False})
check("ti_vt_api_key_is_valid", {"key": "G" * 64},    {"is_valid": False})  # G not hex
check("ti_vt_api_key_is_valid", {"key": "0" * 63},    {"is_valid": False})  # wrong length
check("ti_vt_api_key_is_valid",
      {"key": "abcdef0123456789" * 4},  # 64 chars, all valid hex
      {"is_valid": True})

# ===========================================================================
# 6. ti_vt_analysis_stats_detection_ratio
#    VtAnalysisStats::detection_ratio() = "{malicious}/{total}" (string)
#    total = malicious + suspicious + undetected + harmless + (others default 0)
#    Returns {"ratio": str, "total": u32}
# ===========================================================================
check("ti_vt_analysis_stats_detection_ratio",
      {"malicious": 5, "suspicious": 0, "undetected": 65, "harmless": 0},
      {"ratio": "5/70", "total": 70})
check("ti_vt_analysis_stats_detection_ratio",
      {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0},
      {"ratio": "0/0", "total": 0})
check("ti_vt_analysis_stats_detection_ratio",
      {"malicious": 10, "suspicious": 3, "undetected": 50, "harmless": 7},
      {"ratio": "10/70", "total": 70})
check("ti_vt_analysis_stats_detection_ratio",
      {"malicious": 1},
      {"ratio": "1/1", "total": 1})

# ===========================================================================
# 7. ti_vt_threat_level_from_score
#    ThreatLevel::from_score: 0-15=clean, 16-35=suspicious, 36-60=probably_malicious,
#    61-80=malicious, 81+=highly_malicious
#    Returns {"level": str}
# ===========================================================================
score_cases = [
    (0,   "clean"),
    (15,  "clean"),
    (16,  "suspicious"),
    (35,  "suspicious"),
    (36,  "probably_malicious"),
    (60,  "probably_malicious"),
    (61,  "malicious"),
    (80,  "malicious"),
    (81,  "highly_malicious"),
    (100, "highly_malicious"),
]
for score, expected_level in score_cases:
    check("ti_vt_threat_level_from_score", {"score": score}, {"level": expected_level})

# ===========================================================================
# 8. ti_vt_scoring_weights_av_heavy
#    ScoringWeights::av_heavy() — fixed const values
#    is_valid: sum == 1.0 → 0.60+0.05+0.15+0.05+0.05+0.10 = 1.00
# ===========================================================================
check("ti_vt_scoring_weights_av_heavy", {}, {
    "detection_weight":    0.6,
    "community_weight":    0.05,
    "sandbox_weight":      0.15,
    "file_type_weight":    0.05,
    "age_weight":          0.05,
    "threat_intel_weight": 0.1,
    "is_valid":            True,
})

# ===========================================================================
# 9. ti_misp_distribution_level_from_value
#    Returns {"value": v8, "recognised": bool, "level": str or null}
#    Display impl: OrgOnly→"Organisation only", Community→"Community", etc.
# ===========================================================================
dist_display = {
    0: "Organisation only",
    1: "Community",
    2: "Connected communities",
    3: "All communities",
    4: "Sharing group",
    5: "No distribution",
}
for v in range(7):  # 0-6; 6 is unrecognised
    if v <= 5:
        check("ti_misp_distribution_level_from_value", {"value": v},
              {"value": v, "recognised": True, "level": dist_display[v]})
    else:
        check("ti_misp_distribution_level_from_value", {"value": v},
              {"value": v, "recognised": False, "level": None})

# ===========================================================================
# 10. ti_misp_threat_level_from_value
#     Returns {"value": v8, "recognised": bool, "threat_level": str or null}
#     Display: High→"High", Medium→"Medium", Low→"Low", Undefined→"Undefined"
# ===========================================================================
threat_display = {1: "High", 2: "Medium", 3: "Low", 4: "Undefined"}
for v in [0, 1, 2, 3, 4, 5]:
    if v in threat_display:
        check("ti_misp_threat_level_from_value", {"value": v},
              {"value": v, "recognised": True, "threat_level": threat_display[v]})
    else:
        check("ti_misp_threat_level_from_value", {"value": v},
              {"value": v, "recognised": False, "threat_level": None})

# ===========================================================================
# 11. ti_misp_attribute_type_to_str
#     Wire: from_misp_str(lower).map(|t| t.as_misp_str())
#     Returns {"input": str, "misp_str": str or null}
#     NOTE: "uri" parses to Url variant which as_misp_str returns "url"
# ===========================================================================
attr_cases = [
    ("md5",       "md5"),
    ("sha1",      "sha1"),
    ("sha256",    "sha256"),
    ("ip-src",    "ip-src"),
    ("ip-dst",    "ip-dst"),
    ("domain",    "domain"),
    ("url",       "url"),
    ("uri",       "url"),   # uri maps to Url variant, as_misp_str = "url"
    ("email-src", "email-src"),
    ("yara",      "yara"),
    ("vulnerability", "vulnerability"),
    ("btc",       "btc"),
    ("regkey",    "regkey"),
    ("regkey|value", "regkey"),  # both parse to Regkey
    ("MD5",       "md5"),        # lowercased before lookup
    ("unknown_type_xyz", None),  # no match → null
]
for variant, expected_misp_str in attr_cases:
    check("ti_misp_attribute_type_to_str", {"variant": variant},
          {"misp_str": expected_misp_str})

# ===========================================================================
# 12. ti_malpedia_normalize_family_name
#     normalize_family_name: name.to_lowercase().replace([' ', '-'], '_')
#     Returns {"input": name, "normalized": str}
# ===========================================================================
norm_cases = [
    ("WannaCry",      "wannacry"),
    ("Fancy Bear",    "fancy_bear"),
    ("Poison-Ivy",    "poison_ivy"),
    ("TrickBot",      "trickbot"),
    ("Cobalt Strike", "cobalt_strike"),
    ("APT-28",        "apt_28"),
    ("",              ""),
]
for name, expected_norm in norm_cases:
    check("ti_malpedia_normalize_family_name", {"name": name},
          {"normalized": expected_norm})

# ===========================================================================
# 13. ti_malpedia_family_to_malware_type
#     Returns {"input": str, "malware_type": Debug format of MalwareType}
#     Debug format for enum variants: "Ransomware", "Trojan", etc.
# ===========================================================================
mt_cases = [
    ("ransomware",      "Ransomware"),
    ("trojan",          "Trojan"),
    ("backdoor",        "Backdoor"),
    ("banker",          "Banker"),
    ("banking",         "Banker"),
    ("infostealer",     "Stealer"),
    ("stealer",         "Stealer"),
    ("cryptominer",     "Cryptominer"),
    ("miner",           "Cryptominer"),
    ("stalkerware",     "Spyware"),
    ("spyware",         "Spyware"),
    ("loader",          "Dropper"),
    ("dropper",         "Dropper"),
    ("downloader",      "Downloader"),
    ("worm",            "Worm"),
    ("rootkit",         "Rootkit"),
    ("virus",           "Virus"),
    ("adware",          "Adware"),
    ("botnet",          "Botnet"),
    ("bot",             "Botnet"),
    ("fileless",        "Fileless"),
    ("pua",             "PotentiallyUnwanted"),
    ("pup",             "PotentiallyUnwanted"),
    ("something_weird", "Unknown"),
    ("RANSOMWARE",      "Ransomware"),  # to_lowercase applied
]
for family_type, expected_mt in mt_cases:
    check("ti_malpedia_family_to_malware_type", {"family_type": family_type},
          {"malware_type": expected_mt})

# ===========================================================================
# 14. ti_malpedia_api_key_is_valid
#     is_valid = !key.is_empty() && self.validated
#     Wire accepts optional "validated" bool (default false)
#     Returns {"is_valid": bool, "validated": bool}
# ===========================================================================
# Without validated flag: is_valid = False (validated=false by default)
check("ti_malpedia_api_key_is_valid", {"key": "some-key-value"},
      {"is_valid": False, "validated": False})
# Empty key: is_valid = False even if validated=True
check("ti_malpedia_api_key_is_valid", {"key": "", "validated": True},
      {"is_valid": False})
# Non-empty key + validated=True: is_valid = True
check("ti_malpedia_api_key_is_valid", {"key": "my-api-key", "validated": True},
      {"is_valid": True, "validated": True})

# ===========================================================================
# 15. ti_vt_threat_signals_detection_ratio
#     ThreatSignals::detection_ratio = positives / total_engines (f64)
#     Returns {"detection_ratio": f64}
# ===========================================================================
check("ti_vt_threat_signals_detection_ratio",
      {"positives": 35, "total_engines": 70},
      {"detection_ratio": 0.5})
check("ti_vt_threat_signals_detection_ratio",
      {"positives": 0, "total_engines": 0},
      {"detection_ratio": 0.0})
check("ti_vt_threat_signals_detection_ratio",
      {"positives": 70, "total_engines": 70},
      {"detection_ratio": 1.0})

# ===========================================================================
# 16. ti_otx_pulse_url
#     OtxConfig::new(api_key) → base_url = "https://otx.alienvault.com"
#     pulse_url(pulse_id) = "{base_url}/api/v1/pulses/{pulse_id}"
#     subscribed_url() = "{base_url}/api/v1/pulses/subscribed"
# ===========================================================================
check("ti_otx_pulse_url",
      {"api_key": "test_key_123", "pulse_id": "abc-123"},
      {
          "pulse_url": "https://otx.alienvault.com/api/v1/pulses/abc-123",
          "subscribed_url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
          "base_url": "https://otx.alienvault.com",
      })
check("ti_otx_pulse_url",
      {"pulse_id": "deadbeef"},
      {"pulse_url": "https://otx.alienvault.com/api/v1/pulses/deadbeef"})

# ===========================================================================
# SKIP: nondeterministic / time-dependent / complex-mock tools
# ===========================================================================
skip("ti_vt_token_bucket_available",
     "Token bucket uses Instant::now() — available_tokens is time-dependent")
skip("ti_vt_token_bucket_consume",
     "Token bucket is time-dependent; result changes between calls")
skip("ti_vt_rate_limiter_free_tier",
     "VtRateLimiter::default_free_tier() is time-dependent")
skip("ti_vt_mock_file_report",
     "mock_file_report has complex internal heuristics; no exact ground truth")
skip("ti_vt_mock_ip_report",
     "mock_ip_report — complex mock")
skip("ti_vt_parse_search_response",
     "Parses arbitrary text; output depends on parsing heuristics")
skip("ti_vt_av_result_classify",
     "AV result classification depends on internal category rule set")
skip("ti_vt_ip_report_spec_is_malicious",
     "VtIpReportSpec builder internals not fully traced")
skip("ti_vt_file_report_spec_stats",
     "Depends on mock_file_report internals")
skip("ti_vt_sandbox_verdict_score",
     "SandboxVerdict::weighted_score: base * confidence. "
     "confidence default 0.8 but tool may accept custom; verdict choices are complex")
skip("ti_misp_warning_list_matches",
     "MispWarningList::matches logic partially depends on internal matching impl")
skip("ti_misp_warning_list_check",
     "Same as warning_list_matches")
skip("ti_misp_sighting_is_false_positive",
     "MispSighting::is_false_positive needs full sighting_type trace")
skip("ti_misp_event_spec_has_ids_attributes",
     "Complex event builder with MispAttributeSpec")
skip("ti_misp_event_ioc_count",
     "Complex event builder with add_attribute; ioc_count logic not traced")
skip("ti_misp_sharing_group_new",
     "MispSharingGroup complex builder")
skip("ti_misp_sharing_group_build",
     "Same; org count may vary")
skip("ti_misp_galaxy_find_cluster",
     "MispGalaxy uses uuid_v4_mock which may be nondeterministic")
skip("ti_misp_tag_spec_new",
     "MispTagSpec struct fields not fully traced")
skip("ti_misp_parse_attribute_type",
     "MispApiClient::parse_misp_attribute_type — client-level wrapper not fully traced")
skip("ti_misp_attribute_type_roundtrip",
     "Partially covered by ti_misp_attribute_type_to_str above")
skip("ti_misp_supported_ioc_types",
     "MispApiClient::supported_ioc_types — full list not traced independently")
skip("ti_misp_feed_new",
     "Simple struct; not a logic-sensitive tool")
skip("ti_misp_search_build",
     "MispSearch builder — output depends on default values")
skip("ti_misp_sighting_new",
     "Simple struct new; sighting_type variants not traced")
skip("ti_misp_event_full_new",
     "Simple struct; fields have internal defaults")
skip("ti_misp_distribution_level_describe",
     "Overlaps with ti_misp_distribution_level_from_value already covered")
skip("ti_misp_distribution_level_value",
     "Covered by distribution_level_from_value roundtrip")
skip("ti_misp_threat_level_value",
     "Covered by threat_level_from_value roundtrip")
skip("ti_malpedia_mock_stats",
     "MalpediaStats::mock() — exact field values not traced")
skip("ti_malpedia_mock_family_response",
     "Mock data with internal defaults")
skip("ti_malpedia_alias_resolve",
     "FamilyAliasResolver::with_defaults — built-in alias table unknown")
skip("ti_malpedia_classify_family",
     "FamilyClassifier::with_defaults — scoring table unknown")
skip("ti_malpedia_signature_score",
     "SignatureScoreResult simple struct; no computation to verify")
skip("ti_malpedia_yara_rule_text",
     "MalpediaYaraRule::to_yara_text format not traced")
skip("ti_malpedia_mock_db_search",
     "MalpediaLocalDb::search_families returns mock data")
skip("ti_malpedia_mock_db_find_by_hash",
     "Mock data")
skip("ti_malpedia_attribution_method_display",
     "ActorAttribution fields partially traced; complex state")
skip("ti_malpedia_family_platform_prefix",
     "MalpediaFamilySpec::platform_prefix unknown")
skip("ti_malpedia_search_query_build",
     "MalpediaSearchQuery builder output depends on default serialization")
skip("ti_malpedia_classifier_score_all",
     "FamilyClassifier::score — scoring table internal")
skip("ti_malpedia_client_get_stats",
     "Mock stats; exact fields unknown")
skip("ti_malpedia_client_get_yara_rules",
     "Mock YARA rules")
skip("ti_malpedia_client_search_by_hash",
     "Mock search results")
skip("ti_malpedia_client_list_actors",
     "Mock actor list")
skip("ti_malpedia_family_has_sample",
     "MalpediaFamilySpec::has_sample — internal sample list unknown")
skip("ti_malpedia_local_db_populate_stats",
     "MalpediaLocalDb::populate_mock_data — unknown field values")
skip("ti_malpedia_api_key_new",
     "MalpediaApiKey::new captures SystemTime::now() — created_at nondeterministic")
skip("ti_malpedia_stats_new",
     "MalpediaStats::new — fields unknown")
skip("ti_malpedia_actor_attribution_add_evidence",
     "ActorAttribution complex state mutation with evidence list")
skip("ti_malpedia_actor_spec_new",
     "MalpediaActorSpec::new — fields not traced")
skip("ti_malpedia_sample_spec_new",
     "MalpediaSampleSpec::new — fields not traced")
skip("ti_malpedia_yara_rule_new",
     "MalpediaYaraRule::new — fields not traced")
skip("ti_malpedia_signature_score_result",
     "SignatureScoreResult::new — fields not traced")
skip("ti_malpedia_alias_resolver_count",
     "Count depends on with_defaults alias data")
skip("ti_malpedia_local_db_list_families",
     "Mock data list")
skip("ti_malpedia_client_search_query_exec",
     "Mock exec via MalpediaApiClient::search")
skip("ti_otx_sample_pulse",
     "OtxPulse::sample() — exact mock pulse fields not traced from source")

# ===========================================================================
# Finalize
# ===========================================================================
p.stdin.close()
p.terminate()

total  = len(results)
passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")

print(f"\n=== RIGOROUS TI VALIDATOR ===")
print(f"Test cases run:  {total}")
print(f"PASS:            {passed}")
print(f"FAIL:            {failed}")
print(f"SKIP (tools):    {len(skipped)}")

if mismatches:
    print(f"\nMISMATCHES ({len(mismatches)}):")
    for m in mismatches:
        t = m.get("tool","?")
        k = m.get("key","?")
        e = m.get("expected","?")
        a = m.get("actual","?")
        print(f"  [{t}] key={k!r} expected={e!r} actual={a!r}")

# Distinct tools hardened (tools that have at least one test case)
tools_hardened = len({r["tool"] for r in results})
tools_passed   = len({r["tool"] for r in results
                       if all(x["status"] == "PASS"
                              for x in results if x["tool"] == r["tool"])})
tools_failed   = tools_hardened - tools_passed

print(f"\nDistinct tools hardened: {tools_hardened}")
print(f"Distinct tools all-PASS: {tools_passed}")
print(f"Distinct tools any-FAIL: {tools_failed}")

with open(OUT_PASS, "w") as f:
    json.dump({
        "results": results,
        "summary": {
            "total_cases": total,
            "passed": passed,
            "failed": failed,
            "tools_hardened": tools_hardened,
            "tools_passed": tools_passed,
            "tools_failed": tools_failed,
            "tools_skipped": len(skipped),
        },
        "mismatches": mismatches,
    }, f, indent=2)

with open(OUT_SKIP, "w") as f:
    json.dump(skipped, f, indent=2)

print(f"\nResults → {OUT_PASS}")
print(f"Skips   → {OUT_SKIP}")
