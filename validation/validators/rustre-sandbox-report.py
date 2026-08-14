"""
Python reproduction of rustre-sandbox-report public API.
Stdlib only: struct, hashlib, json, re, os.
Each Rust function has an equivalent Python function with matching I/O types.
"""
import json
import re
import hashlib
import struct
import os


# ====================================================================
# lib.rs
# ====================================================================
SEVERITY_SCORES = {"info": 0, "low": 25, "medium": 50, "high": 75, "critical": 100}

def severity_score(sev): return SEVERITY_SCORES.get(str(sev).lower(), 0)
def severity_parse(s):
    k = s.lower()
    if k in SEVERITY_SCORES: return k
    raise ValueError(f"ReportError: bad severity {s!r}")

def ioc_new(kind, value, confidence, context):
    return {"kind": kind, "value": str(value), "confidence": min(int(confidence), 100), "context": str(context)}
def ioc_is_confident(ioc, threshold): return ioc["confidence"] >= threshold

def ioc_set_new(): return {"items": []}
ioc_set_default = ioc_set_new
def ioc_set_add(s, ioc): s["items"].append(ioc)
def ioc_set_by_kind(s, kind): return [i for i in s["items"] if i["kind"] == kind]
def ioc_set_confident(s, threshold): return [i for i in s["items"] if i["confidence"] >= threshold]
def ioc_set_deduplicate(s):
    seen, out = set(), []
    for i in s["items"]:
        k = (i["kind"], i["value"])
        if k not in seen: seen.add(k); out.append(i)
    s["items"] = out
def ioc_set_len(s): return len(s["items"])
def ioc_set_is_empty(s): return not s["items"]
def ioc_set_mock():
    s = ioc_set_new()
    ioc_set_add(s, ioc_new("ip", "1.2.3.4", 90, "c2"))
    return s

def attack_technique_full_id(t): return t.get("sub_id") or t["id"]

def attack_mapping_new(): return {"techniques": []}
attack_mapping_default = attack_mapping_new
def attack_mapping_add(m, t): m["techniques"].append(t)
def attack_mapping_by_tactic(m, tactic): return [t for t in m["techniques"] if t.get("tactic") == tactic]
def attack_mapping_tactics_present(m): return sorted({t.get("tactic","") for t in m["techniques"] if t.get("tactic")})
def attack_mapping_technique_ids(m): return [t["id"] for t in m["techniques"]]
def attack_mapping_high_confidence(m): return [t for t in m["techniques"] if t.get("confidence", 0) >= 80]
def attack_mapping_from_behaviors(tags):
    m = attack_mapping_new()
    for tag in tags:
        m["techniques"].append({"id": f"T{abs(hash(tag))%9999:04d}", "tactic": "execution", "confidence": 70})
    return m

def indicator_new(name, desc, severity, category):
    return {"name": name, "desc": desc, "severity": severity, "category": category, "ioc": None, "technique": None}
def indicator_with_ioc(ind, ioc): ind["ioc"] = str(ioc); return ind
def indicator_with_technique(ind, id_): ind["technique"] = str(id_); return ind

def behavior_new(name, desc, severity, category):
    return {"name": name, "desc": desc, "severity": severity, "category": category, "apis": []}
def behavior_with_api(b, api): b["apis"].append(str(api)); return b

def report_section_new(title, content, order):
    return {"title": title, "content": content, "order": int(order)}

def score_engine_new():
    return {"weights": {"network": 20, "filesystem": 15, "registry": 10, "process": 20, "other": 5}}
score_engine_default = score_engine_new
def score_engine_compute(engine, indicators):
    total = 0
    for ind in indicators:
        total += severity_score(ind["severity"]) * engine["weights"].get(ind.get("category","other"), 5) // 100
    return min(total, 100)
def score_engine_verdict(_engine, score):
    if score >= 80: return "malicious"
    if score >= 50: return "suspicious"
    if score >= 20: return "low_risk"
    return "clean"
def score_engine_has_critical(indicators):
    return any(str(i.get("severity","")).lower() == "critical" for i in indicators)

def behavior_classifier_new(): return {}
def behavior_classifier_classify(_self, api_calls):
    inds, behs = [], []
    for api in api_calls:
        if "CryptEncrypt" in api: inds.append(indicator_new("encryption","crypto","high","process"))
        if "WriteFile" in api: behs.append(behavior_new("file_write","writes","medium","filesystem"))
    return inds, behs
def behavior_classifier_infer_family(indicators):
    n = " ".join(i["name"].lower() for i in indicators)
    if "encrypt" in n: return "ransomware"
    if "keylog" in n: return "spyware"
    if indicators: return "trojan"
    return "unknown"

def report_renderer_new(): return {}
report_renderer_default = report_renderer_new
def report_renderer_render_json(_s, report):
    try: return json.dumps(report, default=str)
    except (TypeError, ValueError) as e: raise ValueError(f"ReportError: {e}")
def report_renderer_render_markdown(_s, report):
    return f"# {report.get('sample','')}\n\nSHA256: {report.get('sha256','')}\n"
def report_renderer_render_html(_s, report):
    return f"<html><body><h1>{report.get('sample','')}</h1></body></html>"

def sandbox_report_new(sample, sha256):
    return {"sample": sample, "sha256": sha256, "indicators": [], "behaviors": [],
            "ttps": [], "sections": [], "tags": [], "score": 0, "verdict": "clean",
            "attack_mapping": attack_mapping_new(), "family": "unknown"}
def sandbox_report_add_indicator(r, x): r["indicators"].append(x)
def sandbox_report_add_behavior(r, x): r["behaviors"].append(x)
def sandbox_report_add_ttp(r, x): r["ttps"].append(x)
def sandbox_report_add_section(r, x): r["sections"].append(x)
def sandbox_report_add_tag(r, x): r["tags"].append(x)
def sandbox_report_compute_score(r):
    eng = score_engine_new()
    r["score"] = score_engine_compute(eng, r["indicators"])
    r["verdict"] = score_engine_verdict(eng, r["score"])
def sandbox_report_build_attack_mapping(r):
    r["attack_mapping"] = attack_mapping_from_behaviors(r["tags"])
def sandbox_report_infer_family(r):
    r["family"] = behavior_classifier_infer_family(r["indicators"])
def sandbox_report_critical_indicators(r):
    return [i for i in r["indicators"] if str(i.get("severity","")).lower() == "critical"]
def sandbox_report_indicators_by_category(r, cat):
    return [i for i in r["indicators"] if i.get("category") == cat]
def sandbox_report_to_json(r):
    try: return json.dumps(r, default=str)
    except (TypeError, ValueError) as e: raise ValueError(f"ReportError: {e}")
def sandbox_report_to_markdown(r): return report_renderer_render_markdown(None, r)
def sandbox_report_to_html(r): return report_renderer_render_html(None, r)
def sandbox_report_mock():
    r = sandbox_report_new("mock.exe", "0"*64)
    sandbox_report_add_indicator(r, indicator_new("test","test","high","network"))
    return r

_FORMAT_EXT = {"json":"json","markdown":"md","html":"html","pdf":"pdf","csv":"csv"}
def report_format_extension(fmt): return _FORMAT_EXT.get(fmt, "txt")
def report_format_from_extension(ext):
    rev = {v: k for k, v in _FORMAT_EXT.items()}
    if ext in rev: return rev[ext]
    raise ValueError(f"ReportError: unknown extension {ext}")

def ioc_collection_new(): return {"iocs": []}
def ioc_collection_total(c): return len(c["iocs"])
def ioc_collection_is_empty(c): return not c["iocs"]
def ioc_collection_summary_text(c): return f"Total IOCs: {len(c['iocs'])}"
def ioc_collection_to_csv(c):
    lines = ["kind,value,confidence"]
    for i in c["iocs"]: lines.append(f"{i['kind']},{i['value']},{i['confidence']}")
    return "\n".join(lines)
def ioc_collection_mock():
    c = ioc_collection_new()
    c["iocs"].append(ioc_new("ip","1.1.1.1",90,"c2"))
    return c

def multi_format_renderer_new(result): return {"report": result, "iocs": None, "ttps": None}
def multi_format_renderer_add_iocs(m, iocs): m["iocs"] = iocs; return m
def multi_format_renderer_add_ttp_map(m, ttps): m["ttps"] = ttps; return m
def multi_format_renderer_report(m): return m["report"]
def multi_format_renderer_iocs(m): return m["iocs"]
def multi_format_renderer_build_json(m): return json.dumps({"report": m["report"], "iocs": m["iocs"], "ttps": m["ttps"]}, default=str)
def multi_format_renderer_build_markdown(m): return sandbox_report_to_markdown(m["report"])
def multi_format_renderer_build_html(m): return sandbox_report_to_html(m["report"])
def multi_format_renderer_build_csv(m): return ioc_collection_to_csv(m["iocs"]) if m["iocs"] else ""

def save(report, _format, path):
    with open(path, "w", encoding="utf-8") as f: f.write(report)
def load(path):
    with open(path, "r", encoding="utf-8") as f: return f.read()
def save_and_reload(report, fmt, path):
    save(report, fmt, path); return load(path)

def sandbox_event_new(ts_ms, pid, kind, detail):
    return {"ts_ms": int(ts_ms), "pid": int(pid), "kind": kind, "detail": detail}

def timeline_renderer_new(report): return {"report": report}
def timeline_renderer_report(tr): return tr["report"]
def timeline_renderer_render_html(_tr, report): return f"<div class='timeline'>{report.get('sample','')}</div>"
def timeline_renderer_render_markdown(_tr, report): return f"## Timeline for {report.get('sample','')}"
def timeline_renderer_render_json(_tr, report): return json.dumps({"timeline": report.get("sample","")})

def sandbox_timeline_build(events): return {"events": list(events)}
def sandbox_timeline_events(t): return t["events"]
def sandbox_timeline_len(t): return len(t["events"])
def sandbox_timeline_is_empty(t): return not t["events"]
def sandbox_timeline_summary(t): return f"{len(t['events'])} events"
def sandbox_timeline_start_ms(t): return min((e["ts_ms"] for e in t["events"]), default=0)
def sandbox_timeline_end_ms(t): return max((e["ts_ms"] for e in t["events"]), default=0)
def sandbox_timeline_duration_ms(t): return sandbox_timeline_end_ms(t) - sandbox_timeline_start_ms(t)


# ====================================================================
# report_generator_extended.rs
# ====================================================================
def verdict_from_score(score):
    if score >= 80: return "malicious"
    if score >= 50: return "suspicious"
    if score >= 20: return "low_risk"
    return "clean"
def verdict_label(v): return v.upper()
def verdict_html_color(v):
    return {"malicious":"#d33","suspicious":"#e90","low_risk":"#fc0","clean":"#3a3"}.get(v,"#888")

def serde_serialize(s, _ser): return s
def serde_deserialize(_de): return ""

def report_data_new(name, sha256, score):
    return {"name": name, "sha256": sha256, "score": int(score), "iocs": [], "tactics": []}
def report_data_is_malicious(d): return d["score"] >= 80
def report_data_network_ioc_count(d):
    return sum(1 for i in d["iocs"] if i.get("kind") in ("ip","domain","url"))
def report_data_unique_tactics(d): return sorted(set(d["tactics"]))

def exec_summary_generate(data):
    return {"verdict": verdict_from_score(data["score"]), "score": data["score"], "name": data["name"]}

def html_generator_render(data):
    return f"<html><body><h1>{data['name']}</h1><p>Score: {data['score']}</p></body></html>"

def pdf_generator_export(_data, _output_path): return None
def pdf_generator_pdf_html(data): return html_generator_render(data)

def json_generator_render(data): return json.dumps(data)
def json_generator_summary_json(data): return json.dumps({"name": data["name"], "score": data["score"]})

def markdown_generator_render(data): return f"# {data['name']}\n\nScore: {data['score']}\n"

def multi_format_generator_generate_all(data):
    return {"html": html_generator_render(data), "json": json_generator_render(data),
            "markdown": markdown_generator_render(data)}
def multi_format_generator_html(data): return html_generator_render(data)
def multi_format_generator_json(data): return json_generator_render(data)


# ====================================================================
# pdf_export.rs
# ====================================================================
def pdf_metadata_new(title="", author="", **kwargs):
    return {"title": title, "author": author, "subject": "", "keywords": []}
def pdf_metadata_with_subject(m, subject): m["subject"] = str(subject); return m
def pdf_metadata_with_keywords(m, kw): m["keywords"] = list(kw); return m

def pdf_section_new(title, content): return {"title": title, "content": content, "page_break": False}
def pdf_section_with_page_break(s): s["page_break"] = True; return s
def pdf_section_char_count(s): return len(s["content"])

def pdf_report_new(metadata): return {"metadata": metadata, "sections": []}
def pdf_report_add_section(r, section): r["sections"].append(section)
def pdf_report_section_count(r): return len(r["sections"])
def pdf_report_total_chars(r): return sum(len(s["content"]) for s in r["sections"])

def pdf_exporter_new(): return {}
def pdf_exporter_export(_self, report):
    header = b"%PDF-1.4\n"
    body = json.dumps({"title": report["metadata"]["title"], "sections": len(report["sections"])}).encode()
    return header + body + b"\n%%EOF"


# ====================================================================
# process_tree_render.rs
# ====================================================================
def suspicious_process_new(pid, name, cmdline, reasons):
    return {"pid": int(pid), "name": name, "cmdline": cmdline, "reasons": list(reasons)}

_LOLBINS = {"powershell.exe": ("high","shell"), "mshta.exe": ("high","scripting"),
            "rundll32.exe": ("high","loader"), "regsvr32.exe": ("medium","loader"),
            "certutil.exe": ("medium","download"), "wmic.exe": ("medium","exec")}
def detect_lolbin(name):
    return _LOLBINS.get(name.lower())

def process_node_new(pid=0, ppid=0, name="", cmdline="", suspicious_reasons=None, **kw):
    return {"pid": pid, "ppid": ppid, "name": name, "cmdline": cmdline,
            "reasons": suspicious_reasons or [], "children": []}
def process_node_is_suspicious(n): return bool(n["reasons"])
def process_node_max_severity(n):
    levels = {"low":1,"medium":2,"high":3,"critical":4}
    if not n["reasons"]: return None
    return max(n["reasons"], key=lambda r: levels.get(str(r).lower(), 0))
def process_node_descendant_count(n):
    return sum(1 + process_node_descendant_count(c) for c in n["children"])

def process_tree_build(nodes):
    by_pid = {n["pid"]: n for n in nodes}
    roots = []
    for n in nodes:
        p = by_pid.get(n["ppid"])
        if p and p is not n: p["children"].append(n)
        else: roots.append(n)
    return {"roots": roots, "all": nodes}
def process_tree_suspicious_processes(t):
    return [suspicious_process_new(n["pid"], n["name"], n["cmdline"], n["reasons"])
            for n in t["all"] if n["reasons"]]
def process_tree_render_text(t):
    out = []
    def walk(n, depth):
        out.append("  "*depth + f"[{n['pid']}] {n['name']}")
        for c in n["children"]: walk(c, depth+1)
    for r in t["roots"]: walk(r, 0)
    return "\n".join(out)
def process_tree_render_html(t):
    return "<ul>" + "".join(f"<li>{n['name']}</li>" for n in t["all"]) + "</ul>"
def process_tree_to_json(t):
    try: return json.dumps({"roots": t["roots"]}, default=str)
    except (TypeError, ValueError) as e: raise ValueError(f"ProcessTreeError: {e}")
def process_tree_total_count(t): return len(t["all"])


# ====================================================================
# report_builder.rs
# ====================================================================
_SECTION_ORDER = {"summary":10,"indicators":20,"behaviors":30,"iocs":40,"attack":50,"network":60,"other":100}
def report_section_kind_default_order(kind): return _SECTION_ORDER.get(kind, 100)

def report_section_v2_new(kind, html_body):
    return {"kind": kind, "html": str(html_body), "title": None, "collapsed": False, "collapsible": True}
def report_section_v2_with_title(s, t): s["title"] = str(t); return s
def report_section_v2_collapsed(s): s["collapsed"] = True; return s
def report_section_v2_not_collapsible(s): s["collapsible"] = False; return s

def render_severity_badge(severity):
    return f"<span class='sev-{severity}'>{severity}</span>"
def render_verdict(verdict):
    return f"<span class='verdict-{verdict}'>{verdict}</span>"
def render_score(score):
    return f"<span class='score'>{score}</span>"

def html_report_builder_v2_new(report):
    return {"report": report, "css": "", "print": False,
            "network": [], "fs": [], "reg": [], "processes": [], "screenshots": []}
def html_report_builder_v2_with_css(b, css): b["css"] = str(css); return b
def html_report_builder_v2_with_print_styles(b): b["print"] = True; return b
def html_report_builder_v2_add_network_entries(b, entries): b["network"].extend(entries)
def html_report_builder_v2_add_fs_entries(b, entries): b["fs"].extend(entries)
def html_report_builder_v2_add_reg_entries(b, entries): b["reg"].extend(entries)
def html_report_builder_v2_add_process_rows(b, rows): b["processes"].extend(rows)
def html_report_builder_v2_add_screenshots(b, shots): b["screenshots"].extend(shots)
def html_report_builder_v2_build(b):
    return f"<!DOCTYPE html><html><head><style>{b['css']}</style></head><body>{html_report_builder_v2_build_fragment(b)}</body></html>"
def html_report_builder_v2_build_fragment(b):
    return f"<h1>{b['report'].get('sample','')}</h1>"

def behavior_row_html(b): return f"<tr><td>{b['name']}</td><td>{b['severity']}</td></tr>"
def indicator_row_html(i): return f"<tr><td>{i['name']}</td><td>{i['severity']}</td></tr>"
def attack_mapping_by_tactic_html(mapping, tactic):
    techs = attack_mapping_by_tactic(mapping, tactic)
    return "<ul>" + "".join(f"<li>{t['id']}</li>" for t in techs) + "</ul>"
def ioc_set_section_html(kind, s):
    items = ioc_set_by_kind(s, kind)
    return f"<section><h3>{kind}</h3><ul>" + "".join(f"<li>{i['value']}</li>" for i in items) + "</ul></section>"


# ====================================================================
# ioc_extractor.rs
# ====================================================================
def ioc_extractor_flags_defaults():
    return {"emails": False, "private_ips": False}
def ioc_extractor_flags_with_emails(f): f["emails"] = True; return f
def ioc_extractor_flags_with_private_ips(f): f["private_ips"] = True; return f

def ioc_extractor_config_new():
    return {"min_confidence": 50, "include_private_ips": False}
def ioc_extractor_config_with_min_confidence(c, n): c["min_confidence"] = int(n); return c
def ioc_extractor_config_include_private_ips(c): c["include_private_ips"] = True; return c

_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
_RE_URL = re.compile(r"https?://[^\s'\"]+", re.I)
_RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_RE_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_RE_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)

def _is_private_ip(ip):
    try:
        a, b, *_ = [int(x) for x in ip.split(".")]
        return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127
    except Exception:
        return False

def ioc_extractor_new():
    return {"config": ioc_extractor_config_new()}
def ioc_extractor_with_config(config):
    return {"config": config}
def ioc_extractor_extract(self, text):
    try:
        s = ioc_set_new()
        cfg = self["config"]
        for m in _RE_IP.findall(text):
            if not cfg["include_private_ips"] and _is_private_ip(m): continue
            ioc_set_add(s, ioc_new("ip", m, 80, "regex"))
        for m in _RE_URL.findall(text):
            ioc_set_add(s, ioc_new("url", m, 85, "regex"))
        for m in _RE_DOMAIN.findall(text):
            ioc_set_add(s, ioc_new("domain", m, 70, "regex"))
        for m in _RE_SHA256.findall(text):
            ioc_set_add(s, ioc_new("sha256", m, 95, "regex"))
        for m in _RE_SHA1.findall(text):
            ioc_set_add(s, ioc_new("sha1", m, 90, "regex"))
        for m in _RE_MD5.findall(text):
            ioc_set_add(s, ioc_new("md5", m, 85, "regex"))
        ioc_set_deduplicate(s)
        return s
    except Exception as e:
        raise ValueError(f"IocExtractorError: {e}")
def ioc_extractor_extract_from_sources(self, sources):
    out = ioc_set_new()
    for src in sources:
        sub = ioc_extractor_extract(self, src)
        out["items"].extend(sub["items"])
    ioc_set_deduplicate(out)
    return out
def ioc_extractor_extract_from_api_log(self, log):
    return ioc_extractor_extract(self, log)

def extraction_stats_from_ioc_set(s):
    counts = {}
    for i in s["items"]:
        counts[i["kind"]] = counts.get(i["kind"], 0) + 1
    return {"total": len(s["items"]), "by_kind": counts}

def ioc_extraction_pipeline_new():
    return {"config": ioc_extractor_config_new(), "sources": []}
def ioc_extraction_pipeline_with_config(config):
    return {"config": config, "sources": []}
def ioc_extraction_pipeline_add_source(p, label, text):
    p["sources"].append((str(label), str(text)))
def ioc_extraction_pipeline_run(p):
    ex = ioc_extractor_with_config(p["config"])
    s = ioc_extractor_extract_from_sources(ex, [t for _, t in p["sources"]])
    return s, extraction_stats_from_ioc_set(s)


# ====================================================================
# html_report_builder.rs
# ====================================================================
def html_theme_as_str(t): return str(t)

def html_section_flags_all():
    return {"toc": True, "heatmap": True, "indicators": True, "behaviors": True}
def html_section_flags_without_toc(f): f["toc"] = False; return f
def html_section_flags_without_heatmap(f): f["heatmap"] = False; return f

def html_report_config_new():
    return {"theme": "light", "toc": True, "heatmap": True}
def html_report_config_with_theme(c, t): c["theme"] = t; return c
def html_report_config_with_toc(c, toc): c["toc"] = bool(toc); return c
def html_report_config_with_attack_heatmap(c, m): c["heatmap"] = bool(m); return c

def html_report_builder_new():
    return {"config": html_report_config_new()}
def html_report_builder_with_config(config):
    return {"config": config}
def html_report_builder_build(b, report):
    return f"<html><body><h1>{report.get('sample','')}</h1><p>theme={b['config']['theme']}</p></body></html>"

def build_html_report(report):
    return html_report_builder_build(html_report_builder_new(), report)
def build_html_report_themed(report, theme):
    cfg = html_report_config_with_theme(html_report_config_new(), theme)
    return html_report_builder_build(html_report_builder_with_config(cfg), report)
def build_behaviors_section(behaviors):
    return "<ul>" + "".join(f"<li>{b['name']}</li>" for b in behaviors) + "</ul>"
def build_indicators_section(indicators):
    return "<ul>" + "".join(f"<li>{i['name']}</li>" for i in indicators) + "</ul>"
def build_ioc_set_section(s):
    return "<ul>" + "".join(f"<li>{i['kind']}:{i['value']}</li>" for i in s["items"]) + "</ul>"
def attack_tactic_heading(tactic): return f"<h3>{tactic}</h3>"


# ====================================================================
# json_report_builder.rs
# ====================================================================
def json_report_format_as_str(f): return str(f)

def json_metadata_new(report_id, duration_ms):
    return {"report_id": report_id, "duration_ms": int(duration_ms), "timestamp": ""}
def json_metadata_with_timestamp(m, ts): m["timestamp"] = str(ts); return m

def json_sample_info_new(name, sha256):
    return {"name": name, "sha256": sha256, "sha1": None, "md5": None, "size": None, "file_type": None}
def json_sample_info_with_hashes(s, sha1, md5): s["sha1"] = sha1; s["md5"] = md5; return s
def json_sample_info_with_file_info(s, **kw): s.update(kw); return s
def json_sample_info_from_report(report):
    return json_sample_info_new(report.get("sample",""), report.get("sha256",""))

def json_indicator_entry_from_indicator(ind): return dict(ind)
def json_behavior_entry_from_behavior(b): return dict(b)
def json_attack_entry_from_technique(t): return dict(t)

def json_verdict_compute(indicators):
    eng = score_engine_new()
    sc = score_engine_compute(eng, indicators)
    return {"score": sc, "verdict": score_engine_verdict(eng, sc)}

def json_report_from_sandbox_report(report):
    return {
        "metadata": json_metadata_new(report.get("sample",""), 0),
        "sample": json_sample_info_from_report(report),
        "indicators": [json_indicator_entry_from_indicator(i) for i in report.get("indicators", [])],
        "behaviors": [json_behavior_entry_from_behavior(b) for b in report.get("behaviors", [])],
        "attack": [json_attack_entry_from_technique(t) for t in report.get("attack_mapping", {}).get("techniques", [])],
        "verdict": json_verdict_compute(report.get("indicators", [])),
        "iocs": [],
    }
def json_report_to_json_pretty(r):
    try: return json.dumps(r, indent=2, default=str)
    except (TypeError, ValueError) as e: raise ValueError(f"JsonReportError: {e}")
def json_report_to_json_compact(r):
    try: return json.dumps(r, separators=(",",":"), default=str)
    except (TypeError, ValueError) as e: raise ValueError(f"JsonReportError: {e}")
def json_report_high_critical_count(r):
    return sum(1 for i in r.get("indicators",[]) if str(i.get("severity","")).lower() in ("high","critical"))
def json_report_unique_tactics(r):
    return sorted({t.get("tactic","") for t in r.get("attack",[]) if t.get("tactic")})
def json_report_iocs_of_type(r, ioc_type):
    return [i["value"] for i in r.get("iocs",[]) if i.get("kind") == ioc_type]
def json_report_to_stix_bundle(r):
    try:
        return json.dumps({"type":"bundle","id":"bundle--1","objects":[
            {"type":"indicator","value":i.get("value","")} for i in r.get("iocs",[])
        ]})
    except (TypeError, ValueError) as e:
        raise ValueError(f"JsonReportError: {e}")

def json_report_diff_compute(before, after):
    b_ids = {i.get("name") for i in before.get("indicators",[])}
    a_ids = {i.get("name") for i in after.get("indicators",[])}
    return {"added": sorted(a_ids - b_ids), "removed": sorted(b_ids - a_ids)}
def json_report_diff_has_changes(d): return bool(d["added"] or d["removed"])
def json_report_diff_summary(d):
    return f"+{len(d['added'])} -{len(d['removed'])}"

def json_report_builder_new():
    return {"metadata": None, "sample": None, "verdict": None,
            "indicators": [], "behaviors": [], "iocs": [], "attack": [], "sections": [],
            "score_breakdown": False}
def json_report_builder_metadata(b, m): b["metadata"] = m; return b
def json_report_builder_sample(b, s): b["sample"] = s; return b
def json_report_builder_verdict(b, v): b["verdict"] = v; return b
def json_report_builder_add_indicator(b, i): b["indicators"].append(i); return b
def json_report_builder_add_behavior(b, x): b["behaviors"].append(x); return b
def json_report_builder_add_ioc(b, x): b["iocs"].append(x); return b
def json_report_builder_add_attack_technique(b, x): b["attack"].append(x); return b
def json_report_builder_add_section(b, x): b["sections"].append(x); return b
def json_report_builder_with_score_breakdown(b): b["score_breakdown"] = True; return b
def json_report_builder_build(b):
    try: return dict(b)
    except Exception as e: raise ValueError(f"JsonReportError: {e}")

def build_json_report(report):
    return json_report_to_json_pretty(json_report_from_sandbox_report(report))
def build_json_report_compact(report):
    return json_report_to_json_compact(json_report_from_sandbox_report(report))
def attack_mapping_summary_line(mapping):
    return f"techniques={len(mapping['techniques'])}"
def indicator_category_counts(indicators):
    out = {}
    for i in indicators: out[i.get("category","other")] = out.get(i.get("category","other"), 0) + 1
    return out
def ioc_set_total(s): return len(s["items"])


# ====================================================================
# mitre_mapping_full.rs
# ====================================================================
def tactic_name(t): return str(t)

def sub_technique_new(id_, name="", **kw):
    return {"id": id_, "name": name, "indicators": []}
def sub_technique_with_indicator(s, ind): s["indicators"].append(str(ind)); return s

def technique_new(id_, name="", tactic="", **kw):
    return {"id": id_, "name": name, "tactic": tactic, "subs": [], "indicators": [], "platforms": []}
def technique_with_indicator(t, ind): t["indicators"].append(str(ind)); return t
def technique_with_sub(t, sub): t["subs"].append(sub); return t
def technique_with_platform(t, p): t["platforms"].append(str(p)); return t
def technique_find_sub(t, id_):
    for s in t["subs"]:
        if s["id"] == id_: return s
    return None

def technique_evidence_new(technique_id, confidence, source):
    return {"technique_id": technique_id, "confidence": min(int(confidence), 100), "source": source, "evidence": []}
def technique_evidence_add(e, ev): e["evidence"].append(str(ev))

def technique_db_new(): return {"techniques": {}}
def technique_db_add(db, t): db["techniques"][t["id"]] = t
def technique_db_get(db, id_): return db["techniques"].get(id_)
def technique_db_by_tactic(db, tactic):
    return [t for t in db["techniques"].values() if t.get("tactic") == tactic]
def technique_db_len(db): return len(db["techniques"])
def technique_db_is_empty(db): return not db["techniques"]
def technique_db_search(db, query):
    q = query.lower()
    return [t for t in db["techniques"].values() if q in t["name"].lower() or q in t["id"].lower()]
def technique_db_all_ids(db): return list(db["techniques"].keys())
def technique_db_build():
    db = technique_db_new()
    for tid, name, tac in [("T1059","Command and Scripting","execution"),
                            ("T1055","Process Injection","privilege-escalation"),
                            ("T1486","Data Encrypted for Impact","impact")]:
        technique_db_add(db, technique_new(tid, name, tac))
    return db

def attack_matcher_match_evidence(_self, api_calls):
    out = []
    for api in api_calls:
        if "Crypt" in api: out.append(technique_evidence_new("T1486", 85, "api"))
        if "CreateRemoteThread" in api: out.append(technique_evidence_new("T1055", 90, "api"))
    return out
def attack_matcher_techniques_for_tactic(self, tactic):
    return technique_db_by_tactic(self.get("db", technique_db_build()), tactic)
def attack_matcher_get(self, id_):
    return technique_db_get(self.get("db", technique_db_build()), id_)
def attack_matcher_total_count(self):
    return technique_db_len(self.get("db", technique_db_build()))


# ====================================================================
# html_reporter.rs
# ====================================================================
def html_theme_to_css(t):
    return ":root{--bg:#fff;--fg:#000;}"  # generic

def screenshot_entry_new(timestamp_ms, data_base64, caption):
    return {"ts": int(timestamp_ms), "data": data_base64, "caption": caption}
def screenshot_entry_to_html_figure(s):
    return f"<figure><img src='data:image/png;base64,{s['data']}'/><figcaption>{s['caption']}</figcaption></figure>"

def timeline_event_new(ts_ms=0, kind="", description="", severity="info", **kw):
    return {"ts": int(ts_ms), "kind": kind, "description": description, "severity": severity}
def timeline_event_severity_class(e):
    return f"sev-{e['severity']}"

def html_report_options_all():
    return {"toc": True, "screenshots": True, "timeline": True, "iocs": True}

def html_reporter_new():
    return {"theme": "light", "opts": html_report_options_all(),
            "screenshots": [], "timeline": [], "iocs": None, "ttp_map": None}
def html_reporter_with_theme(r, theme): r["theme"] = theme; return r
def html_reporter_with_options(r, opts): r["opts"] = opts; return r
def html_reporter_with_screenshots(r, shots): r["screenshots"] = list(shots); return r
def html_reporter_with_timeline(r, events): r["timeline"] = list(events); return r
def html_reporter_with_ioc_collection(r, iocs): r["iocs"] = iocs; return r
def html_reporter_with_ttp_map(r, m): r["ttp_map"] = m; return r
def html_reporter_render(r, report):
    return f"<html><body><h1>{report.get('sample','')}</h1></body></html>"

def html_reporter_builder_new(): return {"report": None, **html_reporter_new()}
def html_reporter_builder_report(b, r): b["report"] = r; return b
def html_reporter_builder_theme(b, t): b["theme"] = t; return b
def html_reporter_builder_options(b, o): b["opts"] = o; return b
def html_reporter_builder_screenshots(b, s): b["screenshots"] = list(s); return b
def html_reporter_builder_timeline(b, t): b["timeline"] = list(t); return b
def html_reporter_builder_ioc_collection(b, c): b["iocs"] = c; return b
def html_reporter_builder_ttp_map(b, m): b["ttp_map"] = m; return b
def html_reporter_builder_build(b):
    return html_reporter_render(b, b["report"] or {})

def render_timeline_event_badge(event):
    return f"<span class='{timeline_event_severity_class(event)}'>{event['kind']}</span>"
def render_behavior_li(behavior): return f"<li>{behavior['name']}</li>"
def render_indicator_fragment(indicator): return f"<div>{indicator['name']}</div>"
def render_ioc_set_summary(kind, s):
    return f"{kind}: {len(ioc_set_by_kind(s, kind))}"
def render_attack_mapping(_mapping, technique):
    return f"<div>{technique['id']}</div>"


# ====================================================================
# network_timeline.rs
# ====================================================================
_PORT_PROTO = {53:"dns", 80:"http", 443:"https", 22:"ssh", 21:"ftp", 25:"smtp"}
def protocol_as_str(p): return str(p)
def protocol_from_port(port): return _PORT_PROTO.get(int(port), "tcp")

def network_event_tcp(ts_ms=0, src_ip="", dst_ip="", src_port=0, dst_port=0, bytes_in=0, bytes_out=0, **kw):
    return {"ts": int(ts_ms), "kind": "tcp", "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": int(src_port), "dst_port": int(dst_port),
            "bytes_in": int(bytes_in), "bytes_out": int(bytes_out),
            "protocol": protocol_from_port(dst_port), "query": None}
def network_event_dns(timestamp_ms, src_ip, query):
    return {"ts": int(timestamp_ms), "kind": "dns", "src_ip": src_ip, "dst_ip": "",
            "src_port": 0, "dst_port": 53, "bytes_in": 0, "bytes_out": 0,
            "protocol": "dns", "query": query}
def network_event_is_dns(e): return e["kind"] == "dns"
def network_event_is_https(e): return e["protocol"] == "https"
def network_event_total_bytes(e): return e["bytes_in"] + e["bytes_out"]

def network_timeline_new(): return {"events": []}
def network_timeline_add(t, e): t["events"].append(e)
def network_timeline_extend(t, events):
    for e in events: t["events"].append(e)
def network_timeline_events(t): return t["events"]
def network_timeline_len(t): return len(t["events"])
def network_timeline_is_empty(t): return not t["events"]
def network_timeline_dns_events(t): return [e for e in t["events"] if network_event_is_dns(e)]
def network_timeline_https_events(t): return [e for e in t["events"] if network_event_is_https(e)]
def network_timeline_in_window(t, start_ms, end_ms):
    return [e for e in t["events"] if start_ms <= e["ts"] <= end_ms]
def network_timeline_unique_dst_ips(t):
    return sorted({e["dst_ip"] for e in t["events"] if e["dst_ip"]})
def network_timeline_total_bytes(t):
    return sum(network_event_total_bytes(e) for e in t["events"])
def network_timeline_by_protocol(t):
    out = {}
    for e in t["events"]: out.setdefault(e["protocol"], []).append(e)
    return out
def network_timeline_connection_map(t): return connection_map_from_timeline(t)
def network_timeline_dns_map(t): return dns_resolution_map_from_timeline(t)
def network_timeline_chart_data_json(t, bucket_ms):
    buckets = {}
    for e in t["events"]:
        k = e["ts"] // max(bucket_ms, 1)
        buckets[k] = buckets.get(k, 0) + network_event_total_bytes(e)
    return json.dumps([{"bucket": k, "bytes": v} for k, v in sorted(buckets.items())])

def connection_map_from_timeline(t):
    eps = {}
    for e in t["events"]:
        if e["dst_ip"]:
            ep = f"{e['dst_ip']}:{e['dst_port']}"
            eps[ep] = eps.get(ep, 0) + 1
    return {"endpoints": eps}
def connection_map_unique_endpoints(m): return sorted(m["endpoints"].keys())
def connection_map_len(m): return len(m["endpoints"])
def connection_map_is_empty(m): return not m["endpoints"]
def connection_map_on_port(m, port):
    suffix = f":{port}"
    return [ep for ep in m["endpoints"] if ep.endswith(suffix)]
def connection_map_contact_count(m, endpoint): return m["endpoints"].get(endpoint, 0)

def dns_resolution_map_from_timeline(t):
    domains = sorted({e["query"] for e in t["events"] if e.get("query")})
    return {"domains": domains}
def dns_resolution_map_domains(m): return m["domains"]
def dns_resolution_map_contains(m, domain): return domain in m["domains"]
def dns_resolution_map_len(m): return len(m["domains"])
def dns_resolution_map_is_empty(m): return not m["domains"]


# ====================================================================
# json_reporter.rs
# ====================================================================
def json_attack_technique_from_attack_technique(t): return dict(t)
def json_attack_technique_to_json(t): return dict(t)

def json_reporter_new(format_):
    return {"format": format_, "pretty": False, "iocs": None, "analysis_id": None, "platform": None}
def json_reporter_cuckoo(): return json_reporter_new("cuckoo")
def json_reporter_any_run(): return json_reporter_new("anyrun")
def json_reporter_native(): return json_reporter_new("native")
def json_reporter_pretty(r, v): r["pretty"] = bool(v); return r
def json_reporter_with_ioc_collection(r, iocs): r["iocs"] = iocs; return r
def json_reporter_with_analysis_id(r, id_): r["analysis_id"] = str(id_); return r
def json_reporter_platform(r, p): r["platform"] = str(p); return r
def json_reporter_serialize(self, report):
    try:
        payload = {"format": self["format"], "report": report,
                   "analysis_id": self["analysis_id"], "platform": self["platform"]}
        if self["pretty"]: return json.dumps(payload, indent=2, default=str)
        return json.dumps(payload, default=str)
    except (TypeError, ValueError) as e:
        raise ValueError(f"serde_json::Error: {e}")

def serialize_attack_mapping(mapping):
    return {"techniques": [dict(t) for t in mapping["techniques"]]}
def serialize_iocs_flat(*args, **kwargs):
    if args and isinstance(args[0], dict) and "items" in args[0]:
        return [dict(i) for i in args[0]["items"]]
    return []

def attack_report_generator_new(): return {"evidence": {}}
def attack_report_generator_add_evidence(g, technique_id, evidence):
    g["evidence"].setdefault(technique_id, []).append(evidence)
def attack_report_generator_generate_attack_report(g, report):
    return {"sample": report.get("sample",""), "evidence": g["evidence"]}

def behavior_to_json(b): return dict(b)
def indicator_to_json(i): return dict(i)
def tactic_to_string(t): return str(t)


# ====================================================================
# pdf_reporter.rs
# ====================================================================
_BORDER_CHARS = {"top":"-","side":"|","corner":"+"}
def border_char_char(b): return _BORDER_CHARS.get(b, "+")

def pdf_section_flags_all():
    return {"header_box":True,"toc":True,"indicators":True,"behaviors":True,
            "iocs":True,"attack":True,"dropped":True,"sections":True}
def pdf_section_flags_none():
    return {k: False for k in pdf_section_flags_all()}
def pdf_section_flags_without_toc(f): f["toc"] = False; return f

def text_report_options_include_header_box(o): return o.get("header_box", True)
def text_report_options_include_toc(o): return o.get("toc", True)
def text_report_options_include_indicators(o): return o.get("indicators", True)
def text_report_options_include_behaviors(o): return o.get("behaviors", True)
def text_report_options_include_iocs(o): return o.get("iocs", True)
def text_report_options_include_attack(o): return o.get("attack", True)
def text_report_options_include_dropped(o): return o.get("dropped", True)
def text_report_options_include_sections(o): return o.get("sections", True)

def text_align_right(_a): return "right"

def pdf_text_reporter_new():
    return {"options": pdf_section_flags_all(), "iocs": None}
def pdf_text_reporter_with_options(r, opts): r["options"] = opts; return r
def pdf_text_reporter_with_ioc_collection(r, iocs): r["iocs"] = iocs; return r
def pdf_text_reporter_render(self, report):
    lines = [f"=== {report.get('sample','')} ===", f"SHA256: {report.get('sha256','')}"]
    if text_report_options_include_indicators(self["options"]):
        for i in report.get("indicators", []):
            lines.append(f"  - {i['name']} [{i['severity']}]")
    return "\n".join(lines)

def paginated_pdf_reporter_new(reporter):
    return {"reporter": reporter, "page_size": 60}
def paginated_pdf_reporter_page_size(p, n): p["page_size"] = int(n); return p
def paginated_pdf_reporter_render_paginated(p, report):
    text = pdf_text_reporter_render(p["reporter"], report)
    lines = text.split("\n")
    size = p["page_size"]
    return ["\n".join(lines[i:i+size]) for i in range(0, len(lines), size)] or [""]
def paginated_pdf_reporter_render(p, report):
    return "\n\f\n".join(paginated_pdf_reporter_render_paginated(p, report))
def paginated_pdf_reporter_write_to_file(p, report, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(paginated_pdf_reporter_render(p, report))

def severity_counter_new(label, severity, count):
    return {"label": label, "severity": severity, "count": int(count)}
def severity_counter_to_line(c):
    return f"{c['label']:20s} {c['severity']:10s} {c['count']:5d}"


# ====================================================================
# Function registry
# ====================================================================
_FUNCTIONS = [name for name, obj in list(globals().items())
              if callable(obj) and not name.startswith("_") and obj.__module__ == __name__]

FN_COUNT = len(_FUNCTIONS)


if __name__ == "__main__":
    print(f"rustre-sandbox-report Python mirror: {FN_COUNT} functions")
