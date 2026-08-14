#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all MCP tools prefixed with adb_.
Inline Python reference implementations — no external shelling.
"""
import json
import struct
import subprocess
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

# ── MCP transport helpers ─────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

_rid = [0]

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:100]!r}"}}

def call_tool(name, args):
    _rid[0] += 1
    send({"jsonrpc": "2.0", "id": _rid[0], "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return None, str(resp["error"])
    result = resp.get("result", {})
    if result.get("isError"):
        return None, result.get("content", [{}])[0].get("text", "")
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# ── Initialize ────────────────────────────────────────────────────────────────

send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous-adb", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# project.open is required
_rid[0] = 10
send({"jsonrpc": "2.0", "id": 11, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
op = recv()
op_txt = op.get("result", {}).get("content", [{}])[0].get("text", "{}")
op_data = json.loads(op_txt)
BINARY_ID = op_data.get("binary_id", "")
PROJECT_ID = op_data.get("project_id", "")
_rid[0] = 100

# ── Python reference implementations ──────────────────────────────────────────

def ref_compute_crc32(data: bytes) -> int:
    """ADB CRC32 = simple byte sum mod 2^32 (not IEEE CRC-32)."""
    return sum(data) & 0xFFFF_FFFF

def ref_encode_message(command: int, arg0: int, arg1: int, data: bytes) -> bytes:
    data_len = len(data)
    crc = ref_compute_crc32(data)
    magic = (command ^ 0xFFFF_FFFF) & 0xFFFF_FFFF
    hdr = struct.pack("<IIIIII", command, arg0, arg1, data_len, crc, magic)
    return hdr + data

def ref_hex(b: bytes) -> str:
    return b.hex()

def ref_shell_escape(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"

def ref_sync_encode(tag: bytes, path: str) -> bytes:
    path_bytes = path.encode("utf-8")
    return tag + struct.pack("<I", len(path_bytes)) + path_bytes

def ref_sync_encode_quit() -> bytes:
    return b"QUIT" + struct.pack("<I", 0)

# ── Test framework ────────────────────────────────────────────────────────────

passed = []
failed = []
skipped = []
mismatches = []

def run_test(tool_name, args, check_fn, skip_reason=None):
    if skip_reason:
        skipped.append({"tool": tool_name, "reason": skip_reason})
        return

    actual, err = call_tool(tool_name, args)
    if err is not None:
        failed.append(tool_name)
        mismatches.append({"tool": tool_name, "expected": "no error", "actual": err[:200]})
        return

    ok, expected, actual_desc = check_fn(actual)
    if ok:
        passed.append(tool_name)
    else:
        failed.append(tool_name)
        mismatches.append({"tool": tool_name, "expected": str(expected), "actual": str(actual_desc)})

# ── Constants ─────────────────────────────────────────────────────────────────

CMD_CNXN = 0x4E58_4E43
CMD_AUTH = 0x4854_5541
CMD_OPEN = 0x4E45_504F
CMD_OKAY = 0x5941_4B4F
CMD_CLSE = 0x4553_4C43
CMD_WRTE = 0x4554_5257

BRIEF_LINE = "I/ActivityManager(  432): Starting activity"
TT_LINE = "01-15 12:00:00.123  1234  5678 I SomeTag: the message"

# ── 1. adb_compute_crc32 ─────────────────────────────────────────────────────

run_test("adb_compute_crc32", {"hex": "deadbeef"},
         lambda r: (r.get("crc32") == ref_compute_crc32(bytes.fromhex("deadbeef")),
                    ref_compute_crc32(bytes.fromhex("deadbeef")), r.get("crc32") if r else None))

run_test("adb_compute_crc32", {"hex": ""},
         lambda r: (r.get("crc32") == 0, 0, r.get("crc32") if r else None))

run_test("adb_compute_crc32", {"hex": "414243"},  # ABC -> 0x43+0x42+0x41 = 0xC6
         lambda r: (r.get("crc32") == 0xC6, 0xC6, r.get("crc32") if r else None))

# ── 2. adb_encode_message ────────────────────────────────────────────────────

def check_encode_no_data(r):
    exp = ref_encode_message(CMD_CNXN, 0x0100_0001, 0x4_0000, b"")
    exp_hex = ref_hex(exp)
    act_hex = r.get("hex") if r else None
    return act_hex == exp_hex, exp_hex, act_hex

run_test("adb_encode_message",
         {"command": CMD_CNXN, "arg0": 0x0100_0001, "arg1": 0x4_0000, "data_hex": ""},
         check_encode_no_data)

def check_encode_with_data(r):
    data = bytes.fromhex("deadbeef")
    exp = ref_encode_message(0xAABBCCDD, 1, 2, data)
    exp_hex = ref_hex(exp)
    act_hex = r.get("hex") if r else None
    return act_hex == exp_hex, exp_hex, act_hex

run_test("adb_encode_message",
         {"command": 0xAABBCCDD, "arg0": 1, "arg1": 2, "data_hex": "deadbeef"},
         check_encode_with_data)

# ── 3. adb_decode_message ────────────────────────────────────────────────────

def check_decode_roundtrip(r):
    act_command = r.get("command") if r else None
    act_data_hex = r.get("data_hex") if r else None
    act_crc_valid = r.get("crc_valid") if r else None
    ok = (act_command == CMD_CNXN and act_data_hex == "68656c6c6f" and act_crc_valid == True)
    return ok, f"cmd={CMD_CNXN},data=68656c6c6f,crc=True", f"cmd={act_command},data={act_data_hex},crc={act_crc_valid}"

enc_hex = ref_hex(ref_encode_message(CMD_CNXN, 0, 0, b"hello"))
run_test("adb_decode_message", {"hex": enc_hex}, check_decode_roundtrip)

# ── 4. adb_shell_escape ───────────────────────────────────────────────────────

# param is "input", response key is "escaped"
run_test("adb_shell_escape", {"input": "hello"},
         lambda r: (r.get("escaped") == "'hello'", "'hello'", r.get("escaped") if r else None))

run_test("adb_shell_escape", {"input": "it's a test"},
         lambda r: (r.get("escaped") == "'it'\\''s a test'",
                    "'it'\\''s a test'", r.get("escaped") if r else None))

# ── 5. adb_install_succeeded ──────────────────────────────────────────────────

# response key is "success" (not "succeeded")
run_test("adb_install_succeeded", {"output": "Some text\nSuccess\nMore"},
         lambda r: (r.get("success") == True, True, r.get("success") if r else None))

run_test("adb_install_succeeded", {"output": "Failure [INSTALL_FAILED_ALREADY_EXISTS]"},
         lambda r: (r.get("success") == False, False, r.get("success") if r else None))

# ── 6. adb_uninstall_succeeded ────────────────────────────────────────────────

run_test("adb_uninstall_succeeded", {"output": "Success"},
         lambda r: (r.get("success") == True, True, r.get("success") if r else None))

run_test("adb_uninstall_succeeded", {"output": "Failure"},
         lambda r: (r.get("success") == False, False, r.get("success") if r else None))

# ── 7. adb_parse_pm_list_line ─────────────────────────────────────────────────

# response: {"package": {package_name, apk_path, ...}}
def check_pm_list_no_path(r):
    pkg = (r.get("package") or {}).get("package_name") if isinstance(r, dict) else None
    return pkg == "com.example.test", "com.example.test", pkg

run_test("adb_parse_pm_list_line", {"line": "package:com.example.test"}, check_pm_list_no_path)

def check_pm_list_with_path(r):
    info = (r.get("package") or {}) if isinstance(r, dict) else {}
    pkg = info.get("package_name")
    apk = info.get("apk_path")
    ok = (pkg == "com.example.test" and apk == "/data/app/com.example.test-1.apk")
    return ok, "pkg=com.example.test,apk=/data/app/com.example.test-1.apk", f"pkg={pkg},apk={apk}"

run_test("adb_parse_pm_list_line",
         {"line": "package:/data/app/com.example.test-1.apk=com.example.test"},
         check_pm_list_with_path)

# ── 8. adb_parse_brief_line ───────────────────────────────────────────────────

# response: {"parsed": bool, "entry": {tag, pid, level, message, ...}}
def check_parse_brief(r):
    entry = (r.get("entry") or {}) if isinstance(r, dict) else {}
    lvl = entry.get("level")
    tag = entry.get("tag")
    msg = entry.get("message") or ""
    # LogLevel serializes via Serde derive as variant name "Info" (not the char "I")
    ok = (lvl == "Info" and tag == "ActivityManager" and "Starting" in msg)
    return ok, "level=Info,tag=ActivityManager,msg~Starting", f"level={lvl},tag={tag},msg={msg}"

run_test("adb_parse_brief_line", {"line": BRIEF_LINE}, check_parse_brief)

# ── 9. adb_parse_threadtime_line ──────────────────────────────────────────────

def check_parse_threadtime(r):
    entry = (r.get("entry") or {}) if isinstance(r, dict) else {}
    tag = entry.get("tag")
    msg = entry.get("message") or ""
    ok = (tag == "SomeTag" and "the message" in msg)
    return ok, "tag=SomeTag,msg=the message", f"tag={tag},msg={msg}"

run_test("adb_parse_threadtime_line", {"line": TT_LINE}, check_parse_threadtime)

# ── 10. adb_log_level_as_char ─────────────────────────────────────────────────

# Tool accepts: "Verbose","Debug","Info","Warning","Error","Fatal","Silent" (not "Warn")
run_test("adb_log_level_as_char", {"level": "Info"},
         lambda r: (r.get("char") == "I", "I", r.get("char") if r else None))

run_test("adb_log_level_as_char", {"level": "Warning"},
         lambda r: (r.get("char") == "W", "W", r.get("char") if r else None))

run_test("adb_log_level_as_char", {"level": "Error"},
         lambda r: (r.get("char") == "E", "E", r.get("char") if r else None))

# ── 11. adb_message_magic_field ───────────────────────────────────────────────

def check_magic(r):
    exp = (CMD_CNXN ^ 0xFFFF_FFFF) & 0xFFFF_FFFF
    act = r.get("magic") if isinstance(r, dict) else None
    return act == exp, exp, act

run_test("adb_message_magic_field", {"command": CMD_CNXN, "arg0": 0, "arg1": 0}, check_magic)

# ── 12. adb_message_crc_field ─────────────────────────────────────────────────

def check_crc_field(r):
    exp = ref_compute_crc32(bytes.fromhex("deadbeef"))
    act = r.get("crc32") if isinstance(r, dict) else None
    return act == exp, exp, act

run_test("adb_message_crc_field",
         {"command": CMD_CNXN, "data_hex": "deadbeef"},
         check_crc_field)

# ── 13. adb_protocol_default_port ────────────────────────────────────────────

run_test("adb_protocol_default_port", {},
         lambda r: (r.get("value") == 5037, 5037, r.get("value") if r else None))

# ── 14. adb_protocol_version_constant ────────────────────────────────────────

def check_proto_version(r):
    exp_proto = 0x0100_0001
    exp_max = 256 * 1024
    act_proto = r.get("protocol_version") if r else None
    act_max = r.get("max_payload") if r else None
    ok = (act_proto == exp_proto and act_max == exp_max)
    return ok, f"pv={exp_proto},mp={exp_max}", f"pv={act_proto},mp={act_max}"

run_test("adb_protocol_version_constant", {}, check_proto_version)

# ── 15. adb_protocol_auth_constants ──────────────────────────────────────────

def check_auth_consts(r):
    if r:
        ok = (r.get("auth_token") == 1 and r.get("auth_signature") == 2
              and r.get("auth_rsapublickey") == 3)
        return ok, "1,2,3", f"{r.get('auth_token')},{r.get('auth_signature')},{r.get('auth_rsapublickey')}"
    return False, "dict", r

run_test("adb_protocol_auth_constants", {}, check_auth_consts)

# ── 16. adb_protocol_cmd_constants ───────────────────────────────────────────

def check_cmd_consts(r):
    if r:
        exp = {
            "cmd_cnxn": CMD_CNXN,
            "cmd_auth": CMD_AUTH,
            "cmd_open": CMD_OPEN,
            "cmd_okay": CMD_OKAY,
            "cmd_clse": CMD_CLSE,
            "cmd_wrte": CMD_WRTE,
        }
        for k, v in exp.items():
            if r.get(k) != v:
                return False, f"{k}={hex(v)}", f"{k}={r.get(k)}"
        return True, "all match", "all match"
    return False, "dict", r

run_test("adb_protocol_cmd_constants", {}, check_cmd_consts)

# ── 17. adb_version_constant ─────────────────────────────────────────────────

run_test("adb_version_constant", {},
         lambda r: (r.get("value") == 0x0100_0000, 0x0100_0000, r.get("value") if r else None))

# ── 18. adb_max_payload_constant ──────────────────────────────────────────────

run_test("adb_max_payload_constant", {},
         lambda r: (r.get("value") == 256 * 1024, 256 * 1024, r.get("value") if r else None))

# ── 19. adb_sync_cmd_tags ─────────────────────────────────────────────────────

# response keys are uppercase: STAT, LIST, SEND, RECV, DATA, DONE, FAIL, QUIT
def check_sync_tags(r):
    if r:
        for tag in ["STAT", "LIST", "SEND", "RECV", "DATA", "DONE", "FAIL", "QUIT"]:
            if r.get(tag) != tag:
                return False, f"{tag}={tag}", f"{tag}={r.get(tag)}"
        return True, "all tags match", "all tags match"
    return False, "dict", r

run_test("adb_sync_cmd_tags", {}, check_sync_tags)

# ── 20. adb_sync_encode_stat ─────────────────────────────────────────────────

def check_sync_stat(r):
    exp_bytes = ref_sync_encode(b"STAT", "/sdcard")
    exp_hex = ref_hex(exp_bytes)
    exp_len = len(exp_bytes)
    act_hex = r.get("hex") if r else None
    act_len = r.get("len") if r else None
    return (act_hex == exp_hex and act_len == exp_len), f"hex={exp_hex}", f"hex={act_hex}"

run_test("adb_sync_encode_stat", {"path": "/sdcard"}, check_sync_stat)

# ── 21. adb_sync_encode_list ─────────────────────────────────────────────────

def check_sync_list(r):
    exp_hex = ref_hex(ref_sync_encode(b"LIST", "/sdcard"))
    act_hex = r.get("hex") if r else None
    return act_hex == exp_hex, exp_hex, act_hex

run_test("adb_sync_encode_list", {"path": "/sdcard"}, check_sync_list)

# ── 22. adb_sync_encode_recv ─────────────────────────────────────────────────

def check_sync_recv(r):
    exp_hex = ref_hex(ref_sync_encode(b"RECV", "/sdcard/test.txt"))
    act_hex = r.get("hex") if r else None
    return act_hex == exp_hex, exp_hex, act_hex

run_test("adb_sync_encode_recv", {"path": "/sdcard/test.txt"}, check_sync_recv)

# ── 23. adb_sync_encode_quit ─────────────────────────────────────────────────

def check_sync_quit(r):
    exp_hex = ref_hex(ref_sync_encode_quit())
    act_hex = r.get("hex") if r else None
    act_len = r.get("len") if r else None
    return (act_hex == exp_hex and act_len == 8), f"hex={exp_hex}", f"hex={act_hex}"

run_test("adb_sync_encode_quit", {}, check_sync_quit)

# ── 24. adb_service_shell_cmd ─────────────────────────────────────────────────

run_test("adb_service_shell_cmd", {"cmd": "ls -la"},
         lambda r: (r.get("service") == "shell:ls -la", "shell:ls -la", r.get("service") if r else None))

# ── 25. adb_service_transport_serial ─────────────────────────────────────────

run_test("adb_service_transport_serial", {"serial": "emulator-5554"},
         lambda r: (r.get("service") == "host:transport:emulator-5554",
                    "host:transport:emulator-5554", r.get("service") if r else None))

# ── 26. adb_service_forward ──────────────────────────────────────────────────

run_test("adb_service_forward", {"local": "tcp:8080", "remote": "tcp:8080"},
         lambda r: (r.get("service") == "forward:tcp:8080;tcp:8080",
                    "forward:tcp:8080;tcp:8080", r.get("service") if r else None))

# ── 27. adb_service_reverse ──────────────────────────────────────────────────

run_test("adb_service_reverse", {"remote": "tcp:9090", "local": "tcp:9090"},
         lambda r: (r.get("service") == "reverse:forward:tcp:9090;tcp:9090",
                    "reverse:forward:tcp:9090;tcp:9090", r.get("service") if r else None))

# ── 28. adb_encode_message_length ────────────────────────────────────────────

# response key is "length" (not "len")
run_test("adb_encode_message_length",
         {"command": CMD_CNXN, "arg0": 0, "arg1": 0, "data_hex": ""},
         lambda r: (r.get("length") == 24, 24, r.get("length") if r else None))

run_test("adb_encode_message_length",
         {"command": CMD_CNXN, "arg0": 0, "arg1": 0, "data_hex": "deadbeef"},
         lambda r: (r.get("length") == 28, 28, r.get("length") if r else None))

# ── 29. adb_service_constants ─────────────────────────────────────────────────

def check_service_consts(r):
    if r:
        ok = (r.get("shell") == "shell:" and r.get("sync") == "sync:"
              and r.get("logcat") == "shell:logcat"
              and r.get("reboot") == "reboot:")
        return ok, "shell:,sync:,shell:logcat,reboot:", \
               f"shell={r.get('shell')},sync={r.get('sync')},logcat={r.get('logcat')},reboot={r.get('reboot')}"
    return False, "dict", r

run_test("adb_service_constants", {}, check_service_consts)

# ── 30. adb_reboot_service_constants ─────────────────────────────────────────

def check_reboot_consts(r):
    if r:
        ok = (r.get("reboot") == "reboot:"
              and r.get("reboot_bootloader") == "reboot:bootloader"
              and r.get("reboot_recovery") == "reboot:recovery")
        return ok, "reboot:,reboot:bootloader,reboot:recovery", \
               f"reboot={r.get('reboot')},bl={r.get('reboot_bootloader')},rec={r.get('reboot_recovery')}"
    return False, "dict", r

run_test("adb_reboot_service_constants", {}, check_reboot_consts)

# ── 31. adb_protocol_state_machine_new ───────────────────────────────────────

def check_state_machine_new(r):
    if r:
        ok = (r.get("local_id") == 0 and r.get("remote_id") == 0)
        return ok, "local_id=0,remote_id=0", f"local_id={r.get('local_id')},remote_id={r.get('remote_id')}"
    return False, "dict", r

run_test("adb_protocol_state_machine_new", {}, check_state_machine_new)

# ── 32. adb_message_no_data ───────────────────────────────────────────────────

def check_msg_no_data(r):
    if isinstance(r, dict):
        enc_len = r.get("encoded_len") or r.get("len") or r.get("length")
        return enc_len == 24, 24, enc_len
    return False, 24, r

run_test("adb_message_no_data", {"command": CMD_CNXN, "arg0": 0, "arg1": 0}, check_msg_no_data)

# ── 33. adb_msg_no_data_encoded ──────────────────────────────────────────────

def check_msg_no_data_encoded(r):
    if isinstance(r, dict):
        enc_len = r.get("len") or r.get("length")
        return enc_len == 24, 24, enc_len
    return False, 24, r

run_test("adb_msg_no_data_encoded", {"command": CMD_CNXN, "arg0": 0, "arg1": 0}, check_msg_no_data_encoded)

# ── 34. adb_message_command_name_for_u32 ─────────────────────────────────────

run_test("adb_message_command_name_for_u32", {"command": CMD_CNXN},
         lambda r: (r.get("name") == "CNXN", "CNXN", r.get("name") if r else None))

# ── 35. adb_device_state_is_online ───────────────────────────────────────────

# "online" is not a valid ADB state string; "device" is the correct string for online
run_test("adb_device_state_is_online", {"state": "device"},
         lambda r: (r.get("is_online") == True, True, r.get("is_online") if r else None))

run_test("adb_device_state_is_online", {"state": "offline"},
         lambda r: (r.get("is_online") == False, False, r.get("is_online") if r else None))

# ── 36. adb_device_state_needs_auth ──────────────────────────────────────────

run_test("adb_device_state_needs_auth", {"state": "unauthorized"},
         lambda r: (r.get("needs_auth") == True, True, r.get("needs_auth") if r else None))

# ── 37. adb_local_client_info ─────────────────────────────────────────────────

def check_local_client(r):
    if r:
        host = r.get("host")
        port = r.get("port")
        ok = (host == "127.0.0.1" and port == 5037)
        return ok, "host=127.0.0.1,port=5037", f"host={host},port={port}"
    return False, "dict", r

run_test("adb_local_client_info", {}, check_local_client)

# ── 38. adb_local_client_host_v2 ─────────────────────────────────────────────

run_test("adb_local_client_host_v2", {},
         lambda r: (r.get("host") == "127.0.0.1", "127.0.0.1", r.get("host") if r else None))

# ── 39. adb_connect_banner_parse ─────────────────────────────────────────────

# Banner format: "type::key=val;key=val;..."
# response key is "connection_type"
BANNER = "device::ro.product.name=Pixel;ro.serialno=ABC123"

def check_banner_parse(r):
    if r:
        ct = r.get("connection_type")
        serial = r.get("serial")
        ok = (ct == "device")
        return ok, "connection_type=device", f"connection_type={ct},serial={serial}"
    return False, "dict", r

run_test("adb_connect_banner_parse", {"raw": BANNER}, check_banner_parse)

# ── 40. adb_connect_banner_has_feature ───────────────────────────────────────

# Correct banner format uses ';' separator before 'features='
BANNER_WITH_FEAT = "device::ro.product.name=Pixel;features=shell_v2,fixed_push_mkdir"

run_test("adb_connect_banner_has_feature",
         {"raw": BANNER_WITH_FEAT, "feature": "shell_v2"},
         lambda r: (r.get("has_feature") == True, True, r.get("has_feature") if r else None))

run_test("adb_connect_banner_has_feature",
         {"raw": BANNER_WITH_FEAT, "feature": "nonexistent_feature"},
         lambda r: (r.get("has_feature") == False, False, r.get("has_feature") if r else None))

# ── 41. adb_message_encode ───────────────────────────────────────────────────

def check_msg_encode(r):
    exp_bytes = ref_encode_message(CMD_CNXN, 0, 0, b"")
    exp_hex = ref_hex(exp_bytes)
    act_hex = r.get("hex") if r else None
    return act_hex == exp_hex, exp_hex, act_hex

run_test("adb_message_encode",
         {"command": CMD_CNXN, "arg0": 0, "arg1": 0},
         check_msg_encode)

# ── 42. adb_crc32_roundtrip ──────────────────────────────────────────────────

def check_crc32_roundtrip(r):
    if r:
        crc = r.get("crc32")
        exp = ref_compute_crc32(bytes.fromhex("deadbeef"))
        ok = (crc == exp)
        return ok, f"crc32={exp}", f"crc32={crc}"
    return False, "dict with crc32", r

run_test("adb_crc32_roundtrip", {"data_hex": "deadbeef"}, check_crc32_roundtrip)

# ── 43. adb_parse_pm_list_output ─────────────────────────────────────────────

PM_OUTPUT = "package:com.android.settings\npackage:/data/app/com.example.test-1.apk=com.example.test\n"

def check_pm_list_output(r):
    if r:
        count = r.get("count")
        ok = (count == 2)
        return ok, 2, count
    return False, 2, r

run_test("adb_parse_pm_list_output", {"output": PM_OUTPUT}, check_pm_list_output)

# ── 44. adb_parse_devices_output ─────────────────────────────────────────────

DEVICES_OUTPUT = "List of devices attached\nemulator-5554\tdevice\n"

def check_parse_devices(r):
    if r:
        count = r.get("count")
        devices = r.get("devices")
        ok = (count >= 1)
        if ok and devices:
            # DeviceInfo serializes as {"device": {"serial": ...}, "transport": ...}
            first = devices[0]
            serial = (first.get("device") or {}).get("serial") if isinstance(first, dict) else None
            ok2 = (serial == "emulator-5554")
            return ok2, "serial=emulator-5554", f"serial={serial}"
        return ok, "count>=1", count
    return False, "dict", r

run_test("adb_parse_devices_output", {"output": DEVICES_OUTPUT}, check_parse_devices)

# ── 45. adb_build_install_command ─────────────────────────────────────────────

# param is "remote_apk" (not "apk_path")
def check_build_install(r):
    if r:
        cmd = r.get("command")
        ok = (cmd is not None and "pm install" in cmd and "/data/local/test.apk" in cmd)
        return ok, "pm install ... /data/local/test.apk", cmd
    return False, "pm install string", r

run_test("adb_build_install_command", {"remote_apk": "/data/local/test.apk"}, check_build_install)

# ── 46. adb_build_uninstall_command ──────────────────────────────────────────

def check_build_uninstall(r):
    if r:
        cmd = r.get("command")
        ok = (cmd is not None and "pm uninstall" in cmd and "com.example.app" in cmd)
        return ok, "pm uninstall com.example.app", cmd
    return False, "pm uninstall string", r

run_test("adb_build_uninstall_command", {"package": "com.example.app"}, check_build_uninstall)

# ── 47. adb_shell_result_success ─────────────────────────────────────────────

run_test("adb_shell_result_success", {"stdout": "output", "exit_code": 0},
         lambda r: (r.get("success") == True, True, r.get("success") if r else None))

run_test("adb_shell_result_success", {"stdout": "", "exit_code": 1},
         lambda r: (r.get("success") == False, False, r.get("success") if r else None))

# ── 48. adb_current_mtime — SKIP ─────────────────────────────────────────────

skipped.append({"tool": "adb_current_mtime", "reason": "nondeterministic (wall clock)"})

# ── 49. adb_log_entry_parse_brief_v2 ─────────────────────────────────────────

# response: {"parsed": bool, "entry": {tag, pid, tid, level, message, timestamp}}
def check_brief_v2(r):
    if r:
        entry = r.get("entry") or {}
        tag = entry.get("tag") if entry else None
        ok = (tag == "ActivityManager")
        return ok, "tag=ActivityManager", f"tag={tag}"
    return False, "dict", r

run_test("adb_log_entry_parse_brief_v2", {"line": BRIEF_LINE}, check_brief_v2)

# ── 50. adb_log_entry_parse_auto ─────────────────────────────────────────────

def check_parse_auto(r):
    if r:
        entry = r.get("entry") or {}
        tag = entry.get("tag") if entry else None
        ok = (tag == "SomeTag")
        return ok, "tag=SomeTag", f"tag={tag}"
    return False, "dict", r

run_test("adb_log_entry_parse_auto", {"line": TT_LINE}, check_parse_auto)

# ── 51. adb_message_verify_crc ───────────────────────────────────────────────

# requires "crc32" (the claimed crc) and "data_hex" (the payload to check)
data_for_verify = bytes.fromhex("74657374")  # "test"
crc_for_verify = ref_compute_crc32(data_for_verify)

run_test("adb_message_verify_crc",
         {"crc32": crc_for_verify, "data_hex": "74657374"},
         lambda r: (r.get("verified") == True, True, r.get("verified") if r else None))

# Wrong CRC should not verify
run_test("adb_message_verify_crc",
         {"crc32": 9999, "data_hex": "74657374"},
         lambda r: (r.get("verified") == False, False, r.get("verified") if r else None))

# ── 52. adb_message_command_name ─────────────────────────────────────────────

run_test("adb_message_command_name", {"command": CMD_CNXN},
         lambda r: (r.get("name") == "CNXN", "CNXN", r.get("name") if r else None))

# ── 53. adb_cmd_all_constants ─────────────────────────────────────────────────

# response uses uppercase: {"CNXN": value, ...}
def check_cmd_all(r):
    if r:
        cnxn = r.get("CNXN")
        ok = (cnxn == CMD_CNXN)
        return ok, hex(CMD_CNXN), cnxn
    return False, "dict", r

run_test("adb_cmd_all_constants", {}, check_cmd_all)

# ── 54. adb_sync_max_data_chunk ──────────────────────────────────────────────

run_test("adb_sync_max_data_chunk", {},
         lambda r: (r.get("value") == 64 * 1024, 64 * 1024, r.get("value") if r else None))

# ── 55. adb_message_new ──────────────────────────────────────────────────────

def check_msg_new(r):
    if r:
        exp_magic = (CMD_CNXN ^ 0xFFFF_FFFF) & 0xFFFF_FFFF
        exp_crc = ref_compute_crc32(bytes.fromhex("deadbeef"))
        act_magic = r.get("magic")
        act_crc = r.get("crc32")
        ok = (act_magic == exp_magic and act_crc == exp_crc)
        return ok, f"magic={exp_magic},crc={exp_crc}", f"magic={act_magic},crc={act_crc}"
    return False, "dict", r

run_test("adb_message_new",
         {"command": CMD_CNXN, "arg0": 0, "arg1": 0, "data_hex": "deadbeef"},
         check_msg_new)

# ── Shutdown ──────────────────────────────────────────────────────────────────

p.stdin.close()
p.terminate()

# ── Write results ─────────────────────────────────────────────────────────────

OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_adb_v2.json"
SKIP_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\skip_adb.json"

results = {
    "category": "adb",
    "tools_hardened": len(passed) + len(failed),
    "tools_passed": len(passed),
    "tools_failed": len(failed),
    "tools_skipped": len(skipped),
    "mismatches": mismatches,
    "passed_tools": passed,
    "failed_tools": failed,
}

with open(OUT, "w") as f:
    json.dump(results, f, indent=2)

with open(SKIP_OUT, "w") as f:
    json.dump({"skipped": skipped}, f, indent=2)

print(json.dumps(results, indent=2))
