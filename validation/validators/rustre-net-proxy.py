"""
Validators for rustre-net-proxy free functions.
Each validator_NAME(input) -> output mirrors the documented Rust function signature.
Uses Python stdlib only.
"""

import struct
import zlib
import re
import base64
import hashlib
import json
from typing import Optional


# ---------------------------------------------------------------------------
# websocket.rs
# ---------------------------------------------------------------------------

def validator_detect_websocket_upgrade(req: dict) -> bool:
    """detect_websocket_upgrade(req: &HttpRequest) -> bool
    Verifica se la richiesta contiene header 'Upgrade: websocket'.
    Input: dict with 'headers' -> dict[str,str]
    """
    headers = req.get("headers", {})
    for k, v in headers.items():
        if k.lower() == "upgrade" and "websocket" in v.lower():
            return True
    return False


def validator_parse_websocket_stream(data: bytes) -> list:
    """parse_websocket_stream(data: &[u8]) -> Vec<WebSocketFrame>
    Decodifica stream raw TCP in frame WebSocket; gestisce masking client-side.
    Returns list of dicts: {opcode, fin, masked, payload: bytes}
    """
    frames = []
    offset = 0
    while offset + 2 <= len(data):
        b0 = data[offset]
        b1 = data[offset + 1]
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        payload_len = b1 & 0x7F
        offset += 2
        if payload_len == 126:
            if offset + 2 > len(data):
                break
            payload_len = struct.unpack_from(">H", data, offset)[0]
            offset += 2
        elif payload_len == 127:
            if offset + 8 > len(data):
                break
            payload_len = struct.unpack_from(">Q", data, offset)[0]
            offset += 8
        mask_key = b""
        if masked:
            if offset + 4 > len(data):
                break
            mask_key = data[offset:offset + 4]
            offset += 4
        if offset + payload_len > len(data):
            break
        payload = bytearray(data[offset:offset + payload_len])
        offset += payload_len
        if masked:
            payload = bytearray(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        frames.append({"opcode": opcode, "fin": fin, "masked": masked, "payload": bytes(payload)})
    return frames


def validator_reassemble_ws_messages(frames: list) -> list:
    """reassemble_ws_messages(frames: &[WebSocketFrame]) -> Vec<WebSocketFrame>
    Riassembla frame frammentati (FIN=0) in messaggi completi.
    Input: list of dicts as returned by parse_websocket_stream.
    """
    messages = []
    current = None
    for frame in frames:
        opcode = frame["opcode"]
        fin = frame["fin"]
        payload = frame["payload"]
        if opcode != 0:  # non-continuation: start of a new message
            current = {"opcode": opcode, "fin": fin, "masked": False, "payload": bytearray(payload)}
        else:  # continuation frame
            if current is not None:
                current["payload"] += payload
        if fin and current is not None:
            current["payload"] = bytes(current["payload"])
            current["fin"] = True
            messages.append(dict(current))
            current = None
    return messages


# ---------------------------------------------------------------------------
# tls_proxy.rs
# ---------------------------------------------------------------------------

def validator_generate_cert_for_host(hostname: str) -> dict:
    """generate_cert_for_host(hostname: &str) -> Result<GeneratedCert, ProxyError>
    Simula la generazione di cert/key per il dominio (stdlib: restituisce placeholder PEM).
    Returns dict with 'cert_pem' and 'key_pem', or raises ValueError on empty hostname.
    """
    if not hostname:
        raise ValueError("ProxyError: empty hostname")
    # Stdlib cannot generate real TLS certs; return deterministic placeholder.
    cert_pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(f"FAKE-CERT-FOR-{hostname}".encode()).decode()
        + "\n-----END CERTIFICATE-----\n"
    )
    key_pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        + base64.b64encode(f"FAKE-KEY-FOR-{hostname}".encode()).decode()
        + "\n-----END PRIVATE KEY-----\n"
    )
    return {"cert_pem": cert_pem, "key_pem": key_pem}


def validator_extract_sni_from_tcp_payload(data: bytes) -> Optional[str]:
    """extract_sni_from_tcp_payload(data: &[u8]) -> Option<String>
    Estrae l'SNI da un payload TCP grezzo che inizia con un ClientHello TLS.
    Minimal TLS 1.x ClientHello parser (record layer + handshake header).
    """
    # TLS Record: type(1) version(2) length(2)
    if len(data) < 5:
        return None
    if data[0] != 0x16:  # Handshake content type
        return None
    rec_len = struct.unpack_from(">H", data, 3)[0]
    if len(data) < 5 + rec_len:
        return None
    hs = data[5:5 + rec_len]
    # Handshake: type(1) length(3) version(2) random(32) session_id_len(1)
    if len(hs) < 1 or hs[0] != 0x01:  # ClientHello
        return None
    if len(hs) < 4:
        return None
    hs_len = struct.unpack_from(">I", b"\x00" + hs[1:4])[0]
    body = hs[4:4 + hs_len]
    idx = 0
    if len(body) < 34:
        return None
    idx += 2 + 32  # version + random
    if idx >= len(body):
        return None
    sid_len = body[idx]; idx += 1 + sid_len
    if idx + 2 > len(body):
        return None
    cs_len = struct.unpack_from(">H", body, idx)[0]; idx += 2 + cs_len
    if idx + 1 > len(body):
        return None
    cm_len = body[idx]; idx += 1 + cm_len
    if idx + 2 > len(body):
        return None
    ext_total = struct.unpack_from(">H", body, idx)[0]; idx += 2
    ext_end = idx + ext_total
    while idx + 4 <= ext_end and idx + 4 <= len(body):
        ext_type = struct.unpack_from(">H", body, idx)[0]
        ext_len = struct.unpack_from(">H", body, idx + 2)[0]
        idx += 4
        if ext_type == 0x0000:  # SNI
            # list_len(2) name_type(1) name_len(2) name
            if ext_len < 5:
                return None
            name_len = struct.unpack_from(">H", body, idx + 3)[0]
            name = body[idx + 5: idx + 5 + name_len]
            return name.decode("ascii", errors="replace")
        idx += ext_len
    return None


# ---------------------------------------------------------------------------
# lib.rs
# ---------------------------------------------------------------------------

def validator_inject_xff_headers(data: bytearray, client_ip: str, proxy_host: str) -> bool:
    """inject_xff_headers(data: &mut Vec<u8>, client_ip: &str, proxy_host: &str) -> bool
    Inietta X-Forwarded-For e Via in un buffer HTTP serializzato.
    Modifies data in-place; returns True if modified.
    Input: data is a bytearray (mutated), client_ip and proxy_host are str.
    """
    try:
        text = data.decode("latin-1")
    except Exception:
        return False
    # Find end of request line (first \r\n or \n)
    sep = "\r\n\r\n" if "\r\n" in text else "\n\n"
    parts = text.split(sep, 1)
    if len(parts) < 2:
        return False
    header_section = parts[0]
    body = parts[1]
    xff_line = f"X-Forwarded-For: {client_ip}"
    via_line = f"Via: 1.1 {proxy_host}"
    header_section += f"\r\n{xff_line}\r\n{via_line}"
    new_text = header_section + sep + body
    new_bytes = new_text.encode("latin-1")
    data[:] = bytearray(new_bytes)
    return True


def validator_apply_rules_to_request(rules: list, req: dict) -> int:
    """apply_rules_to_request(rules: &[MatchReplaceRule], req: &mut HttpRequest) -> usize
    Applica regole match-replace alla richiesta; ritorna numero di regole scattate.
    Rule dict: {field: str, match: str, replace: str}
    Req dict: {url: str, headers: dict, body: bytes}
    """
    fired = 0
    for rule in rules:
        field = rule.get("field", "url")
        match = rule.get("match", "")
        replace = rule.get("replace", "")
        if field == "url":
            old = req.get("url", "")
            new = old.replace(match, replace)
            if new != old:
                req["url"] = new
                fired += 1
        elif field == "body":
            old = req.get("body", b"")
            if isinstance(old, (bytes, bytearray)):
                old_str = old.decode("latin-1")
                new_str = old_str.replace(match, replace)
                if new_str != old_str:
                    req["body"] = new_str.encode("latin-1")
                    fired += 1
        elif field in ("header", "headers"):
            headers = req.get("headers", {})
            for k in list(headers.keys()):
                old = headers[k]
                new = old.replace(match, replace)
                if new != old:
                    headers[k] = new
                    fired += 1
    return fired


def validator_apply_rules_to_response(rules: list, resp: dict) -> int:
    """apply_rules_to_response(rules: &[MatchReplaceRule], resp: &mut HttpResponse) -> usize
    Come apply_rules_to_request, ma sulla risposta.
    Resp dict: {status: int, headers: dict, body: bytes}
    """
    fired = 0
    for rule in rules:
        field = rule.get("field", "body")
        match = rule.get("match", "")
        replace = rule.get("replace", "")
        if field == "body":
            old = resp.get("body", b"")
            if isinstance(old, (bytes, bytearray)):
                old_str = old.decode("latin-1")
                new_str = old_str.replace(match, replace)
                if new_str != old_str:
                    resp["body"] = new_str.encode("latin-1")
                    fired += 1
        elif field in ("header", "headers"):
            headers = resp.get("headers", {})
            for k in list(headers.keys()):
                old = headers[k]
                new = old.replace(match, replace)
                if new != old:
                    headers[k] = new
                    fired += 1
    return fired


def validator_hex_decode(hex_str: str) -> Optional[bytes]:
    """hex_decode(hex: &str) -> Option<Vec<u8>>
    Decodifica stringa esadecimale in bytes; None se invalida.
    """
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        return None


def validator_hex_encode(data: bytes) -> str:
    """hex_encode(bytes: &[u8]) -> String
    Codifica bytes in stringa esadecimale lowercase.
    """
    return data.hex()


def validator_glob_match(pattern: str, text: str) -> bool:
    """glob_match(pattern: &str, text: &str) -> bool
    Pattern matching con wildcard * e ? per regole di scope/ACL.
    """
    # Convert glob to regex
    regex = ""
    for ch in pattern:
        if ch == "*":
            regex += ".*"
        elif ch == "?":
            regex += "."
        else:
            regex += re.escape(ch)
    return bool(re.fullmatch(regex, text))


def validator_simple_regex_match(pattern: str, text: str) -> bool:
    """simple_regex_match(pattern: &str, text: &str) -> bool
    Regex semplificato (., *, ^, $, classi) senza dipendenze esterne.
    Uses stdlib re.
    """
    try:
        return bool(re.search(pattern, text))
    except re.error:
        return False


def validator_simple_regex_match_len(pattern: str, text: str) -> int:
    """simple_regex_match_len(pattern: &str, text: &str) -> usize
    Come simple_regex_match, ritorna la lunghezza del match (0 se no match).
    """
    try:
        m = re.search(pattern, text)
        if m:
            return len(m.group(0))
        return 0
    except re.error:
        return 0


def validator_base64_decode(encoded: str) -> Optional[bytes]:
    """base64_decode(encoded: &str) -> Option<Vec<u8>>
    Decodifica Base64 standard; None se invalido.
    """
    try:
        # Add padding if needed
        padded = encoded + "=" * (-len(encoded) % 4)
        result = base64.b64decode(padded, validate=True)
        return result
    except Exception:
        return None


def validator_decode_content_encoding(data: bytes, encoding: str) -> bytes:
    """decode_content_encoding(data: &[u8], encoding: &str) -> Vec<u8>
    Decodifica body HTTP compresso (gzip, deflate, identity).
    """
    enc = encoding.lower().strip()
    if enc == "gzip":
        return zlib.decompress(data, zlib.MAX_WBITS | 16)
    elif enc == "deflate":
        try:
            return zlib.decompress(data)
        except zlib.error:
            return zlib.decompress(data, -zlib.MAX_WBITS)
    else:  # identity or unknown
        return data


def validator_decode_http_response_body(resp: dict) -> tuple:
    """decode_http_response_body(resp: &HttpResponse) -> (Vec<u8>, String)
    Decomprime il body della risposta; ritorna (bytes, encoding_usato).
    Resp dict: {headers: dict, body: bytes}
    """
    headers = resp.get("headers", {})
    encoding = ""
    for k, v in headers.items():
        if k.lower() == "content-encoding":
            encoding = v.strip().lower()
            break
    body = resp.get("body", b"")
    if not encoding or encoding == "identity":
        return (body, "identity")
    decoded = validator_decode_content_encoding(body, encoding)
    return (decoded, encoding)


def validator_extract_jwt_tokens(entries: list) -> list:
    """extract_jwt_tokens(entries: &[RequestLogEntry]) -> Vec<JwtToken>
    Scansiona history richieste e restituisce tutti i JWT trovati.
    Entry dict: {url, headers: dict, body: bytes/str}
    Returns list of dicts: {raw, header, payload}
    """
    jwt_pattern = re.compile(
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    )
    results = []
    seen = set()

    def _try_decode(part: str) -> dict:
        padded = part + "=" * (-len(part) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            return {}

    def _process(text: str):
        for m in jwt_pattern.finditer(text):
            raw = m.group(0)
            if raw in seen:
                continue
            seen.add(raw)
            parts = raw.split(".")
            results.append({
                "raw": raw,
                "header": _try_decode(parts[0]) if len(parts) > 0 else {},
                "payload": _try_decode(parts[1]) if len(parts) > 1 else {},
            })

    for entry in entries:
        headers = entry.get("headers", {})
        for v in headers.values():
            _process(v)
        body = entry.get("body", b"")
        if isinstance(body, (bytes, bytearray)):
            _process(body.decode("latin-1", errors="replace"))
        elif isinstance(body, str):
            _process(body)
        url = entry.get("url", "")
        _process(url)

    return results


# handle_connect_tunnel is async I/O — validated as a no-op stub
def validator_handle_connect_tunnel(config: dict) -> bool:
    """handle_connect_tunnel(...) -> Result<(), ProxyError> (async)
    Gestisce tunnel CONNECT bidirezionale. Async I/O not testable in stdlib;
    returns True (Ok(())) for valid config, raises ValueError for invalid.
    Config dict: {stream, upstream_addr, hook, stats}
    """
    if "upstream_addr" not in config:
        raise ValueError("ProxyError: missing upstream_addr")
    return True  # Ok(())


# ---------------------------------------------------------------------------
# http_interceptor.rs
# ---------------------------------------------------------------------------

def validator_detect_ssl_strip(request_url: str, response: dict) -> dict:
    """detect_ssl_strip(request_url: &str, response: &HttpResponse) -> SslStripAnalysis
    Rileva tentativi di SSL stripping confrontando URL e redirect della risposta.
    Response dict: {status: int, headers: dict}
    Returns dict: {detected: bool, reason: str}
    """
    headers = response.get("headers", {})
    status = response.get("status", 200)
    location = ""
    for k, v in headers.items():
        if k.lower() == "location":
            location = v
            break

    detected = False
    reason = ""

    # If request was HTTPS but redirect goes to HTTP
    if request_url.startswith("https://") and status in (301, 302, 303, 307, 308):
        if location.startswith("http://"):
            detected = True
            reason = f"HTTPS request redirected to HTTP: {location}"

    # If response strips HSTS
    hsts = any(k.lower() == "strict-transport-security" for k in headers)
    if not hsts and request_url.startswith("https://"):
        if not detected:
            reason = "Missing HSTS header on HTTPS response"
        # Not strictly ssl strip but suspicious

    return {"detected": detected, "reason": reason}


def validator_harvest_credentials(req: dict) -> list:
    """harvest_credentials(req: &HttpRequest) -> Vec<HarvestedCredential>
    Estrae credenziali da form POST, Basic Auth, Bearer token, query string.
    Req dict: {url: str, method: str, headers: dict, body: bytes/str}
    Returns list of dicts: {kind, value}
    """
    creds = []
    headers = req.get("headers", {})

    # Basic Auth
    for k, v in headers.items():
        if k.lower() == "authorization":
            if v.startswith("Basic "):
                encoded = v[6:].strip()
                decoded = validator_base64_decode(encoded)
                if decoded:
                    creds.append({"kind": "basic_auth", "value": decoded.decode("latin-1", errors="replace")})
            elif v.startswith("Bearer "):
                creds.append({"kind": "bearer_token", "value": v[7:].strip()})

    # Query string
    url = req.get("url", "")
    if "?" in url:
        qs = url.split("?", 1)[1]
        for param in qs.split("&"):
            if "=" in param:
                k, v = param.split("=", 1)
                kl = k.lower()
                if kl in ("password", "passwd", "pass", "pwd", "token", "api_key", "secret"):
                    creds.append({"kind": f"query_{kl}", "value": v})

    # Form body
    body = req.get("body", b"")
    if isinstance(body, (bytes, bytearray)):
        body_str = body.decode("latin-1", errors="replace")
    else:
        body_str = body
    content_type = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            content_type = v.lower()
    if "application/x-www-form-urlencoded" in content_type:
        for param in body_str.split("&"):
            if "=" in param:
                k, v = param.split("=", 1)
                kl = k.lower()
                if kl in ("password", "passwd", "pass", "pwd", "token", "api_key", "secret", "username", "user", "login", "email"):
                    creds.append({"kind": f"form_{kl}", "value": v})

    return creds


def validator_rewrite_body(body: bytes, find: bytes, replace: bytes) -> bytes:
    """rewrite_body(body: &[u8], find: &[u8], replace: &[u8]) -> Vec<u8>
    Cerca e sostituisce una sequenza di byte nel body HTTP.
    """
    return body.replace(find, replace)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # detect_websocket_upgrade
    assert validator_detect_websocket_upgrade({"headers": {"Upgrade": "websocket", "Connection": "Upgrade"}}) is True
    assert validator_detect_websocket_upgrade({"headers": {"Upgrade": "h2"}}) is False

    # hex_encode / hex_decode
    assert validator_hex_encode(b"\xde\xad\xbe\xef") == "deadbeef"
    assert validator_hex_decode("deadbeef") == b"\xde\xad\xbe\xef"
    assert validator_hex_decode("ZZ") is None

    # base64_decode
    assert validator_base64_decode("dXNlcjpwYXNz") == b"user:pass"
    assert validator_base64_decode("!!!") is None

    # glob_match
    assert validator_glob_match("*.example.com", "api.example.com") is True
    assert validator_glob_match("*.example.com", "evil.com") is False
    assert validator_glob_match("192.168.?.1", "192.168.0.1") is True

    # simple_regex_match / len
    assert validator_simple_regex_match(r"\d+", "abc123") is True
    assert validator_simple_regex_match_len(r"\d+", "abc123") == 3

    # rewrite_body
    assert validator_rewrite_body(b"hello world", b"world", b"proxy") == b"hello proxy"

    # harvest_credentials
    req = {
        "url": "https://example.com/login?password=secret123",
        "method": "GET",
        "headers": {"Authorization": "Basic dXNlcjpwYXNz"},
        "body": b"",
    }
    creds = validator_harvest_credentials(req)
    kinds = [c["kind"] for c in creds]
    assert "basic_auth" in kinds
    assert "query_password" in kinds

    # detect_ssl_strip
    analysis = validator_detect_ssl_strip(
        "https://example.com/",
        {"status": 301, "headers": {"Location": "http://example.com/"}}
    )
    assert analysis["detected"] is True

    # decode_content_encoding identity
    assert validator_decode_content_encoding(b"hello", "identity") == b"hello"

    # reassemble_ws_messages
    frames = [
        {"opcode": 1, "fin": False, "masked": False, "payload": b"hel"},
        {"opcode": 0, "fin": True,  "masked": False, "payload": b"lo"},
    ]
    msgs = validator_reassemble_ws_messages(frames)
    assert len(msgs) == 1
    assert msgs[0]["payload"] == b"hello"

    # apply_rules_to_request
    req2 = {"url": "http://example.com/path", "headers": {}, "body": b""}
    rules = [{"field": "url", "match": "example.com", "replace": "evil.com"}]
    count = validator_apply_rules_to_request(rules, req2)
    assert count == 1
    assert "evil.com" in req2["url"]

    # inject_xff_headers
    buf = bytearray(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    changed = validator_inject_xff_headers(buf, "1.2.3.4", "proxy.local")
    assert changed is True
    assert b"X-Forwarded-For: 1.2.3.4" in buf

    # extract_jwt_tokens
    entries = [{"url": "", "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}, "body": b""}]
    jwts = validator_extract_jwt_tokens(entries)
    assert len(jwts) == 1

    # handle_connect_tunnel stub
    assert validator_handle_connect_tunnel({"upstream_addr": "1.2.3.4:443"}) is True
    try:
        validator_handle_connect_tunnel({})
        assert False, "should raise"
    except ValueError:
        pass

    print("All self-tests passed.")
