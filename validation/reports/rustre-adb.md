# rustre-adb

## Scopo
Client Rust async per Android Debug Bridge (ADB). Implementa il wire protocol ADB (CNXN/AUTH/OPEN/OKAY/CLSE/WRTE/SYNC), il host protocol verso adb server locale (default 127.0.0.1:5037), sync (push/pull/stat/list), shell, logcat (brief + threadtime), package manager, port forwarding. Non e' parte del core RE: e' un client di trasporto verso device Android.

## Moduli pubblici
`adb_protocol`, `android_shell`, `device`, `device_manager`, `file_transfer`, `logcat`, `package`, `protocol`, `shell`, `shell_executor`, `sync`, `adb_file_sync`, `android_package_analyzer`, `logcat_parser`, `apk_installer`, `device_profiler`.

## Tipi pubblici principali (lib.rs)
- `AdbError` (Connection/Protocol/DeviceNotFound/CommandFailed/Timeout/Sync/LogcatParse/AuthFailed), `Result<T>`
- `DeviceState` enum (Offline/Bootloader/Device/Host/Recovery/NoPermissions/Sideload/Unauthorized/Unknown) con `is_online()`, `needs_auth()`
- `AdbDevice { serial, state, product, model, device, transport_id }` con `is_ready()`
- `LogLevel` (V/D/I/W/E/F/S) con `as_char()`, `severity()`
- `LogEntry { tag, pid, tid, level, message, timestamp }` con `parse_brief`, `parse_threadtime`, `parse`
- `AdbMessage { command, arg0, arg1, data, crc32, magic }` con `new`, `encode`, `command_name`, `verify_crc`
- `StatEntry { mode, size, mtime }`, `DirEntry { mode, size, mtime, name }`
- `ShellResult { stdout, exit_code }` con `success()`
- `PackageInfo { package_name, apk_path, version_code, version_name, is_system }`
- `ProcessInfo { pid, name, user, ppid }`
- `AdbClient { host, port, timeout }`

## Funzioni pubbliche (lib.rs)
Wire codec:
- `compute_crc32(&[u8]) -> u32` — ADB CRC = somma byte mod 2^32 (NON IEEE)
- `encode_message(cmd, arg0, arg1, &[u8]) -> Bytes`
- `decode_message(&[u8]) -> Result<AdbMessage>`

Sync protocol (su TcpStream gia' aperto):
- `push_file(stream, local: &[u8], remote: &str, mode: u32)`
- `pull_file(stream, remote: &str) -> Vec<u8>`
- `stat_remote(stream, remote) -> StatEntry`
- `list_remote_dir(stream, remote) -> Vec<DirEntry>`

Logcat parsing:
- `parse_logcat_line(&str) -> Option<LogEntry>`
- `parse_logcat_output(&str) -> Vec<LogEntry>`
- `filter_by_level`, `filter_by_tag`, `group_by_tag`

`AdbClient` (async, tokio): `new`, `with_timeout`, `connect`, `server_version`, `list_devices`, `shell`, `shell_result`, `push`, `push_bytes`, `pull`, `pull_bytes`, `install`, `uninstall`, `logcat`, `logcat_raw`, `logcat_clear`, `forward`, `forward_remove`, `reverse`, (+ getprop e altri oltre la riga 1569).

Re-export rilevanti dai sotto-moduli: `protocol::{HandshakeDriver, HandshakeState, AdbRsaKey, AuthType, AdbFeature, build_banner, make_connect, make_auth_*, make_open, make_okay, make_write, make_close, parse_features, read_message, write_message}`; `device::{DeviceMonitor, DeviceList, DeviceSelector, parse_devices_output}`; `shell::{CommandBuilder, shell_escape, cmd_*}`; `sync::{SyncSession, ...}`; `logcat::{LogcatReader, LogcatFilter, LogcatFormat, parse_threadtime_line, parse_brief_line, parse_binary_log}`; `package::{AdbPackageManager, parse_pm_list_*, parse_pm_dump, build_install_command, build_uninstall_command}`.

## Costanti
- `ADB_VERSION = 0x01000000`
- `ADB_MAX_PAYLOAD = 262144`
- `cmd::{SYNC,CNXN,AUTH,OPEN,OKAY,CLSE,WRTE}` (ASCII little-endian u32)
- `sync_cmd::{DENT,RECV,SEND,STAT,DATA,DONE,FAIL,OKAY,QUIT,LIST, MAX_DATA_CHUNK=65536}`

## Input / Output
- Input: TCP socket verso adb server; serial device; path locali/remoti; bytes APK; comandi shell stringa.
- Output: strutture serde-serializzabili (devices/logs/packages/stat/dir entries); risultato shell; effetti collaterali su filesystem locale e device.

## Ground truth verificabile esternamente
1. Costanti wire confrontabili con la fonte AOSP `system/core/adb/protocol.txt` e `adb.h` (magic = cmd XOR 0xFFFFFFFF; CRC = somma byte mod 2^32; payload max 256 KiB; sync chunk max 64 KiB; host:version, host:devices-l, host:transport:<serial>, sync:, shell:, host-serial:<s>:forward:tcp:..).
2. Codec round-trip: `decode_message(encode_message(c,a0,a1,d)) == AdbMessage::new(c,a0,a1,d)` — testabile offline senza device.
3. `compute_crc32` confrontabile con somma byte calcolata a mano (es. crc("ABC") = 65+66+67 = 198).
4. `LogEntry::parse_brief("I/Foo(123): hello")` deve dare tag="Foo", pid=123, level=Info.
5. `LogEntry::parse_threadtime("01-01 12:00:00.000  1234  5678 I Tag: msg")` deve dare pid=1234, tid=5678.
6. `AdbDevice::parse` confrontabile con output reale `adb devices -l`.
7. `host_request("host:version")` deve produrre `"000Chost:version"` (12 = 0x000C).
8. Interop end-to-end con `adb` ufficiale Google su server locale (richiede adb in esecuzione).

## Tool MCP esistenti correlati
Nessun tool MCP del workspace rustre-mcp e' specifico per ADB. Le funzionalita' ADB non rientrano nel set RE (binary/analysis/disasm/decompile/debug). Il modulo `debug_*` di rustre-mcp e' per debugging nativo, non ADB. Quindi il crate e' isolato rispetto al MCP server attuale e non duplica strumenti esposti.

## Testabilita'
- Pure-logic testabile offline: codec wire (`encode_message`/`decode_message`/`compute_crc32`), parser logcat (`LogEntry::parse_*`), parser devices (`AdbDevice::parse`), `host_request`, `PackageInfo::parse_pm_line`, `ProcessInfo::parse_ps_line`, `DeviceState::from_str`, `LogLevel::from_char/severity`.
- Network/IO testabile solo con adb server + device (integration test, non riproducibile in CI senza emulator).
- Esiste cartella `tests/` (contenuto non ispezionato in questa analisi).
