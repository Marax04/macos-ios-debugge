# rustre-debug-gdb

## Scopo
Implementazione completa del GDB Remote Serial Protocol (RSP) client per RustRE Suite. Si connette a un `gdbserver` su TCP, gestisce framing pacchetti (`$data#XX`), ACK/no-ack mode, qSupported negotiation, target.xml parsing, register codec, stop-reply parsing, memory/breakpoint commands, e fornisce `GdbDebugger` che implementa il trait `rustre_debug::Debugger`. Include anche MI parser, Python API stubs, RSP extensions (qXfer, vFile, qRcmd) e flash writer.

## Public modules
- `gdb_client` — alternativo client RSP con transport astratto, loopback, register file
- `gdb_commands` — builder MI-style commands (Break, Exec, Data, Stack, File, Thread, Misc, Trace)
- `gdb_mi_parser` — parser GDB/MI records (Result/Async/Console/Log)
- `gdb_remote_target` — RSP basso livello: checksum, encode/decode packet, transport
- `gdb_rsp_extensions` — qXfer, vFile, qRcmd, qSupported, QPassSignals, QCatchSyscalls
- `gdb_value_formatter` — formattazione valori (hex, dec, ecc.)
- `gdb_python_api` — modello dati GdbValue/GdbType/GdbSymbol/GdbFrame
- `gdb_session` — sessione di alto livello (target, breakpoint, watchpoint, frame, thread)
- `xml_target_desc` — parser/renderer XML target description; built-in i386/x86-64/arm/aarch64/mips
- `gdb_thread_manager` — gestione thread
- `gdb_breakpoint_manager` — BP id-based con conditions, ignore counts, catchpoints
- `gdb_packet_protocol` — RLE encode/decode, RspEncoder, RspDecoder, FlashWriter, AckState
- `gdb_register_set` — definizioni canoniche register per arch
- `gdb_symbol_lookup` — index simboli con glob, completion, demangle
- `remote_target` — multi-transport, feature negotiation, flash write

## Public types (key)
- `GdbRspError` (BadChecksum, FramingError, ConnectionError, UnsupportedCommand, TargetError, Timeout, Io) — converte in `DebugError`
- `GdbPacket { data: String }` — `new`, `encode`, `decode`, `checksum`, `checksum_hex`, `escape_data`, `unescape_data`
- `GdbConnection` — `connect_tcp(addr, port)`, `send_packet`, `command`, `recv_packet`, `negotiate_features`, `enable_no_ack_mode`
- `GdbRegisterDef { name, bitsize, regnum, type_, group }` — `byte_size()`
- `GdbTargetXml { architecture, registers }` — `parse(xml)`, `register_by_name`, `register_by_num`, `total_register_bytes`
- `GdbRegisterCodec { target }` — `new`, `decode_g_packet`, `encode_g_packet`, `decode_p_response`, `encode_p_command`
- `GdbStopReplyParser` — `parse(reply, pid) -> StopReason` (S/T/W/X/O)
- `GdbMemoryOps` — `read_cmd`, `parse_read_response`, `write_cmd`, `write_binary_cmd`, `parse_memory_map_xml`
- `GdbBreakpointOps` — `set_sw_bp_cmd`, `remove_sw_bp_cmd`, `set_hw_bp_cmd`, `remove_hw_bp_cmd`, `set_watchpoint_cmd`, `remove_watchpoint_cmd`
- `GdbDebugger` — `new`, `connect(host,port)`, `disconnect`, `is_connected`, `session`; implementa `Debugger`: `name`, `supported_architectures`, `launch` (Unsupported), `attach`, `detach`, `kill`, `continue_execution`, `single_step`, `step_over` (riconosce CALL rel32 0xE8 e usa BP temporaneo a PC+5), `step_out` (fallback single_step), `pause` (Ctrl-C 0x03), `threads`, `current_thread`, `get_registers`, `set_registers`, `get_register`

## Input / Output
- Input: indirizzo TCP `host:port` di un `gdbserver`, opzioni di launch, `Address`, `ProcessId`, `ThreadId`, `RegisterSet`, kind di breakpoint.
- Output: `DebugEvent` con `StopReason` (Signal/Breakpoint/ProcessExit/Unknown), `RegisterSet`, `Vec<u8>` per memoria, `Vec<MemoryMap>`, `Vec<ThreadId>`.
- Wire format: stringhe `$data#XX` con escape `} ^ 0x20` per `# $ } *`; checksum = sum mod 256 in hex.

## Ground truth verificabile esternamente
1. **Checksum RSP**: `GdbPacket::checksum(b"vCont;c")` deve dare `0xa8`; `checksum("g")` = `0x67`. Confronto diretto con specifica GDB Remote Protocol Appendix E.
2. **Encoding**: `GdbPacket::new("g").encode()` deve produrre `"$g#67"`. Confrontabile con `gdb --target-help` o cattura `socat`/`tcpdump` su gdbserver reale.
3. **Escape**: bytes `# $ } *` → `}` + (b XOR 0x20). Round-trip `unescape_data(escape_data(x)) == x`.
4. **Comandi memoria**: `GdbMemoryOps::read_cmd(Address::new(0x1000), 4)` = `"m1000,4"`; `write_cmd` = `"M1000,4:deadbeef"` (hex lowercase). Verificabile contro manuale GDB §E.4.
5. **Comandi breakpoint**: `set_sw_bp_cmd(0x401000)` = `"Z0,401000,1"`; watchpoint write = `"Z2,addr,len"`. Spec GDB §E.5.
6. **target.xml**: parsing di XML standard GDB (i386/x86-64) — confrontabile con `gdb -ex "maint print xml-tdesc"` su gdbserver reale.
7. **Stop reply**: `T05thread:1;reason:breakpoint;pc:0x400500` deve risultare in `StopReason::Breakpoint` con address 0x400500. Solo reason esplicito breakpoint/swbreak/hwbreak è classificato BP (SIGTRAP nudo resta Signal).
8. **Signal names**: mapping POSIX (5→SIGTRAP, 11→SIGSEGV) — verificabile con `kill -l` o `signal.h`.
9. **Integrazione live**: avviare `gdbserver :1234 /bin/ls`, `GdbDebugger::connect("127.0.0.1", 1234)`, confrontare comportamento con sessione `gdb -ex "target remote :1234"`.
10. **qSupported features**: feature list deve corrispondere a quanto restituito da `gdbserver --version`-specifica.

## Tool MCP esistenti (rustre-mcp)
- `mcp__rustre-mcp__debug_attach`, `debug_launch`, `debug_continue`, `debug_step_into`, `debug_step_over`, `debug_backtrace`, `debug_evaluate`, `debug_set_breakpoint`, `debug_remove_breakpoint`, `debug_read_memory`, `debug_write_memory`, `debug_read_registers` — questi sono i punti di consumo del trait `Debugger`. Il backend GDB-RSP è uno dei provider; verificare end-to-end con un `gdbserver` esterno.
- Nessun tool MCP dedicato a parsing RSP raw — non c'è oracolo MCP per checksum/encode; validazione unitaria + cattura traffico esterna richiesta.

## Testability
Sì. La crate ha già `tests/`. Tutti i parser/encoder (GdbPacket, GdbTargetXml, GdbRegisterCodec, GdbStopReplyParser, GdbMemoryOps, GdbBreakpointOps, rle_encode/decode, RspEncoder/Decoder) sono pure functions con vettori di test deterministici contro la spec GDB. Integration test richiede `gdbserver` reale sulla macchina (Linux/WSL).
