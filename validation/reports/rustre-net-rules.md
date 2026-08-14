# rustre-net-rules

Network traffic rules and signature engine: Snort/Suricata rule parsing, packet evaluation, persistent `RuleStore` backed by SQLite and MySQL, Aho-Corasick multi-pattern matcher.

## Cargo.toml

- name: `rustre-net-rules`
- edition/version: workspace
- deps: `rustre-net`, `thiserror`, `regex`, `serde`, `serde_json`, `rusqlite`, `mysql`, `parking_lot`

## Modules (re-exported from lib.rs)

- `packet_matcher`, `rule_compiler`, `rule_engine_full`
- `snort_extended`, `snort_rules`, `suricata_rules`, `suricata_rule_parser`
- `protocol_signatures`, `protocol_fingerprinter`, `traffic_classifier`
- `rule_engine`, `signature_matcher`, `alert_correlator`

## Core types (lib.rs)

- `RuleError` — enum (ParseError, InvalidId, NotFound, Sqlite, Mysql, Serialization, DuplicateId, UnsupportedCondition)
- `RuleAction` (alias `Action`) — Alert/Pass/Drop/Log/Reject
- `Proto` — Tcp/Udp/Icmp/Any
- `IpSpec` — Any/Single/Range/Cidr/Group/Not; `matches(IpAddr) -> bool`
- `PortSpec` — Any/Single/Range/List/Not; `matches(u16) -> bool`
- `NetworkSpec { addr, port }` — `any()`, `matches(IpAddr, u16)`
- `Condition` — Content/Pcre/DSize/Flags/Offset/Depth/Within/Distance/Ttl/SrcPort/DstPort
- `Rule { id, action, proto, src, dst, conditions, msg, enabled }` — `new(...)`
- `MatchResult { matched, rule_id, action, msg }`
- `PacketContext { src_ip, dst_ip, src_port, dst_port, ip_proto, ttl, payload, tcp_flags }` — `from_ipv4(&[u8]) -> Option<Self>`

## RuleEngine

- `new()`, `default()`
- `add_rule(Rule)`, `remove_rule(u32)`, `rules() -> Vec<Rule>`
- `evaluate(&PacketContext) -> Option<MatchResult>` — first match
- `evaluate_all(&PacketContext) -> Vec<MatchResult>` — all matches

## RuleParser (Snort-style)

- `RuleParser::parse(&str) -> Result<Rule, RuleError>`
- `RuleParser::parse_many(&str) -> Vec<Result<Rule, RuleError>>`
- Supported options: `msg:`, `sid:`, `content:` (quoted or `|hex|`), `pcre:`, `dsize:` (N, `<N`, `>N`, `N<>M`), `flags:` (S/A/F/R/P/U), `offset:`, `depth:`, `within:`, `distance:`, `ttl:`

## RuleStore (SQLite)

- `open(path) -> Result<Self, RuleError>`
- `in_memory() -> Result<Self, RuleError>`
- `save_rule(&Rule)` (INSERT OR REPLACE)
- `load_all() -> Result<Vec<Rule>, RuleError>`
- `delete_rule(u32)` (NotFound if absent)
- `set_enabled(u32, bool)`
- `count() -> Result<u64, RuleError>`

## MySqlRuleStore

- `connect(url) -> Result<Self, RuleError>`
- `save_rule(&Rule)` (upsert via ON DUPLICATE KEY)
- `load_all() -> Result<Vec<Rule>, RuleError>`
- `delete_rule(u32)`

## Spec-required types

- `RuleProtocol`, `RuleDir`, `RuleOption` (Content, Nocase, Offset, Depth, Pcre, Msg, Sid, Rev, Classtype, Within)
- `SpecRule { action, proto, src, src_port, dir, dst, dst_port, options }` — `sid()`, `msg()`, `content_patterns()`
- `MatchPacket { src_ip, dst_ip, src_port, dst_port, proto, payload }`
- `SpecMatchResult { rule_sid, action, msg, offsets }`
- `RuleSet { rules }` — `new()`, `add(SpecRule)`, `by_sid(u32)`, `count()`
- `SpecRuleEngine { ruleset }` — `new(RuleSet)`, `match_packet(&MatchPacket) -> Vec<SpecMatchResult>`
- `SpecRuleError` (ParseError/MissingSid/InvalidSid)

## Aho-Corasick

- `AcMatch { pattern_idx, start, end }`
- `AhoCorasick::build(&[&[u8]]) -> Self`
- `find_all(&[u8]) -> Vec<AcMatch>`
- `find_first(&[u8]) -> Option<AcMatch>`
- `contains_any(&[u8]) -> bool`
- `state_count() -> usize`

## CompiledRuleSet

Compiled multi-pattern rule set using Aho-Corasick for simultaneous content-pattern matching across all rules. (Defined further in lib.rs beyond reviewed range; submodules `rule_compiler`, `rule_engine_full`, `signature_matcher` expand on this.)

## I/O Summary

- **Input**: raw IPv4 packet bytes (`PacketContext::from_ipv4`), Snort-style rule text (`RuleParser`), SQLite path / MySQL URL.
- **Output**: `MatchResult`/`SpecMatchResult` records, persisted rules (JSON in `rules` table), pattern offsets.
- **Storage schema**: `rules(id, action, proto, msg, enabled, json)` (both SQLite and MySQL).

## Testability

Fully testable in-process: `RuleStore::in_memory()` for SQLite, pure functions for parser/matcher/Aho-Corasick. MySQL backend requires a live server.
