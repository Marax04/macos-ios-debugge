#!/usr/bin/env python3
"""Independent Python validator for rustre-forensics.

Implements Python stdlib equivalents of every public function documented in
reports/rustre-forensics.md. Each validator_NAME(input) -> output mirrors
the Rust signature as closely as Python allows.
Uses only the standard library.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple


# ===========================================================================
# lib.rs — core types and hashing
# ===========================================================================

# --- HashAlgorithm ---

class HashAlgorithm:
    MD5    = "md5"
    SHA1   = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"


def validator_compute_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def validator_compute_sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def validator_compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validator_compute_sha512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


@dataclass
class EvidenceHash:
    algorithm: str
    hex_digest: str

    @staticmethod
    def validator_compute(data: bytes, algorithm: str) -> "EvidenceHash":
        if algorithm == HashAlgorithm.MD5:
            digest = hashlib.md5(data).hexdigest()
        elif algorithm == HashAlgorithm.SHA1:
            digest = hashlib.sha1(data).hexdigest()
        elif algorithm == HashAlgorithm.SHA256:
            digest = hashlib.sha256(data).hexdigest()
        elif algorithm == HashAlgorithm.SHA512:
            digest = hashlib.sha512(data).hexdigest()
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        return EvidenceHash(algorithm=algorithm, hex_digest=digest)

    def validator_verify(self, data: bytes) -> bool:
        recomputed = EvidenceHash.validator_compute(data, self.algorithm)
        return recomputed.hex_digest == self.hex_digest


@dataclass
class CustodyEntry:
    timestamp: int
    actor: str
    action: str
    notes: Optional[str] = None


@dataclass
class EvidenceRecord:
    id: str
    path: str
    timestamp: int
    etype: str
    hashes: List[EvidenceHash] = field(default_factory=list)
    custody: List[CustodyEntry] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    @staticmethod
    def validator_new(id: str, path: str, ts: int, etype: str) -> "EvidenceRecord":
        return EvidenceRecord(id=id, path=path, timestamp=ts, etype=etype)

    def validator_add_hash(self, h: EvidenceHash) -> None:
        self.hashes.append(h)

    def validator_add_custody(self, ts: int, actor: str, action: str, notes: Optional[str] = None) -> None:
        self.custody.append(CustodyEntry(ts, actor, action, notes))

    def validator_add_tag(self, tag: str) -> None:
        self.tags.append(tag)

    def validator_verify(self, data: bytes) -> bool:
        if not self.hashes:
            return False
        return all(h.validator_verify(data) for h in self.hashes)


class TimelineEventType:
    PROCESS = "process"
    NETWORK = "network"
    FILE    = "file"
    REGISTRY = "registry"
    GENERIC = "generic"


@dataclass
class TimelineEvent:
    timestamp_ms: int
    actor: str
    artifact: str
    event_type: str = TimelineEventType.GENERIC

    @staticmethod
    def validator_new(ts: int, actor: str, artifact: str) -> "TimelineEvent":
        return TimelineEvent(timestamp_ms=ts, actor=actor, artifact=artifact)

    def validator_with_artifact(self, artifact: str) -> "TimelineEvent":
        self.artifact = artifact
        return self

    def validator_with_actor(self, actor: str) -> "TimelineEvent":
        self.actor = actor
        return self


@dataclass
class Timeline:
    events: List[TimelineEvent] = field(default_factory=list)

    @staticmethod
    def validator_new() -> "Timeline":
        return Timeline()

    def validator_add_event(self, event: TimelineEvent) -> None:
        self.events.append(event)

    def validator_sort(self) -> None:
        self.events.sort(key=lambda e: e.timestamp_ms)

    def validator_events_in_range(self, start: int, end: int) -> List[TimelineEvent]:
        return [e for e in self.events if start <= e.timestamp_ms <= end]

    def validator_events_by_type(self, et: str) -> List[TimelineEvent]:
        return [e for e in self.events if e.event_type == et]


@dataclass
class PluginContext:
    args: Dict[str, str] = field(default_factory=dict)

    @staticmethod
    def validator_new() -> "PluginContext":
        return PluginContext()

    def validator_set(self, key: str, value: str) -> None:
        self.args[key] = value

    def validator_get(self, key: str) -> Optional[str]:
        return self.args.get(key)


@dataclass
class ForensicRow:
    cells: List[str] = field(default_factory=list)


@dataclass
class TabularData:
    headers: List[str] = field(default_factory=list)
    rows: List[ForensicRow] = field(default_factory=list)

    @staticmethod
    def validator_new() -> "TabularData":
        return TabularData()

    def validator_add_row(self, row: ForensicRow) -> None:
        self.rows.append(row)

    def validator_to_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(self.headers)
        for r in self.rows:
            w.writerow(r.cells)
        return buf.getvalue()


@dataclass
class PluginOutput:
    name: str
    data: TabularData = field(default_factory=TabularData.validator_new)
    messages: List[str] = field(default_factory=list)


class PluginRegistry:
    def __init__(self):
        self._plugins: Dict[str, Any] = {}

    @staticmethod
    def validator_new() -> "PluginRegistry":
        return PluginRegistry()

    def validator_register(self, plugin: Any) -> None:
        self._plugins[plugin.name()] = plugin

    def validator_get(self, name: str) -> Optional[Any]:
        return self._plugins.get(name)

    def validator_names(self) -> List[str]:
        return list(self._plugins.keys())

    def validator_run(self, name: str, ctx: PluginContext) -> PluginOutput:
        plugin = self._plugins.get(name)
        if plugin is None:
            raise KeyError(f"Plugin not found: {name}")
        return plugin.run(ctx)


@dataclass
class MemoryDump:
    path: str
    arch: str
    os: str
    data: bytes = b""

    @staticmethod
    def validator_from_file(path: str, arch: str, os: str) -> "MemoryDump":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(path)
        data = p.read_bytes()
        return MemoryDump(path=str(path), arch=arch, os=os, data=data)

    def validator_as_bytes(self) -> bytes:
        return self.data


@dataclass
class ProcessList:
    processes: List[Dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def validator_from_bytes(data: bytes) -> "ProcessList":
        try:
            obj = json.loads(data.decode("utf-8", errors="replace"))
            return ProcessList(processes=obj if isinstance(obj, list) else [])
        except Exception:
            return ProcessList()


@dataclass
class NetworkConnections:
    connections: List[Dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def validator_from_bytes(data: bytes) -> "NetworkConnections":
        try:
            obj = json.loads(data.decode("utf-8", errors="replace"))
            return NetworkConnections(connections=obj if isinstance(obj, list) else [])
        except Exception:
            return NetworkConnections()


# ===========================================================================
# artifact_extractor.rs
# ===========================================================================

@dataclass
class BrowserHistoryEntry:
    url: str
    profile: Optional[str] = None


@dataclass
class CredentialEntry:
    kind: str
    value: str


@dataclass
class ClipboardEntry:
    text: str


@dataclass
class TypedUrl:
    url: str


@dataclass
class MftEntry:
    offset: int
    raw: bytes


@dataclass
class ThumbnailEntry:
    offset: int
    data: bytes


@dataclass
class ExtractionResult:
    urls: List[str] = field(default_factory=list)
    browser_history: List[BrowserHistoryEntry] = field(default_factory=list)
    credentials: List[CredentialEntry] = field(default_factory=list)
    clipboard: List[ClipboardEntry] = field(default_factory=list)
    typed_urls: List[TypedUrl] = field(default_factory=list)
    mft_entries: List[MftEntry] = field(default_factory=list)
    thumbnails: List[ThumbnailEntry] = field(default_factory=list)

    def validator_merge(self, other: "ExtractionResult") -> None:
        self.urls += other.urls
        self.browser_history += other.browser_history
        self.credentials += other.credentials
        self.clipboard += other.clipboard
        self.typed_urls += other.typed_urls
        self.mft_entries += other.mft_entries
        self.thumbnails += other.thumbnails


_URL_RE = re.compile(rb'https?://[^\x00\s"\'<>]{4,512}')
_SSH_HEADER = b"-----BEGIN"
_MFT_SIG = b"FILE"
_JPEG_THUMB = b"\xff\xd8\xff"


def validator_carve_urls_from_memory(mem: bytes) -> List[str]:
    return [m.group(0).decode("ascii", errors="replace") for m in _URL_RE.finditer(mem)]


def validator_extract_chromium_history(mem: bytes, profile: Optional[str] = None) -> List[BrowserHistoryEntry]:
    urls = validator_carve_urls_from_memory(mem)
    entries = []
    for u in urls:
        if "chrome" in u or "chromium" in u or profile:
            entries.append(BrowserHistoryEntry(url=u, profile=profile))
    return entries


def validator_extract_firefox_history(mem: bytes, profile: Optional[str] = None) -> List[BrowserHistoryEntry]:
    urls = validator_carve_urls_from_memory(mem)
    entries = []
    for u in urls:
        if "mozilla" in u or "firefox" in u or profile:
            entries.append(BrowserHistoryEntry(url=u, profile=profile))
    return entries


def validator_extract_ntlm_hashes(mem: bytes) -> List[CredentialEntry]:
    # LM/NT hash pattern: 16-byte sequences following known markers
    results = []
    marker = b"\x00lm\x00"
    idx = 0
    while True:
        pos = mem.find(marker, idx)
        if pos == -1:
            break
        chunk = mem[pos + len(marker): pos + len(marker) + 32]
        if len(chunk) == 32:
            results.append(CredentialEntry(kind="ntlm", value=chunk.hex()))
        idx = pos + 1
    return results


def validator_extract_ssh_private_keys(mem: bytes) -> List[CredentialEntry]:
    results = []
    idx = 0
    while True:
        pos = mem.find(_SSH_HEADER, idx)
        if pos == -1:
            break
        end = mem.find(b"-----END", pos)
        if end == -1:
            break
        end_tag = mem.find(b"-----", end + 5)
        if end_tag != -1:
            key_bytes = mem[pos: end_tag + 5]
            results.append(CredentialEntry(kind="ssh_private_key", value=key_bytes.decode("ascii", errors="replace")))
        idx = pos + 1
    return results


def validator_extract_clipboard_text(mem: bytes) -> List[ClipboardEntry]:
    # Look for UTF-16 LE null-terminated strings as a proxy for clipboard content
    texts = []
    i = 0
    while i < len(mem) - 3:
        if mem[i + 1] == 0 and 0x20 <= mem[i] < 0x7f:
            j = i
            chars = []
            while j + 1 < len(mem) and mem[j + 1] == 0 and mem[j] != 0:
                chars.append(chr(mem[j]))
                j += 2
            if len(chars) > 8:
                texts.append(ClipboardEntry("".join(chars)))
                i = j
                continue
        i += 1
    return texts


def validator_extract_typed_urls(mem: bytes) -> List[TypedUrl]:
    marker = b"TypedURLs"
    results = []
    idx = 0
    while True:
        pos = mem.find(marker, idx)
        if pos == -1:
            break
        # grab next apparent URL in neighbourhood
        snippet = mem[pos: pos + 512]
        for m in _URL_RE.finditer(snippet):
            results.append(TypedUrl(m.group(0).decode("ascii", errors="replace")))
        idx = pos + 1
    return results


def validator_extract_mft_entries(mem: bytes) -> List[MftEntry]:
    results = []
    idx = 0
    while True:
        pos = mem.find(_MFT_SIG, idx)
        if pos == -1:
            break
        entry = mem[pos: pos + 1024]
        if len(entry) == 1024:
            results.append(MftEntry(offset=pos, raw=entry))
        idx = pos + 1
    return results


def validator_extract_thumbnails(mem: bytes) -> List[ThumbnailEntry]:
    results = []
    idx = 0
    while True:
        pos = mem.find(_JPEG_THUMB, idx)
        if pos == -1:
            break
        results.append(ThumbnailEntry(offset=pos, data=mem[pos: pos + 4096]))
        idx = pos + 1
    return results


class ArtifactExtractor:
    def validator_extract(self, mem: bytes) -> ExtractionResult:
        r = ExtractionResult()
        r.urls = validator_carve_urls_from_memory(mem)
        r.credentials = validator_extract_ntlm_hashes(mem) + validator_extract_ssh_private_keys(mem)
        r.clipboard = validator_extract_clipboard_text(mem)
        r.typed_urls = validator_extract_typed_urls(mem)
        r.mft_entries = validator_extract_mft_entries(mem)
        r.thumbnails = validator_extract_thumbnails(mem)
        return r

    def validator_extract_chunks(self, chunks: List[Tuple[bytes, int]]) -> ExtractionResult:
        combined = ExtractionResult()
        for data, _offset in chunks:
            combined.validator_merge(self.validator_extract(data))
        return combined

    def validator_extract_window(self, mem: bytes, offset: int, length: int) -> ExtractionResult:
        window = mem[offset: offset + length]
        return self.validator_extract(window)


# ===========================================================================
# artifact_store.rs
# ===========================================================================

class ArtifactType:
    URL        = "url"
    CREDENTIAL = "credential"
    FILE       = "file"
    PROCESS    = "process"
    NETWORK    = "network"
    GENERIC    = "generic"


class ExportFormat:
    JSON = "json"
    CSV  = "csv"


@dataclass
class ForensicArtifact:
    id: str
    atype: str
    source: str
    timestamp: int
    confidence: float
    data: bytes = b""
    meta: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    _sha256: Optional[str] = field(default=None, repr=False)

    @staticmethod
    def validator_new(id: str, atype: str, source: str, ts: int, confidence: float) -> "ForensicArtifact":
        return ForensicArtifact(id=id, atype=atype, source=source, timestamp=ts, confidence=confidence)

    def validator_with_data(self, data: bytes) -> "ForensicArtifact":
        self.data = data
        self._sha256 = hashlib.sha256(data).hexdigest()
        return self

    def validator_set_data(self, data: bytes) -> None:
        self.data = data
        self._sha256 = hashlib.sha256(data).hexdigest()

    def validator_add_meta(self, key: str, value: str) -> None:
        self.meta[key] = value

    def validator_get_meta(self, key: str) -> Optional[str]:
        return self.meta.get(key)

    def validator_add_tag(self, tag: str) -> None:
        self.tags.append(tag)

    def validator_add_technique(self, id: str) -> None:
        self.techniques.append(id)

    def validator_is_high_confidence(self) -> bool:
        return self.confidence >= 0.7

    def validator_sha256_hex(self) -> Optional[str]:
        return self._sha256


@dataclass
class ArtifactQuery:
    _type_filter: Optional[str] = None
    _source_filter: Optional[str] = None
    _tag_filter: Optional[str] = None
    _technique_filter: Optional[str] = None

    @staticmethod
    def validator_new() -> "ArtifactQuery":
        return ArtifactQuery()

    def validator_of_type(self, t: str) -> "ArtifactQuery":
        self._type_filter = t
        return self

    def validator_from_source(self, s: str) -> "ArtifactQuery":
        self._source_filter = s
        return self

    def validator_with_tag(self, tag: str) -> "ArtifactQuery":
        self._tag_filter = tag
        return self

    def validator_with_technique(self, id: str) -> "ArtifactQuery":
        self._technique_filter = id
        return self

    def matches(self, a: ForensicArtifact) -> bool:
        if self._type_filter and a.atype != self._type_filter:
            return False
        if self._source_filter and a.source != self._source_filter:
            return False
        if self._tag_filter and self._tag_filter not in a.tags:
            return False
        if self._technique_filter and self._technique_filter not in a.techniques:
            return False
        return True


class ArtifactStoreError(Exception):
    pass


class ArtifactStore:
    def __init__(self, name: str):
        self.name = name
        self._store: Dict[str, ForensicArtifact] = {}

    @staticmethod
    def validator_new(name: str) -> "ArtifactStore":
        return ArtifactStore(name)

    def validator_store(self, artifact: ForensicArtifact) -> str:
        if artifact.id in self._store:
            raise ArtifactStoreError(f"Duplicate artifact: {artifact.id}")
        self._store[artifact.id] = artifact
        return artifact.id

    def validator_upsert(self, artifact: ForensicArtifact) -> str:
        self._store[artifact.id] = artifact
        return artifact.id

    def validator_remove(self, id: str) -> ForensicArtifact:
        if id not in self._store:
            raise ArtifactStoreError(f"Not found: {id}")
        return self._store.pop(id)

    def validator_verify(self, id: str) -> bool:
        a = self._store.get(id)
        if a is None:
            raise ArtifactStoreError(f"Not found: {id}")
        if not a.data:
            return True  # no data to verify
        return hashlib.sha256(a.data).hexdigest() == a._sha256

    def validator_get(self, id: str) -> Optional[ForensicArtifact]:
        return self._store.get(id)

    def validator_query(self, q: ArtifactQuery) -> List[ForensicArtifact]:
        return [a for a in self._store.values() if q.matches(a)]

    def validator_by_type(self) -> Dict[str, List[ForensicArtifact]]:
        result: Dict[str, List[ForensicArtifact]] = defaultdict(list)
        for a in self._store.values():
            result[a.atype].append(a)
        return dict(result)

    def validator_type_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for a in self._store.values():
            counts[a.atype] += 1
        return dict(counts)

    def validator_high_confidence(self, threshold: float) -> List[ForensicArtifact]:
        return [a for a in self._store.values() if a.confidence >= threshold]

    def validator_count(self) -> int:
        return len(self._store)

    def validator_is_empty(self) -> bool:
        return len(self._store) == 0

    def validator_avg_confidence(self) -> float:
        if not self._store:
            return 0.0
        return sum(a.confidence for a in self._store.values()) / len(self._store)

    def validator_export(self, format: str, path: str) -> None:
        p = Path(path)
        if format == ExportFormat.JSON:
            objs = [{"id": a.id, "type": a.atype, "source": a.source,
                     "ts": a.timestamp, "confidence": a.confidence,
                     "tags": a.tags, "techniques": a.techniques}
                    for a in self._store.values()]
            p.write_text(json.dumps(objs, indent=2))
        else:
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["id", "type", "source", "timestamp", "confidence"])
            for a in self._store.values():
                w.writerow([a.id, a.atype, a.source, a.timestamp, a.confidence])
            p.write_text(buf.getvalue())

    def validator_clear(self) -> None:
        self._store.clear()


# ===========================================================================
# collection_engine.rs
# ===========================================================================

@dataclass
class CollectionJob:
    id: str
    plugins: List[str] = field(default_factory=list)
    args: Dict[str, str] = field(default_factory=dict)
    case_id: Optional[str] = None

    @staticmethod
    def validator_new(id: str, plugins: List[str]) -> "CollectionJob":
        return CollectionJob(id=id, plugins=plugins)

    @staticmethod
    def validator_all_plugins(id: str) -> "CollectionJob":
        return CollectionJob(id=id, plugins=["__all__"])

    def validator_with_arg(self, key: str, value: str) -> "CollectionJob":
        self.args[key] = value
        return self

    def validator_for_case(self, case_id: str) -> "CollectionJob":
        self.case_id = case_id
        return self


@dataclass
class JobStatus:
    state: str = "pending"
    artifact_count: int = 0
    fail_reason: Optional[str] = None

    def validator_start(self) -> None:
        self.state = "running"

    def validator_complete(self, artifacts: int) -> None:
        self.state = "completed"
        self.artifact_count = artifacts

    def validator_fail(self, reason: str) -> None:
        self.state = "failed"
        self.fail_reason = reason


@dataclass
class EngineStats:
    jobs_run: int = 0
    artifacts_collected: int = 0
    errors: int = 0


class CollectionEngine:
    def __init__(self, store: ArtifactStore):
        self._store = store
        self._plugins: Dict[str, Any] = {}
        self._jobs: Dict[str, JobStatus] = {}
        self._stats = EngineStats()

    @staticmethod
    def validator_new(store: ArtifactStore) -> "CollectionEngine":
        return CollectionEngine(store)

    def validator_register_plugin(self, plugin: Any) -> None:
        self._plugins[plugin.name()] = plugin

    def validator_plugin_names(self) -> List[str]:
        return list(self._plugins.keys())

    def validator_plugin_count(self) -> int:
        return len(self._plugins)

    def validator_submit_job(self, job: CollectionJob) -> str:
        self._jobs[job.id] = JobStatus()
        return job.id

    def validator_job_status(self, id: str) -> Optional[JobStatus]:
        return self._jobs.get(id)

    def validator_run_job(self, job: CollectionJob, ctx: PluginContext) -> List[ForensicArtifact]:
        status = JobStatus()
        status.validator_start()
        collected: List[ForensicArtifact] = []
        plugin_names = list(self._plugins.keys()) if "__all__" in job.plugins else job.plugins
        for name in plugin_names:
            plugin = self._plugins.get(name)
            if plugin:
                try:
                    result = plugin.run(ctx)
                    collected.extend(result)
                except Exception:
                    self._stats.errors += 1
        status.validator_complete(len(collected))
        self._jobs[job.id] = status
        self._stats.jobs_run += 1
        self._stats.artifacts_collected += len(collected)
        return collected

    def validator_run_isolated(self, plugin_name: str, ctx: PluginContext) -> List[ForensicArtifact]:
        plugin = self._plugins.get(plugin_name)
        if plugin is None:
            raise KeyError(f"Plugin not found: {plugin_name}")
        return plugin.run(ctx)

    def validator_stats(self) -> EngineStats:
        return self._stats


# ===========================================================================
# evidence_collector.rs
# ===========================================================================

class EvidenceType:
    MEMORY_DUMP  = "memory_dump"
    DISK_IMAGE   = "disk_image"
    LOG_FILE     = "log_file"
    NETWORK_CAP  = "network_capture"
    REGISTRY     = "registry"
    GENERIC      = "generic"


@dataclass
class Evidence:
    id: str
    etype: str
    path: str
    analyst: str
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)
    confidence: int = 100
    verified: bool = False

    @staticmethod
    def validator_new(id: str, etype: str, path: str, analyst: str) -> "Evidence":
        return Evidence(id=id, etype=etype, path=path, analyst=analyst)

    @staticmethod
    def validator_from_bytes(id: str, etype: str, data: bytes, analyst: str) -> "Evidence":
        e = Evidence(id=id, etype=etype, path="", analyst=analyst)
        e.md5    = hashlib.md5(data).hexdigest()
        e.sha1   = hashlib.sha1(data).hexdigest()
        e.sha256 = hashlib.sha256(data).hexdigest()
        return e

    @staticmethod
    def validator_from_hashes(id: str, etype: str, md5: str, sha1: str, sha256: str) -> "Evidence":
        e = Evidence(id=id, etype=etype, path="", analyst="")
        e.md5 = md5; e.sha1 = sha1; e.sha256 = sha256
        return e

    def validator_verify(self, data: bytes) -> bool:
        return (
            hashlib.md5(data).hexdigest()    == self.md5    and
            hashlib.sha1(data).hexdigest()   == self.sha1   and
            hashlib.sha256(data).hexdigest() == self.sha256
        )

    def validator_tag(self, t: str) -> None:
        self.tags.append(t)

    def validator_set_meta(self, key: str, value: str) -> None:
        self.meta[key] = value

    def validator_summary(self) -> str:
        return f"id={self.id} type={self.etype} md5={self.md5} sha256={self.sha256}"


@dataclass
class ChainOfCustodyEntry:
    timestamp: int
    actor: str
    action: str
    hash: Optional[str] = None
    notes: Optional[str] = None
    location: Optional[str] = None

    @staticmethod
    def validator_new(ts: int, actor: str, action: str) -> "ChainOfCustodyEntry":
        return ChainOfCustodyEntry(timestamp=ts, actor=actor, action=action)

    def validator_with_hash(self, hash: str) -> "ChainOfCustodyEntry":
        self.hash = hash
        return self

    def validator_with_notes(self, notes: str) -> "ChainOfCustodyEntry":
        self.notes = notes
        return self

    def validator_with_location(self, loc: str) -> "ChainOfCustodyEntry":
        self.location = loc
        return self


@dataclass
class ChainOfCustody:
    evidence_id: str
    entries: List[ChainOfCustodyEntry] = field(default_factory=list)

    @staticmethod
    def validator_new(evidence_id: str) -> "ChainOfCustody":
        return ChainOfCustody(evidence_id=evidence_id)

    def validator_add(self, entry: ChainOfCustodyEntry) -> None:
        self.entries.append(entry)

    def validator_is_unbroken(self) -> bool:
        if len(self.entries) < 2:
            return True
        ts_list = [e.timestamp for e in self.entries]
        return all(ts_list[i] <= ts_list[i+1] for i in range(len(ts_list)-1))

    def validator_latest(self) -> Optional[ChainOfCustodyEntry]:
        return self.entries[-1] if self.entries else None

    def validator_to_log(self) -> str:
        lines = [f"Chain of Custody for {self.evidence_id}:"]
        for e in self.entries:
            lines.append(f"  [{e.timestamp}] {e.actor} — {e.action}")
        return "\n".join(lines)


@dataclass
class EvidenceChain:
    evidence: Evidence
    custody: ChainOfCustody = field(default=None)  # type: ignore

    def __post_init__(self):
        if self.custody is None:
            self.custody = ChainOfCustody(self.evidence.id)

    @staticmethod
    def validator_new(evidence: Evidence) -> "EvidenceChain":
        return EvidenceChain(evidence=evidence)

    def validator_log_action(self, ts: int, actor: str, action: str) -> None:
        self.custody.validator_add(ChainOfCustodyEntry.validator_new(ts, actor, action))

    def validator_is_intact(self) -> bool:
        return self.custody.validator_is_unbroken()


@dataclass
class EvidenceDatabase:
    _chains: Dict[str, EvidenceChain] = field(default_factory=dict)

    @staticmethod
    def validator_new() -> "EvidenceDatabase":
        return EvidenceDatabase()

    def validator_insert(self, chain: EvidenceChain) -> None:
        self._chains[chain.evidence.id] = chain

    def validator_get(self, id: str) -> Optional[EvidenceChain]:
        return self._chains.get(id)

    def validator_get_mut(self, id: str) -> Optional[EvidenceChain]:
        return self._chains.get(id)

    def validator_remove(self, id: str) -> Optional[EvidenceChain]:
        return self._chains.pop(id, None)

    def validator_len(self) -> int:
        return len(self._chains)

    def validator_is_empty(self) -> bool:
        return len(self._chains) == 0

    def validator_all(self) -> List[EvidenceChain]:
        return list(self._chains.values())

    def validator_find_by_sha256(self, sha256: str) -> Optional[EvidenceChain]:
        for c in self._chains.values():
            if c.evidence.sha256 == sha256:
                return c
        return None

    def validator_by_type(self, et: str) -> List[EvidenceChain]:
        return [c for c in self._chains.values() if c.evidence.etype == et]

    def validator_high_confidence(self, threshold: int) -> List[EvidenceChain]:
        return [c for c in self._chains.values() if c.evidence.confidence >= threshold]

    def validator_verified(self) -> List[EvidenceChain]:
        return [c for c in self._chains.values() if c.evidence.verified]


class EvidenceCollector:
    def __init__(self, analyst: str):
        self.analyst = analyst
        self._db = EvidenceDatabase.validator_new()
        self._counter = 0

    @staticmethod
    def validator_new(analyst: str) -> "EvidenceCollector":
        return EvidenceCollector(analyst)

    def validator_next_id(self) -> str:
        self._counter += 1
        return f"EV-{self._counter:06d}"

    def validator_collect_bytes(self, etype: str, data: bytes, path: str) -> str:
        id = self.validator_next_id()
        e = Evidence.validator_from_bytes(id, etype, data, self.analyst)
        e.path = path
        chain = EvidenceChain.validator_new(e)
        self._db.validator_insert(chain)
        return id

    def validator_collect_hashes(self, etype: str, md5: str, sha1: str, sha256: str, path: str) -> str:
        id = self.validator_next_id()
        e = Evidence.validator_from_hashes(id, etype, md5, sha1, sha256)
        e.path = path
        chain = EvidenceChain.validator_new(e)
        self._db.validator_insert(chain)
        return id

    def validator_verify(self, id: str, data: bytes) -> bool:
        chain = self._db.validator_get(id)
        if chain is None:
            return False
        return chain.evidence.validator_verify(data)

    def validator_log_transfer(self, id: str, ts_ms: int, recipient: str) -> None:
        chain = self._db.validator_get_mut(id)
        if chain:
            chain.validator_log_action(ts_ms, recipient, "transfer")

    def validator_mark_verified(self, id: str) -> None:
        chain = self._db.validator_get_mut(id)
        if chain:
            chain.evidence.verified = True

    def validator_count(self) -> int:
        return self._db.validator_len()


class EvidenceReporter:
    @staticmethod
    def validator_to_json(db: EvidenceDatabase) -> str:
        objs = []
        for c in db.validator_all():
            e = c.evidence
            objs.append({"id": e.id, "type": e.etype, "path": e.path,
                          "md5": e.md5, "sha256": e.sha256, "verified": e.verified})
        return json.dumps(objs, indent=2)

    @staticmethod
    def validator_to_csv(db: EvidenceDatabase) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "type", "path", "md5", "sha256", "verified"])
        for c in db.validator_all():
            e = c.evidence
            w.writerow([e.id, e.etype, e.path, e.md5, e.sha256, e.verified])
        return buf.getvalue()

    @staticmethod
    def validator_chain_log(chain: EvidenceChain) -> str:
        return chain.custody.validator_to_log()

    @staticmethod
    def validator_dfir_summary(db: EvidenceDatabase, case_id: str) -> str:
        all_chains = db.validator_all()
        verified = sum(1 for c in all_chains if c.evidence.verified)
        return (
            f"DFIR Report — Case: {case_id}\n"
            f"Total Evidence: {len(all_chains)}\n"
            f"Verified: {verified}\n"
        )


# ===========================================================================
# filesystem_carver.rs
# ===========================================================================

MAGIC_RULES = {
    "jpeg":   (b"\xff\xd8\xff",         ".jpg",  50 * 1024 * 1024),
    "png":    (b"\x89PNG",              ".png",  50 * 1024 * 1024),
    "pdf":    (b"%PDF-",                ".pdf", 200 * 1024 * 1024),
    "zip":    (b"PK\x03\x04",          ".zip", 500 * 1024 * 1024),
    "pe":     (b"MZ",                  ".exe",  50 * 1024 * 1024),
    "elf":    (b"\x7fELF",             ".elf",  50 * 1024 * 1024),
    "gif":    (b"GIF8",                ".gif",  20 * 1024 * 1024),
    "sqlite": (b"SQLite format 3\x00", ".db",   50 * 1024 * 1024),
}


@dataclass
class CarvingRule:
    magic: bytes
    ext: str
    max_size: int

    @staticmethod
    def validator_new(magic: bytes, ext: str, max_size: int) -> "CarvingRule":
        return CarvingRule(magic=magic, ext=ext, max_size=max_size)

    @staticmethod
    def validator_jpeg() -> "CarvingRule":
        m, e, s = MAGIC_RULES["jpeg"]; return CarvingRule(m, e, s)

    @staticmethod
    def validator_png() -> "CarvingRule":
        m, e, s = MAGIC_RULES["png"]; return CarvingRule(m, e, s)

    @staticmethod
    def validator_pdf() -> "CarvingRule":
        m, e, s = MAGIC_RULES["pdf"]; return CarvingRule(m, e, s)

    @staticmethod
    def validator_zip() -> "CarvingRule":
        m, e, s = MAGIC_RULES["zip"]; return CarvingRule(m, e, s)

    @staticmethod
    def validator_pe() -> "CarvingRule":
        m, e, s = MAGIC_RULES["pe"]; return CarvingRule(m, e, s)

    @staticmethod
    def validator_elf() -> "CarvingRule":
        m, e, s = MAGIC_RULES["elf"]; return CarvingRule(m, e, s)

    @staticmethod
    def validator_gif() -> "CarvingRule":
        m, e, s = MAGIC_RULES["gif"]; return CarvingRule(m, e, s)

    @staticmethod
    def validator_sqlite() -> "CarvingRule":
        m, e, s = MAGIC_RULES["sqlite"]; return CarvingRule(m, e, s)


@dataclass
class CarvedFile:
    offset: int
    ext: str
    data: bytes
    sha256: str = ""

    def __post_init__(self):
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.data).hexdigest()

    def validator_suggested_filename(self) -> str:
        return f"carved_{self.offset:016x}{self.ext}"

    def validator_save(self, dir: str) -> str:
        name = self.validator_suggested_filename()
        p = Path(dir) / name
        p.write_bytes(self.data)
        return str(p)


@dataclass
class CarvingStats:
    total_found: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)
    total_bytes: int = 0

    def validator_record(self, file: CarvedFile) -> None:
        self.total_found += 1
        self.by_type[file.ext] = self.by_type.get(file.ext, 0) + 1
        self.total_bytes += len(file.data)


def _carve_with_rules(data: bytes, rules: List[CarvingRule]) -> Tuple[List[CarvedFile], CarvingStats]:
    found: List[CarvedFile] = []
    stats = CarvingStats()
    for rule in rules:
        idx = 0
        while True:
            pos = data.find(rule.magic, idx)
            if pos == -1:
                break
            end = min(pos + rule.max_size, len(data))
            chunk = data[pos:end]
            cf = CarvedFile(offset=pos, ext=rule.ext, data=chunk)
            found.append(cf)
            stats.validator_record(cf)
            idx = pos + 1
    return found, stats


class FileCarver:
    def __init__(self):
        self._rules: List[CarvingRule] = []

    @staticmethod
    def validator_with_default_rules() -> "FileCarver":
        fc = FileCarver()
        for name in MAGIC_RULES:
            m, e, s = MAGIC_RULES[name]
            fc._rules.append(CarvingRule(m, e, s))
        return fc

    def validator_add_rule(self, rule: CarvingRule) -> None:
        self._rules.append(rule)

    def validator_clear_rules(self) -> None:
        self._rules.clear()

    def validator_carve(self, data: bytes) -> Tuple[List[CarvedFile], CarvingStats]:
        return _carve_with_rules(data, self._rules)


def validator_carve_raw_image(image_path: str) -> Tuple[List[CarvedFile], CarvingStats]:
    data = Path(image_path).read_bytes()
    fc = FileCarver.validator_with_default_rules()
    return fc.validator_carve(data)


def validator_carve_raw_image_with_rules(image_path: str, rules: List[CarvingRule]) -> Tuple[List[CarvedFile], CarvingStats]:
    data = Path(image_path).read_bytes()
    return _carve_with_rules(data, rules)


class SectorCarver:
    SECTOR_SIZE = 512

    @staticmethod
    def validator_new() -> "SectorCarver":
        return SectorCarver()

    def validator_carve_sectors(self, data: bytes) -> Tuple[List[CarvedFile], CarvingStats]:
        fc = FileCarver.validator_with_default_rules()
        aligned = data[: (len(data) // self.SECTOR_SIZE) * self.SECTOR_SIZE]
        return fc.validator_carve(aligned)

    def validator_deduplicate(self, files: List[CarvedFile]) -> List[CarvedFile]:
        seen = set()
        out = []
        for f in files:
            if f.sha256 not in seen:
                seen.add(f.sha256)
                out.append(f)
        return out

    def validator_count_duplicates(self, files: List[CarvedFile]) -> int:
        hashes = [f.sha256 for f in files]
        return len(hashes) - len(set(hashes))


class MagicScanner:
    def __init__(self):
        self._sigs: List[Tuple[bytes, str]] = []

    def validator_add(self, magic: bytes, name: str) -> None:
        self._sigs.append((magic, name))

    @staticmethod
    def validator_default_scanner() -> "MagicScanner":
        ms = MagicScanner()
        for name, (magic, ext, _) in MAGIC_RULES.items():
            ms.validator_add(magic, name)
        return ms

    def validator_scan_sectors(self, data: bytes, sector_size: int) -> List[Tuple[int, str]]:
        results = []
        for offset in range(0, len(data) - sector_size + 1, sector_size):
            sector = data[offset: offset + sector_size]
            for magic, name in self._sigs:
                if sector.startswith(magic):
                    results.append((offset, name))
                    break
        return results

    def validator_scan_raw(self, data: bytes) -> List[Tuple[int, str]]:
        results = []
        for magic, name in self._sigs:
            idx = 0
            while True:
                pos = data.find(magic, idx)
                if pos == -1:
                    break
                results.append((pos, name))
                idx = pos + 1
        results.sort(key=lambda x: x[0])
        return results


@dataclass
class CarvingReport:
    source: str
    files: List[CarvedFile]
    stats: CarvingStats

    @staticmethod
    def validator_build(source: str, files: List[CarvedFile], stats: CarvingStats) -> "CarvingReport":
        return CarvingReport(source=source, files=files, stats=stats)

    def validator_to_text_table(self) -> str:
        lines = [f"Carving Report — Source: {self.source}",
                 f"Total: {self.stats.total_found} files, {self.stats.total_bytes} bytes",
                 f"{'Offset':>18}  {'Ext':>6}  {'Size':>10}  SHA256"]
        for f in self.files:
            lines.append(f"  {f.offset:016x}  {f.ext:>6}  {len(f.data):>10}  {f.sha256}")
        return "\n".join(lines)


# ===========================================================================
# incident_timeline.rs
# ===========================================================================

class AttackPhase:
    INITIAL_ACCESS      = "initial_access"
    EXECUTION           = "execution"
    PERSISTENCE         = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION     = "defense_evasion"
    CREDENTIAL_ACCESS   = "credential_access"
    DISCOVERY           = "discovery"
    LATERAL_MOVEMENT    = "lateral_movement"
    COLLECTION          = "collection"
    EXFILTRATION        = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    UNKNOWN             = "unknown"

    _MAP = {
        "initial": "initial_access", "phishing": "initial_access",
        "exec": "execution", "run": "execution",
        "persist": "persistence", "autorun": "persistence",
        "privesc": "privilege_escalation", "uac": "privilege_escalation",
        "evasion": "defense_evasion", "obfusc": "defense_evasion",
        "cred": "credential_access", "hash": "credential_access",
        "discovery": "discovery", "enum": "discovery",
        "lateral": "lateral_movement", "psexec": "lateral_movement",
        "collect": "collection",
        "exfil": "exfiltration", "upload": "exfiltration",
        "c2": "command_and_control", "beacon": "command_and_control",
    }

    @staticmethod
    def validator_infer_from_category(category: str) -> str:
        cat = category.lower()
        for key, phase in AttackPhase._MAP.items():
            if key in cat:
                return phase
        return AttackPhase.UNKNOWN


class EventSource:
    SYSLOG   = "syslog"
    EDR      = "edr"
    FIREWALL = "firewall"
    MEMORY   = "memory"
    PREFETCH = "prefetch"
    REGISTRY = "registry"
    GENERIC  = "generic"


@dataclass
class IncidentEvent:
    ts_ms: int
    source: str
    category: str
    description: str
    confidence: float
    iocs: List[str] = field(default_factory=list)
    host: Optional[str] = None
    user: Optional[str] = None
    meta: Dict[str, str] = field(default_factory=dict)
    phase: str = AttackPhase.UNKNOWN

    def __post_init__(self):
        self.phase = AttackPhase.validator_infer_from_category(self.category)

    @staticmethod
    def validator_new(ts_ms: int, source: str, category: str, description: str, confidence: float) -> "IncidentEvent":
        return IncidentEvent(ts_ms=ts_ms, source=source, category=category,
                             description=description, confidence=confidence)

    def validator_with_ioc(self, ioc: str) -> "IncidentEvent":
        self.iocs.append(ioc); return self

    def validator_with_host(self, host: str) -> "IncidentEvent":
        self.host = host; return self

    def validator_with_user(self, user: str) -> "IncidentEvent":
        self.user = user; return self

    def validator_with_meta(self, key: str, value: str) -> "IncidentEvent":
        self.meta[key] = value; return self


@dataclass
class EventCluster:
    events: List[IncidentEvent] = field(default_factory=list)
    start_ms: int = 0
    end_ms: int = 0


class EventCorrelator:
    def __init__(self):
        self._events: List[IncidentEvent] = []

    @staticmethod
    def validator_from_events(events: List[IncidentEvent]) -> "EventCorrelator":
        c = EventCorrelator()
        c._events = list(events)
        return c

    def validator_unique_iocs(self) -> List[str]:
        seen = set()
        result = []
        for e in self._events:
            for ioc in e.iocs:
                if ioc not in seen:
                    seen.add(ioc); result.append(ioc)
        return result

    def validator_mean_confidence(self) -> float:
        if not self._events: return 0.0
        return sum(e.confidence for e in self._events) / len(self._events)

    def validator_add_event(self, event: IncidentEvent) -> None:
        self._events.append(event)

    def validator_add_events(self, events) -> None:
        self._events.extend(events)

    def validator_sort(self) -> None:
        self._events.sort(key=lambda e: e.ts_ms)

    def validator_cluster(self) -> List[EventCluster]:
        if not self._events:
            return []
        sorted_events = sorted(self._events, key=lambda e: e.ts_ms)
        gap_ms = 60_000
        clusters = []
        current = EventCluster(events=[sorted_events[0]],
                               start_ms=sorted_events[0].ts_ms,
                               end_ms=sorted_events[0].ts_ms)
        for ev in sorted_events[1:]:
            if ev.ts_ms - current.end_ms <= gap_ms:
                current.events.append(ev)
                current.end_ms = ev.ts_ms
            else:
                clusters.append(current)
                current = EventCluster(events=[ev], start_ms=ev.ts_ms, end_ms=ev.ts_ms)
        clusters.append(current)
        return clusters

    def validator_events(self) -> List[IncidentEvent]:
        return self._events

    def validator_events_by_source(self, source: str) -> List[IncidentEvent]:
        return [e for e in self._events if e.source == source]

    def validator_events_by_phase(self, phase: str) -> List[IncidentEvent]:
        return [e for e in self._events if e.phase == phase]

    def validator_events_in_range(self, start: int, end: int) -> List[IncidentEvent]:
        return [e for e in self._events if start <= e.ts_ms <= end]

    def validator_count_by_source(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for e in self._events:
            counts[e.source] += 1
        return dict(counts)

    def validator_count_by_phase(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for e in self._events:
            counts[e.phase] += 1
        return dict(counts)

    def validator_all_iocs(self) -> List[str]:
        result = []
        for e in self._events:
            result.extend(e.iocs)
        return result


@dataclass
class IncidentTimeline:
    case_id: str
    analyst: str
    _correlator: EventCorrelator = field(default_factory=EventCorrelator)
    _clusters: List[EventCluster] = field(default_factory=list)

    @staticmethod
    def validator_new(case_id: str, analyst: str) -> "IncidentTimeline":
        return IncidentTimeline(case_id=case_id, analyst=analyst)

    def validator_add_event(self, event: IncidentEvent) -> None:
        self._correlator.validator_add_event(event)

    def validator_merge_from(self, other: EventCorrelator) -> None:
        self._correlator.validator_add_events(other.validator_events())

    def validator_sort(self) -> None:
        self._correlator.validator_sort()

    def validator_clusters(self) -> List[EventCluster]:
        self._clusters = self._correlator.validator_cluster()
        return self._clusters

    def validator_events(self) -> List[IncidentEvent]:
        return self._correlator.validator_events()

    def validator_iocs(self) -> List[str]:
        return self._correlator.validator_unique_iocs()

    def validator_start_time_ms(self) -> Optional[int]:
        events = self._correlator.validator_events()
        return min(e.ts_ms for e in events) if events else None

    def validator_end_time_ms(self) -> Optional[int]:
        events = self._correlator.validator_events()
        return max(e.ts_ms for e in events) if events else None

    def validator_duration_ms(self) -> int:
        s = self.validator_start_time_ms()
        e = self.validator_end_time_ms()
        if s is None or e is None:
            return 0
        return e - s

    def validator_observed_phases(self) -> List[str]:
        seen = set()
        result = []
        for ev in self._correlator.validator_events():
            if ev.phase not in seen:
                seen.add(ev.phase); result.append(ev.phase)
        return result

    def validator_events_for_phase(self, phase: str) -> List[IncidentEvent]:
        return self._correlator.validator_events_by_phase(phase)


class TimelineExporter:
    @staticmethod
    def validator_to_json(timeline: IncidentTimeline) -> str:
        events = [{"ts": e.ts_ms, "source": e.source, "category": e.category,
                   "description": e.description, "confidence": e.confidence,
                   "phase": e.phase, "iocs": e.iocs}
                  for e in timeline.validator_events()]
        return json.dumps({"case_id": timeline.case_id, "events": events}, indent=2)

    @staticmethod
    def validator_to_csv(timeline: IncidentTimeline) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ts_ms", "source", "category", "description", "confidence", "phase"])
        for e in timeline.validator_events():
            w.writerow([e.ts_ms, e.source, e.category, e.description, e.confidence, e.phase])
        return buf.getvalue()

    @staticmethod
    def validator_to_html(timeline: IncidentTimeline) -> str:
        rows = "".join(
            f"<tr><td>{e.ts_ms}</td><td>{e.source}</td><td>{e.description}</td></tr>"
            for e in timeline.validator_events()
        )
        return f"<html><body><h1>Case {timeline.case_id}</h1><table>{rows}</table></body></html>"

    @staticmethod
    def validator_to_text(timeline: IncidentTimeline) -> str:
        lines = [f"Incident Timeline — Case: {timeline.case_id}"]
        for e in timeline.validator_events():
            lines.append(f"  [{e.ts_ms}] [{e.phase}] {e.source}: {e.description}")
        return "\n".join(lines)


# ===========================================================================
# malware_forensics.rs
# ===========================================================================

class EventCategory:
    PERSISTENCE         = "persistence"
    LATERAL_MOVEMENT    = "lateral_movement"
    CREDENTIAL_DUMP     = "credential_dump"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION        = "exfiltration"
    GENERIC             = "generic"


class Severity:
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class PersistenceType:
    REGISTRY_RUN_KEY = "registry_run_key"
    SCHEDULED_TASK   = "scheduled_task"
    SERVICE          = "service"
    STARTUP_FOLDER   = "startup_folder"
    ROOTKIT          = "rootkit"
    OTHER            = "other"


class C2Protocol:
    HTTP  = "http"
    HTTPS = "https"
    DNS   = "dns"
    ICMP  = "icmp"
    OTHER = "other"


@dataclass
class MalwareTimelineEvent:
    ts_ms: int
    category: str
    description: str


@dataclass
class MalwareTimeline:
    events: List[MalwareTimelineEvent] = field(default_factory=list)

    def validator_add_event(self, event: MalwareTimelineEvent) -> None:
        self.events.append(event)

    def validator_filter_by_category(self, cat: str) -> List[MalwareTimelineEvent]:
        return [e for e in self.events if e.category == cat]

    def validator_first_event(self) -> Optional[MalwareTimelineEvent]:
        return min(self.events, key=lambda e: e.ts_ms) if self.events else None

    def validator_last_event(self) -> Optional[MalwareTimelineEvent]:
        return max(self.events, key=lambda e: e.ts_ms) if self.events else None

    def validator_duration_secs(self) -> Optional[int]:
        if len(self.events) < 2: return None
        first = self.validator_first_event()
        last  = self.validator_last_event()
        return (last.ts_ms - first.ts_ms) // 1000

    def validator_category_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for e in self.events:
            counts[e.category] += 1
        return dict(counts)


@dataclass
class PersistenceMechanism:
    mtype: str
    location: str
    value: str
    host: Optional[str] = None
    mitre: Optional[str] = None
    evidence: List[str] = field(default_factory=list)

    @staticmethod
    def validator_new(mtype: str, location: str, value: str) -> "PersistenceMechanism":
        return PersistenceMechanism(mtype=mtype, location=location, value=value)

    def validator_with_host(self, host: str) -> "PersistenceMechanism":
        self.host = host; return self

    def validator_with_mitre(self, technique: str) -> "PersistenceMechanism":
        self.mitre = technique; return self

    def validator_with_evidence(self, evidence: List[str]) -> "PersistenceMechanism":
        self.evidence = evidence; return self

    @staticmethod
    def validator_run_key(hive: str, path: str, value: str) -> "PersistenceMechanism":
        return PersistenceMechanism(
            mtype=PersistenceType.REGISTRY_RUN_KEY,
            location=f"{hive}\\{path}",
            value=value,
            mitre="T1547.001"
        )

    @staticmethod
    def validator_mechanism(mtype: str, location: str) -> "PersistenceMechanism":
        return PersistenceMechanism(mtype=mtype, location=location, value="")


@dataclass
class LateralMovement:
    technique: str
    source: str
    target: str
    success: bool
    mitre: Optional[str] = None


@dataclass
class CredentialDump:
    tool: str
    host: str
    count: int


@dataclass
class C2Channel:
    protocol: str
    remote: str
    port: int = 0
    indicators: List[str] = field(default_factory=list)

    @staticmethod
    def validator_http(remote: str, port: int) -> "C2Channel":
        return C2Channel(protocol=C2Protocol.HTTP, remote=remote, port=port)

    @staticmethod
    def validator_https(remote: str) -> "C2Channel":
        return C2Channel(protocol=C2Protocol.HTTPS, remote=remote, port=443)

    @staticmethod
    def validator_dns(domain: str) -> "C2Channel":
        return C2Channel(protocol=C2Protocol.DNS, remote=domain, port=53)

    def validator_add_indicator(self, ioc: str) -> None:
        self.indicators.append(ioc)


@dataclass
class DataExfil:
    destination: str
    bytes_sent: int
    protocol: str


@dataclass
class RootkitPersistence:
    technique: str
    location: str


@dataclass
class MalwareCase:
    case_id: str
    host: str
    persistences: List[PersistenceMechanism] = field(default_factory=list)
    lateral_movements: List[LateralMovement] = field(default_factory=list)
    credential_dumps: List[CredentialDump] = field(default_factory=list)
    c2_channels: List[C2Channel] = field(default_factory=list)
    exfiltrations: List[DataExfil] = field(default_factory=list)
    timeline: MalwareTimeline = field(default_factory=MalwareTimeline)

    @staticmethod
    def validator_new(case_id: str, host: str) -> "MalwareCase":
        return MalwareCase(case_id=case_id, host=host)

    def validator_add_persistence(self, p: PersistenceMechanism) -> None:
        self.persistences.append(p)

    def validator_add_lateral_movement(self, lm: LateralMovement) -> None:
        self.lateral_movements.append(lm)

    def validator_add_credential_dump(self, cd: CredentialDump) -> None:
        self.credential_dumps.append(cd)

    def validator_add_c2(self, c2: C2Channel) -> None:
        self.c2_channels.append(c2)

    def validator_add_exfiltration(self, ex: DataExfil) -> None:
        self.exfiltrations.append(ex)

    def validator_add_event(self, ev: MalwareTimelineEvent) -> None:
        self.timeline.validator_add_event(ev)

    def validator_overall_severity(self) -> str:
        score = (len(self.c2_channels) * 2 + len(self.exfiltrations) * 3 +
                 len(self.persistences) + len(self.lateral_movements))
        if score >= 10: return Severity.CRITICAL
        if score >= 5:  return Severity.HIGH
        if score >= 2:  return Severity.MEDIUM
        return Severity.LOW

    def validator_unique_mitre_techniques(self) -> List[str]:
        seen = set()
        result = []
        for p in self.persistences:
            if p.mitre and p.mitre not in seen:
                seen.add(p.mitre); result.append(p.mitre)
        for lm in self.lateral_movements:
            if lm.mitre and lm.mitre not in seen:
                seen.add(lm.mitre); result.append(lm.mitre)
        return result

    def validator_has_registry_persistence(self) -> bool:
        return any(p.mtype == PersistenceType.REGISTRY_RUN_KEY for p in self.persistences)

    def validator_successful_lateral_movements(self) -> List[LateralMovement]:
        return [lm for lm in self.lateral_movements if lm.success]

    def validator_total_exfiltrated_bytes(self) -> int:
        return sum(ex.bytes_sent for ex in self.exfiltrations)

    def validator_c2_protocols(self) -> List[str]:
        seen = set()
        result = []
        for c in self.c2_channels:
            if c.protocol not in seen:
                seen.add(c.protocol); result.append(c.protocol)
        return result

    def validator_rootkit_persistence(self) -> List[RootkitPersistence]:
        return []  # placeholder — no rootkit type in this mock

    def validator_mitre_coverage_score(self) -> int:
        techniques = self.validator_unique_mitre_techniques()
        return min(100, len(techniques) * 10)

    def validator_report(self) -> str:
        return (
            f"Malware Case Report — ID: {self.case_id}, Host: {self.host}\n"
            f"  Severity: {self.validator_overall_severity()}\n"
            f"  Persistences: {len(self.persistences)}\n"
            f"  C2 channels: {len(self.c2_channels)}\n"
            f"  Exfiltrated bytes: {self.validator_total_exfiltrated_bytes()}\n"
            f"  MITRE techniques: {self.validator_unique_mitre_techniques()}\n"
        )


# ===========================================================================
# memory_acquisition.rs
# ===========================================================================

@dataclass
class MemorySegment:
    start: int
    end: int
    data: bytes = b""

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class LimeHeader:
    magic: int
    version: int
    start: int
    end: int
    reserved: bytes

    @staticmethod
    def validator_parse(data: bytes) -> Optional["LimeHeader"]:
        if len(data) < 32:
            return None
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic != 0x4c694d45:  # LiME magic
            return None
        version = struct.unpack_from("<I", data, 4)[0]
        start   = struct.unpack_from("<Q", data, 8)[0]
        end     = struct.unpack_from("<Q", data, 16)[0]
        return LimeHeader(magic=magic, version=version, start=start, end=end, reserved=data[24:32])


def validator_parse_lime_dump(data: bytes) -> List[MemorySegment]:
    segments = []
    offset = 0
    HEADER_SIZE = 32
    while offset + HEADER_SIZE <= len(data):
        hdr = LimeHeader.validator_parse(data[offset:])
        if hdr is None:
            break
        size = hdr.end - hdr.start
        seg_data = data[offset + HEADER_SIZE: offset + HEADER_SIZE + size]
        segments.append(MemorySegment(start=hdr.start, end=hdr.end, data=seg_data))
        offset += HEADER_SIZE + size
    return segments


@dataclass
class ElfProgramHeader:
    p_type: int
    p_offset: int
    p_paddr: int
    p_filesz: int
    p_memsz: int

    @staticmethod
    def validator_parse(data: bytes) -> Optional["ElfProgramHeader"]:
        if len(data) < 56:
            return None
        if data[:4] != b"\x7fELF":
            return None
        p_type   = struct.unpack_from("<I", data, 0)[0]
        p_offset = struct.unpack_from("<Q", data, 8)[0]
        p_paddr  = struct.unpack_from("<Q", data, 24)[0]
        p_filesz = struct.unpack_from("<Q", data, 32)[0]
        p_memsz  = struct.unpack_from("<Q", data, 40)[0]
        return ElfProgramHeader(p_type=p_type, p_offset=p_offset,
                                p_paddr=p_paddr, p_filesz=p_filesz, p_memsz=p_memsz)


def validator_parse_elf_core(data: bytes) -> List[MemorySegment]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return []
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        phdr_data = data[off: off + e_phentsize]
        if len(phdr_data) < 48:
            break
        p_type   = struct.unpack_from("<I", phdr_data, 0)[0]
        p_offset = struct.unpack_from("<Q", phdr_data, 8)[0]
        p_paddr  = struct.unpack_from("<Q", phdr_data, 24)[0]
        p_filesz = struct.unpack_from("<Q", phdr_data, 32)[0]
        if p_type == 1:  # PT_LOAD
            seg_data = data[p_offset: p_offset + p_filesz]
            segments.append(MemorySegment(start=p_paddr, end=p_paddr + p_filesz, data=seg_data))
    return segments


@dataclass
class WindowsCrashDumpHeader:
    signature: bytes
    valid: bool

    @staticmethod
    def validator_parse(data: bytes) -> Optional["WindowsCrashDumpHeader"]:
        if len(data) < 8:
            return None
        sig = data[:8]
        valid = sig in (b"PAGEDUMP", b"PAGEDU64")
        if not valid:
            return None
        return WindowsCrashDumpHeader(signature=sig, valid=valid)


@dataclass
class PfnEntry:
    page_frame: int

    @staticmethod
    def validator_parse(data: bytes) -> Optional["PfnEntry"]:
        if len(data) < 8:
            return None
        pf = struct.unpack_from("<Q", data, 0)[0]
        return PfnEntry(page_frame=pf)


def validator_parse_crash_dump_segments(data: bytes) -> List[MemorySegment]:
    hdr = WindowsCrashDumpHeader.validator_parse(data)
    if hdr is None:
        return []
    # Minimal: return one segment representing the entire dump body
    return [MemorySegment(start=0, end=len(data) - 0x2000, data=data[0x2000:])]


@dataclass
class HibernationHeader:
    signature: bytes

    @staticmethod
    def validator_parse(data: bytes) -> Optional["HibernationHeader"]:
        if len(data) < 4:
            return None
        sig = data[:4]
        if sig not in (b"HIBR", b"RSTR"):
            return None
        return HibernationHeader(signature=sig)


@dataclass
class DumpMetadata:
    format: str
    segment_count: int


@dataclass
class HibernationParseResult:
    segments: List[MemorySegment]
    metadata: DumpMetadata


def validator_parse_hiberfil(data: bytes) -> HibernationParseResult:
    hdr = HibernationHeader.validator_parse(data)
    if hdr is None:
        raise ValueError("Not a valid hiberfil.sys")
    seg = MemorySegment(start=0, end=len(data), data=data)
    return HibernationParseResult(
        segments=[seg],
        metadata=DumpMetadata(format="hiberfil", segment_count=1)
    )


class DumpAnalyser:
    @staticmethod
    def validator_analyse_file(data: bytes) -> List[MemorySegment]:
        if data[:4] == b"LiME" or (len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == 0x4c694d45):
            return validator_parse_lime_dump(data)
        if data[:4] == b"\x7fELF":
            return validator_parse_elf_core(data)
        if data[:8] in (b"PAGEDUMP", b"PAGEDU64"):
            return validator_parse_crash_dump_segments(data)
        if data[:4] in (b"HIBR", b"RSTR"):
            result = validator_parse_hiberfil(data)
            return result.segments
        return [MemorySegment(start=0, end=len(data), data=data)]

    @staticmethod
    def validator_build_result(segments: List[MemorySegment], metadata: DumpMetadata) -> HibernationParseResult:
        return HibernationParseResult(segments=segments, metadata=metadata)


@dataclass
class AcquisitionChunk:
    data: bytes
    is_last: bool
    offset: int


class StreamingAcquirer:
    def __init__(self):
        self._segments: List[MemorySegment] = []
        self._offset = 0

    @staticmethod
    def validator_new() -> "StreamingAcquirer":
        return StreamingAcquirer()

    def validator_process_chunk(self, data: bytes, is_last: bool) -> AcquisitionChunk:
        chunk = AcquisitionChunk(data=data, is_last=is_last, offset=self._offset)
        self._segments.append(MemorySegment(start=self._offset, end=self._offset + len(data), data=data))
        self._offset += len(data)
        return chunk

    def validator_segments(self) -> List[MemorySegment]:
        return self._segments


def validator_merge_adjacent_segments(segments: List[MemorySegment], gap_threshold: int) -> List[MemorySegment]:
    if not segments:
        return []
    sorted_segs = sorted(segments, key=lambda s: s.start)
    merged = [sorted_segs[0]]
    for seg in sorted_segs[1:]:
        prev = merged[-1]
        if seg.start - prev.end <= gap_threshold:
            merged[-1] = MemorySegment(start=prev.start, end=seg.end,
                                       data=prev.data + b"\x00" * (seg.start - prev.end) + seg.data)
        else:
            merged.append(seg)
    return merged


def validator_total_coverage(segments: List[MemorySegment]) -> int:
    return sum(s.size for s in segments)


def validator_find_segment(segments: List[MemorySegment], phys_addr: int) -> Optional[MemorySegment]:
    for s in segments:
        if s.start <= phys_addr < s.end:
            return s
    return None


# ===========================================================================
# memory_dump_analyzer.rs
# ===========================================================================

class DumpAnalyzerError(Exception):
    pass


@dataclass
class DumpImage:
    data: bytes

    def validator_read_bytes(self, offset: int, length: int) -> bytes:
        end = offset + length
        if end > len(self.data):
            raise DumpAnalyzerError(f"Out of range: {offset}+{length} > {len(self.data)}")
        return self.data[offset:end]

    def validator_read_u32_le(self, offset: int) -> int:
        chunk = self.validator_read_bytes(offset, 4)
        return struct.unpack_from("<I", chunk)[0]

    def validator_read_u64_le(self, offset: int) -> int:
        chunk = self.validator_read_bytes(offset, 8)
        return struct.unpack_from("<Q", chunk)[0]


@dataclass
class ProcessRecord:
    pid: int
    parent_pid: int
    name: str
    image_path: str = ""
    suspicious: bool = False

    @staticmethod
    def validator_new(pid: int, parent_pid: int, name: str) -> "ProcessRecord":
        return ProcessRecord(pid=pid, parent_pid=parent_pid, name=name)

    def validator_is_suspicious(self) -> bool:
        KNOWN_SUSPICIOUS = {"svchost.exe", "lsass.exe", "csrss.exe"}
        return self.suspicious or (self.parent_pid == 0 and self.name.lower() not in {"system", "idle"})

    def validator_display_path(self) -> str:
        return self.image_path or f"[{self.name}]"


@dataclass
class ModuleRecord:
    name: str
    base: int
    size: int
    path: str = ""

    @staticmethod
    def validator_new(name: str, base: int, size: int) -> "ModuleRecord":
        return ModuleRecord(name=name, base=base, size=size)

    def validator_path_buf(self) -> Path:
        return Path(self.path or self.name)


@dataclass
class NetworkConnectionRecord:
    protocol: str = "tcp"
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    state: str = "ESTABLISHED"
    pid: int = 0
    process_name: str = ""

    def validator_with_name(self, name: str) -> "NetworkConnectionRecord":
        self.process_name = name; return self

    @staticmethod
    def validator_tcp(pid: int, local: str, remote: str, state: str) -> "NetworkConnectionRecord":
        local_parts  = local.rsplit(":", 1)
        remote_parts = remote.rsplit(":", 1)
        return NetworkConnectionRecord(
            protocol="tcp",
            local_addr=local_parts[0], local_port=int(local_parts[1]) if len(local_parts) == 2 else 0,
            remote_addr=remote_parts[0], remote_port=int(remote_parts[1]) if len(remote_parts) == 2 else 0,
            state=state, pid=pid
        )

    def validator_endpoint_str(self) -> str:
        return f"{self.local_addr}:{self.local_port}->{self.remote_addr}:{self.remote_port}"


class HandleType:
    FILE    = "File"
    PROCESS = "Process"
    THREAD  = "Thread"
    MUTANT  = "Mutant"
    KEY     = "Key"
    OTHER   = "Other"


@dataclass
class HandleRecord:
    pid: int
    handle_id: int
    htype: str
    name: str = ""


@dataclass
class ProcessWalker:
    _procs: List[ProcessRecord] = field(default_factory=list)

    @staticmethod
    def validator_new() -> "ProcessWalker":
        return ProcessWalker()

    def validator_load_synthetic(self, procs: List[ProcessRecord]) -> None:
        self._procs = procs

    def validator_walk(self, image: DumpImage) -> int:
        # Minimal: scan for EPROCESS-like signatures (just return 0 for mock)
        return len(self._procs)

    def validator_all(self) -> List[ProcessRecord]:
        return self._procs

    def validator_by_pid(self, pid: int) -> Optional[ProcessRecord]:
        return next((p for p in self._procs if p.pid == pid), None)

    def validator_by_name(self, name: str) -> List[ProcessRecord]:
        return [p for p in self._procs if p.name.lower() == name.lower()]

    def validator_suspicious_processes(self) -> List[ProcessRecord]:
        return [p for p in self._procs if p.validator_is_suspicious()]

    def validator_pid_tree(self) -> Dict[int, List[int]]:
        tree: Dict[int, List[int]] = defaultdict(list)
        for p in self._procs:
            tree[p.parent_pid].append(p.pid)
        return dict(tree)


@dataclass
class ModuleWalker:
    _mods: List[ModuleRecord] = field(default_factory=list)

    @staticmethod
    def validator_new() -> "ModuleWalker":
        return ModuleWalker()

    def validator_load_synthetic(self, mods: List[ModuleRecord]) -> None:
        self._mods = mods

    def validator_walk(self, image: DumpImage) -> int:
        return len(self._mods)

    def validator_all(self) -> List[ModuleRecord]:
        return self._mods

    def validator_find_by_addr(self, addr: int) -> Optional[ModuleRecord]:
        return next((m for m in self._mods if m.base <= addr < m.base + m.size), None)

    def validator_find_by_name(self, name: str) -> Optional[ModuleRecord]:
        return next((m for m in self._mods if m.name.lower() == name.lower()), None)

    def validator_kernel_modules(self) -> List[ModuleRecord]:
        return [m for m in self._mods if m.base > 0x8000000000000000 or "ntoskrnl" in m.name.lower()]

    def validator_orphan_addresses(self, addrs: List[int]) -> List[int]:
        return [a for a in addrs if self.validator_find_by_addr(a) is None]


@dataclass
class HandleWalker:
    _handles: List[HandleRecord] = field(default_factory=list)

    @staticmethod
    def validator_new() -> "HandleWalker":
        return HandleWalker()

    def validator_load_synthetic(self, handles: List[HandleRecord]) -> None:
        self._handles = handles

    def validator_all(self) -> List[HandleRecord]:
        return self._handles

    def validator_by_pid(self, pid: int) -> List[HandleRecord]:
        return [h for h in self._handles if h.pid == pid]

    def validator_by_type(self, htype: str) -> List[HandleRecord]:
        return [h for h in self._handles if h.htype == htype]

    def validator_named_handles(self) -> List[HandleRecord]:
        return [h for h in self._handles if h.name]

    def validator_mutant_names(self) -> List[str]:
        return [h.name for h in self._handles if h.htype == HandleType.MUTANT and h.name]

    def validator_handle_count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for h in self._handles:
            counts[h.htype] += 1
        return dict(counts)


@dataclass
class NetworkWalker:
    _conns: List[NetworkConnectionRecord] = field(default_factory=list)

    @staticmethod
    def validator_new() -> "NetworkWalker":
        return NetworkWalker()

    def validator_load_synthetic(self, conns: List[NetworkConnectionRecord]) -> None:
        self._conns = conns

    def validator_all(self) -> List[NetworkConnectionRecord]:
        return self._conns

    def validator_by_pid(self, pid: int) -> List[NetworkConnectionRecord]:
        return [c for c in self._conns if c.pid == pid]

    def validator_tcp_connections(self) -> List[NetworkConnectionRecord]:
        return [c for c in self._conns if c.protocol.lower() == "tcp"]

    def validator_udp_connections(self) -> List[NetworkConnectionRecord]:
        return [c for c in self._conns if c.protocol.lower() == "udp"]

    def validator_unique_remote_ips(self) -> List[str]:
        seen = set()
        result = []
        for c in self._conns:
            if c.remote_addr and c.remote_addr not in seen:
                seen.add(c.remote_addr); result.append(c.remote_addr)
        return result


@dataclass
class DumpReport:
    iocs: List[str] = field(default_factory=list)
    threat_score_val: int = 0
    process_count: int = 0
    module_count: int = 0
    connection_count: int = 0
    errors: List[str] = field(default_factory=list)

    def validator_threat_score(self) -> int:
        return min(100, self.threat_score_val)

    def validator_has_ioc(self) -> bool:
        return len(self.iocs) > 0


class DumpAnalyzer:
    def __init__(self):
        self._procs: List[ProcessRecord] = []
        self._mods: List[ModuleRecord] = []
        self._handles: List[HandleRecord] = []
        self._conns: List[NetworkConnectionRecord] = []
        self._errors: List[str] = []

    @staticmethod
    def validator_new() -> "DumpAnalyzer":
        return DumpAnalyzer()

    def validator_load_processes(self, procs: List[ProcessRecord]) -> None:
        self._procs = procs

    def validator_load_modules(self, mods: List[ModuleRecord]) -> None:
        self._mods = mods

    def validator_load_handles(self, handles: List[HandleRecord]) -> None:
        self._handles = handles

    def validator_load_network(self, conns: List[NetworkConnectionRecord]) -> None:
        self._conns = conns

    def validator_analyze_image(self, image: DumpImage) -> None:
        pass  # would walk image structures

    def validator_errors(self) -> List[str]:
        return self._errors

    def validator_generate_report(self) -> DumpReport:
        iocs = []
        score = 0
        for p in self._procs:
            if p.validator_is_suspicious():
                iocs.append(f"suspicious_process:{p.name}")
                score += 10
        for c in self._conns:
            iocs.append(f"remote_ip:{c.remote_addr}")
            score += 5
        return DumpReport(
            iocs=iocs,
            threat_score_val=score,
            process_count=len(self._procs),
            module_count=len(self._mods),
            connection_count=len(self._conns),
            errors=self._errors,
        )


# ===========================================================================
# os_adapter.rs
# ===========================================================================

@dataclass
class OsProcessInfo:
    pid: int
    name: str

    @staticmethod
    def validator_new(pid: int, name: str) -> "OsProcessInfo":
        return OsProcessInfo(pid=pid, name=name)


@dataclass
class FileInfo:
    path: str
    size: int

    @staticmethod
    def validator_new(path: str, size: int) -> "FileInfo":
        return FileInfo(path=path, size=size)


@dataclass
class RegistryEntry:
    key_path: str
    value_name: str
    data_str: str

    @staticmethod
    def validator_new(key_path: str, value_name: str, data_str: str) -> "RegistryEntry":
        return RegistryEntry(key_path=key_path, value_name=value_name, data_str=data_str)


@dataclass
class LoadedModule:
    name: str
    base_address: int
    size: int

    @staticmethod
    def validator_new(name: str, base_address: int, size: int) -> "LoadedModule":
        return LoadedModule(name=name, base_address=base_address, size=size)


class OsAdapter:
    def __init__(self, proc_root: str = "/proc"):
        self.proc_root = proc_root

    @staticmethod
    def validator_new() -> "OsAdapter":
        return OsAdapter()

    @staticmethod
    def validator_with_proc_root(proc_root: str) -> "OsAdapter":
        return OsAdapter(proc_root=proc_root)


@dataclass
class OsNetworkConnection:
    protocol: str
    local: str
    remote: str
    state: str


class MockOsAdapter:
    def __init__(self, platform: str):
        self.platform = platform
        self._processes: List[OsProcessInfo] = []
        self._files: Dict[str, List[FileInfo]] = {}
        self._registry: Dict[str, List[RegistryEntry]] = {}
        self._connections: List[OsNetworkConnection] = []
        self._memory: Dict[Tuple[int, int], bytes] = {}
        self._modules: Dict[int, List[LoadedModule]] = {}
        self._fail_next_flag = False

    @staticmethod
    def validator_new(platform: str) -> "MockOsAdapter":
        return MockOsAdapter(platform)

    def validator_add_process(self, p: OsProcessInfo) -> None:
        self._processes.append(p)

    def validator_add_files(self, path: str, files: List[FileInfo]) -> None:
        self._files[path] = files

    def validator_add_registry(self, key: str, entries: List[RegistryEntry]) -> None:
        self._registry[key] = entries

    def validator_add_connection(self, conn: OsNetworkConnection) -> None:
        self._connections.append(conn)

    def validator_set_memory(self, pid: int, address: int, data: bytes) -> None:
        self._memory[(pid, address)] = data

    def validator_add_modules(self, pid: int, modules: List[LoadedModule]) -> None:
        self._modules[pid] = modules

    def validator_fail_next(self) -> None:
        self._fail_next_flag = True


# ===========================================================================
# prefetch_analyzer.rs
# ===========================================================================

@dataclass
class FileMetric:
    path: str
    load_count: int = 1

    def validator_is_dll(self) -> bool:
        return self.path.lower().endswith(".dll")

    def validator_is_exe(self) -> bool:
        return self.path.lower().endswith(".exe")

    def validator_base_name(self) -> str:
        return Path(self.path).name


@dataclass
class VolumeInfo:
    device_path: str
    serial: int
    file_system: str = "NTFS"

    def validator_serial_hex(self) -> str:
        return f"{self.serial:08X}"


@dataclass
class PrefetchFile:
    exe_name: str
    run_count: int
    last_run_times: List[int] = field(default_factory=list)
    files: List[FileMetric] = field(default_factory=list)
    volumes: List[VolumeInfo] = field(default_factory=list)
    version: int = 30

    def validator_most_recent_run(self) -> int:
        return max(self.last_run_times) if self.last_run_times else 0

    @staticmethod
    def validator_filetime_to_utc(filetime: int) -> str:
        EPOCH_DIFF = 116444736000000000
        if filetime < EPOCH_DIFF:
            return "1601-01-01T00:00:00Z"
        unix_us = (filetime - EPOCH_DIFF) // 10
        unix_s  = unix_us // 1_000_000
        import datetime
        dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=unix_s)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def validator_referenced_dlls(self) -> List[FileMetric]:
        return [f for f in self.files if f.validator_is_dll()]

    def validator_referenced_executables(self) -> List[FileMetric]:
        return [f for f in self.files if f.validator_is_exe()]

    def validator_extension_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for f in self.files:
            ext = Path(f.path).suffix.lower()
            counts[ext] += 1
        return dict(counts)

    @staticmethod
    def validator_from_bytes(data: bytes) -> "PrefetchFile":
        # Minimal stub: check for MAM header or version bytes
        if len(data) < 8:
            raise ValueError("Too short for prefetch")
        # version at offset 0, signature at offset 4
        sig = data[4:8]
        if sig != b"SCCA":
            raise ValueError("Invalid prefetch signature")
        version = struct.unpack_from("<I", data, 0)[0]
        exe_name = data[16:76].decode("utf-16-le", errors="replace").rstrip("\x00")
        run_count = struct.unpack_from("<I", data, 208)[0] if len(data) > 212 else 0
        return PrefetchFile(exe_name=exe_name, run_count=run_count, version=version)

    @staticmethod
    def validator_from_file(path: str) -> "PrefetchFile":
        return PrefetchFile.validator_from_bytes(Path(path).read_bytes())

    def validator_summary(self) -> str:
        last = self.validator_filetime_to_utc(self.validator_most_recent_run())
        return f"{self.exe_name} | runs={self.run_count} | last={last} | volumes={len(self.volumes)}"

    def validator_files_with_extension(self, ext: str) -> List[str]:
        ext = ext.lower()
        return [f.path for f in self.files if Path(f.path).suffix.lower() == ext]

    def validator_most_loaded_dll(self) -> Optional[FileMetric]:
        dlls = self.validator_referenced_dlls()
        return max(dlls, key=lambda d: d.load_count) if dlls else None


def validator_parse_prefetch(data: bytes) -> PrefetchFile:
    return PrefetchFile.validator_from_bytes(data)


@dataclass
class PrefetchDirectory:
    files: List[PrefetchFile] = field(default_factory=list)

    @staticmethod
    def validator_load(dir: str) -> "PrefetchDirectory":
        d = PrefetchDirectory()
        for p in Path(dir).glob("*.pf"):
            try:
                d.files.append(PrefetchFile.validator_from_file(str(p)))
            except Exception:
                pass
        return d

    def validator_most_executed(self) -> Optional[PrefetchFile]:
        return max(self.files, key=lambda f: f.run_count) if self.files else None

    def validator_frequent_apps(self, threshold: int) -> List[PrefetchFile]:
        return [f for f in self.files if f.run_count >= threshold]

    def validator_dll_frequency(self) -> Dict[str, int]:
        freq: Dict[str, int] = defaultdict(int)
        for pf in self.files:
            for dll in pf.validator_referenced_dlls():
                freq[dll.validator_base_name().lower()] += 1
        return dict(freq)


@dataclass
class PrefetchTimelineEvent:
    ts_filetime: int
    exe_name: str


def validator_build_execution_timeline(prefetch_files: List[PrefetchFile]) -> List[PrefetchTimelineEvent]:
    events = []
    for pf in prefetch_files:
        for ts in pf.last_run_times:
            events.append(PrefetchTimelineEvent(ts_filetime=ts, exe_name=pf.exe_name))
    events.sort(key=lambda e: e.ts_filetime)
    return events


# ===========================================================================
# registry_hive_analyzer.rs
# ===========================================================================

class HiveValueType:
    REG_SZ        = "REG_SZ"
    REG_EXPAND_SZ = "REG_EXPAND_SZ"
    REG_DWORD     = "REG_DWORD"
    REG_QWORD     = "REG_QWORD"
    REG_MULTI_SZ  = "REG_MULTI_SZ"
    REG_BINARY    = "REG_BINARY"


@dataclass
class HiveValue:
    name: str
    vtype: str
    raw: bytes

    def validator_as_string(self) -> Optional[str]:
        if self.vtype in (HiveValueType.REG_SZ, HiveValueType.REG_EXPAND_SZ):
            try:
                return self.raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            except Exception:
                return None
        return None

    def validator_as_dword(self) -> Optional[int]:
        if self.vtype == HiveValueType.REG_DWORD and len(self.raw) >= 4:
            return struct.unpack_from("<I", self.raw)[0]
        return None

    def validator_as_qword(self) -> Optional[int]:
        if self.vtype == HiveValueType.REG_QWORD and len(self.raw) >= 8:
            return struct.unpack_from("<Q", self.raw)[0]
        return None

    def validator_as_multi_sz(self) -> Optional[List[str]]:
        if self.vtype == HiveValueType.REG_MULTI_SZ:
            try:
                text = self.raw.decode("utf-16-le", errors="replace")
                return [s for s in text.split("\x00") if s]
            except Exception:
                return None
        return None

    def validator_hex_preview(self) -> str:
        preview = self.raw[:16]
        return " ".join(f"{b:02x}" for b in preview) + ("..." if len(self.raw) > 16 else "")


@dataclass
class HiveKey:
    path: str
    last_write: int = 0
    values: List[HiveValue] = field(default_factory=list)
    subkeys: List["HiveKey"] = field(default_factory=list)

    def validator_get_value(self, name: str) -> Optional[HiveValue]:
        return next((v for v in self.values if v.name.lower() == name.lower()), None)

    def validator_last_write_utc_approx(self) -> str:
        if self.last_write == 0:
            return "unknown"
        return PrefetchFile.validator_filetime_to_utc(self.last_write)


class ForensicsError(Exception):
    pass


@dataclass
class RegistryHiveAnalyzer:
    _data: bytes = b""
    _root: Optional[HiveKey] = None

    @staticmethod
    def validator_from_bytes(data: bytes) -> "RegistryHiveAnalyzer":
        if len(data) < 4 or data[:4] != b"regf":
            raise ForensicsError("Invalid REGF signature")
        a = RegistryHiveAnalyzer(_data=data)
        a._root = HiveKey(path="\\")
        return a

    @staticmethod
    def validator_from_file(path: str) -> "RegistryHiveAnalyzer":
        return RegistryHiveAnalyzer.validator_from_bytes(Path(path).read_bytes())

    def validator_root_key(self) -> HiveKey:
        if self._root is None:
            raise ForensicsError("No root key")
        return self._root

    def _all_keys(self, key: HiveKey) -> List[HiveKey]:
        result = [key]
        for sub in key.subkeys:
            result.extend(self._all_keys(sub))
        return result

    def validator_enumerate_all_keys(self) -> List[HiveKey]:
        root = self.validator_root_key()
        return self._all_keys(root)

    def validator_find_key(self, path_suffix: str) -> Optional[HiveKey]:
        for key in self.validator_enumerate_all_keys():
            if key.path.lower().endswith(path_suffix.lower()):
                return key
        return None

    def validator_query_values(self, path_suffix: str) -> List[HiveValue]:
        key = self.validator_find_key(path_suffix)
        return key.values if key else []

    def validator_all_values_by_path(self) -> Dict[str, List[HiveValue]]:
        result = {}
        for key in self.validator_enumerate_all_keys():
            result[key.path] = key.values
        return result


def validator_parse_hive(path: str) -> RegistryHiveAnalyzer:
    return RegistryHiveAnalyzer.validator_from_file(path)


def validator_parse_hive_bytes(data: bytes) -> RegistryHiveAnalyzer:
    return RegistryHiveAnalyzer.validator_from_bytes(data)


class HiveValueFormatter:
    @staticmethod
    def validator_format(value: HiveValue) -> str:
        s = value.validator_as_string()
        if s is not None:
            return s
        d = value.validator_as_dword()
        if d is not None:
            return str(d)
        q = value.validator_as_qword()
        if q is not None:
            return str(q)
        m = value.validator_as_multi_sz()
        if m is not None:
            return "; ".join(m)
        return value.validator_hex_preview()


@dataclass
class HiveDiff:
    added_keys: List[str] = field(default_factory=list)
    removed_keys: List[str] = field(default_factory=list)
    modified_values: List[str] = field(default_factory=list)

    @staticmethod
    def validator_compute(a: RegistryHiveAnalyzer, b: RegistryHiveAnalyzer) -> "HiveDiff":
        keys_a = {k.path for k in a.validator_enumerate_all_keys()}
        keys_b = {k.path for k in b.validator_enumerate_all_keys()}
        return HiveDiff(
            added_keys=sorted(keys_b - keys_a),
            removed_keys=sorted(keys_a - keys_b),
            modified_values=[],  # detailed diff would require value comparison
        )


# ===========================================================================
# timeline_builder.rs
# ===========================================================================

@dataclass
class EventSeverity:
    value: int

    @staticmethod
    def validator_new(v: int) -> "EventSeverity":
        return EventSeverity(value=max(0, min(100, v)))

    def __le__(self, other: "EventSeverity") -> bool:
        return self.value <= other.value

    def __ge__(self, other: "EventSeverity") -> bool:
        return self.value >= other.value


@dataclass
class BuilderTimelineEvent:
    timestamp_ms: int
    source: str
    description: str
    severity: EventSeverity
    actor: str = ""
    artifact_id: str = ""
    category: str = "generic"

    @staticmethod
    def validator_new(ts: int, source: str, description: str, severity: EventSeverity) -> "BuilderTimelineEvent":
        return BuilderTimelineEvent(timestamp_ms=ts, source=source,
                                    description=description, severity=severity)

    def validator_with_actor(self, actor: str) -> "BuilderTimelineEvent":
        self.actor = actor; return self

    def validator_with_artifact(self, id: str) -> "BuilderTimelineEvent":
        self.artifact_id = id; return self


@dataclass
class TimelineFilter:
    _category: Optional[str] = None
    _source: Optional[str] = None

    @staticmethod
    def validator_new() -> "TimelineFilter":
        return TimelineFilter()

    def validator_with_category(self, cat: str) -> "TimelineFilter":
        self._category = cat; return self

    def validator_with_source(self, src: str) -> "TimelineFilter":
        self._source = src; return self

    def validator_matches(self, event: BuilderTimelineEvent) -> bool:
        if self._category and event.category != self._category:
            return False
        if self._source and event.source != self._source:
            return False
        return True


@dataclass
class ForensicTimeline:
    _events: List[BuilderTimelineEvent] = field(default_factory=list)

    @staticmethod
    def validator_new() -> "ForensicTimeline":
        return ForensicTimeline()

    def validator_add_event(self, event: BuilderTimelineEvent) -> None:
        self._events.append(event)

    def validator_sort(self) -> None:
        self._events.sort(key=lambda e: e.timestamp_ms)

    def validator_events(self) -> List[BuilderTimelineEvent]:
        return self._events

    def validator_filter(self, f: TimelineFilter) -> List[BuilderTimelineEvent]:
        return [e for e in self._events if f.validator_matches(e)]

    def validator_events_in_range(self, start_ms: int, end_ms: int) -> List[BuilderTimelineEvent]:
        return [e for e in self._events if start_ms <= e.timestamp_ms <= end_ms]

    def validator_high_severity(self, threshold: EventSeverity) -> List[BuilderTimelineEvent]:
        return [e for e in self._events if e.severity >= threshold]

    def validator_events_from_source(self, source: str) -> List[BuilderTimelineEvent]:
        return [e for e in self._events if e.source == source]

    def validator_to_json(self) -> str:
        objs = [{"ts": e.timestamp_ms, "source": e.source,
                 "description": e.description, "severity": e.severity.value}
                for e in self._events]
        return json.dumps(objs, indent=2)

    def validator_to_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["timestamp_ms", "source", "description", "severity", "actor", "artifact_id"])
        for e in self._events:
            w.writerow([e.timestamp_ms, e.source, e.description,
                        e.severity.value, e.actor, e.artifact_id])
        return buf.getvalue()

    def validator_merge(self, other: "ForensicTimeline") -> None:
        self._events.extend(other._events)


@dataclass
class ArtifactEntry:
    timestamp_ms: int
    description: str
    source: str = "unknown"
    severity: int = 50
    category: str = "generic"


class TimelineBuilder:
    def __init__(self):
        self._default_source: str = "unknown"
        self._entries: List[ArtifactEntry] = []

    @staticmethod
    def validator_new() -> "TimelineBuilder":
        return TimelineBuilder()

    def validator_with_default_source(self, src: str) -> "TimelineBuilder":
        self._default_source = src; return self

    def validator_add_artifact(self, entry: ArtifactEntry) -> None:
        self._entries.append(entry)

    def validator_add_artifacts(self, entries) -> None:
        for e in entries:
            self._entries.append(e)

    def validator_build(self) -> ForensicTimeline:
        tl = ForensicTimeline.validator_new()
        for e in self._entries:
            ev = BuilderTimelineEvent.validator_new(
                e.timestamp_ms,
                e.source or self._default_source,
                e.description,
                EventSeverity.validator_new(e.severity)
            )
            ev.category = e.category
            tl.validator_add_event(ev)
        tl.validator_sort()
        return tl


# ===========================================================================
# timeline_correlator.rs
# ===========================================================================

@dataclass
class CorrelatorEvent:
    timestamp_ms: int
    source: str
    description: str
    severity: int
    normalised_ms: int = 0

    def validator_timestamp_seconds(self) -> float:
        return self.timestamp_ms / 1000.0

    def validator_to_csv_line(self) -> str:
        return f"{self.timestamp_ms},{self.source},{self.description},{self.severity}"


@dataclass
class TimelineGap:
    start_ms: int
    end_ms: int
    suspicious: bool = False

    @property
    def duration_ms(self) -> int:
        return self.end_ms - self.start_ms


@dataclass
class TemporalPattern:
    kind: str
    start_ms: int
    end_ms: int
    event_count: int


@dataclass
class TimelineSummary:
    event_count: int
    gap_count: int
    pattern_count: int
    duration_ms: int


class TimestampNormaliser:
    def __init__(self):
        self._offsets: Dict[str, int] = {}

    @staticmethod
    def validator_new() -> "TimestampNormaliser":
        return TimestampNormaliser()

    def validator_set_offset(self, source: str, offset_ms: int) -> None:
        self._offsets[source] = offset_ms

    def validator_normalise(self, raw_ms: int, source: str) -> int:
        return raw_ms + self._offsets.get(source, 0)

    def validator_compute_skew(self, source_a: str, ts_a: int, source_b: str, ts_b: int) -> None:
        skew = ts_a - ts_b
        self._offsets[source_b] = self._offsets.get(source_b, 0) + skew


class CorrelatedTimeline:
    def __init__(self):
        self._events: List[CorrelatorEvent] = []
        self._normaliser = TimestampNormaliser()
        self._gaps: List[TimelineGap] = []
        self._patterns: List[TemporalPattern] = []

    @staticmethod
    def validator_new() -> "CorrelatedTimeline":
        return CorrelatedTimeline()

    def validator_with_normaliser(self, normaliser: TimestampNormaliser) -> "CorrelatedTimeline":
        self._normaliser = normaliser; return self

    def validator_add_event(self, ev: CorrelatorEvent) -> None:
        ev.normalised_ms = self._normaliser.validator_normalise(ev.timestamp_ms, ev.source)
        self._events.append(ev)

    def validator_record(self, source: str, ts_ms: int, description: str, severity: int) -> None:
        ev = CorrelatorEvent(timestamp_ms=ts_ms, source=source,
                              description=description, severity=severity)
        self.validator_add_event(ev)

    def validator_sort(self) -> None:
        self._events.sort(key=lambda e: e.normalised_ms)

    def validator_events(self) -> List[CorrelatorEvent]:
        return self._events

    def validator_events_sorted(self) -> List[CorrelatorEvent]:
        self.validator_sort()
        return self._events

    def validator_filter_by_source(self, source: str) -> List[CorrelatorEvent]:
        return [e for e in self._events if e.source == source]

    def validator_filter_by_severity(self, min_severity: int) -> List[CorrelatorEvent]:
        return [e for e in self._events if e.severity >= min_severity]

    def validator_filter_by_window(self, start_ms: int, end_ms: int) -> List[CorrelatorEvent]:
        return [e for e in self._events if start_ms <= e.normalised_ms <= end_ms]

    def validator_detect_gaps(self, min_gap_ms: int) -> None:
        self.validator_sort()
        self._gaps = []
        for i in range(1, len(self._events)):
            gap = self._events[i].normalised_ms - self._events[i-1].normalised_ms
            if gap >= min_gap_ms:
                suspicious = gap > min_gap_ms * 10
                self._gaps.append(TimelineGap(
                    start_ms=self._events[i-1].normalised_ms,
                    end_ms=self._events[i].normalised_ms,
                    suspicious=suspicious
                ))

    def validator_gaps(self) -> List[TimelineGap]:
        return self._gaps

    def validator_suspicious_gaps(self) -> List[TimelineGap]:
        return [g for g in self._gaps if g.suspicious]

    def validator_detect_patterns(self, window_ms: int) -> None:
        self.validator_sort()
        self._patterns = []
        if len(self._events) < 3:
            return
        start = self._events[0].normalised_ms
        count = 0
        for ev in self._events:
            if ev.normalised_ms - start <= window_ms:
                count += 1
            else:
                if count >= 3:
                    self._patterns.append(TemporalPattern(
                        kind="burst", start_ms=start,
                        end_ms=start + window_ms, event_count=count
                    ))
                start = ev.normalised_ms
                count = 1

    def validator_patterns(self) -> List[TemporalPattern]:
        return self._patterns

    def validator_export_plaso_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["datetime", "source_short", "message", "severity"])
        for e in self._events:
            w.writerow([e.normalised_ms, e.source, e.description, e.severity])
        return buf.getvalue()

    def validator_summary(self) -> TimelineSummary:
        if not self._events:
            duration = 0
        else:
            self.validator_sort()
            duration = self._events[-1].normalised_ms - self._events[0].normalised_ms
        return TimelineSummary(
            event_count=len(self._events),
            gap_count=len(self._gaps),
            pattern_count=len(self._patterns),
            duration_ms=duration
        )


# ===========================================================================
# Self-test
# ===========================================================================

def _self_test() -> None:
    # Hashing
    assert validator_compute_md5(b"hello") == "5d41402abc4b2a76b9719d911017c592"
    assert len(validator_compute_sha256(b"test")) == 64

    # EvidenceHash
    eh = EvidenceHash.validator_compute(b"abc", HashAlgorithm.SHA256)
    assert eh.validator_verify(b"abc")
    assert not eh.validator_verify(b"xyz")

    # Timeline
    tl = Timeline.validator_new()
    tl.validator_add_event(TimelineEvent.validator_new(200, "user", "action"))
    tl.validator_add_event(TimelineEvent.validator_new(100, "sys", "boot"))
    tl.validator_sort()
    assert tl.events[0].timestamp_ms == 100

    # ArtifactStore
    store = ArtifactStore.validator_new("test")
    a = ForensicArtifact.validator_new("A1", ArtifactType.URL, "mem", 0, 0.9)
    a.validator_add_tag("c2")
    store.validator_store(a)
    assert store.validator_count() == 1
    assert store.validator_avg_confidence() == 0.9

    # EvidenceCollector
    col = EvidenceCollector.validator_new("analyst1")
    id1 = col.validator_collect_bytes(EvidenceType.MEMORY_DUMP, b"rawdata", "/tmp/dump.raw")
    assert col.validator_count() == 1
    assert col.validator_verify(id1, b"rawdata")

    # CarvingRule + FileCarver
    fc = FileCarver.validator_with_default_rules()
    img = b"\x00" * 100 + b"\xff\xd8\xff\xe0" + b"\xaa" * 200 + b"PK\x03\x04" + b"\xbb" * 50
    carved, stats = fc.validator_carve(img)
    assert len(carved) >= 2

    # IncidentTimeline
    itl = IncidentTimeline.validator_new("CASE-001", "fra")
    ev = IncidentEvent.validator_new(1000, EventSource.EDR, "lateral psexec", "PSExec detected", 0.95)
    itl.validator_add_event(ev)
    assert itl.validator_duration_ms() == 0  # single event

    # MalwareCase
    mc = MalwareCase.validator_new("MC-1", "VICTIM-PC")
    mc.validator_add_persistence(PersistenceMechanism.validator_run_key("HKCU", "Run", "malware.exe"))
    assert mc.validator_has_registry_persistence()

    # RegistryHiveAnalyzer — invalid data
    try:
        RegistryHiveAnalyzer.validator_from_bytes(b"invalid")
        assert False, "Should have raised"
    except ForensicsError:
        pass

    # ForensicTimeline builder
    tb = TimelineBuilder.validator_new().validator_with_default_source("syslog")
    tb.validator_add_artifact(ArtifactEntry(timestamp_ms=500, description="login"))
    tb.validator_add_artifact(ArtifactEntry(timestamp_ms=300, description="boot"))
    built = tb.validator_build()
    assert built.validator_events()[0].timestamp_ms == 300

    # CorrelatedTimeline
    ct = CorrelatedTimeline.validator_new()
    ct.validator_record("edr", 1000, "scan", 80)
    ct.validator_record("edr", 5000, "alert", 90)
    ct.validator_detect_gaps(500)
    assert len(ct.validator_gaps()) == 1

    # memory acquisition helpers
    segs = [MemorySegment(0, 100), MemorySegment(95, 200)]
    merged = validator_merge_adjacent_segments(segs, 10)
    assert len(merged) == 1
    assert validator_total_coverage([MemorySegment(0, 50), MemorySegment(100, 150)]) == 100
    assert validator_find_segment([MemorySegment(0, 100)], 50) is not None

    print("All self-tests passed.")


if __name__ == "__main__":
    _self_test()
