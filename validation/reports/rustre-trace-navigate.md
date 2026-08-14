# rustre-trace-navigate

## Cargo.toml
- name: `rustre-trace-navigate` v0.1.0, edition 2024
- license/repo/desc inherited from workspace
- dependencies: `anyhow`, `thiserror`, `serde`, `serde_json`, `petgraph`,
  `tokio` (sync, rt, macros), `tokio-util`, `async-trait`, `rusqlite`, `bincode`
- Note: must NOT depend on `rustre-trace` (would create workspace cycle — this
  crate is currently self-contained).
- lints: workspace

## Purpose
Navigation, search, diff, replay, slicing, bookmarking and graph-building over
execution traces (time-travel debugging primitives). Self-contained core types
mirror what `rustre-trace` consumes.

## Public modules (`lib.rs`)
- `address_timeline` — `AddressTimeline`, `TimelineNavigator`, `AddressQuery`, `ExecutionEvent`, `ExecutionGap`, `FrequencyMap`
- `backward_nav` — `BackwardNavigator`, `ReverseStep`, `BackwardSearchResult`
- `bookmark_manager` — `BookmarkManager`, `Bookmark`, `BookmarkSet`, `BookmarkQuery`, `BookmarkDiff`, `BookmarkCategory`
- `call_tree_navigator` — `CallTreeNavigator`, `CallTree`, `CallFrame`, `CallTreeQuery`, `NavigationState`, `RecursionInfo`
- `step_navigator` — `StepNavigator`, `StepNavigatorConfig`, `NavigatorState`, `StepResult`, `BreakpointSet`, `VecTraceProvider`, trait `TraceProvider`
- `trace_index` — `TraceIndex`, `TraceIndexConfig`, `IndexEntry`, `IpTimeRange`, `IndexStats`, `IndexStreamer`; async `serialize_index`/`deserialize_into`
- `tenet_navigation` — `TenetNavigation`, `TracePosition`, `TraceEntry`, `ForwardStep`, `BackwardStep`, `JumpToFunction`, `JumpToMemoryWrite`, `NavigationHistory`, `NavError`
- `time_travel_search` — `TimeTravelSearch`, `SearchQuery`, `SearchResult`, `SearchRange`, `SearchDirection`, `SearchForMemWrite`, `SearchForApiCall`, `SearchForException`, `SearchForValue`, `SearchForInstruction`, `SearchError`
- `execution_graph_builder` — `ExecutionGraphBuilder`, `ExecutionGraph`, `ExecNode`, `ExecEdge`, `EdgeType`
- `time_travel_navigator` — `TimeTravelNavigator`, `NavigationPoint`, `Breakpoint`, `BpCondition`, `Direction`, `NavigationHistory`
- `trace_search_engine` — `TraceSearchEngine`, `SearchQuery`, `SearchPattern`, `SearchResult`, `TraceEntry`
- `trace_diff_engine` — `TraceDiffEngine`, `TraceDiffReport`, `DiffOptions`, `DiffStats`, `DivergencePoint`, `DivergenceKind`, `HeatmapDelta`; free fns `diff_traces`, `call_lcs`
- `trace_replay_controller` — `ReplaySession`, `ReplayStateSnapshot`, `Breakpoint`, `StepResult`, `ReplayError`
- `trace_slice_extractor` — `TraceSliceExtractor`, `SliceGraph`, `SliceNode`, `SliceEdgeKind`, `SliceCriterion`, `CriterionAccessKind`, `SliceDirection`, `SliceStats`, `VariableTainter`
- `function_call_navigator` — `FunctionCallNavigator`, `CallSite`, `CallNavigation`, `CallTreeNode`, `CallNavStats`
- `memory_access_navigator` — `MemoryAccessNavigator`, `MemAccess`, `AccessPattern`, `MemoryRange`
- `trace_bookmark_manager` — `TraceBookmarkManager`, `TraceBookmark`, `BookmarkQuery`, `BookmarkPosition`, `BookmarkCategory`, `BookmarkStats`

## Crate-level public API (`lib.rs`)
Core data model:
- `NavError`, `AccessKind`, `EntryKind`, `TraceEntry`, `StackFrame`, `ExecutionTrace`
- Indices: `MemAccessIndex`, `CallIndex`, `RegTimeline`, `TraceIndex`
- High-level orchestrator: `TraceNavigator` (+ `NavigatorSummary`, `NavigatorSnapshot`)
- Building/editing: `TraceBuilder`
- Analysis: `CallStackReconstructor`, `LoopDetector`, `ExecutionHeatmap`, `CoverageStats`, `TraceStatistics`, `PatternMatcher`, `TraceResampler`
- Slicing/filter/search: `TraceFilter`, `TraceSearcher`, `TraceSlice`, `SliceStats`, `FunctionSlice`, `ThreadView`, `TimedRegion`
- Diff: `TraceDiff`
- Call graph: `CallGraphNode`, `CallGraph`
- Step/window/history: `StepWindow`, `NavigationHistory`, `NavEvent`
- Bookmarks/annotations: `Bookmark`, `BookmarkStore`, `TraceAnnotation`, `AnnotationStore`
- Data flow: `DataFlowTracker`, `DataFlowEvent`, `DataFlowSource`
- I/O: `TraceExport`, `CompressedTrace`, `TraceEventIter`, `DrcovModule`, `DrcovBB`, `DrcovData`
- Events: `SyscallEvent`, `ExceptionEvent`
- Helper: `pub fn bytes_to_u64(bytes: &[u8]) -> u64`

## Testable
Yes — the crate is self-contained (no `rustre-trace` dependency), exposes
constructive APIs (`TraceBuilder`, `VecTraceProvider`, `ExecutionTrace`),
and modules already define stable struct/enum surfaces that can be unit-tested
in isolation against synthetic traces.
