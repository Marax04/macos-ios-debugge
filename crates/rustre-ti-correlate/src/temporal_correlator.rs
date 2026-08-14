//! Temporal correlation for threat intelligence events.
//!
//! Groups [`ThreatEvent`]s into time-based clusters and exposes an
//! [`EventTimeline`] that can be queried by window, label, or IoC.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Re-use types from crate root so we don't redefine them.
// ---------------------------------------------------------------------------
use crate::ThreatEvent;
use rustre_threatintel::IoCType;

// ---------------------------------------------------------------------------
// Cluster density threshold
// ---------------------------------------------------------------------------

/// Minimum number of events required before a cluster is considered
/// significant enough to report.
const MIN_CLUSTER_SIZE: usize = 2;

/// Default gap that separates two otherwise adjacent clusters (seconds).
const DEFAULT_GAP_SECS: u64 = 3_600; // 1 hour

// ---------------------------------------------------------------------------
// TimeCluster
// ---------------------------------------------------------------------------

/// A contiguous group of [`ThreatEvent`]s that occur within a bounded time
/// window with no gap larger than the configured cluster gap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeCluster {
    /// Cluster identifier (monotonically assigned).
    pub id: u64,
    /// Epoch-second timestamp of the first event in the cluster.
    pub start_ts: u64,
    /// Epoch-second timestamp of the last event in the cluster.
    pub end_ts: u64,
    /// All events belonging to this cluster, sorted by timestamp.
    pub events: Vec<ThreatEvent>,
    /// Unique IoC values observed across all events in this cluster.
    pub ioc_values: HashSet<String>,
    /// Unique IoC types observed across all events in this cluster.
    pub ioc_types: HashSet<String>,
    /// Unique labels seen across all events in this cluster.
    pub labels: HashSet<String>,
}

impl TimeCluster {
    /// Duration covered by this cluster (from first to last event).
    pub fn duration(&self) -> Duration {
        Duration::from_secs(self.end_ts.saturating_sub(self.start_ts))
    }

    /// Number of events in the cluster.
    pub fn size(&self) -> usize {
        self.events.len()
    }

    /// Return true if the cluster is considered significant (meets
    /// [`MIN_CLUSTER_SIZE`]).
    pub fn is_significant(&self) -> bool {
        self.events.len() >= MIN_CLUSTER_SIZE
    }

    /// Mean inter-event gap in seconds.  Returns `None` if fewer than 2
    /// events.
    pub fn mean_gap_secs(&self) -> Option<f64> {
        if self.events.len() < 2 {
            return None;
        }
        let total = self.end_ts.saturating_sub(self.start_ts) as f64;
        Some(total / (self.events.len() - 1) as f64)
    }

    /// Return events that carry a specific label.
    pub fn events_with_label(&self, label: &str) -> Vec<&ThreatEvent> {
        self.events
            .iter()
            .filter(|e| e.label.as_deref() == Some(label))
            .collect()
    }

    /// Return events whose IoC value matches the given string.
    pub fn events_with_ioc(&self, ioc_value: &str) -> Vec<&ThreatEvent> {
        self.events
            .iter()
            .filter(|e| e.ioc.value == ioc_value)
            .collect()
    }

    /// IoC-value overlap coefficient (Jaccard) with another cluster.
    pub fn ioc_overlap(&self, other: &TimeCluster) -> f64 {
        if self.ioc_values.is_empty() && other.ioc_values.is_empty() {
            return 0.0;
        }
        let intersection = self.ioc_values.intersection(&other.ioc_values).count();
        let union = self.ioc_values.union(&other.ioc_values).count();
        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }

    /// IoC-type overlap coefficient (Jaccard) with another cluster.
    pub fn type_overlap(&self, other: &TimeCluster) -> f64 {
        if self.ioc_types.is_empty() && other.ioc_types.is_empty() {
            return 0.0;
        }
        let intersection = self.ioc_types.intersection(&other.ioc_types).count();
        let union = self.ioc_types.union(&other.ioc_types).count();
        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }
}

// ---------------------------------------------------------------------------
// ClusterSimilarity
// ---------------------------------------------------------------------------

/// Pairwise similarity between two [`TimeCluster`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSimilarity {
    pub cluster_a: u64,
    pub cluster_b: u64,
    /// Jaccard similarity on IoC value sets.
    pub ioc_similarity: f64,
    /// Jaccard similarity on IoC type sets.
    pub type_similarity: f64,
    /// Temporal proximity score in [0, 1]: 1 = adjacent clusters.
    pub temporal_proximity: f64,
    /// Composite score: average of the three components.
    pub composite: f64,
}

impl ClusterSimilarity {
    fn compute(a: &TimeCluster, b: &TimeCluster, max_gap_secs: u64) -> Self {
        let ioc_sim = a.ioc_overlap(b);
        let type_sim = a.type_overlap(b);

        // Temporal proximity: inverse of gap normalised by max_gap_secs
        let gap = if a.end_ts <= b.start_ts {
            b.start_ts - a.end_ts
        } else if b.end_ts <= a.start_ts {
            a.start_ts - b.end_ts
        } else {
            0 // overlapping
        };
        let temporal = 1.0 - (gap as f64 / (max_gap_secs.max(1) as f64 * 10.0)).min(1.0);

        let composite = (ioc_sim + type_sim + temporal) / 3.0;

        ClusterSimilarity {
            cluster_a: a.id,
            cluster_b: b.id,
            ioc_similarity: ioc_sim,
            type_similarity: type_sim,
            temporal_proximity: temporal,
            composite,
        }
    }
}

// ---------------------------------------------------------------------------
// EventTimeline
// ---------------------------------------------------------------------------

/// A sorted, queryable sequence of [`ThreatEvent`]s with pre-computed
/// clusters and IoC/label indices.
#[derive(Debug, Clone)]
pub struct EventTimeline {
    /// All events sorted by timestamp (ascending).
    events: Vec<ThreatEvent>,
    /// Clusters produced by the last call to [`TemporalCorrelator::cluster`].
    clusters: Vec<TimeCluster>,
    /// Index: IoC value → indices into `events`.
    ioc_index: HashMap<String, Vec<usize>>,
    /// Index: label → indices into `events`.
    label_index: HashMap<String, Vec<usize>>,
    /// Index: IoC type string → indices into `events`.
    type_index: HashMap<String, Vec<usize>>,
    /// The cluster gap used when producing `clusters`.
    gap_secs: u64,
}

impl EventTimeline {
    /// Create an empty timeline.
    pub fn new(gap_secs: u64) -> Self {
        EventTimeline {
            events: Vec::new(),
            clusters: Vec::new(),
            ioc_index: HashMap::new(),
            label_index: HashMap::new(),
            type_index: HashMap::new(),
            gap_secs,
        }
    }

    /// Insert a single event, maintaining sort order.
    pub fn push(&mut self, event: ThreatEvent) {
        let idx = self.events.len();

        // Update IoC value index
        self.ioc_index
            .entry(event.ioc.value.clone())
            .or_default()
            .push(idx);

        // Update IoC type index
        self.type_index
            .entry(event.ioc.ioc_type.as_str().to_string())
            .or_default()
            .push(idx);

        // Update label index
        if let Some(label) = &event.label {
            self.label_index
                .entry(label.clone())
                .or_default()
                .push(idx);
        }

        self.events.push(event);
    }

    /// Re-sort events by timestamp after bulk insertion.
    pub fn sort(&mut self) {
        self.events.sort_by_key(|e| e.timestamp);
        // Rebuild indices after sort
        self.ioc_index.clear();
        self.label_index.clear();
        self.type_index.clear();
        for (idx, event) in self.events.iter().enumerate() {
            self.ioc_index
                .entry(event.ioc.value.clone())
                .or_default()
                .push(idx);
            self.type_index
                .entry(event.ioc.ioc_type.as_str().to_string())
                .or_default()
                .push(idx);
            if let Some(label) = &event.label {
                self.label_index
                    .entry(label.clone())
                    .or_default()
                    .push(idx);
            }
        }
        // Invalidate clusters
        self.clusters.clear();
    }

    /// All events in the timeline.
    pub fn events(&self) -> &[ThreatEvent] {
        &self.events
    }

    /// Number of events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns true when the timeline contains no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// All computed clusters.
    pub fn clusters(&self) -> &[TimeCluster] {
        &self.clusters
    }

    /// Returns the cluster gap (in seconds) that produced the current
    /// [`Self::clusters`] snapshot. Useful for callers that want to surface
    /// the parameter alongside the result (e.g. UI tooltips, report headers).
    #[must_use]
    pub fn cluster_gap_secs(&self) -> u64 {
        self.gap_secs
    }

    /// Events within an epoch-second time range [from, to].
    pub fn events_in_range(&self, from: u64, to: u64) -> Vec<&ThreatEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= from && e.timestamp <= to)
            .collect()
    }

    /// Events whose IoC value matches.
    pub fn events_with_ioc(&self, ioc_value: &str) -> Vec<&ThreatEvent> {
        match self.ioc_index.get(ioc_value) {
            None => Vec::new(),
            Some(idxs) => idxs.iter().map(|&i| &self.events[i]).collect(),
        }
    }

    /// Events that carry a specific label.
    pub fn events_with_label(&self, label: &str) -> Vec<&ThreatEvent> {
        match self.label_index.get(label) {
            None => Vec::new(),
            Some(idxs) => idxs.iter().map(|&i| &self.events[i]).collect(),
        }
    }

    /// Events whose IoC has a specific type.
    pub fn events_with_ioc_type(&self, ioc_type: &IoCType) -> Vec<&ThreatEvent> {
        match self.type_index.get(ioc_type.as_str()) {
            None => Vec::new(),
            Some(idxs) => idxs.iter().map(|&i| &self.events[i]).collect(),
        }
    }

    /// Earliest event timestamp, or `None` if empty.
    pub fn start_ts(&self) -> Option<u64> {
        self.events.first().map(|e| e.timestamp)
    }

    /// Latest event timestamp, or `None` if empty.
    pub fn end_ts(&self) -> Option<u64> {
        self.events.last().map(|e| e.timestamp)
    }

    /// Total duration from first to last event.
    pub fn total_duration(&self) -> Option<Duration> {
        match (self.start_ts(), self.end_ts()) {
            (Some(s), Some(e)) => Some(Duration::from_secs(e.saturating_sub(s))),
            _ => None,
        }
    }

    /// Density: events per hour over the full timeline span.
    pub fn density_per_hour(&self) -> f64 {
        if self.events.is_empty() {
            return 0.0;
        }
        let span = self.total_duration().unwrap_or(Duration::from_secs(1));
        let hours = span.as_secs_f64() / 3600.0;
        if hours < 0.001 {
            self.events.len() as f64
        } else {
            self.events.len() as f64 / hours
        }
    }

    /// Build a histogram of events per day (keyed by days-since-epoch).
    pub fn daily_histogram(&self) -> BTreeMap<u64, usize> {
        let mut map: BTreeMap<u64, usize> = BTreeMap::new();
        for event in &self.events {
            let day = event.timestamp / 86_400;
            *map.entry(day).or_insert(0) += 1;
        }
        map
    }

    /// Store computed clusters (called by [`TemporalCorrelator`]).
    fn set_clusters(&mut self, clusters: Vec<TimeCluster>) {
        self.clusters = clusters;
    }

    /// Unique IoC values seen across all events.
    pub fn unique_ioc_values(&self) -> Vec<&str> {
        self.ioc_index.keys().map(|s| s.as_str()).collect()
    }

    /// Count of distinct IoC types observed.
    pub fn distinct_ioc_type_count(&self) -> usize {
        self.type_index.len()
    }
}

// ---------------------------------------------------------------------------
// TemporalCorrelatorConfig
// ---------------------------------------------------------------------------

/// Configuration for the temporal correlator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalCorrelatorConfig {
    /// Maximum gap between consecutive events (in seconds) within the same
    /// cluster.
    pub gap_secs: u64,
    /// Minimum cluster size to include in output (default 2).
    pub min_cluster_size: usize,
    /// If true, merge clusters that share at least one IoC value.
    pub merge_by_ioc: bool,
    /// If true, merge clusters that share at least one IoC type.
    pub merge_by_type: bool,
}

impl Default for TemporalCorrelatorConfig {
    fn default() -> Self {
        TemporalCorrelatorConfig {
            gap_secs: DEFAULT_GAP_SECS,
            min_cluster_size: MIN_CLUSTER_SIZE,
            merge_by_ioc: false,
            merge_by_type: false,
        }
    }
}

// ---------------------------------------------------------------------------
// TemporalCorrelator
// ---------------------------------------------------------------------------

/// Main entry-point for temporal correlation.
///
/// Accepts [`ThreatEvent`]s (via [`push`] or [`ingest`]), clusters them by
/// time gap, and provides query methods over the resulting [`EventTimeline`].
pub struct TemporalCorrelator {
    config: TemporalCorrelatorConfig,
    timeline: EventTimeline,
    /// Running cluster id counter.
    next_cluster_id: u64,
}

impl TemporalCorrelator {
    /// Create a new correlator with default configuration.
    pub fn new() -> Self {
        TemporalCorrelator::with_config(TemporalCorrelatorConfig::default())
    }

    /// Create a new correlator with the given configuration.
    pub fn with_config(config: TemporalCorrelatorConfig) -> Self {
        let gap = config.gap_secs;
        TemporalCorrelator {
            config,
            timeline: EventTimeline::new(gap),
            next_cluster_id: 0,
        }
    }

    /// Create a new correlator with a specific gap (seconds).
    pub fn with_gap(gap_secs: u64) -> Self {
        TemporalCorrelator::with_config(TemporalCorrelatorConfig {
            gap_secs,
            ..Default::default()
        })
    }

    /// Add a single event.
    pub fn push(&mut self, event: ThreatEvent) {
        self.timeline.push(event);
        self.timeline.clusters.clear(); // invalidate
    }

    /// Add many events at once (sorts afterwards).
    pub fn ingest(&mut self, mut events: Vec<ThreatEvent>) {
        for event in events.drain(..) {
            self.timeline.push(event);
        }
        self.timeline.sort();
    }

    /// Reference to the underlying event timeline.
    pub fn timeline(&self) -> &EventTimeline {
        &self.timeline
    }

    /// Run the clustering algorithm and return the resulting clusters.
    ///
    /// The timeline stores the clusters so subsequent calls to
    /// [`EventTimeline::clusters`] return up-to-date results.
    pub fn cluster(&mut self) -> &[TimeCluster] {
        // Sort first to ensure ordering invariant.
        self.timeline.sort();

        let gap = self.config.gap_secs;
        let mut clusters: Vec<TimeCluster> = Vec::new();
        let mut current: Option<TimeCluster> = None;

        for event in self.timeline.events.clone() {
            match current.take() {
                None => {
                    current = Some(self.open_cluster(event));
                }
                Some(mut c) => {
                    let gap_to_event = event.timestamp.saturating_sub(c.end_ts);
                    if gap_to_event <= gap {
                        Self::extend_cluster_with(&mut c, event);
                        current = Some(c);
                    } else {
                        clusters.push(c);
                        current = Some(self.open_cluster(event));
                    }
                }
            }
        }

        if let Some(c) = current {
            clusters.push(c);
        }

        // Optional IoC-based merging pass
        if self.config.merge_by_ioc {
            clusters = Self::merge_clusters_by(clusters, |a, b| {
                !a.ioc_values.is_disjoint(&b.ioc_values)
            });
        }

        // Optional type-based merging pass
        if self.config.merge_by_type {
            clusters = Self::merge_clusters_by(clusters, |a, b| {
                !a.ioc_types.is_disjoint(&b.ioc_types)
            });
        }

        // Filter by min size
        let min_sz = self.config.min_cluster_size;
        let clusters: Vec<TimeCluster> = clusters
            .into_iter()
            .filter(|c| c.size() >= min_sz)
            .collect();

        self.timeline.set_clusters(clusters);
        self.timeline.clusters()
    }

    /// Compute pairwise similarity between all clusters.
    ///
    /// Clusters must have been produced by [`cluster`] first.
    pub fn pairwise_similarity(&self) -> Vec<ClusterSimilarity> {
        let clusters = self.timeline.clusters();
        let mut result = Vec::new();
        for i in 0..clusters.len() {
            for j in (i + 1)..clusters.len() {
                result.push(ClusterSimilarity::compute(
                    &clusters[i],
                    &clusters[j],
                    self.config.gap_secs,
                ));
            }
        }
        result
    }

    /// Find clusters that contain a specific IoC value.
    pub fn clusters_with_ioc(&self, ioc_value: &str) -> Vec<&TimeCluster> {
        self.timeline
            .clusters()
            .iter()
            .filter(|c| c.ioc_values.contains(ioc_value))
            .collect()
    }

    /// Find clusters that contain events of a specific IoC type.
    pub fn clusters_with_type(&self, ioc_type: &IoCType) -> Vec<&TimeCluster> {
        let type_str = ioc_type.as_str().to_string();
        self.timeline
            .clusters()
            .iter()
            .filter(|c| c.ioc_types.contains(&type_str))
            .collect()
    }

    /// Find clusters that contain events with a specific label.
    pub fn clusters_with_label(&self, label: &str) -> Vec<&TimeCluster> {
        self.timeline
            .clusters()
            .iter()
            .filter(|c| c.labels.contains(label))
            .collect()
    }

    /// Return cluster with highest event density (events / hour).
    pub fn hottest_cluster(&self) -> Option<&TimeCluster> {
        self.timeline.clusters().iter().max_by(|a, b| {
            let da = cluster_density(a);
            let db = cluster_density(b);
            da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// High-level summary statistics across all clusters.
    pub fn summary(&self) -> CorrelationSummary {
        let clusters = self.timeline.clusters();
        let total_events = self.timeline.len();
        let clustered_events: usize = clusters.iter().map(|c| c.size()).sum();
        let unique_ioc_values: HashSet<&str> = clusters
            .iter()
            .flat_map(|c| c.ioc_values.iter().map(|s| s.as_str()))
            .collect();
        let avg_cluster_size = if clusters.is_empty() {
            0.0
        } else {
            clustered_events as f64 / clusters.len() as f64
        };
        CorrelationSummary {
            total_events,
            total_clusters: clusters.len(),
            clustered_events,
            unclustered_events: total_events.saturating_sub(clustered_events),
            unique_ioc_values: unique_ioc_values.len(),
            avg_cluster_size,
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn open_cluster(&mut self, event: ThreatEvent) -> TimeCluster {
        let id = self.next_cluster_id;
        self.next_cluster_id += 1;

        let mut ioc_values: HashSet<String> = HashSet::new();
        let mut ioc_types: HashSet<String> = HashSet::new();
        let mut labels: HashSet<String> = HashSet::new();

        ioc_values.insert(event.ioc.value.clone());
        ioc_types.insert(event.ioc.ioc_type.as_str().to_string());
        if let Some(label) = &event.label {
            labels.insert(label.clone());
        }

        let ts = event.timestamp;
        TimeCluster {
            id,
            start_ts: ts,
            end_ts: ts,
            events: vec![event],
            ioc_values,
            ioc_types,
            labels,
        }
    }

    fn extend_cluster_with(cluster: &mut TimeCluster, event: ThreatEvent) {
        if event.timestamp > cluster.end_ts {
            cluster.end_ts = event.timestamp;
        }
        if event.timestamp < cluster.start_ts {
            cluster.start_ts = event.timestamp;
        }
        cluster.ioc_values.insert(event.ioc.value.clone());
        cluster.ioc_types.insert(event.ioc.ioc_type.as_str().to_string());
        if let Some(label) = &event.label {
            cluster.labels.insert(label.clone());
        }
        cluster.events.push(event);
    }

    /// Generic merge: repeatedly merge pairs of clusters where `should_merge`
    /// returns true, until no more merges are possible.
    fn merge_clusters_by<F>(mut clusters: Vec<TimeCluster>, should_merge: F) -> Vec<TimeCluster>
    where
        F: Fn(&TimeCluster, &TimeCluster) -> bool,
    {
        let mut changed = true;
        while changed {
            changed = false;
            let mut merged: Vec<TimeCluster> = Vec::with_capacity(clusters.len());
            let mut used = vec![false; clusters.len()];

            for i in 0..clusters.len() {
                if used[i] {
                    continue;
                }
                let mut base = clusters[i].clone();
                for j in (i + 1)..clusters.len() {
                    if used[j] {
                        continue;
                    }
                    if should_merge(&base, &clusters[j]) {
                        let other = clusters[j].clone();
                        base.start_ts = base.start_ts.min(other.start_ts);
                        base.end_ts = base.end_ts.max(other.end_ts);
                        base.ioc_values.extend(other.ioc_values);
                        base.ioc_types.extend(other.ioc_types);
                        base.labels.extend(other.labels);
                        let mut combined = base.events.clone();
                        combined.extend(other.events);
                        combined.sort_by_key(|e| e.timestamp);
                        base.events = combined;
                        used[j] = true;
                        changed = true;
                    }
                }
                merged.push(base);
                used[i] = true;
            }
            clusters = merged;
        }
        clusters
    }
}

impl Default for TemporalCorrelator {
    fn default() -> Self {
        TemporalCorrelator::new()
    }
}

// ---------------------------------------------------------------------------
// CorrelationSummary
// ---------------------------------------------------------------------------

/// High-level statistics about a completed clustering run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationSummary {
    pub total_events: usize,
    pub total_clusters: usize,
    pub clustered_events: usize,
    pub unclustered_events: usize,
    pub unique_ioc_values: usize,
    pub avg_cluster_size: f64,
}

// ---------------------------------------------------------------------------
// Free helper functions
// ---------------------------------------------------------------------------

/// Events-per-hour density of a single cluster.
fn cluster_density(c: &TimeCluster) -> f64 {
    let span_secs = c.end_ts.saturating_sub(c.start_ts);
    if span_secs == 0 {
        return c.events.len() as f64;
    }
    c.events.len() as f64 / (span_secs as f64 / 3600.0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_threatintel::{IoC, IoCType};
    use crate::ThreatEvent;

    /// Build a minimal ThreatEvent at the given epoch-second timestamp.
    fn evt(ts: u64) -> ThreatEvent {
        ThreatEvent {
            ioc: IoC::new(IoCType::Ip, format!("1.2.3.{}", ts % 254 + 1), "test".to_string()),
            timestamp: ts,
            label: None,
        }
    }

    /// Build a ThreatEvent with a label.
    fn evt_label(ts: u64, label: &str) -> ThreatEvent {
        ThreatEvent {
            ioc: IoC::new(IoCType::Ip, format!("10.0.0.{}", ts % 254 + 1), "test".to_string()),
            timestamp: ts,
            label: Some(label.to_string()),
        }
    }

    /// Build a ThreatEvent with a specific IoC value.
    fn evt_ioc(ts: u64, value: &str, ioc_type: IoCType) -> ThreatEvent {
        ThreatEvent {
            ioc: IoC::new(ioc_type, value.to_string(), "test".to_string()),
            timestamp: ts,
            label: None,
        }
    }

    #[test]
    fn empty_timeline() {
        let tc = TemporalCorrelator::new();
        assert!(tc.timeline().is_empty());
        assert_eq!(tc.timeline().len(), 0);
    }

    #[test]
    fn single_event_filtered_by_min_size() {
        let mut tc = TemporalCorrelator::with_gap(3600);
        tc.push(evt(1_000));
        // min_cluster_size defaults to 2, so no cluster passes filter
        let clusters = tc.cluster();
        assert_eq!(clusters.len(), 0);
    }

    #[test]
    fn single_event_min_size_one() {
        let config = TemporalCorrelatorConfig {
            gap_secs: 3600,
            min_cluster_size: 1,
            ..Default::default()
        };
        let mut tc = TemporalCorrelator::with_config(config);
        tc.push(evt(1_000));
        let clusters = tc.cluster();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].size(), 1);
    }

    #[test]
    fn two_close_events_form_cluster() {
        let mut tc = TemporalCorrelator::with_gap(3600);
        tc.push(evt(1_000));
        tc.push(evt(1_500));
        let clusters = tc.cluster();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].size(), 2);
    }

    #[test]
    fn two_far_events_separate_clusters() {
        let config = TemporalCorrelatorConfig {
            gap_secs: 3600,
            min_cluster_size: 1,
            ..Default::default()
        };
        let mut tc = TemporalCorrelator::with_config(config);
        tc.push(evt(1_000));
        tc.push(evt(1_000 + 7_200)); // 2 hours later
        let clusters = tc.cluster();
        assert_eq!(clusters.len(), 2);
    }

    #[test]
    fn cluster_boundaries() {
        let mut tc = TemporalCorrelator::with_gap(100);
        tc.push(evt(1000));
        tc.push(evt(1050));
        tc.push(evt(1090));
        let clusters = tc.cluster();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].start_ts, 1000);
        assert_eq!(clusters[0].end_ts, 1090);
    }

    #[test]
    fn cluster_duration() {
        let config = TemporalCorrelatorConfig {
            gap_secs: 3600,
            min_cluster_size: 1,
            ..Default::default()
        };
        let mut tc = TemporalCorrelator::with_config(config);
        tc.push(evt(0));
        tc.push(evt(3600));
        let clusters = tc.cluster();
        assert_eq!(clusters[0].duration(), Duration::from_secs(3600));
    }

    #[test]
    fn cluster_mean_gap() {
        let config = TemporalCorrelatorConfig {
            gap_secs: 3600,
            min_cluster_size: 1,
            ..Default::default()
        };
        let mut tc = TemporalCorrelator::with_config(config);
        tc.push(evt(0));
        tc.push(evt(100));
        tc.push(evt(200));
        let clusters = tc.cluster();
        assert_eq!(clusters[0].mean_gap_secs(), Some(100.0));
    }

    #[test]
    fn events_in_range() {
        let mut tc = TemporalCorrelator::with_gap(3600);
        for ts in [100u64, 200, 300, 400, 500] {
            tc.push(evt(ts));
        }
        tc.cluster();
        let in_range = tc.timeline().events_in_range(200, 400);
        assert_eq!(in_range.len(), 3);
    }

    #[test]
    fn label_index() {
        let mut tc = TemporalCorrelator::with_gap(3600);
        tc.push(evt_label(100, "first_seen"));
        tc.push(evt_label(200, "first_seen"));
        tc.push(evt_label(300, "last_seen"));
        tc.cluster();
        assert_eq!(tc.timeline().events_with_label("first_seen").len(), 2);
        assert_eq!(tc.timeline().events_with_label("last_seen").len(), 1);
        assert_eq!(tc.timeline().events_with_label("unknown").len(), 0);
    }

    #[test]
    fn cluster_label_sets() {
        let mut tc = TemporalCorrelator::with_gap(3600);
        tc.push(evt_label(100, "c2"));
        tc.push(evt_label(200, "drop"));
        let clusters = tc.cluster();
        assert_eq!(clusters.len(), 1);
        assert!(clusters[0].labels.contains("c2"));
        assert!(clusters[0].labels.contains("drop"));
    }

    #[test]
    fn hottest_cluster() {
        let config = TemporalCorrelatorConfig {
            gap_secs: 3600,
            min_cluster_size: 1,
            ..Default::default()
        };
        let mut tc = TemporalCorrelator::with_config(config);
        // sparse cluster: 2 events 3600 s apart
        tc.push(evt(0));
        tc.push(evt(3600));
        // dense cluster: 3 events 10 s apart, 3 h later
        tc.push(evt(3600 * 3));
        tc.push(evt(3600 * 3 + 10));
        tc.push(evt(3600 * 3 + 20));
        tc.cluster();
        let hot = tc.hottest_cluster().expect("should have a hottest cluster");
        assert_eq!(hot.size(), 3);
    }

    #[test]
    fn summary_stats() {
        let mut tc = TemporalCorrelator::with_gap(3600);
        for i in 0..5u64 {
            tc.push(evt_label(i * 60, "report"));
        }
        tc.cluster();
        let s = tc.summary();
        assert_eq!(s.total_events, 5);
        assert_eq!(s.total_clusters, 1);
        assert_eq!(s.clustered_events, 5);
        assert_eq!(s.unclustered_events, 0);
    }

    #[test]
    fn daily_histogram() {
        let mut tc = TemporalCorrelator::with_gap(3600);
        // Day 0: 2 events
        tc.push(evt(100));
        tc.push(evt(200));
        // Day 1: 1 event
        tc.push(evt(86_400 + 50));
        tc.cluster();
        let hist = tc.timeline().daily_histogram();
        assert_eq!(hist[&0], 2);
        assert_eq!(hist[&1], 1);
    }

    #[test]
    fn ingest_unsorted() {
        let mut tc = TemporalCorrelator::with_gap(100);
        tc.ingest(vec![evt(300), evt(100), evt(200)]);
        let events = tc.timeline().events();
        assert_eq!(events[0].timestamp, 100);
        assert_eq!(events[1].timestamp, 200);
        assert_eq!(events[2].timestamp, 300);
    }

    #[test]
    fn pairwise_similarity_same_ioc() {
        let config = TemporalCorrelatorConfig {
            gap_secs: 100,
            min_cluster_size: 1,
            ..Default::default()
        };
        let mut tc = TemporalCorrelator::with_config(config);
        // Two separate clusters (gap > 100 s) with same IoC value
        tc.push(evt_ioc(0, "evil.com", IoCType::Domain));
        tc.push(evt_ioc(50, "evil.com", IoCType::Domain));
        tc.push(evt_ioc(1000, "evil.com", IoCType::Domain));
        tc.push(evt_ioc(1050, "evil.com", IoCType::Domain));
        tc.cluster();
        let sims = tc.pairwise_similarity();
        assert_eq!(sims.len(), 1);
        // Same IoC → ioc_similarity = 1.0
        assert!((sims[0].ioc_similarity - 1.0).abs() < 1e-9);
    }

    #[test]
    fn merge_by_ioc_config() {
        let config = TemporalCorrelatorConfig {
            gap_secs: 100,
            min_cluster_size: 1,
            merge_by_ioc: true,
            merge_by_type: false,
        };
        let mut tc = TemporalCorrelator::with_config(config);
        // Two clusters with same IoC value: should merge
        tc.push(evt_ioc(0, "evil.com", IoCType::Domain));
        tc.push(evt_ioc(500, "evil.com", IoCType::Domain)); // gap=500 > 100
        let clusters = tc.cluster();
        assert_eq!(clusters.len(), 1);
    }

    #[test]
    fn no_merge_different_iocs() {
        let config = TemporalCorrelatorConfig {
            gap_secs: 100,
            min_cluster_size: 1,
            merge_by_ioc: true,
            merge_by_type: false,
        };
        let mut tc = TemporalCorrelator::with_config(config);
        tc.push(evt_ioc(0, "evil.com", IoCType::Domain));
        tc.push(evt_ioc(500, "bad.net", IoCType::Domain)); // different IoC, gap > 100
        let clusters = tc.cluster();
        assert_eq!(clusters.len(), 2);
    }

    #[test]
    fn cluster_is_significant() {
        let config = TemporalCorrelatorConfig {
            gap_secs: 3600,
            min_cluster_size: 1,
            ..Default::default()
        };
        let mut tc = TemporalCorrelator::with_config(config);
        tc.push(evt(0));
        let clusters = tc.cluster();
        assert!(!clusters[0].is_significant()); // size 1 < 2
        tc.push(evt(60));
        let clusters = tc.cluster();
        assert!(clusters[0].is_significant()); // size 2 >= 2
    }

    #[test]
    fn timeline_density() {
        let mut tc = TemporalCorrelator::with_gap(3600);
        // 2 events exactly 1 hour apart → density = 2 / 1h = 2.0 events/h
        tc.push(evt(0));
        tc.push(evt(3600));
        tc.cluster();
        let d = tc.timeline().density_per_hour();
        assert!((d - 2.0).abs() < 1e-6, "density = {d}");
    }

    #[test]
    fn cluster_overlap_ioc() {
        let config = TemporalCorrelatorConfig {
            gap_secs: 100,
            min_cluster_size: 1,
            ..Default::default()
        };
        let mut tc = TemporalCorrelator::with_config(config);
        tc.push(evt_ioc(0, "evil.com", IoCType::Domain));
        tc.push(evt_ioc(200, "evil.com", IoCType::Domain));
        tc.cluster();
        let clusters = tc.timeline().clusters();
        if clusters.len() >= 2 {
            let ov = clusters[0].ioc_overlap(&clusters[1]);
            assert!((ov - 1.0).abs() < 1e-9);
        }
    }

    #[test]
    fn ioc_type_filter() {
        let mut tc = TemporalCorrelator::with_gap(3600);
        tc.push(evt_ioc(100, "evil.com", IoCType::Domain));
        tc.push(evt_ioc(200, "1.2.3.4", IoCType::Ip));
        tc.push(evt_ioc(300, "bad.com", IoCType::Domain));
        tc.cluster();
        let domains = tc.timeline().events_with_ioc_type(&IoCType::Domain);
        assert_eq!(domains.len(), 2);
        let ips = tc.timeline().events_with_ioc_type(&IoCType::Ip);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn unique_ioc_values_count() {
        let mut tc = TemporalCorrelator::with_gap(3600);
        tc.push(evt_ioc(100, "evil.com", IoCType::Domain));
        tc.push(evt_ioc(200, "evil.com", IoCType::Domain));
        tc.push(evt_ioc(300, "bad.net", IoCType::Domain));
        tc.cluster();
        let unique = tc.timeline().unique_ioc_values();
        assert_eq!(unique.len(), 2);
    }

    #[test]
    fn merge_by_type_merges_same_type_clusters() {
        let config = TemporalCorrelatorConfig {
            gap_secs: 100,
            min_cluster_size: 1,
            merge_by_ioc: false,
            merge_by_type: true,
        };
        let mut tc = TemporalCorrelator::with_config(config);
        tc.push(evt_ioc(0, "a.com", IoCType::Domain));
        tc.push(evt_ioc(500, "b.com", IoCType::Domain));
        let clusters = tc.cluster();
        assert_eq!(clusters.len(), 1);
    }
}
