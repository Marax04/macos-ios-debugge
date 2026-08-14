//! Temporal analysis of IoC observations.
//!
//! Provides:
//! * [`TimeSeries`] — ordered series of IoC observation counts per time bucket.
//! * [`CampaignDetector`] — detect activity bursts that signal campaigns.
//! * [`TtlPredictor`] — estimate when an IoC will become stale.
//! * [`SeasonalityAnalyzer`] — detect recurrent campaign patterns.
//! * [`TemporalCorrelationMatrix`] — pairwise temporal correlation between IoC sets.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ── Time bucket ───────────────────────────────────────────────────────────────

/// Resolution of a time series bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BucketResolution {
    Hourly,
    Daily,
    Weekly,
}

impl BucketResolution {
    pub fn secs(&self) -> u64 {
        match self {
            Self::Hourly => 3600,
            Self::Daily => 86400,
            Self::Weekly => 7 * 86400,
        }
    }

    /// Convert a UNIX timestamp to a bucket index.
    pub fn bucket_of(&self, ts: u64) -> u64 {
        ts / self.secs()
    }
}

// ── Time series ───────────────────────────────────────────────────────────────

/// A time series of IoC observation counts, bucketed by resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeries {
    pub label: String,
    pub resolution: BucketResolution,
    /// bucket_index → observation count
    pub buckets: HashMap<u64, u64>,
    pub first_seen: u64,
    pub last_seen: u64,
}

impl TimeSeries {
    pub fn new(label: impl Into<String>, resolution: BucketResolution) -> Self {
        Self {
            label: label.into(),
            resolution,
            buckets: HashMap::new(),
            first_seen: u64::MAX,
            last_seen: 0,
        }
    }

    /// Record an observation at the given UNIX timestamp.
    pub fn observe(&mut self, ts: u64) {
        let bucket = self.resolution.bucket_of(ts);
        *self.buckets.entry(bucket).or_insert(0) += 1;
        self.first_seen = self.first_seen.min(ts);
        self.last_seen = self.last_seen.max(ts);
    }

    /// Observe multiple timestamps at once.
    pub fn observe_batch(&mut self, timestamps: &[u64]) {
        for &ts in timestamps {
            self.observe(ts);
        }
    }

    /// Total number of observations.
    pub fn total(&self) -> u64 {
        self.buckets.values().sum()
    }

    /// Mean observations per bucket (over active buckets).
    pub fn mean(&self) -> f64 {
        if self.buckets.is_empty() {
            return 0.0;
        }
        self.total() as f64 / self.buckets.len() as f64
    }

    /// Standard deviation of observations per bucket.
    pub fn std_dev(&self) -> f64 {
        if self.buckets.len() < 2 {
            return 0.0;
        }
        let mean = self.mean();
        let variance: f64 = self
            .buckets
            .values()
            .map(|&v| {
                let diff = v as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / (self.buckets.len() - 1) as f64;
        variance.sqrt()
    }

    /// Ordered vector of `(bucket_ts, count)`.
    pub fn sorted_buckets(&self) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self
            .buckets
            .iter()
            .map(|(&b, &c)| (b * self.resolution.secs(), c))
            .collect();
        v.sort_by_key(|(ts, _)| *ts);
        v
    }

    /// Count in the latest N buckets.
    pub fn recent_activity(&self, n: usize) -> u64 {
        let mut buckets: Vec<(u64, u64)> = self.buckets.iter().map(|(&b, &c)| (b, c)).collect();
        buckets.sort_by_key(|(b, _)| *b);
        buckets.iter().rev().take(n).map(|(_, c)| c).sum()
    }
}

// ── Burst / campaign detection ────────────────────────────────────────────────

/// Configuration for burst detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstConfig {
    /// Number of standard deviations above mean to consider a burst.
    pub z_threshold: f64,
    /// Minimum number of observations in a burst bucket to trigger.
    pub min_observations: u64,
    /// Merge adjacent burst buckets within this many buckets.
    pub merge_gap: u64,
}

impl Default for BurstConfig {
    fn default() -> Self {
        Self {
            z_threshold: 2.0,
            min_observations: 3,
            merge_gap: 2,
        }
    }
}

/// A detected activity burst.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Burst {
    /// Start UNIX timestamp of the burst.
    pub start_ts: u64,
    /// End UNIX timestamp of the burst.
    pub end_ts: u64,
    /// Peak observations in a single bucket during the burst.
    pub peak_count: u64,
    /// Total observations during the burst.
    pub total_count: u64,
    /// Z-score of the peak bucket.
    pub peak_z_score: f64,
}

impl Burst {
    pub fn duration_secs(&self) -> u64 {
        self.end_ts.saturating_sub(self.start_ts)
    }
}

/// Detects campaign bursts in a time series.
pub struct CampaignDetector {
    config: BurstConfig,
}

impl CampaignDetector {
    pub fn new(config: BurstConfig) -> Self {
        Self { config }
    }

    pub fn default() -> Self {
        Self::new(BurstConfig::default())
    }

    /// Detect bursts in a time series.
    pub fn detect(&self, ts: &TimeSeries) -> Vec<Burst> {
        let mean = ts.mean();
        let std = ts.std_dev();
        if std == 0.0 {
            return vec![];
        }

        // Find burst buckets
        let mut burst_buckets: Vec<(u64, u64, f64)> = ts
            .buckets
            .iter()
            .filter_map(|(&bucket, &count)| {
                let z = (count as f64 - mean) / std;
                if z >= self.config.z_threshold && count >= self.config.min_observations {
                    Some((bucket, count, z))
                } else {
                    None
                }
            })
            .collect();
        burst_buckets.sort_by_key(|(b, _, _)| *b);

        if burst_buckets.is_empty() {
            return vec![];
        }

        // Merge adjacent buckets
        let bucket_secs = ts.resolution.secs();
        let mut bursts: Vec<Burst> = Vec::new();
        let mut current_start = burst_buckets[0].0;
        let mut current_end = burst_buckets[0].0;
        let mut peak_count = burst_buckets[0].1;
        let mut peak_z = burst_buckets[0].2;
        let mut total_count = burst_buckets[0].1;

        for &(bucket, count, z) in &burst_buckets[1..] {
            if bucket <= current_end + self.config.merge_gap {
                current_end = current_end.max(bucket);
                if count > peak_count {
                    peak_count = count;
                    peak_z = z;
                }
                total_count += count;
            } else {
                bursts.push(Burst {
                    start_ts: current_start * bucket_secs,
                    end_ts: (current_end + 1) * bucket_secs,
                    peak_count,
                    total_count,
                    peak_z_score: peak_z,
                });
                current_start = bucket;
                current_end = bucket;
                peak_count = count;
                peak_z = z;
                total_count = count;
            }
        }
        bursts.push(Burst {
            start_ts: current_start * bucket_secs,
            end_ts: (current_end + 1) * bucket_secs,
            peak_count,
            total_count,
            peak_z_score: peak_z,
        });

        bursts
    }
}

// ── TTL prediction ────────────────────────────────────────────────────────────

/// Predicted TTL for an IoC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlPrediction {
    /// Estimated UNIX timestamp when this IoC will become stale.
    pub stale_at: u64,
    /// Confidence in the prediction `[0.0, 1.0]`.
    pub confidence: f32,
    /// Method used for prediction.
    pub method: TtlMethod,
}

impl TtlPrediction {
    pub fn secs_remaining(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        // Use checked arithmetic to avoid wrap-around from u64→i64 casts.
        // If stale_at < now the IoC is already stale; return a clamped negative.
        match self.stale_at.checked_sub(now) {
            Some(remaining) => i64::try_from(remaining).unwrap_or(i64::MAX),
            None => {
                // stale_at < now — already stale; return negative elapsed time.
                let elapsed = now - self.stale_at;
                i64::try_from(elapsed).map(|v| -v).unwrap_or(i64::MIN)
            }
        }
    }

    pub fn is_stale(&self) -> bool {
        self.secs_remaining() <= 0
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TtlMethod {
    /// Based on historical median lifetime of IoCs of this type.
    HistoricalMedian,
    /// Based on last observed activity + decay threshold.
    DecayBased,
    /// Expert-defined fixed TTL.
    Fixed,
}

/// Predicts the TTL of an IoC based on its observation history.
pub struct TtlPredictor {
    /// Default TTLs per IoC kind (in seconds).
    default_ttls: HashMap<String, u64>,
}

impl TtlPredictor {
    pub fn new() -> Self {
        let mut m = HashMap::new();
        m.insert("Ip".into(), 30 * 86400);      // IPs: 30 days
        m.insert("Domain".into(), 90 * 86400);  // Domains: 90 days
        m.insert("Hash".into(), 365 * 86400);   // Hashes: 1 year (immutable)
        m.insert("Url".into(), 14 * 86400);     // URLs: 14 days
        m.insert("Email".into(), 60 * 86400);
        Self { default_ttls: m }
    }

    /// Predict TTL using a decay-based model.
    ///
    /// The IoC is predicted to become stale when its estimated activity level
    /// drops below `decay_threshold` (fraction of peak activity).
    pub fn predict_decay(
        &self,
        ts: &TimeSeries,
        ioc_kind: &str,
        decay_threshold: f64,
    ) -> TtlPrediction {
        if ts.buckets.is_empty() {
            let default_secs = self.default_ttls.get(ioc_kind).copied().unwrap_or(30 * 86400);
            let stale_at = ts.last_seen + default_secs;
            return TtlPrediction {
                stale_at,
                confidence: 0.3,
                method: TtlMethod::Fixed,
            };
        }

        let mean = ts.mean();
        let sorted = ts.sorted_buckets();
        let last_ts = sorted.last().map(|(ts, _)| *ts).unwrap_or(ts.last_seen);

        // Simple linear regression on log(count) to estimate decay rate
        let n = sorted.len() as f64;
        if n < 3.0 {
            // Fall back to historical median
            let median_secs = self.default_ttls.get(ioc_kind).copied().unwrap_or(30 * 86400);
            return TtlPrediction {
                stale_at: last_ts + median_secs,
                confidence: 0.4,
                method: TtlMethod::HistoricalMedian,
            };
        }

        // Estimate when extrapolated trend reaches decay_threshold * mean
        let target = decay_threshold * mean;
        let _bucket_secs = ts.resolution.secs() as f64;

        // Naive: look at rate of decline in last 25% of the series.
        // Compute tail_start in integer arithmetic to avoid f64 precision
        // loss for very long series (len > 2^53).
        let tail_start = sorted.len() - sorted.len() / 4;
        let tail: Vec<(f64, f64)> = sorted[tail_start..]
            .iter()
            .map(|(t, c)| (*t as f64, *c as f64))
            .collect();

        let slope = if tail.len() >= 2 {
            let first = &tail[0];
            let last = &tail[tail.len() - 1];
            let dt = last.0 - first.0;
            if dt > 0.0 { (last.1 - first.1) / dt } else { 0.0 }
        } else {
            0.0
        };

        let last_count = sorted.last().map(|(_, c)| *c as f64).unwrap_or(mean);
        let stale_at = if slope < 0.0 && target < last_count {
            let secs_to_stale = (last_count - target) / (-slope);
            // Guard against NaN / infinite / negative f64 before casting to u64,
            // which is UB in Rust < 1.45 and saturates in later editions only
            // for non-NaN values. Clamp to a reasonable upper bound.
            let secs_to_stale_u64 = if secs_to_stale.is_finite() && secs_to_stale >= 0.0 {
                (secs_to_stale as u64).min(365 * 10 * 86_400) // cap at 10 years
            } else {
                self.default_ttls.get(ioc_kind).copied().unwrap_or(30 * 86_400)
            };
            last_ts + secs_to_stale_u64
        } else {
            // If not declining, use default
            last_ts + self.default_ttls.get(ioc_kind).copied().unwrap_or(30 * 86400)
        };

        TtlPrediction {
            stale_at,
            confidence: 0.65,
            method: TtlMethod::DecayBased,
        }
    }
}

impl Default for TtlPredictor {
    fn default() -> Self {
        Self::new()
    }
}

// ── Seasonality analyzer ──────────────────────────────────────────────────────

/// Detected seasonal pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeasonalPattern {
    /// Period in buckets.
    pub period_buckets: u64,
    /// Period in human-readable form.
    pub period_label: String,
    /// Autocorrelation coefficient at this period `[-1, 1]`.
    pub autocorrelation: f64,
    /// Whether this pattern is statistically significant (autocorr > threshold).
    pub significant: bool,
}

/// Detects recurring campaign patterns via autocorrelation.
pub struct SeasonalityAnalyzer {
    /// Minimum autocorrelation to consider significant.
    pub significance_threshold: f64,
}

impl SeasonalityAnalyzer {
    pub fn new(threshold: f64) -> Self {
        Self {
            significance_threshold: threshold,
        }
    }

    /// Compute autocorrelation at lag `k` buckets.
    pub fn autocorrelation(ts: &TimeSeries, lag: u64) -> f64 {
        let sorted = ts.sorted_buckets();
        let n = sorted.len();
        if n <= lag as usize {
            return 0.0;
        }

        let mean = ts.mean();
        let denominator: f64 = sorted
            .iter()
            .map(|(_, c)| {
                let diff = *c as f64 - mean;
                diff * diff
            })
            .sum::<f64>();

        if denominator == 0.0 {
            return 0.0;
        }

        let numerator: f64 = sorted[..n - lag as usize]
            .iter()
            .zip(sorted[lag as usize..].iter())
            .map(|((_, c1), (_, c2))| (*c1 as f64 - mean) * (*c2 as f64 - mean))
            .sum::<f64>();

        numerator / denominator
    }

    /// Analyze seasonality for common periods (7-day, 14-day, 30-day).
    pub fn analyze(&self, ts: &TimeSeries) -> Vec<SeasonalPattern> {
        let _bucket_secs = ts.resolution.secs();
        let periods: Vec<(u64, &str)> = match ts.resolution {
            BucketResolution::Hourly => vec![
                (24, "daily"),
                (24 * 7, "weekly"),
                (24 * 30, "monthly"),
            ],
            BucketResolution::Daily => vec![
                (7, "weekly"),
                (14, "biweekly"),
                (30, "monthly"),
            ],
            BucketResolution::Weekly => vec![
                (4, "monthly"),
                (13, "quarterly"),
            ],
        };

        periods
            .into_iter()
            .map(|(lag, label)| {
                let ac = Self::autocorrelation(ts, lag);
                SeasonalPattern {
                    period_buckets: lag,
                    period_label: label.to_string(),
                    autocorrelation: ac,
                    significant: ac >= self.significance_threshold,
                }
            })
            .collect()
    }
}

// ── Temporal correlation matrix ───────────────────────────────────────────────

/// Pearson correlation between two time series (aligned by bucket).
pub fn pearson_correlation(a: &TimeSeries, b: &TimeSeries) -> f64 {
    // Align by common buckets
    let keys_a: std::collections::HashSet<u64> = a.buckets.keys().copied().collect();
    let keys_b: std::collections::HashSet<u64> = b.buckets.keys().copied().collect();
    let common: Vec<u64> = keys_a.intersection(&keys_b).copied().collect();

    if common.len() < 2 {
        return 0.0;
    }

    let vals_a: Vec<f64> = common.iter().map(|k| *a.buckets.get(k).unwrap() as f64).collect();
    let vals_b: Vec<f64> = common.iter().map(|k| *b.buckets.get(k).unwrap() as f64).collect();

    let n = vals_a.len() as f64;
    let mean_a = vals_a.iter().sum::<f64>() / n;
    let mean_b = vals_b.iter().sum::<f64>() / n;

    let num: f64 = vals_a.iter().zip(vals_b.iter())
        .map(|(a, b)| (a - mean_a) * (b - mean_b))
        .sum();
    let den_a: f64 = vals_a.iter().map(|a| (a - mean_a).powi(2)).sum::<f64>().sqrt();
    let den_b: f64 = vals_b.iter().map(|b| (b - mean_b).powi(2)).sum::<f64>().sqrt();

    if den_a.abs() < f64::EPSILON || den_b.abs() < f64::EPSILON {
        // Zero variance on either side. If both sides are identical constant
        // series, treat as perfectly correlated (Pearson is undefined here).
        if vals_a == vals_b {
            return 1.0;
        }
        return 0.0;
    }
    let r = num / (den_a * den_b);
    if r.is_nan() { 0.0 } else { r.clamp(-1.0, 1.0) }
}

/// Matrix of pairwise temporal correlations between named IoC time series.
pub struct TemporalCorrelationMatrix {
    pub labels: Vec<String>,
    pub matrix: Vec<Vec<f64>>,
}

impl TemporalCorrelationMatrix {
    pub fn compute(series: &[TimeSeries]) -> Self {
        let n = series.len();
        let labels = series.iter().map(|s| s.label.clone()).collect();
        let mut matrix = vec![vec![0.0_f64; n]; n];
        for i in 0..n {
            matrix[i][i] = 1.0;
            for j in (i + 1)..n {
                let r = pearson_correlation(&series[i], &series[j]);
                matrix[i][j] = r;
                matrix[j][i] = r;
            }
        }
        Self { labels, matrix }
    }

    /// Find pairs with correlation above threshold.
    pub fn high_correlation_pairs(&self, threshold: f64) -> Vec<(String, String, f64)> {
        let n = self.labels.len();
        let mut pairs = Vec::new();
        for i in 0..n {
            for j in (i + 1)..n {
                let r = self.matrix[i][j];
                if r.abs() >= threshold {
                    pairs.push((self.labels[i].clone(), self.labels[j].clone(), r));
                }
            }
        }
        pairs.sort_by(|a, b| b.2.abs().total_cmp(&a.2.abs()));
        pairs
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_burst_series() -> TimeSeries {
        let mut ts = TimeSeries::new("test", BucketResolution::Daily);
        // Normal baseline: 1 observation/day
        for day in 0..30u64 {
            ts.observe(day * 86400);
        }
        // Burst on day 20: 20 observations
        for _ in 0..19 {
            ts.observe(20 * 86400 + 100);
        }
        ts
    }

    #[test]
    fn burst_detection() {
        let ts = make_burst_series();
        let detector = CampaignDetector::default();
        let bursts = detector.detect(&ts);
        assert!(!bursts.is_empty(), "should detect at least one burst");
        let burst = &bursts[0];
        assert!(burst.peak_count >= 10, "peak should be high: {}", burst.peak_count);
    }

    #[test]
    fn time_series_mean_std() {
        let mut ts = TimeSeries::new("x", BucketResolution::Daily);
        for i in 0..10u64 {
            for _ in 0..5 {
                ts.observe(i * 86400);
            }
        }
        assert!((ts.mean() - 5.0).abs() < 0.1, "mean should be 5: {}", ts.mean());
        assert!(ts.std_dev() < 0.1, "std_dev should be 0: {}", ts.std_dev());
    }

    #[test]
    fn ttl_predictor_fallback() {
        let ts = TimeSeries::new("empty", BucketResolution::Daily);
        let pred = TtlPredictor::new();
        let result = pred.predict_decay(&ts, "Ip", 0.1);
        assert!(result.stale_at > 0);
    }

    #[test]
    fn pearson_corr_identical() {
        let mut ts = TimeSeries::new("a", BucketResolution::Daily);
        for i in 0..10u64 { ts.observe(i * 86400); }
        // Correlation with itself should be 1.0 or close
        let r = pearson_correlation(&ts, &ts);
        assert!((r - 1.0).abs() < 1e-6, "self-correlation: {r}");
    }

    #[test]
    fn correlation_matrix_high_pair() {
        let mut ts_a = TimeSeries::new("ioc_a", BucketResolution::Daily);
        let mut ts_b = TimeSeries::new("ioc_b", BucketResolution::Daily);
        for i in 0..10u64 {
            for _ in 0..(i + 1) {
                ts_a.observe(i * 86400);
                ts_b.observe(i * 86400); // identical pattern
            }
        }
        let matrix = TemporalCorrelationMatrix::compute(&[ts_a, ts_b]);
        let pairs = matrix.high_correlation_pairs(0.95);
        assert!(!pairs.is_empty(), "should find high-correlation pair");
    }
}
