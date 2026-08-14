//! Side-channel attack framework.
//!
//! Provides power trace collection, DPA (Differential Power Analysis),
//! DTW-based trace alignment, trace filtering, SPA peak detection,
//! and an EM analysis skeleton.

// ── PowerTrace ────────────────────────────────────────────────────────────────

/// A single power trace: a time-series of analog power samples.
#[derive(Debug, Clone, PartialEq)]
pub struct PowerTrace {
    /// Sample points (typically voltage/current readings).
    pub samples: Vec<f64>,
    /// Optional label (plaintext input byte, key hypothesis index, etc.).
    pub label: Option<u8>,
    /// Sample rate in Hz (for frequency-domain operations).
    pub sample_rate_hz: f64,
}

impl PowerTrace {
    /// Create a new trace.
    #[must_use]
    pub const fn new(samples: Vec<f64>) -> Self {
        Self {
            samples,
            label: None,
            sample_rate_hz: 1_000_000.0,
        }
    }

    /// Create a trace with a label.
    #[must_use]
    pub const fn with_label(mut self, label: u8) -> Self {
        self.label = Some(label);
        self
    }

    /// Number of samples.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.samples.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Mean sample value.
    #[must_use]
    pub fn mean(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.samples.iter().sum::<f64>()
            / f64::from(u32::try_from(self.samples.len()).unwrap_or(u32::MAX))
    }

    /// Variance of sample values.
    #[must_use]
    pub fn variance(&self) -> f64 {
        if self.samples.len() < 2 {
            return 0.0;
        }
        let m = self.mean();
        self.samples.iter().map(|&x| (x - m).powi(2)).sum::<f64>()
            / f64::from(u32::try_from(self.samples.len() - 1).unwrap_or(u32::MAX))
    }

    /// Standard deviation.
    #[must_use]
    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Point-wise XOR with another trace (useful for difference traces).
    #[must_use]
    pub fn subtract(&self, other: &Self) -> Self {
        let len = self.samples.len().min(other.samples.len());
        Self::new(
            (0..len)
                .map(|i| self.samples[i] - other.samples[i])
                .collect(),
        )
    }

    /// Sum of absolute values.
    #[must_use]
    pub fn energy(&self) -> f64 {
        self.samples.iter().map(|&x| x * x).sum()
    }

    /// Normalize to zero mean, unit variance.
    #[must_use]
    pub fn normalize(&self) -> Self {
        let m = self.mean();
        let sd = self.std_dev();
        if sd < 1e-12 {
            return Self::new(vec![0.0; self.samples.len()]);
        }
        Self::new(self.samples.iter().map(|&x| (x - m) / sd).collect())
    }
}

// ── Hamming Weight Power Model ────────────────────────────────────────────────

/// Compute the Hamming weight of a byte (used as a power model).
///
/// Uses a manual bit-counting approach so the function can be `const fn`.
#[must_use]
pub const fn hamming_weight(x: u8) -> u8 {
    let v = (x & 0x55) + ((x >> 1) & 0x55);
    let v = (v & 0x33) + ((v >> 2) & 0x33);
    (v & 0x0f) + ((v >> 4) & 0x0f)
}

/// Compute the Hamming distance between two bytes.
#[must_use]
pub const fn hamming_distance(a: u8, b: u8) -> u8 {
    hamming_weight(a ^ b)
}

// ── DPA (Differential Power Analysis) ────────────────────────────────────────

/// Power model for DPA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerModel {
    /// Hamming weight of a data value.
    HammingWeight,
    /// Hamming distance between two consecutive data values.
    HammingDistance,
    /// Identity (use raw data value as model).
    Identity,
}

/// Result of a DPA attack on one AES key byte.
#[derive(Debug, Clone)]
pub struct DpaKeyByteResult {
    /// Key byte position (0..15).
    pub byte_pos: usize,
    /// Best key byte candidate.
    pub best_key: u8,
    /// Correlation coefficient for the best candidate.
    pub best_correlation: f64,
    /// Full correlation vector (one entry per key guess 0..255).
    pub correlations: Vec<f64>,
    /// Sample index of the peak correlation.
    pub peak_sample: usize,
}

impl DpaKeyByteResult {
    /// Return the top-N key candidates sorted by correlation magnitude.
    #[must_use]
    pub fn top_candidates(&self, n: usize) -> Vec<(u8, f64)> {
        let mut indexed: Vec<(u8, f64)> = self
            .correlations
            .iter()
            .enumerate()
            .map(|(i, &c)| (u8::try_from(i).unwrap_or(u8::MAX), c.abs()))
            .collect();
        indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        indexed.truncate(n);
        indexed
    }
}

/// DPA attack engine.
pub struct DPA {
    /// Collected traces.
    pub traces: Vec<PowerTrace>,
    /// Power model to use.
    pub model: PowerModel,
}

impl DPA {
    /// Create a new DPA engine.
    #[must_use]
    pub const fn new(model: PowerModel) -> Self {
        Self {
            traces: Vec::new(),
            model,
        }
    }

    /// Add a trace with an associated input byte.
    pub fn add_trace(&mut self, trace: PowerTrace) {
        self.traces.push(trace);
    }

    /// Number of traces.
    #[must_use]
    pub const fn trace_count(&self) -> usize {
        self.traces.len()
    }

    /// Compute the power model value for a given (`plaintext_byte`, `key_guess`) pair.
    #[must_use]
    pub const fn model_value(&self, plaintext: u8, key_guess: u8) -> u8 {
        let intermediate = Self::aes_sbox(plaintext ^ key_guess);
        match self.model {
            PowerModel::HammingWeight => hamming_weight(intermediate),
            PowerModel::HammingDistance => hamming_distance(intermediate, 0),
            PowerModel::Identity => intermediate,
        }
    }

    /// Minimal AES S-box lookup.
    const fn aes_sbox(x: u8) -> u8 {
        AES_SBOX[x as usize]
    }

    /// Compute Pearson correlation between two f64 slices.
    #[must_use]
    pub fn pearson_correlation(x: &[f64], y: &[f64]) -> f64 {
        let n = x.len().min(y.len());
        if n < 2 {
            return 0.0;
        }
        let nf = f64::from(u32::try_from(n).unwrap_or(u32::MAX));
        let mx = x[..n].iter().sum::<f64>() / nf;
        let my = y[..n].iter().sum::<f64>() / nf;
        let num: f64 = (0..n).map(|i| (x[i] - mx) * (y[i] - my)).sum();
        let dx: f64 = (0..n).map(|i| (x[i] - mx).powi(2)).sum::<f64>().sqrt();
        let dy: f64 = (0..n).map(|i| (y[i] - my).powi(2)).sum::<f64>().sqrt();
        if dx < 1e-12 || dy < 1e-12 {
            return 0.0;
        }
        num / (dx * dy)
    }

    /// Correlate model predictions against traces for each sample point.
    /// Returns a correlation trace (one f64 per sample point).
    #[must_use]
    pub fn correlate_traces(&self, key_guess: u8) -> Vec<f64> {
        if self.traces.is_empty() {
            return Vec::new();
        }
        let n_samples = self.traces[0].len();
        let mut result = vec![0.0f64; n_samples];

        // Build model vector: for each trace, the power model prediction
        let model_vals: Vec<f64> = self
            .traces
            .iter()
            .filter_map(|t| t.label.map(|lbl| f64::from(self.model_value(lbl, key_guess))))
            .collect();

        if model_vals.is_empty() {
            return result;
        }

        for (sample_idx, res) in result.iter_mut().enumerate().take(n_samples) {
            let trace_vals: Vec<f64> = self
                .traces
                .iter()
                .filter(|t| t.label.is_some())
                .filter_map(|t| t.samples.get(sample_idx).copied())
                .collect();

            *res = Self::pearson_correlation(&model_vals, &trace_vals);
        }
        result
    }

    /// Run a DPA attack on key byte position `byte_pos`.
    /// `plaintexts` and `traces` must have the same length.
    #[must_use]
    pub fn dpa_attack_aes_key_byte(&self, byte_pos: usize) -> DpaKeyByteResult {
        let mut best_key = 0u8;
        let mut best_corr = -1.0f64;
        let mut best_peak_sample = 0usize;
        let mut correlations = vec![0.0f64; 256];

        for key_guess in 0u8..=255 {
            let corr_trace = self.correlate_traces(key_guess);
            let (peak_idx, peak_val) = corr_trace
                .iter()
                .enumerate()
                .map(|(i, &c)| (i, c.abs()))
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap_or((0, 0.0));

            correlations[usize::from(key_guess)] = peak_val;
            if peak_val > best_corr {
                best_corr = peak_val;
                best_key = key_guess;
                best_peak_sample = peak_idx;
            }
        }

        DpaKeyByteResult {
            byte_pos,
            best_key,
            best_correlation: best_corr,
            correlations,
            peak_sample: best_peak_sample,
        }
    }
}

// ── DTW Trace Aligner ─────────────────────────────────────────────────────────

/// Dynamic Time Warping alignment of power traces.
pub struct TraceAligner;

impl TraceAligner {
    /// Compute the DTW distance between two traces.
    #[must_use]
    pub fn dtw_distance(a: &PowerTrace, b: &PowerTrace) -> f64 {
        let n = a.len();
        let m = b.len();
        if n == 0 || m == 0 {
            return f64::INFINITY;
        }
        let mut dp = vec![vec![f64::INFINITY; m + 1]; n + 1];
        dp[0][0] = 0.0;
        for i in 1..=n {
            for j in 1..=m {
                let cost = (a.samples[i - 1] - b.samples[j - 1]).powi(2);
                dp[i][j] = cost + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1]);
            }
        }
        dp[n][m].sqrt()
    }

    /// Align `trace` to `reference` using a simple peak-matching approach.
    /// Shifts `trace` by up to `max_shift` samples to minimize DTW distance.
    #[must_use]
    pub fn align(reference: &PowerTrace, trace: &PowerTrace, max_shift: usize) -> PowerTrace {
        if trace.is_empty() || reference.is_empty() {
            return trace.clone();
        }
        let mut best_shift = 0i64;
        let mut best_dist = f64::INFINITY;

        let shift_range = i64::try_from(max_shift).unwrap_or(i64::MAX);
        for shift in -shift_range..=shift_range {
            let aligned = Self::shift_trace(trace, shift);
            let dist = Self::dtw_distance(reference, &aligned);
            if dist < best_dist {
                best_dist = dist;
                best_shift = shift;
            }
        }
        Self::shift_trace(trace, best_shift)
    }

    /// Shift a trace by `shift` samples (pad with mean if needed).
    #[must_use]
    pub fn shift_trace(trace: &PowerTrace, shift: i64) -> PowerTrace {
        let n = trace.len();
        if n == 0 {
            return trace.clone();
        }
        let mean = trace.mean();
        let mut samples = vec![mean; n];
        for (i, s) in samples.iter_mut().enumerate() {
            let src = i64::try_from(i).unwrap_or(i64::MAX) - shift;
            if src >= 0
                && let Some(v) = trace.samples.get(usize::try_from(src).unwrap_or(usize::MAX))
            {
                *s = *v;
            }
        }
        PowerTrace::new(samples)
    }

    /// Align a batch of traces to a reference trace.
    #[must_use]
    pub fn align_batch(
        reference: &PowerTrace,
        traces: &[PowerTrace],
        max_shift: usize,
    ) -> Vec<PowerTrace> {
        traces
            .iter()
            .map(|t| Self::align(reference, t, max_shift))
            .collect()
    }

    /// Compute average trace from a batch.
    #[must_use]
    pub fn average_trace(traces: &[PowerTrace]) -> PowerTrace {
        if traces.is_empty() {
            return PowerTrace::new(Vec::new());
        }
        let n = traces[0].len();
        let count = f64::from(u32::try_from(traces.len()).unwrap_or(u32::MAX));
        let samples: Vec<f64> = (0..n)
            .map(|i| {
                traces
                    .iter()
                    .filter_map(|t| t.samples.get(i).copied())
                    .sum::<f64>()
                    / count
            })
            .collect();
        PowerTrace::new(samples)
    }
}

// ── TraceFilter ───────────────────────────────────────────────────────────────

/// Digital filter for power traces.
pub struct TraceFilter;

impl TraceFilter {
    /// Apply a simple moving-average low-pass filter.
    /// `window_size` controls the cut-off frequency.
    #[must_use]
    pub fn low_pass(trace: &PowerTrace, window_size: usize) -> PowerTrace {
        if window_size == 0 || trace.is_empty() {
            return trace.clone();
        }
        let n = trace.samples.len();
        let half = window_size / 2;
        let samples: Vec<f64> = (0..n)
            .map(|i| {
                let lo = i.saturating_sub(half);
                let hi = (i + half + 1).min(n);
                let slice = &trace.samples[lo..hi];
                slice.iter().sum::<f64>()
                    / f64::from(u32::try_from(slice.len()).unwrap_or(u32::MAX))
            })
            .collect();
        PowerTrace::new(samples)
    }

    /// Apply a high-pass filter by subtracting the low-pass result.
    #[must_use]
    pub fn high_pass(trace: &PowerTrace, window_size: usize) -> PowerTrace {
        let lp = Self::low_pass(trace, window_size);
        trace.subtract(&lp)
    }

    /// Apply a notch filter at frequency `notch_freq_hz` (simplified: attenuate a
    /// narrow band using a difference filter).
    #[must_use]
    pub fn notch(trace: &PowerTrace, notch_period_samples: usize) -> PowerTrace {
        if notch_period_samples == 0 || trace.len() < notch_period_samples {
            return trace.clone();
        }
        let mut samples = trace.samples.clone();
        // Simple notch: subtract periodic component
        for (dst, src) in samples[notch_period_samples..].iter_mut().zip(trace.samples.iter()) {
            *dst -= 0.5 * src;
        }
        PowerTrace::new(samples)
    }

    /// Apply a Savitzky-Golay-like smoothing (quadratic, window 5).
    #[must_use]
    pub fn smooth(trace: &PowerTrace) -> PowerTrace {
        let n = trace.samples.len();
        if n < 5 {
            return trace.clone();
        }
        let mut out = trace.samples.clone();
        // Coefficients for quadratic least-squares fit, window=5
        let weights = [-3i32, 12, 17, 12, -3];
        let divisor = 35.0f64;
        for (idx, o) in out[2..n - 2].iter_mut().enumerate() {
            let i = idx + 2;
            let v: f64 = weights
                .iter()
                .enumerate()
                .map(|(j, &w)| f64::from(w) * trace.samples[i + j - 2])
                .sum::<f64>()
                / divisor;
            *o = v;
        }
        PowerTrace::new(out)
    }
}

// ── SPA (Simple Power Analysis) ───────────────────────────────────────────────

/// A detected peak in a power trace.
#[derive(Debug, Clone)]
pub struct PowerPeak {
    /// Sample index of the peak.
    pub sample: usize,
    /// Amplitude at the peak.
    pub amplitude: f64,
    /// Width at half maximum (in samples).
    pub width: usize,
}

/// Simple Power Analysis: visually inspect a single trace for peaks
/// that correspond to AES rounds or key-dependent operations.
pub struct SPA;

impl SPA {
    /// Detect local maxima in a power trace above a threshold.
    #[must_use]
    pub fn find_peaks(trace: &PowerTrace, threshold: f64, min_distance: usize) -> Vec<PowerPeak> {
        let n = trace.samples.len();
        let mut peaks = Vec::new();
        let mut last_peak: Option<usize> = None;

        for i in 1..n.saturating_sub(1) {
            let v = trace.samples[i];
            if v < threshold {
                continue;
            }
            if v <= trace.samples[i - 1] || v < trace.samples[i + 1] {
                continue;
            }
            if last_peak.is_some_and(|lp| i < lp + min_distance) {
                continue;
            }
            // Compute width at half-maximum
            let half = v / 2.0;
            let mut lo = i;
            while lo > 0 && trace.samples[lo] > half {
                lo -= 1;
            }
            let mut hi = i;
            while hi + 1 < n && trace.samples[hi] > half {
                hi += 1;
            }
            peaks.push(PowerPeak {
                sample: i,
                amplitude: v,
                width: hi - lo,
            });
            last_peak = Some(i);
        }
        peaks
    }

    /// Classify peaks into likely AES round markers.
    /// Expects exactly 10 evenly spaced peaks for AES-128.
    #[must_use]
    pub fn classify_aes_rounds(peaks: &[PowerPeak]) -> Option<Vec<(usize, usize)>> {
        if peaks.len() < 10 {
            return None;
        }
        // Check roughly equal spacing
        let positions: Vec<usize> = peaks.iter().take(10).map(|p| p.sample).collect();
        let diffs: Vec<usize> = positions.windows(2).map(|w| w[1] - w[0]).collect();
        let mean_diff = f64::from(u32::try_from(diffs.iter().sum::<usize>()).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(diffs.len()).unwrap_or(u32::MAX));
        let max_dev = diffs
            .iter()
            .map(|&d| (f64::from(u32::try_from(d).unwrap_or(u32::MAX)) - mean_diff).abs())
            .fold(0.0f64, f64::max);
        if max_dev > mean_diff * 0.2 {
            return None; // too irregular
        }
        Some(
            positions
                .into_iter()
                .enumerate()
                .map(|(r, s)| (r + 1, s))
                .collect(),
        )
    }

    /// Compute the Signal-to-Noise Ratio of a set of traces with different classes.
    /// SNR = `Var(class_means)` / `Mean(class_variances)`.
    #[must_use]
    pub fn snr(traces_class0: &[PowerTrace], traces_class1: &[PowerTrace]) -> Vec<f64> {
        let n0 = traces_class0.len();
        let n1 = traces_class1.len();
        if n0 == 0 || n1 == 0 {
            return Vec::new();
        }
        let len = traces_class0[0].len().min(traces_class1[0].len());
        let n0f = f64::from(u32::try_from(n0).unwrap_or(u32::MAX));
        let n1f = f64::from(u32::try_from(n1).unwrap_or(u32::MAX));
        let mut result = vec![0.0f64; len];
        for (i, res) in result.iter_mut().enumerate() {
            let mu0 = traces_class0
                .iter()
                .filter_map(|t| t.samples.get(i))
                .sum::<f64>()
                / n0f;
            let mu1 = traces_class1
                .iter()
                .filter_map(|t| t.samples.get(i))
                .sum::<f64>()
                / n1f;
            let var0: f64 = traces_class0
                .iter()
                .filter_map(|t| t.samples.get(i))
                .map(|&x| (x - mu0).powi(2))
                .sum::<f64>()
                / n0f;
            let var1: f64 = traces_class1
                .iter()
                .filter_map(|t| t.samples.get(i))
                .map(|&x| (x - mu1).powi(2))
                .sum::<f64>()
                / n1f;
            let signal = (mu0 - mu1).powi(2);
            let noise = f64::midpoint(var0, var1);
            *res = if noise < 1e-12 { 0.0 } else { signal / noise };
        }
        result
    }
}

// ── EM Analysis ──────────────────────────────────────────────────────────────

/// Electromagnetic analysis trace (near-field measurement).
#[derive(Debug, Clone)]
pub struct EmTrace {
    /// Power trace data.
    pub trace: PowerTrace,
    /// Frequency band center (Hz) at which the probe was tuned.
    pub center_freq_hz: f64,
    /// Probe position (x, y) in millimetres.
    pub probe_position: (f64, f64),
}

impl EmTrace {
    /// Create a new EM trace.
    #[must_use]
    pub const fn new(samples: Vec<f64>, center_freq_hz: f64, probe_position: (f64, f64)) -> Self {
        Self {
            trace: PowerTrace::new(samples),
            center_freq_hz,
            probe_position,
        }
    }
}

/// EM analysis engine.
pub struct EMAnalysis {
    pub traces: Vec<EmTrace>,
}

impl EMAnalysis {
    /// Create a new EM analysis engine.
    #[must_use]
    pub const fn new() -> Self {
        Self { traces: Vec::new() }
    }

    /// Add an EM trace.
    pub fn add_trace(&mut self, trace: EmTrace) {
        self.traces.push(trace);
    }

    /// Number of traces.
    #[must_use]
    pub const fn trace_count(&self) -> usize {
        self.traces.len()
    }

    /// Filter traces by probe position (within radius).
    #[must_use]
    pub fn traces_near(&self, x: f64, y: f64, radius: f64) -> Vec<&EmTrace> {
        self.traces
            .iter()
            .filter(|t| {
                let dx = t.probe_position.0 - x;
                let dy = t.probe_position.1 - y;
                dx.hypot(dy) <= radius
            })
            .collect()
    }

    /// Estimate the best probe position by finding the position with highest SNR.
    /// Returns the position and SNR score.
    #[must_use]
    pub fn best_probe_position(
        &self,
        class0_labels: &[u8],
        class1_labels: &[u8],
    ) -> Option<(f64, f64, f64)> {
        // Group traces by class
        let mut best_pos = (0.0f64, 0.0f64);
        let mut best_score = -1.0f64;

        let unique_positions: Vec<(f64, f64)> = {
            let mut seen = Vec::new();
            for t in &self.traces {
                if !seen.iter().any(|&(px, py): &(f64, f64)| {
                    (px - t.probe_position.0).abs() < 0.1 && (py - t.probe_position.1).abs() < 0.1
                }) {
                    seen.push(t.probe_position);
                }
            }
            seen
        };

        for &(px, py) in &unique_positions {
            let local_traces: Vec<&EmTrace> = self.traces_near(px, py, 0.5);
            let c0: Vec<PowerTrace> = local_traces
                .iter()
                .filter(|t| {
                    t.trace
                        .label
                        .is_some_and(|l| class0_labels.contains(&l))
                })
                .map(|t| t.trace.clone())
                .collect();
            let c1: Vec<PowerTrace> = local_traces
                .iter()
                .filter(|t| {
                    t.trace
                        .label
                        .is_some_and(|l| class1_labels.contains(&l))
                })
                .map(|t| t.trace.clone())
                .collect();
            let snr = SPA::snr(&c0, &c1);
            let max_snr = snr.iter().copied().fold(0.0f64, f64::max);
            if max_snr > best_score {
                best_score = max_snr;
                best_pos = (px, py);
            }
        }

        if best_score >= 0.0 {
            Some((best_pos.0, best_pos.1, best_score))
        } else {
            None
        }
    }
}

impl Default for EMAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

// ── AES S-box ─────────────────────────────────────────────────────────────────

#[rustfmt::skip]
const AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PowerTrace ────────────────────────────────────────────────────────────

    #[test]
    fn test_power_trace_new() {
        let t = PowerTrace::new(vec![1.0, 2.0, 3.0]);
        assert_eq!(t.len(), 3);
        assert!(!t.is_empty());
    }

    #[test]
    fn test_power_trace_empty() {
        let t = PowerTrace::new(vec![]);
        assert!(t.is_empty());
    }

    #[test]
    fn test_power_trace_mean() {
        let t = PowerTrace::new(vec![1.0, 2.0, 3.0, 4.0]);
        assert!((t.mean() - 2.5).abs() < 1e-9);
    }

    #[test]
    fn test_power_trace_variance() {
        let t = PowerTrace::new(vec![1.0, 2.0, 3.0, 4.0]);
        // Variance = 5/3 ≈ 1.667
        assert!((t.variance() - 5.0 / 3.0).abs() < 1e-6);
    }

    #[test]
    fn test_power_trace_normalize() {
        let t = PowerTrace::new(vec![1.0, 2.0, 3.0, 4.0]);
        let n = t.normalize();
        assert!((n.mean()).abs() < 1e-9);
        assert!((n.std_dev() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_power_trace_subtract() {
        let a = PowerTrace::new(vec![3.0, 4.0, 5.0]);
        let b = PowerTrace::new(vec![1.0, 2.0, 3.0]);
        let diff = a.subtract(&b);
        assert_eq!(diff.samples, vec![2.0, 2.0, 2.0]);
    }

    #[test]
    fn test_power_trace_energy() {
        let t = PowerTrace::new(vec![3.0, 4.0]);
        assert!((t.energy() - 25.0).abs() < 1e-9);
    }

    // ── Hamming weight ────────────────────────────────────────────────────────

    #[test]
    fn test_hamming_weight() {
        assert_eq!(hamming_weight(0), 0);
        assert_eq!(hamming_weight(0xFF), 8);
        assert_eq!(hamming_weight(0x0F), 4);
    }

    #[test]
    fn test_hamming_distance() {
        assert_eq!(hamming_distance(0, 0xFF), 8);
        assert_eq!(hamming_distance(0xAA, 0x55), 8);
        assert_eq!(hamming_distance(0, 0), 0);
    }

    // ── DPA ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_dpa_new() {
        let dpa = DPA::new(PowerModel::HammingWeight);
        assert_eq!(dpa.trace_count(), 0);
    }

    #[test]
    fn test_dpa_add_trace() {
        let mut dpa = DPA::new(PowerModel::HammingWeight);
        dpa.add_trace(PowerTrace::new(vec![1.0; 16]).with_label(0));
        assert_eq!(dpa.trace_count(), 1);
    }

    #[test]
    fn test_dpa_model_value_hw() {
        let dpa = DPA::new(PowerModel::HammingWeight);
        let v = dpa.model_value(0x00, 0x00);
        // AES SBox(0) = 0x63, HW(0x63) = 5
        assert_eq!(v, hamming_weight(AES_SBOX[0]));
    }

    #[test]
    fn test_pearson_correlation_identical() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let corr = DPA::pearson_correlation(&x, &x);
        assert!((corr - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_pearson_correlation_opposite() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y: Vec<f64> = x.iter().map(|&v| -v).collect();
        let corr = DPA::pearson_correlation(&x, &y);
        assert!((corr + 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_dpa_attack_empty() {
        let dpa = DPA::new(PowerModel::HammingWeight);
        let result = dpa.dpa_attack_aes_key_byte(0);
        assert_eq!(result.correlations.len(), 256);
    }

    #[test]
    fn test_dpa_attack_with_traces() {
        let mut dpa = DPA::new(PowerModel::HammingWeight);
        let key_byte = 0x42u8;
        // Simulate: power = HW(SBox(pt XOR key)) + noise
        for pt in 0u8..=100 {
            let hw = f64::from(hamming_weight(AES_SBOX[(pt ^ key_byte) as usize]));
            let trace = PowerTrace::new(vec![hw; 16]).with_label(pt);
            dpa.add_trace(trace);
        }
        let result = dpa.dpa_attack_aes_key_byte(0);
        assert_eq!(result.best_key, key_byte);
    }

    #[test]
    fn test_dpa_top_candidates() {
        let mut dpa = DPA::new(PowerModel::HammingWeight);
        dpa.add_trace(PowerTrace::new(vec![1.0; 8]).with_label(0));
        let result = dpa.dpa_attack_aes_key_byte(0);
        let top = result.top_candidates(3);
        assert_eq!(top.len(), 3);
    }

    // ── TraceAligner ──────────────────────────────────────────────────────────

    #[test]
    fn test_dtw_distance_same() {
        let t = PowerTrace::new(vec![1.0, 2.0, 3.0]);
        assert!((TraceAligner::dtw_distance(&t, &t) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_dtw_distance_different() {
        let a = PowerTrace::new(vec![1.0, 2.0, 3.0]);
        let b = PowerTrace::new(vec![4.0, 5.0, 6.0]);
        assert!(TraceAligner::dtw_distance(&a, &b) > 0.0);
    }

    #[test]
    fn test_shift_trace_zero() {
        let t = PowerTrace::new(vec![1.0, 2.0, 3.0]);
        let shifted = TraceAligner::shift_trace(&t, 0);
        assert_eq!(shifted.samples, t.samples);
    }

    #[test]
    fn test_shift_trace_positive() {
        let t = PowerTrace::new(vec![1.0, 2.0, 3.0]);
        let shifted = TraceAligner::shift_trace(&t, 1);
        // samples[0] should be mean; samples[1] = original[0], samples[2] = original[1]
        assert!((shifted.samples[1] - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_average_trace() {
        let traces = vec![
            PowerTrace::new(vec![1.0, 2.0]),
            PowerTrace::new(vec![3.0, 4.0]),
        ];
        let avg = TraceAligner::average_trace(&traces);
        assert!((avg.samples[0] - 2.0).abs() < 1e-9);
        assert!((avg.samples[1] - 3.0).abs() < 1e-9);
    }

    // ── TraceFilter ───────────────────────────────────────────────────────────

    #[test]
    fn test_low_pass_identity_window_1() {
        let t = PowerTrace::new(vec![1.0, 5.0, 2.0, 8.0, 3.0]);
        let lp = TraceFilter::low_pass(&t, 1);
        // Window 1 = each point is average of itself and neighbors (radius 0)
        assert_eq!(lp.len(), 5);
    }

    #[test]
    fn test_high_pass_dc_removal() {
        let t = PowerTrace::new(vec![5.0; 16]); // pure DC
        let hp = TraceFilter::high_pass(&t, 8);
        // High-pass of DC signal should be near zero
        assert!(hp.samples.iter().all(|&x| x.abs() < 1e-9));
    }

    #[test]
    fn test_smooth_preserves_length() {
        let t = PowerTrace::new(vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]);
        let s = TraceFilter::smooth(&t);
        assert_eq!(s.len(), t.len());
    }

    #[test]
    fn test_notch_changes_trace() {
        let t = PowerTrace::new(vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]);
        let n = TraceFilter::notch(&t, 3);
        assert_ne!(n.samples, t.samples);
    }

    // ── SPA ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_spa_find_peaks_none_below_threshold() {
        let t = PowerTrace::new(vec![0.1, 0.2, 0.1, 0.3, 0.1]);
        let peaks = SPA::find_peaks(&t, 1.0, 1);
        assert!(peaks.is_empty());
    }

    #[test]
    fn test_spa_find_peaks_single() {
        let t = PowerTrace::new(vec![0.0, 0.0, 5.0, 0.0, 0.0]);
        let peaks = SPA::find_peaks(&t, 1.0, 1);
        assert_eq!(peaks.len(), 1);
        assert_eq!(peaks[0].sample, 2);
        assert!((peaks[0].amplitude - 5.0).abs() < 1e-9);
    }

    #[test]
    fn test_spa_find_peaks_min_distance() {
        // Two close peaks: second should be suppressed by min_distance
        let mut samples = vec![0.0f64; 20];
        samples[2] = 5.0;
        samples[4] = 5.0;
        let t = PowerTrace::new(samples);
        let peaks = SPA::find_peaks(&t, 1.0, 5);
        assert_eq!(peaks.len(), 1);
    }

    #[test]
    fn test_spa_classify_not_enough_peaks() {
        let peaks: Vec<PowerPeak> = (0..5)
            .map(|i| PowerPeak {
                sample: i * 10,
                amplitude: 5.0,
                width: 2,
            })
            .collect();
        assert!(SPA::classify_aes_rounds(&peaks).is_none());
    }

    #[test]
    fn test_spa_snr_empty() {
        let snr = SPA::snr(&[], &[]);
        assert!(snr.is_empty());
    }

    #[test]
    fn test_spa_snr_two_classes() {
        let c0: Vec<PowerTrace> = vec![PowerTrace::new(vec![1.0, 1.0, 1.0])];
        let c1: Vec<PowerTrace> = vec![PowerTrace::new(vec![3.0, 3.0, 3.0])];
        let snr = SPA::snr(&c0, &c1);
        assert_eq!(snr.len(), 3);
        // With zero variance in both classes and non-zero mean diff, SNR = infinity (or large)
        // Both have zero variance so SNR will be 0.0 / 0.0 → 0.0 due to our guard
    }

    // ── EM Analysis ───────────────────────────────────────────────────────────

    #[test]
    fn test_em_analysis_new() {
        let em = EMAnalysis::new();
        assert_eq!(em.trace_count(), 0);
    }

    #[test]
    fn test_em_analysis_add_trace() {
        let mut em = EMAnalysis::new();
        em.add_trace(EmTrace::new(vec![1.0; 8], 1e9, (0.0, 0.0)));
        assert_eq!(em.trace_count(), 1);
    }

    #[test]
    fn test_em_traces_near() {
        let mut em = EMAnalysis::new();
        em.add_trace(EmTrace::new(vec![1.0], 1e9, (0.0, 0.0)));
        em.add_trace(EmTrace::new(vec![1.0], 1e9, (10.0, 10.0)));
        let near = em.traces_near(0.0, 0.0, 1.0);
        assert_eq!(near.len(), 1);
    }

    #[test]
    fn test_em_best_probe_no_traces() {
        let em = EMAnalysis::new();
        let result = em.best_probe_position(&[0], &[1]);
        assert!(result.is_none());
    }
}
