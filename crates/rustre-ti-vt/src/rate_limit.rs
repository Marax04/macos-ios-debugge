//! Token-bucket rate limiter for the `VirusTotal` free-tier API (4 req/min).

use parking_lot::Mutex;
use std::time::{Duration, Instant};

/// Token-bucket rate limiter.
///
/// Default capacity is 4 tokens with a refill rate of 4 tokens per 60 seconds
/// (matching the `VirusTotal` free-tier limit).
pub struct VtRateLimiter {
    inner: Mutex<RateLimiterInner>,
}

struct RateLimiterInner {
    /// Maximum number of tokens in the bucket.
    capacity: u32,
    /// Tokens currently available.
    tokens: f64,
    /// Tokens added per second.
    refill_rate: f64,
    /// Time of the last token refill.
    last_refill: Instant,
}

impl VtRateLimiter {
    /// Create a limiter with the given capacity and requests-per-minute.
    #[must_use]
    pub fn new(capacity: u32, requests_per_minute: u32) -> Self {
        let refill_rate = f64::from(requests_per_minute) / 60.0;
        Self {
            inner: Mutex::new(RateLimiterInner {
                capacity,
                tokens: f64::from(capacity),
                refill_rate,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Create the default `VirusTotal` free-tier limiter (4 req/min).
    #[must_use]
    pub fn default_free_tier() -> Self {
        Self::new(4, 4)
    }

    /// Attempt to acquire a single token.
    ///
    /// Returns `Ok(())` if a token was available, or `Err(wait_duration)` if
    /// the caller must wait before retrying.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub fn try_acquire(&self) -> Result<(), Duration> {
        let mut inner = self.inner.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(inner.last_refill).as_secs_f64();
        inner.tokens = elapsed.mul_add(inner.refill_rate, inner.tokens).min(f64::from(inner.capacity));
        inner.last_refill = now;

        if inner.tokens >= 1.0 {
            inner.tokens -= 1.0;
            Ok(())
        } else {
            let secs_until_token = (1.0 - inner.tokens) / inner.refill_rate;
            drop(inner);
            Err(Duration::from_secs_f64(secs_until_token))
        }
    }

    /// Block asynchronously until a token is available, then consume it.
    pub async fn acquire(&self) {
        loop {
            match self.try_acquire() {
                Ok(()) => return,
                Err(wait) => {
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }

    /// Return the number of tokens currently available (may be fractional).
    #[must_use]
    pub fn available_tokens(&self) -> f64 {
        let inner = self.inner.lock();
        inner.tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_basic() {
        // High capacity so we can drain without waiting.
        let limiter = VtRateLimiter::new(10, 600); // 10 req/s
        for _ in 0..10 {
            assert!(limiter.try_acquire().is_ok());
        }
        // 11th should fail.
        assert!(limiter.try_acquire().is_err());
    }

    #[test]
    fn test_rate_limiter_refill() {
        let limiter = VtRateLimiter::new(1, 60); // 1 req/s
        assert!(limiter.try_acquire().is_ok());
        // Bucket is empty; should require waiting.
        let result = limiter.try_acquire();
        assert!(result.is_err());
        let wait = result.unwrap_err();
        assert!(wait.as_secs_f64() > 0.0);
        assert!(wait.as_secs_f64() <= 1.1); // Should be ~1 sec
    }

    #[test]
    fn test_default_free_tier() {
        let limiter = VtRateLimiter::default_free_tier();
        // Should start with 4 tokens.
        assert!((limiter.available_tokens() - 4.0).abs() < 0.01);
    }
}
