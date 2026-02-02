use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use db_vfs_core::policy::VfsPolicy;

#[derive(Clone)]
pub(super) struct RateLimiter {
    cfg: RateLimitConfig,
    buckets: Arc<tokio::sync::Mutex<HashMap<IpAddr, RateLimitBucket>>>,
}

#[derive(Clone, Copy)]
struct RateLimitConfig {
    enabled: bool,
    refill_per_sec: f64,
    capacity: f64,
    max_ips: usize,
}

#[derive(Clone, Copy)]
struct RateLimitBucket {
    tokens: f64,
    last: Instant,
    last_seen: Instant,
}

impl RateLimiter {
    pub(super) fn new(policy: &VfsPolicy) -> Self {
        let enabled = policy.limits.max_requests_per_ip_per_sec > 0;
        let cfg = RateLimitConfig {
            enabled,
            refill_per_sec: policy.limits.max_requests_per_ip_per_sec as f64,
            capacity: policy.limits.max_requests_burst_per_ip as f64,
            max_ips: policy.limits.max_rate_limit_ips as usize,
        };
        Self {
            cfg,
            buckets: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    pub(super) async fn allow(&self, ip: Option<IpAddr>) -> bool {
        if !self.cfg.enabled {
            return true;
        }
        let Some(ip) = ip else {
            return true;
        };

        const MAX_BUCKETS_BEFORE_PRUNE: usize = 4096;
        const BUCKET_TTL: Duration = Duration::from_secs(10 * 60);

        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;

        if buckets.len() > MAX_BUCKETS_BEFORE_PRUNE {
            buckets.retain(|_, bucket| now.duration_since(bucket.last_seen) <= BUCKET_TTL);
        }

        if self.cfg.max_ips > 0 && buckets.len() >= self.cfg.max_ips && !buckets.contains_key(&ip) {
            buckets.retain(|_, bucket| now.duration_since(bucket.last_seen) <= BUCKET_TTL);
            if buckets.len() >= self.cfg.max_ips {
                if let Some((&victim, _)) =
                    buckets.iter().min_by_key(|(_, bucket)| bucket.last_seen)
                {
                    buckets.remove(&victim);
                } else {
                    return false;
                }
            }
        }

        let bucket = buckets.entry(ip).or_insert(RateLimitBucket {
            tokens: self.cfg.capacity,
            last: now,
            last_seen: now,
        });
        bucket.last_seen = now;

        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.cfg.refill_per_sec).min(self.cfg.capacity);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_vfs_core::policy::VfsPolicy;

    #[tokio::test]
    async fn rate_limiter_caps_tracked_ips() {
        let policy = VfsPolicy {
            limits: db_vfs_core::policy::Limits {
                max_requests_per_ip_per_sec: 10,
                max_requests_burst_per_ip: 10,
                max_rate_limit_ips: 4,
                ..db_vfs_core::policy::Limits::default()
            },
            ..VfsPolicy::default()
        };
        let limiter = RateLimiter::new(&policy);

        for idx in 1u8..=5 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, idx));
            assert!(limiter.allow(Some(ip)).await);
        }

        let buckets = limiter.buckets.lock().await;
        assert!(buckets.len() <= 4);
        assert!(buckets.contains_key(&IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 5))));
    }
}
