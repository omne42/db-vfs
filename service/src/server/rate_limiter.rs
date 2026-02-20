use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use db_vfs_core::policy::VfsPolicy;

#[derive(Clone)]
pub(super) struct RateLimiter {
    cfg: RateLimitConfig,
    shards: Arc<[tokio::sync::Mutex<RateLimitState>]>,
    tracked_ips: Arc<AtomicUsize>,
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

struct RateLimitState {
    buckets: HashMap<IpAddr, RateLimitBucket>,
    last_prune: Instant,
}

const MAX_BUCKETS_BEFORE_PRUNE: usize = 4096;
const BUCKET_TTL: Duration = Duration::from_secs(10 * 60);
const PRUNE_INTERVAL: Duration = Duration::from_secs(1);
const MAX_SHARDS: usize = 32;

impl RateLimiter {
    pub(super) fn new(policy: &VfsPolicy) -> Self {
        let enabled = policy.limits.max_requests_per_ip_per_sec > 0
            && policy.limits.max_requests_burst_per_ip > 0
            && policy.limits.max_rate_limit_ips > 0;
        let cfg = RateLimitConfig {
            enabled,
            refill_per_sec: policy.limits.max_requests_per_ip_per_sec as f64,
            capacity: policy.limits.max_requests_burst_per_ip as f64,
            max_ips: policy.limits.max_rate_limit_ips as usize,
        };
        let now = Instant::now();

        let initial_capacity = if cfg.enabled {
            cfg.max_ips.clamp(1, MAX_BUCKETS_BEFORE_PRUNE)
        } else {
            1
        };
        let shard_count = if cfg.enabled {
            shard_count_for(cfg.max_ips)
        } else {
            1
        };
        let per_shard_capacity = initial_capacity.div_ceil(shard_count).max(1);
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(tokio::sync::Mutex::new(RateLimitState {
                buckets: HashMap::with_capacity(per_shard_capacity),
                last_prune: now,
            }));
        }

        Self {
            cfg,
            shards: Arc::from(shards),
            tracked_ips: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(super) async fn allow(&self, ip: Option<IpAddr>) -> bool {
        if !self.cfg.enabled {
            return true;
        }
        let Some(ip) = ip else {
            return true;
        };

        let now = Instant::now();
        let idx = self.shard_index(&ip);
        let mut state = self.shards[idx].lock().await;

        if now.saturating_duration_since(state.last_prune) >= PRUNE_INTERVAL {
            let removed = prune_stale_buckets(&mut state, now);
            self.release_ip_slots(removed);
        }

        if let Some(bucket) = state.buckets.get_mut(&ip) {
            return allow_from_bucket(bucket, now, self.cfg.refill_per_sec, self.cfg.capacity);
        }

        if !self.try_reserve_ip_slot() {
            drop(state);

            let removed = self.prune_stale_across_shards(now).await;
            if removed == 0 || !self.try_reserve_ip_slot() {
                return false;
            }

            let mut state = self.shards[idx].lock().await;
            if let Some(bucket) = state.buckets.get_mut(&ip) {
                self.release_ip_slots(1);
                return allow_from_bucket(bucket, now, self.cfg.refill_per_sec, self.cfg.capacity);
            }

            let bucket = state.buckets.entry(ip).or_insert(RateLimitBucket {
                tokens: self.cfg.capacity,
                last: now,
                last_seen: now,
            });

            return allow_from_bucket(bucket, now, self.cfg.refill_per_sec, self.cfg.capacity);
        }

        let bucket = state.buckets.entry(ip).or_insert(RateLimitBucket {
            tokens: self.cfg.capacity,
            last: now,
            last_seen: now,
        });

        allow_from_bucket(bucket, now, self.cfg.refill_per_sec, self.cfg.capacity)
    }

    fn shard_index(&self, ip: &IpAddr) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        ip.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len()
    }

    fn try_reserve_ip_slot(&self) -> bool {
        loop {
            let current = self.tracked_ips.load(Ordering::Acquire);
            if current >= self.cfg.max_ips {
                return false;
            }
            if self
                .tracked_ips
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn release_ip_slots(&self, removed: usize) {
        if removed == 0 {
            return;
        }
        let mut current = self.tracked_ips.load(Ordering::Acquire);
        loop {
            let next = current.saturating_sub(removed);
            match self.tracked_ips.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    async fn prune_stale_across_shards(&self, now: Instant) -> usize {
        let mut removed_total = 0usize;
        for shard in self.shards.iter() {
            let mut state = shard.lock().await;
            if now.saturating_duration_since(state.last_prune) < PRUNE_INTERVAL {
                continue;
            }
            removed_total = removed_total.saturating_add(prune_stale_buckets(&mut state, now));
        }
        self.release_ip_slots(removed_total);
        removed_total
    }

    #[cfg(test)]
    async fn total_bucket_count(&self) -> usize {
        let mut total = 0usize;
        for shard in self.shards.iter() {
            total = total.saturating_add(shard.lock().await.buckets.len());
        }
        total
    }
}

fn shard_count_for(max_ips: usize) -> usize {
    if max_ips == 0 {
        return 1;
    }
    max_ips.clamp(1, MAX_SHARDS)
}

fn allow_from_bucket(
    bucket: &mut RateLimitBucket,
    now: Instant,
    refill_per_sec: f64,
    capacity: f64,
) -> bool {
    bucket.last_seen = now;

    let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(capacity);
    bucket.last = now;

    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        false
    }
}

fn prune_stale_buckets(state: &mut RateLimitState, now: Instant) -> usize {
    let before = state.buckets.len();
    state
        .buckets
        .retain(|_, bucket| now.saturating_duration_since(bucket.last_seen) <= BUCKET_TTL);
    let len = state.buckets.len();
    let capacity = state.buckets.capacity();
    if capacity > MAX_BUCKETS_BEFORE_PRUNE && len.saturating_mul(4) < capacity {
        state.buckets.shrink_to(len.max(1));
    }
    state.last_prune = now;
    before.saturating_sub(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_vfs_core::policy::VfsPolicy;

    fn ips_for_shard(limiter: &RateLimiter, target: usize, count: usize) -> Vec<IpAddr> {
        let mut out = Vec::with_capacity(count);
        for idx in 1u16..=u16::MAX {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 20, (idx >> 8) as u8, idx as u8));
            if limiter.shard_index(&ip) == target {
                out.push(ip);
                if out.len() == count {
                    return out;
                }
            }
        }
        panic!("not enough ips found for shard");
    }

    fn ip_for_shard(limiter: &RateLimiter, target: usize) -> IpAddr {
        for idx in 1u16..=u16::MAX {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 20, (idx >> 8) as u8, idx as u8));
            if limiter.shard_index(&ip) == target {
                return ip;
            }
        }
        panic!("no ip found for shard");
    }

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

        for idx in 1u8..=4 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, idx));
            assert!(limiter.allow(Some(ip)).await);
        }

        let denied_ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 5));
        assert!(!limiter.allow(Some(denied_ip)).await);

        assert!(limiter.total_bucket_count().await <= 4);
        assert!(limiter.tracked_ips.load(Ordering::Acquire) <= 4);
    }

    #[tokio::test]
    async fn rate_limiter_allows_requests_without_ip_and_keeps_buckets_empty() {
        let policy = VfsPolicy {
            limits: db_vfs_core::policy::Limits {
                max_requests_per_ip_per_sec: 5,
                max_requests_burst_per_ip: 5,
                max_rate_limit_ips: 16,
                ..db_vfs_core::policy::Limits::default()
            },
            ..VfsPolicy::default()
        };
        let limiter = RateLimiter::new(&policy);

        assert!(limiter.allow(None).await);
        assert!(limiter.allow(None).await);

        assert_eq!(limiter.total_bucket_count().await, 0);
        assert_eq!(limiter.tracked_ips.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn disabled_rate_limiter_keeps_single_minimal_shard() {
        let policy = VfsPolicy {
            limits: db_vfs_core::policy::Limits {
                max_requests_per_ip_per_sec: 0,
                max_requests_burst_per_ip: 0,
                max_rate_limit_ips: 1_000_000,
                ..db_vfs_core::policy::Limits::default()
            },
            ..VfsPolicy::default()
        };
        let limiter = RateLimiter::new(&policy);

        assert_eq!(limiter.shards.len(), 1);
        assert!(
            limiter
                .allow(Some(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))))
                .await
        );
        assert_eq!(limiter.total_bucket_count().await, 0);
        assert_eq!(limiter.tracked_ips.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn rate_limiter_prunes_stale_buckets_on_interval() {
        let policy = VfsPolicy {
            limits: db_vfs_core::policy::Limits {
                max_requests_per_ip_per_sec: 5,
                max_requests_burst_per_ip: 5,
                max_rate_limit_ips: 10_000,
                ..db_vfs_core::policy::Limits::default()
            },
            ..VfsPolicy::default()
        };
        let limiter = RateLimiter::new(&policy);

        let now = Instant::now();
        let target_shard = 0usize;

        {
            let mut state = limiter.shards[target_shard].lock().await;
            let stale = now
                .checked_sub(BUCKET_TTL.saturating_add(Duration::from_secs(1)))
                .unwrap_or(now);
            for idx in 0u16..=MAX_BUCKETS_BEFORE_PRUNE as u16 {
                let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, (idx >> 8) as u8, idx as u8));
                state.buckets.insert(
                    ip,
                    RateLimitBucket {
                        tokens: 1.0,
                        last: stale,
                        last_seen: stale,
                    },
                );
            }
            limiter
                .tracked_ips
                .store(state.buckets.len(), Ordering::Release);
            state.last_prune = now
                .checked_sub(PRUNE_INTERVAL.saturating_add(Duration::from_millis(1)))
                .unwrap_or(now);
        }

        let fresh_ip = ip_for_shard(&limiter, target_shard);
        assert!(limiter.allow(Some(fresh_ip)).await);

        assert_eq!(limiter.total_bucket_count().await, 1);
        assert_eq!(limiter.tracked_ips.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn rate_limiter_prunes_stale_buckets_when_not_full() {
        let policy = VfsPolicy {
            limits: db_vfs_core::policy::Limits {
                max_requests_per_ip_per_sec: 5,
                max_requests_burst_per_ip: 5,
                max_rate_limit_ips: 10_000,
                ..db_vfs_core::policy::Limits::default()
            },
            ..VfsPolicy::default()
        };
        let limiter = RateLimiter::new(&policy);
        let now = Instant::now();
        let target_shard = 0usize;
        let ips = ips_for_shard(&limiter, target_shard, 5);

        {
            let mut state = limiter.shards[target_shard].lock().await;
            let stale = now
                .checked_sub(BUCKET_TTL.saturating_add(Duration::from_secs(1)))
                .unwrap_or(now);
            for ip in &ips[..4] {
                state.buckets.insert(
                    *ip,
                    RateLimitBucket {
                        tokens: 1.0,
                        last: stale,
                        last_seen: stale,
                    },
                );
            }
            limiter
                .tracked_ips
                .store(state.buckets.len(), Ordering::Release);
            state.last_prune = now
                .checked_sub(PRUNE_INTERVAL.saturating_add(Duration::from_millis(1)))
                .unwrap_or(now);
        }

        assert!(limiter.allow(Some(ips[4])).await);
        assert_eq!(limiter.total_bucket_count().await, 1);
        assert_eq!(limiter.tracked_ips.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn rate_limiter_reclaims_stale_entries_before_denying_new_ip() {
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
        let now = Instant::now();

        let target_shard = 0usize;
        let stale_shard = 1usize.min(limiter.shards.len().saturating_sub(1));
        let stale_ips = ips_for_shard(&limiter, stale_shard, 4);
        {
            let mut state = limiter.shards[stale_shard].lock().await;
            let stale = now
                .checked_sub(BUCKET_TTL.saturating_add(Duration::from_secs(1)))
                .unwrap_or(now);
            for ip in stale_ips {
                state.buckets.insert(
                    ip,
                    RateLimitBucket {
                        tokens: 1.0,
                        last: stale,
                        last_seen: stale,
                    },
                );
            }
            state.last_prune = now
                .checked_sub(PRUNE_INTERVAL.saturating_add(Duration::from_millis(1)))
                .unwrap_or(now);
        }
        limiter.tracked_ips.store(4, Ordering::Release);

        let fresh_ip = ip_for_shard(&limiter, target_shard);
        assert!(limiter.allow(Some(fresh_ip)).await);
        assert_eq!(limiter.total_bucket_count().await, 1);
        assert_eq!(limiter.tracked_ips.load(Ordering::Acquire), 1);
    }
}
