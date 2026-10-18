//! Shared quotas, pacing and cooperative controls for network tasks.
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{
        Arc, LazyLock, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PoolConfig {
    pub name: String,
    pub concurrency: usize,
    pub delay_ms: u64,
    pub throttle_codes: Vec<u16>,
    pub backoff_ms: u64,
}
impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            name: "Default".into(),
            concurrency: 10,
            delay_ms: 0,
            throttle_codes: vec![429, 503],
            backoff_ms: 1000,
        }
    }
}
struct Pool {
    slots: Arc<tokio::sync::Semaphore>,
    next: tokio::sync::Mutex<Instant>,
    cooldown: AtomicU64,
}
static POOLS: LazyLock<Mutex<HashMap<String, Weak<Pool>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
fn millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
#[derive(Default)]
pub struct Control {
    pub paused: AtomicBool,
    pub cancelled: AtomicBool,
    pub sent: AtomicUsize,
    pub completed: AtomicUsize,
    pub errors: AtomicUsize,
}
impl Control {
    pub async fn ready(&self) -> Result<(), String> {
        loop {
            if self.cancelled.load(Ordering::Relaxed) {
                return Err("Task cancelled".into());
            }
            if !self.paused.load(Ordering::Relaxed) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }
    async fn wait(&self, delay: Duration) -> Result<(), String> {
        let end = Instant::now() + delay;
        while Instant::now() < end {
            self.ready().await?;
            tokio::time::sleep(
                end.saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(30)),
            )
            .await;
        }
        self.ready().await
    }
}
#[derive(Clone)]
pub struct Work {
    pool: Arc<Pool>,
    pub control: Arc<Control>,
    config: PoolConfig,
}
impl Work {
    pub fn new(config: PoolConfig, control: Arc<Control>) -> Self {
        let mut pools = POOLS.lock().unwrap();
        // Configuration changes apply when a pool next becomes idle, keeping one quota
        // shared by all active users of that name.
        let pool = pools
            .get(&config.name)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let p = Arc::new(Pool {
                    slots: Arc::new(tokio::sync::Semaphore::new(
                        config.concurrency.clamp(1, 200),
                    )),
                    next: tokio::sync::Mutex::new(Instant::now()),
                    cooldown: AtomicU64::new(0),
                });
                pools.insert(config.name.clone(), Arc::downgrade(&p));
                p
            });
        Self {
            pool,
            control,
            config,
        }
    }
    pub async fn begin(&self) -> Result<tokio::sync::OwnedSemaphorePermit, String> {
        loop {
            self.control.ready().await?;
            if let Ok(permit) = self.pool.slots.clone().try_acquire_owned() {
                let delay = {
                    let mut next = self.pool.next.lock().await;
                    let now = Instant::now();
                    let at = (*next).max(now);
                    *next = at + Duration::from_millis(self.config.delay_ms.min(60_000));
                    at.saturating_duration_since(now)
                };
                self.control.wait(delay).await?;
                loop {
                    let cooldown = self
                        .pool
                        .cooldown
                        .load(Ordering::Relaxed)
                        .saturating_sub(millis());
                    if cooldown == 0 {
                        break;
                    }
                    self.control
                        .wait(Duration::from_millis(cooldown.min(60_000)))
                        .await?;
                }
                self.control.sent.fetch_add(1, Ordering::Relaxed);
                return Ok(permit);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    pub fn finish(&self, result: &Result<crate::http::Reply, String>) {
        self.control.completed.fetch_add(1, Ordering::Relaxed);
        if result.is_err() {
            self.control.errors.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(reply) = result {
            if self.config.throttle_codes.contains(&reply.status) {
                let msg = crate::http::Msg::parse(&reply.raw);
                let wait = msg
                    .header("retry-after")
                    .and_then(|v| {
                        v.parse::<u64>()
                            .ok()
                            .map(|s| s.saturating_mul(1000))
                            .or_else(|| {
                                httpdate::parse_http_date(v).ok().map(|t| {
                                    t.duration_since(SystemTime::now())
                                        .unwrap_or_default()
                                        .as_millis()
                                        .min(u64::MAX as u128)
                                        as u64
                                })
                            })
                    })
                    .unwrap_or(self.config.backoff_ms)
                    .min(60_000);
                self.pool
                    .cooldown
                    .fetch_max(millis() + wait, Ordering::Relaxed);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cancelled_work_never_reserves_or_sends() {
        let control = Arc::new(Control::default());
        control.cancelled.store(true, Ordering::Relaxed);
        let work = Work::new(
            PoolConfig {
                name: "cancel-test".into(),
                ..Default::default()
            },
            control.clone(),
        );
        assert!(work.begin().await.is_err());
        assert_eq!(control.sent.load(Ordering::Relaxed), 0);
    }
    #[tokio::test]
    async fn same_named_pool_shares_concurrency() {
        let config = PoolConfig {
            name: "shared-test".into(),
            concurrency: 1,
            ..Default::default()
        };
        let a = Work::new(config.clone(), Arc::default());
        let b = Work::new(config, Arc::default());
        let first = a.begin().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(60), b.begin())
                .await
                .is_err()
        );
        drop(first);
        assert!(b.begin().await.is_ok());
    }
}

#[cfg(test)]
mod control_regressions {
    use super::*;
    #[tokio::test]
    async fn pause_blocks_new_requests_and_cancel_releases_waiting_workers() {
        let control = Arc::new(Control::default());
        control.paused.store(true, Ordering::Relaxed);
        let work = Work::new(
            PoolConfig {
                name: "pause-regression".into(),
                ..Default::default()
            },
            control.clone(),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(70), work.begin())
                .await
                .is_err()
        );
        assert_eq!(control.sent.load(Ordering::Relaxed), 0);
        control.paused.store(false, Ordering::Relaxed);
        drop(work.begin().await.unwrap());
        assert_eq!(control.sent.load(Ordering::Relaxed), 1);
        control.paused.store(true, Ordering::Relaxed);
        let task = tokio::spawn(async move { work.begin().await });
        control.cancelled.store(true, Ordering::Relaxed);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }
    #[tokio::test]
    async fn throttle_response_delays_other_users_of_the_same_pool() {
        let config = PoolConfig {
            name: "backoff-regression".into(),
            backoff_ms: 160,
            ..Default::default()
        };
        let a = Work::new(config.clone(), Arc::default());
        let b = Work::new(config, Arc::default());
        a.finish(&Ok(crate::http::Reply {
            status: 429,
            raw: b"HTTP/1.1 429 Too Many Requests\r\n\r\n".to_vec(),
            elapsed: Duration::ZERO,
        }));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), b.begin())
                .await
                .is_err()
        );
        drop(
            tokio::time::timeout(Duration::from_millis(250), b.begin())
                .await
                .unwrap()
                .unwrap(),
        );
    }
}
