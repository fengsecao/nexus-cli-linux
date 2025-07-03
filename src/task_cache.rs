//! Cache for recently used task IDs.

use crate::consts::prover::CACHE_EXPIRATION;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Thread-safe queue of most recent task IDs (bounded).
#[derive(Clone, Debug)]
pub struct TaskCache {
    capacity: usize,
    inner: Arc<Mutex<VecDeque<(String, Instant)>>>,
}

impl TaskCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
        }
    }

    /// Prune expired tasks from the cache.
    async fn prune_expired(&self) {
        let mut queue = self.inner.lock().await;
        queue
            .retain(|(_, timestamp)| timestamp.elapsed() < Duration::from_millis(CACHE_EXPIRATION));
    }

    /// Returns true if the task ID is already in the queue.
    pub async fn contains(&self, task_id: &str) -> bool {
        self.prune_expired().await;

        let queue = self.inner.lock().await;
        queue.iter().any(|(id, _)| id == task_id)
    }

    /// Appends a task ID to the queue, evicting the oldest if full.
    pub async fn insert(&self, task_id: String) {
        self.prune_expired().await;

        let mut queue = self.inner.lock().await;
        if queue.iter().any(|(id, _)| *id == task_id) {
            return;
        }
        if queue.len() == self.capacity {
            queue.pop_front();
        }

        queue.push_back((task_id, Instant::now()));
    }
    
    /// 强制清理所有过期任务并返回清理数量
    pub async fn force_prune(&self) -> usize {
        let mut queue = self.inner.lock().await;
        let before_len = queue.len();
        queue.retain(|(_, timestamp)| timestamp.elapsed() < Duration::from_millis(CACHE_EXPIRATION));
        let after_len = queue.len();
        before_len - after_len
    }
    
    /// 获取当前缓存中的任务数量
    pub async fn len(&self) -> usize {
        let queue = self.inner.lock().await;
        queue.len()
    }
    
    /// 获取最旧任务的存活时间（毫秒）
    pub async fn oldest_task_age_ms(&self) -> Option<u64> {
        let queue = self.inner.lock().await;
        queue.front().map(|(_, timestamp)| timestamp.elapsed().as_millis() as u64)
    }
}
