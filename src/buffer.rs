use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use parking_lot::Mutex;

/// Fixed-size buffer for WireGuard operations (MTU + overhead).
///
/// NOTE: This constant must be large enough to hold both encrypted WireGuard UDP packets
/// and decrypted IP packets produced/consumed by the smoltcp device.
pub const WG_BUFFER_SIZE: usize = 2048;

/// A pool of reusable buffers to reduce allocations on hot paths.
pub struct BufferPool {
    // We intentionally use Box here to avoid stack overflow when moving large arrays.
    #[allow(clippy::vec_box)]
    small_buffers: Mutex<Vec<Box<[u8; WG_BUFFER_SIZE]>>>,
    max_small: usize,
}

impl BufferPool {
    pub fn new(max_small: usize) -> Self {
        Self {
            small_buffers: Mutex::new(Vec::with_capacity(max_small)),
            max_small,
        }
    }

    /// Get a small buffer from the pool or allocate a new one.
    pub fn get_small(self: &Arc<Self>) -> PooledSmallBuffer {
        let buf = self
            .small_buffers
            .lock()
            .pop()
            .unwrap_or_else(|| Box::new([0u8; WG_BUFFER_SIZE]));
        PooledSmallBuffer {
            pool: Arc::clone(self),
            buf: Some(buf),
        }
    }

    fn put_small(&self, buf: Box<[u8; WG_BUFFER_SIZE]>) {
        let mut pool = self.small_buffers.lock();
        if pool.len() < self.max_small {
            // Avoid clearing in release builds; hot paths fully overwrite used ranges.
            #[cfg(debug_assertions)]
            let mut buf = buf;
            #[cfg(debug_assertions)]
            buf.fill(0);
            pool.push(buf);
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new(128)
    }
}

/// A small pooled buffer (WG_BUFFER_SIZE).
pub struct PooledSmallBuffer {
    pool: Arc<BufferPool>,
    buf: Option<Box<[u8; WG_BUFFER_SIZE]>>,
}

impl Deref for PooledSmallBuffer {
    type Target = [u8; WG_BUFFER_SIZE];

    fn deref(&self) -> &Self::Target {
        self.buf
            .as_deref()
            .expect("pooled small buffer already returned")
    }
}

impl DerefMut for PooledSmallBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf
            .as_deref_mut()
            .expect("pooled small buffer already returned")
    }
}

impl Drop for PooledSmallBuffer {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.put_small(buf);
        }
    }
}
