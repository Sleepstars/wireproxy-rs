use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use parking_lot::Mutex;

/// Fixed-size buffer for WireGuard operations (MTU + overhead).
///
/// NOTE: This constant must be large enough to hold both encrypted WireGuard UDP packets
/// and decrypted IP packets produced/consumed by the smoltcp device.
pub const WG_BUFFER_SIZE: usize = 2048;

/// Fixed-size buffer for TCP proxy operations.
pub const TCP_BUFFER_SIZE: usize = 32 * 1024;

/// A pool of reusable buffers to reduce allocations on hot paths.
pub struct BufferPool {
    // We intentionally use Box here to avoid stack overflow when moving large arrays.
    #[allow(clippy::vec_box)]
    small_buffers: Mutex<Vec<Box<[u8; WG_BUFFER_SIZE]>>>,
    #[allow(clippy::vec_box)]
    large_buffers: Mutex<Vec<Box<[u8; TCP_BUFFER_SIZE]>>>,
    max_small: usize,
    max_large: usize,
}

impl BufferPool {
    pub fn new(max_small: usize, max_large: usize) -> Self {
        Self {
            small_buffers: Mutex::new(Vec::with_capacity(max_small)),
            large_buffers: Mutex::new(Vec::with_capacity(max_large)),
            max_small,
            max_large,
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

    /// Get a large buffer from the pool or allocate a new one.
    pub fn get_large(self: &Arc<Self>) -> PooledLargeBuffer {
        let buf = self
            .large_buffers
            .lock()
            .pop()
            .unwrap_or_else(|| Box::new([0u8; TCP_BUFFER_SIZE]));
        PooledLargeBuffer {
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

    fn put_large(&self, buf: Box<[u8; TCP_BUFFER_SIZE]>) {
        let mut pool = self.large_buffers.lock();
        if pool.len() < self.max_large {
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
        Self::new(128, 64)
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

/// A large pooled buffer (TCP_BUFFER_SIZE).
pub struct PooledLargeBuffer {
    pool: Arc<BufferPool>,
    buf: Option<Box<[u8; TCP_BUFFER_SIZE]>>,
}

impl Deref for PooledLargeBuffer {
    type Target = [u8; TCP_BUFFER_SIZE];

    fn deref(&self) -> &Self::Target {
        self.buf
            .as_deref()
            .expect("pooled large buffer already returned")
    }
}

impl DerefMut for PooledLargeBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf
            .as_deref_mut()
            .expect("pooled large buffer already returned")
    }
}

impl Drop for PooledLargeBuffer {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.put_large(buf);
        }
    }
}
