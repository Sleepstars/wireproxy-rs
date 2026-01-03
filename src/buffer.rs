use parking_lot::Mutex;

/// Fixed-size buffer for WireGuard operations (MTU + overhead)
pub const WG_BUFFER_SIZE: usize = 2048;
/// Fixed-size buffer for TCP proxy operations
pub const TCP_BUFFER_SIZE: usize = 32 * 1024;

/// A pool of reusable buffers to reduce allocations
pub struct BufferPool {
    small_buffers: Mutex<Vec<Box<[u8; WG_BUFFER_SIZE]>>>,
    large_buffers: Mutex<Vec<Box<[u8; TCP_BUFFER_SIZE]>>>,
    #[allow(dead_code)]
    max_small: usize,
    #[allow(dead_code)]
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

    /// Get a small buffer from the pool or allocate a new one
    pub fn get_small(&self) -> PooledSmallBuffer {
        let buf = self
            .small_buffers
            .lock()
            .pop()
            .unwrap_or_else(|| Box::new([0u8; WG_BUFFER_SIZE]));
        PooledSmallBuffer { buf }
    }

    /// Get a large buffer from the pool or allocate a new one
    pub fn get_large(&self) -> PooledLargeBuffer {
        let buf = self
            .large_buffers
            .lock()
            .pop()
            .unwrap_or_else(|| Box::new([0u8; TCP_BUFFER_SIZE]));
        PooledLargeBuffer { buf }
    }

    /// Return a small buffer to the pool
    #[allow(dead_code)]
    pub fn return_small(&self, mut buf: Box<[u8; WG_BUFFER_SIZE]>) {
        let mut pool = self.small_buffers.lock();
        if pool.len() < self.max_small {
            buf.fill(0);
            pool.push(buf);
        }
    }

    /// Return a large buffer to the pool
    #[allow(dead_code)]
    pub fn return_large(&self, mut buf: Box<[u8; TCP_BUFFER_SIZE]>) {
        let mut pool = self.large_buffers.lock();
        if pool.len() < self.max_large {
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

/// A small pooled buffer (WG_BUFFER_SIZE)
pub struct PooledSmallBuffer {
    pub buf: Box<[u8; WG_BUFFER_SIZE]>,
}

impl std::ops::Deref for PooledSmallBuffer {
    type Target = [u8; WG_BUFFER_SIZE];
    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl std::ops::DerefMut for PooledSmallBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

/// A large pooled buffer (TCP_BUFFER_SIZE)
pub struct PooledLargeBuffer {
    pub buf: Box<[u8; TCP_BUFFER_SIZE]>,
}

impl std::ops::Deref for PooledLargeBuffer {
    type Target = [u8; TCP_BUFFER_SIZE];
    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl std::ops::DerefMut for PooledLargeBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}
