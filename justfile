# justfile for wireproxy-rs

# List all available recipes
default:
    @just --list

# Build for local development
build:
    cargo build

# Build with release optimizations
build-release:
    cargo build --release

# Run tests
test:
    cargo test

# Check code without building
check:
    cargo check

# Run clippy linter
lint:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Format check (CI-friendly)
fmt-check:
    cargo fmt -- --check

# Clean build artifacts
clean:
    cargo clean

# Install common cross-compilation targets
install-targets:
    rustup target add x86_64-unknown-linux-gnu
    rustup target add x86_64-unknown-linux-musl
    rustup target add aarch64-unknown-linux-gnu
    rustup target add aarch64-unknown-linux-musl
    rustup target add x86_64-pc-windows-gnu

# Install cargo-zigbuild for easy cross-compilation
install-zigbuild:
    cargo install cargo-zigbuild

# Install cross (alternative cross-compilation tool)
install-cross:
    cargo install cross --git https://github.com/cross-rs/cross

# Setup everything needed for cross-compilation via zigbuild
setup-zigbuild: install-zigbuild install-targets
    @echo "Zigbuild setup complete."

# Setup everything needed for cross-compilation via cross
setup-cross: install-cross install-targets
    @echo "Cross setup complete."

# Cross-compile for x86_64 Linux (requires cargo-zigbuild and zig)
build-linux:
    cargo zigbuild --release --target x86_64-unknown-linux-gnu

# Cross-compile for x86_64 Linux using musl (statically linked)
build-linux-musl:
    cargo zigbuild --release --target x86_64-unknown-linux-musl

# Cross-compile for aarch64 Linux (glibc)
build-linux-aarch64:
    cargo zigbuild --release --target aarch64-unknown-linux-gnu

# Cross-compile for aarch64 Linux using musl
build-linux-aarch64-musl:
    cargo zigbuild --release --target aarch64-unknown-linux-musl

# Cross-compile for Windows (GNU toolchain via zig)
build-windows:
    cargo zigbuild --release --target x86_64-pc-windows-gnu

# Cross-compile using cross tool (works in Docker, no zig needed)
build-linux-cross:
    cross build --release --target x86_64-unknown-linux-gnu

# Cross-compile musl using cross tool
build-linux-musl-cross:
    cross build --release --target x86_64-unknown-linux-musl

# Cross-compile aarch64 using cross tool
build-linux-aarch64-cross:
    cross build --release --target aarch64-unknown-linux-gnu

# Cross-compile Windows using cross tool
build-windows-cross:
    cross build --release --target x86_64-pc-windows-gnu

# Show build artifacts
show-artifacts:
    @echo "Local build artifacts:"
    @ls -lh target/release/ 2>/dev/null || echo "No release builds found"
    @echo ""
    @echo "Linux cross-compilation artifacts:"
    @ls -lh target/x86_64-unknown-linux-gnu/release/ 2>/dev/null || echo "No Linux builds found"
    @ls -lh target/x86_64-unknown-linux-musl/release/ 2>/dev/null || echo "No Linux musl builds found"
    @ls -lh target/aarch64-unknown-linux-gnu/release/ 2>/dev/null || echo "No aarch64 Linux builds found"
    @ls -lh target/aarch64-unknown-linux-musl/release/ 2>/dev/null || echo "No aarch64 Linux musl builds found"
    @ls -lh target/x86_64-pc-windows-gnu/release/ 2>/dev/null || echo "No Windows builds found"

# Full CI check (lint, format, test, build)
ci: fmt-check lint test build-release
    @echo "All CI checks passed."
