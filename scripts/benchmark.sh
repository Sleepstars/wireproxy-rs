#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

CONFIG_FILE="/tmp/wireproxy.conf"
RESULTS_FILE="/tmp/benchmark_results.json"
DURATION=180
WARMUP=5

echo -e "${GREEN}=== WireProxy Performance Benchmark ===${NC}"
echo ""

# Paths
GO_WIREPROXY=$(which wireproxy || echo "$HOME/go/bin/wireproxy")
RS_WIREPROXY="./target/release/wireproxy-rs"

if [ ! -f "$GO_WIREPROXY" ]; then
    echo -e "${RED}Go wireproxy not found${NC}"
    exit 1
fi

if [ ! -f "$RS_WIREPROXY" ]; then
    echo -e "${RED}Rust wireproxy not found. Run: cargo build --release${NC}"
    exit 1
fi

# Start HTTP server on WireGuard interface for throughput testing
echo -e "${YELLOW}Starting HTTP server for throughput test...${NC}"
# Create a 100MB test file
dd if=/dev/zero of=/tmp/testfile bs=1M count=1000 2>/dev/null
# Start Python HTTP server on WireGuard interface
cd /tmp && python3 -m http.server 8080 --bind 10.200.200.1 &
HTTP_SERVER_PID=$!
cd - > /dev/null
sleep 2

# Function to measure process stats
measure_stats() {
    local pid=$1
    local name=$2
    local duration=$3

    local max_mem=0
    local total_cpu=0
    local samples=0

    for i in $(seq 1 $duration); do
        if ps -p $pid > /dev/null 2>&1; then
            local mem=$(ps -o rss= -p $pid 2>/dev/null | tr -d ' ')
            local cpu=$(ps -o %cpu= -p $pid 2>/dev/null | tr -d ' ')

            if [ -n "$mem" ] && [ "$mem" -gt "$max_mem" ]; then
                max_mem=$mem
            fi
            if [ -n "$cpu" ]; then
                total_cpu=$(echo "$total_cpu + $cpu" | bc)
                samples=$((samples + 1))
            fi
        fi
        sleep 1
    done

    local avg_cpu=0
    if [ $samples -gt 0 ]; then
        avg_cpu=$(echo "scale=2; $total_cpu / $samples" | bc)
    fi

    echo "$max_mem $avg_cpu"
}

# Function to run throughput test via SOCKS5
run_throughput_test() {
    local name=$1
    echo -e "${YELLOW}Running throughput test for $name...${NC}" >&2

    # Use curl to download test file through SOCKS5 proxy multiple times
    local total_bytes=0
    local start_time=$(date +%s.%N)

    for i in $(seq 1 $DURATION); do
        local bytes=$(curl -s -x socks5://127.0.0.1:1080 -o /dev/null -w '%{size_download}' \
            http://10.200.200.1:8080/testfile 2>/dev/null || echo "0")
        total_bytes=$((total_bytes + bytes))
    done

    local end_time=$(date +%s.%N)
    local elapsed=$(echo "$end_time - $start_time" | bc)

    # Calculate Mbps: (bytes * 8) / (seconds * 1000000)
    local mbps=$(echo "scale=2; ($total_bytes * 8) / ($elapsed * 1000000)" | bc 2>/dev/null || echo "0")

    echo "$mbps"
}

# ============================================
# Benchmark Go wireproxy
# ============================================
echo -e "${GREEN}[1/2] Benchmarking Go wireproxy...${NC}"

$GO_WIREPROXY -c "$CONFIG_FILE" 2>/dev/null &
GO_PID=$!
sleep $WARMUP

# Run throughput test and measure stats in parallel
measure_stats $GO_PID "Go" $DURATION > /tmp/go_stats.txt &
STATS_PID=$!
GO_THROUGHPUT=$(run_throughput_test "Go")
wait $STATS_PID
read GO_MEM GO_CPU < /tmp/go_stats.txt

kill $GO_PID 2>/dev/null || true
wait $GO_PID 2>/dev/null || true
sleep 2

# ============================================
# Benchmark Rust wireproxy
# ============================================
echo -e "${GREEN}[2/2] Benchmarking Rust wireproxy...${NC}"

$RS_WIREPROXY -c "$CONFIG_FILE" 2>/dev/null &
RS_PID=$!
sleep $WARMUP

# Run throughput test and measure stats in parallel
measure_stats $RS_PID "Rust" $DURATION > /tmp/rs_stats.txt &
STATS_PID=$!
RS_THROUGHPUT=$(run_throughput_test "Rust")
wait $STATS_PID
read RS_MEM RS_CPU < /tmp/rs_stats.txt

kill $RS_PID 2>/dev/null || true
wait $RS_PID 2>/dev/null || true

# ============================================
# Results
# ============================================
echo ""
echo -e "${GREEN}=== Benchmark Results ===${NC}"
echo ""
printf "%-20s %15s %15s\n" "Metric" "Go" "Rust"
printf "%-20s %15s %15s\n" "--------------------" "---------------" "---------------"
printf "%-20s %12s MB %12s MB\n" "Peak Memory" "$((GO_MEM / 1024))" "$((RS_MEM / 1024))"
printf "%-20s %14s%% %14s%%\n" "Avg CPU" "$GO_CPU" "$RS_CPU"
printf "%-20s %11s Mbps %11s Mbps\n" "Throughput" "$GO_THROUGHPUT" "$RS_THROUGHPUT"

# Calculate improvements
MEM_IMPROVEMENT=$(echo "scale=1; (1 - $RS_MEM / $GO_MEM) * 100" | bc 2>/dev/null || echo "0")
CPU_IMPROVEMENT=$(echo "scale=1; (1 - $RS_CPU / $GO_CPU) * 100" | bc 2>/dev/null || echo "0")

echo ""
echo -e "${YELLOW}Rust vs Go:${NC}"
echo "  Memory: ${MEM_IMPROVEMENT}% less"
echo "  CPU: ${CPU_IMPROVEMENT}% less"

# Save JSON results
cat > "$RESULTS_FILE" << EOF
{
  "timestamp": "$(date -Iseconds)",
  "go": {
    "memory_kb": $GO_MEM,
    "cpu_percent": $GO_CPU,
    "throughput_mbps": $GO_THROUGHPUT
  },
  "rust": {
    "memory_kb": $RS_MEM,
    "cpu_percent": $RS_CPU,
    "throughput_mbps": $RS_THROUGHPUT
  },
  "improvement": {
    "memory_percent": $MEM_IMPROVEMENT,
    "cpu_percent": $CPU_IMPROVEMENT
  }
}
EOF

echo ""
echo -e "${GREEN}Results saved to $RESULTS_FILE${NC}"

# Cleanup
kill $HTTP_SERVER_PID 2>/dev/null || true
rm -f /tmp/testfile
