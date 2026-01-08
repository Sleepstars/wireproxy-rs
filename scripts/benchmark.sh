#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

CONFIG_FILE="/tmp/wireproxy.conf"
RESULTS_FILE="/tmp/benchmark_results.json"
DURATION=10
WARMUP=2

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

# Start iperf3 server on WireGuard interface
echo -e "${YELLOW}Starting iperf3 server...${NC}"
sudo iperf3 -s -B 10.200.200.1 -D -p 5201 2>/dev/null || true
sleep 1

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
    echo -e "${YELLOW}Running throughput test for $name...${NC}"

    # Use curl through SOCKS5 to download from iperf server
    local result=$(iperf3 -c 10.200.200.1 -p 5201 -t $DURATION --json 2>/dev/null || echo '{}')
    local bps=$(echo "$result" | jq -r '.end.sum_received.bits_per_second // 0' 2>/dev/null || echo "0")
    local mbps=$(echo "scale=2; $bps / 1000000" | bc 2>/dev/null || echo "0")

    echo "$mbps"
}

# ============================================
# Benchmark Go wireproxy
# ============================================
echo -e "${GREEN}[1/2] Benchmarking Go wireproxy...${NC}"

$GO_WIREPROXY -c "$CONFIG_FILE" &
GO_PID=$!
sleep $WARMUP

# Measure during load
GO_THROUGHPUT=$(run_throughput_test "Go")
read GO_MEM GO_CPU <<< $(measure_stats $GO_PID "Go" $DURATION)

kill $GO_PID 2>/dev/null || true
wait $GO_PID 2>/dev/null || true
sleep 2

# ============================================
# Benchmark Rust wireproxy
# ============================================
echo -e "${GREEN}[2/2] Benchmarking Rust wireproxy...${NC}"

$RS_WIREPROXY -c "$CONFIG_FILE" &
RS_PID=$!
sleep $WARMUP

RS_THROUGHPUT=$(run_throughput_test "Rust")
read RS_MEM RS_CPU <<< $(measure_stats $RS_PID "Rust" $DURATION)

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
sudo pkill iperf3 2>/dev/null || true
