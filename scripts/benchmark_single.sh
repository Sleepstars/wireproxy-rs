#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

IMPL=$1
if [ -z "$IMPL" ]; then
    echo -e "${RED}Usage: $0 <go|rust>${NC}"
    exit 1
fi

CONFIG_FILE="/tmp/wireproxy.conf"
DURATION=180
WARMUP=5

echo -e "${GREEN}=== WireProxy Benchmark: $IMPL ===${NC}"

# Determine binary path
if [ "$IMPL" = "go" ]; then
    BINARY="/tmp/bin/wireproxy"
elif [ "$IMPL" = "rust" ]; then
    BINARY="/tmp/bin/wireproxy-rs"
else
    echo -e "${RED}Unknown implementation: $IMPL${NC}"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo -e "${RED}Binary not found: $BINARY${NC}"
    exit 1
fi

# Start wireproxy
echo -e "${YELLOW}Starting $IMPL wireproxy...${NC}"
$BINARY -c "$CONFIG_FILE" 2>/dev/null &
PID=$!
sleep $WARMUP

# Measure stats in background
measure_stats() {
    local pid=$1
    local duration=$2
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

# Run throughput test
run_throughput_test() {
    local total_bytes=0
    local start_time=$(date +%s.%N)

    for i in $(seq 1 $DURATION); do
        local bytes=$(curl -s -x socks5://127.0.0.1:1080 -o /dev/null -w '%{size_download}' \
            http://10.200.200.1:8080/testfile 2>/dev/null || echo "0")
        total_bytes=$((total_bytes + bytes))
    done

    local end_time=$(date +%s.%N)
    local elapsed=$(echo "$end_time - $start_time" | bc)
    local mbps=$(echo "scale=2; ($total_bytes * 8) / ($elapsed * 1000000)" | bc 2>/dev/null || echo "0")

    echo "$mbps"
}

echo -e "${YELLOW}Running benchmark...${NC}"

# Run stats and throughput in parallel
measure_stats $PID $DURATION > /tmp/stats.txt &
STATS_PID=$!

THROUGHPUT=$(run_throughput_test)

wait $STATS_PID
read MEM CPU < /tmp/stats.txt

# Cleanup
kill $PID 2>/dev/null || true
wait $PID 2>/dev/null || true

# Output results
echo -e "${GREEN}=== Results ===${NC}"
echo "Memory: $((MEM / 1024)) MB"
echo "CPU: ${CPU}%"
echo "Throughput: ${THROUGHPUT} Mbps"

# Save JSON
cat > /tmp/benchmark_${IMPL}.json << EOF
{
  "impl": "$IMPL",
  "memory_kb": $MEM,
  "cpu_percent": $CPU,
  "throughput_mbps": $THROUGHPUT
}
EOF

echo -e "${GREEN}Results saved to /tmp/benchmark_${IMPL}.json${NC}"
