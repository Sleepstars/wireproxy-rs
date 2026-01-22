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

CONFIG_FILE=${CONFIG_FILE:-"/tmp/wireproxy.conf"}
DURATION=${DURATION:-180}
WARMUP=${WARMUP:-5}

if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Config not found: $CONFIG_FILE${NC}"
    echo -e "${YELLOW}Set CONFIG_FILE=/path/to/wireproxy.conf and rerun.${NC}"
    exit 1
fi

echo -e "${GREEN}=== WireProxy Benchmark: $IMPL ===${NC}"

# Determine binary path
if [ "$IMPL" = "go" ]; then
    # Prefer the CI artifact location, fall back to local install.
    if [ -f "/tmp/bin/wireproxy" ]; then
        BINARY="/tmp/bin/wireproxy"
    else
        BINARY="$(command -v wireproxy || echo "$HOME/go/bin/wireproxy")"
    fi
elif [ "$IMPL" = "rust" ]; then
    # Prefer the CI artifact location, fall back to local build output.
    if [ -f "/tmp/bin/wireproxy-rs" ]; then
        BINARY="/tmp/bin/wireproxy-rs"
    else
        BINARY="./target/release/wireproxy-rs"
    fi
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
# Runs until the shared end timestamp so total benchmark time is fixed.
measure_stats() {
    local pid=$1
    local end_ns=$2
    local max_mem=0
    local total_cpu=0
    local samples=0

    while true; do
        local now_ns
        now_ns=$(date +%s%N)
        if [ "$now_ns" -ge "$end_ns" ]; then
            break
        fi

        if ps -p "$pid" > /dev/null 2>&1; then
            local mem cpu
            mem=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
            cpu=$(ps -o %cpu= -p "$pid" 2>/dev/null | tr -d ' ')

            if [ -n "$mem" ] && [ "$mem" -gt "$max_mem" ]; then
                max_mem=$mem
            fi
            if [ -n "$cpu" ]; then
                total_cpu=$(echo "$total_cpu + $cpu" | bc)
                samples=$((samples + 1))
            fi
        fi

        # Sleep up to 1s but don't significantly overshoot the deadline.
        now_ns=$(date +%s%N)
        local remaining_ns=$((end_ns - now_ns))
        if [ "$remaining_ns" -le 0 ]; then
            break
        fi
        if [ "$remaining_ns" -lt 1000000000 ]; then
            sleep "$(echo "scale=3; $remaining_ns / 1000000000" | bc)"
        else
            sleep 1
        fi
    done

    local avg_cpu=0
    if [ "$samples" -gt 0 ]; then
        avg_cpu=$(echo "scale=2; $total_cpu / $samples" | bc)
    fi

    echo "$max_mem $avg_cpu"
}

# Run throughput test
# Runs until the shared end timestamp so total benchmark time is fixed.
run_throughput_test() {
    local start_ns=$1
    local end_ns=$2
    local total_bytes=0

    while true; do
        local now_ns
        now_ns=$(date +%s%N)
        if [ "$now_ns" -ge "$end_ns" ]; then
            break
        fi

        local remaining_ns=$((end_ns - now_ns))
        if [ "$remaining_ns" -le 0 ]; then
            break
        fi

        local remaining_s
        remaining_s=$(echo "scale=3; $remaining_ns / 1000000000" | bc)

        # curl may time out on the final iteration; don't let `set -e` abort the script.
        # We still want to count bytes downloaded so far.
        local bytes
        bytes=$(curl -s --max-time "$remaining_s" -x socks5://127.0.0.1:1080 -o /dev/null -w '%{size_download}' \
            http://10.200.200.1:8080/testfile 2>/dev/null || true)

        if [ -z "$bytes" ]; then
            bytes=0
        fi
        total_bytes=$((total_bytes + bytes))
    done

    local end_ns_actual
    end_ns_actual=$(date +%s%N)
    local elapsed_s
    elapsed_s=$(echo "scale=3; ($end_ns_actual - $start_ns) / 1000000000" | bc)

    local mbps
    mbps=$(echo "scale=2; ($total_bytes * 8) / ($elapsed_s * 1000000)" | bc 2>/dev/null || echo "0")

    echo "$mbps"
}

echo -e "${YELLOW}Running benchmark...${NC}"

# Run stats and throughput in parallel
START_NS=$(date +%s%N)
END_NS=$((START_NS + DURATION * 1000000000))

measure_stats "$PID" "$END_NS" > /tmp/stats.txt &
STATS_PID=$!

THROUGHPUT=$(run_throughput_test "$START_NS" "$END_NS")

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
