#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

VERBOSE=false

# Parse arguments correctly
while getopts ":v" opt; do
  case $opt in
    v)
      VERBOSE=true
      ;;
    \?)
      echo -e "${RED}Invalid option: -$OPTARG${NC}" >&2
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))

if [ -z "$1" ]; then
    echo -e ">> ${RED}Error: Please provide target IP address as argument${NC}"
    exit 1
fi

IP=$1

echo -e ">> ${CYAN}---------- Measuring network metrics for ${IP} ----------${NC}\n"

# Function to check command existence
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}Error: $1 could not be found. Please install it.${NC}"
        exit 1
    fi
}

# Check required commands
check_command ping
check_command iperf3
check_command traceroute
check_command bc
check_command jq
check_command awk

# Temporary file setup
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Generic real-time execution function
execute_with_realtime() {
    local command="$1"
    local logfile="$2"
    local description="$3"

    echo -e "${BLUE}$description...${NC}"
    > "$logfile"  # Clear existing file

    # Execute command with real-time output
    echo -e "${CYAN} → Command: ${command}${NC}"
    eval "$command" 2>&1 | while IFS= read -r line; do
        $VERBOSE && echo "  $line"  # Show real-time output if verbose
        echo "$line" >> "$logfile"
    done

    return ${PIPESTATUS[0]}  # Return original command's exit code
}

# RTT and Packet Loss Measurement
measure_rtt_loss() {
    local logfile="$TMPDIR/ping.log"
    execute_with_realtime "ping -c 10 $IP" "$logfile" "Measuring RTT and Packet Loss (ping)"

    # Parse results from log file
    local rtt=$(awk -F'/' '/round-trip|rtt/ {print $5}' "$logfile")
    local loss=$(awk -F'[,%]' '/packet loss/ {print $3}' "$logfile")

    echo -e "🟦 ${GREEN}Avg RTT (ping): $rtt ms${NC}"
    echo -e "🟦 ${GREEN}Packet Loss (ping): $loss%${NC}"
}

# One-Way Delay Approximation (from ping)
measure_one_way_delay() {
    local logfile="$TMPDIR/owd.log"
    execute_with_realtime "ping -c 4 $IP" "$logfile" "One-Way Delay (ping)"

    local avg_rtt=$(awk -F'/' '/round-trip|rtt/ {print $5}' "$logfile")
    local one_way=$(echo "scale=2; $avg_rtt / 2" | bc)
    echo -e "$${GREEN} {GREEN}Approximated One-Way Delay: $one_way ms${NC} (Approximated from RTT/2)"
}

# UDP Bitrate Stats for exact “total” volumes (avg / peak / std in Mbps)
measure_udp_bitrate_stats() {
    local sizes_kb=(60 80 200 500 1024)
    local max_payload=65507   # max UDP payload in bytes

    for kb in "${sizes_kb[@]}"; do
        # compute total bytes and clamp per‐datagram payload
        local total_bytes=$(( kb * 1024 ))
        local payload=$total_bytes
        if (( payload > max_payload )); then
            echo -e "${CYAN}Clamping datagram size to ${max_payload} bytes (requested ${payload})${NC}"
            payload=$max_payload
        fi

        # file paths
        local logfile="$TMPDIR/udp_${kb}K.log"
        local ratesfile="$TMPDIR/udp_rates_${kb}K.list"

        # run iperf3 via your realtime wrapper, drop stderr warnings
        execute_with_realtime \
          "iperf3 -u -c $IP -b 1G -l $payload -n $total_bytes -i 1 -J 2>/dev/null" \
          "$logfile" \
          "Measuring UDP bitrate (total ${kb}K in ${payload}-byte fragments)"

        # extract per‐second bits_per_second
        > "$ratesfile"
        jq -r '.intervals[].sum.bits_per_second' "$logfile" > "$ratesfile"

        # compute avg, peak, stddev in Mbps
        local stats
        stats=$(awk '
            {
                sum   += $1
                sumsq += ($1)^2
                if (NR==1 || $1>max) max=$1
            }
            END {
                if (NR>0) {
                    avg = sum/NR
                    var = sumsq/NR - avg^2
                    if (var<0) var=0
                    std = sqrt(var)
                    printf "Avg: %.2f Mbps, Peak: %.2f Mbps, StdDev: %.2f Mbps",\
                           (avg/1e6),(max/1e6),(std/1e6)
                } else {
                    printf "No interval data"
                }
            }' "$ratesfile")

        # Extract overall loss (%) and jitter (ms) from JSON
        local lost_pct=$(jq -r '.end.sum.lost_percent' "$logfile")
        local jitter=$(jq -r '.end.sum.jitter_ms' "$logfile")

        # display
        echo -e "🟦 ${GREEN}${kb}K total: $stats${NC}"
        echo -e "🟦 ${GREEN}Packet Loss: $lost_pct%${NC}"
        echo -e "🟦 ${GREEN}Jitter: $jitter ms${NC}"
        echo
    done
}






# Hop Count
measure_hop_count() {
    local logfile="$TMPDIR/traceroute.log"
    execute_with_realtime "traceroute -n -q 1 -w 1 $IP" "$logfile" "Measuring Hop Count"

    if $VERBOSE; then
        echo -e "\n${BLUE}Raw traceroute output:${NC}"
        cat "$logfile"
    fi

    # Count lines starting with a hop number
    local hops=$(grep -E '^[[:space:]]*[0-9]+' "$logfile" | wc -l)
    echo -e "Hop Count: ${GREEN}$hops${NC}"
}

# TCP Bitrate Metrics (avg, peak, std) via iperf3
measure_tcp_bitrate_stats() {
    local logfile="$TMPDIR/tcp_bitrate.log"
    execute_with_realtime "iperf3 -c $IP -t 10 -i 1 -J" "$logfile" "Measuring TCP Bitrate (intervals)"

    # Extract bits_per_second for each 1s interval
    jq -r '.intervals[].sum.bits_per_second' "$logfile" > "$TMPDIR/tcp_rates.list"

    # Compute avg, peak, std (in Mbps)
    awk '
    {
        rates[NR] = $1
        sum += $1
        sumsq += ($1)^2
        if (NR == 1 || $1 > max) { max = $1 }
    }
    END {
        if (NR > 0) {
            avg = sum / NR
            var = sumsq / NR - avg^2
            if (var < 0) { var = 0 }  # guard against negative zeros
            std = sqrt(var)
            printf "TCP Bitrate → Avg: %.2f Mbps, Peak: %.2f Mbps, StdDev: %.2f Mbps\n", (avg/1e6), (max/1e6), (std/1e6)
        } else {
            print "TCP Bitrate: No interval data"
        }
    }' "$TMPDIR/tcp_rates.list"
}

# TCP Throughput (overall), summary only
measure_tcp_throughput() {
    local logfile="$TMPDIR/tcp.log"
    # Quietly run iperf3, redirecting all output to logfile
    iperf3 -c $IP -t 10 -J > "$logfile" 2>&1

    # Extract overall throughput in Mbps
    local tput=$(jq -r '.end.sum_received.bits_per_second / 1e6' "$logfile")
    echo -e "TCP Throughput: ${GREEN}$(printf "%.2f" "$tput") Mbps${NC}"
}

# UDP Bitrate & Loss & Jitter Metrics via iperf3, summary only
measure_udp_metrics() {
    local logfile="$TMPDIR/udp_metrics.log"
    local ratesfile="$TMPDIR/udp_rates.list"

    # 1) Run iperf3 under your realtime wrapper, discard stderr warnings
    execute_with_realtime \
      "iperf3 -u -c $IP -b 1G -t 10 -i 1 -J 2>/dev/null" \
      "$logfile" \
      "Measuring UDP bitrate, loss & jitter"

    # 2) Extract per-second bits_per_second
    > "$ratesfile"
    jq -r '.intervals[].sum.bits_per_second' "$logfile" > "$ratesfile"

    # 3) Compute avg, peak, std (in Mbps)
    awk '
    {
        sum   += $1
        sumsq += ($1)^2
        if (NR==1 || $1>max) max=$1
    }
    END {
        if (NR>0) {
            avg = sum/NR
            var = sumsq/NR - avg^2
            if (var<0) var=0
            std = sqrt(var)
            printf "UDP Bitrate → Avg: %.2f Mbps, Peak: %.2f Mbps, StdDev: %.2f Mbps\n",\
                   (avg/1e6),(max/1e6),(std/1e6)
        } else {
            print "UDP Bitrate: No interval data"
        }
    }' "$ratesfile"

    # 4) Extract overall loss (%) and jitter (ms)
    local lost_pct
    local jitter_ms
    lost_pct=$(jq -r '.end.sum.lost_percent' "$logfile")
    jitter_ms=$(jq -r '.end.sum.jitter_ms' "$logfile")

    echo -e "🟦 ${GREEN}UDP Packet Loss: $lost_pct%${NC}"
    echo -e "🟦 ${GREEN}UDP Jitter: $jitter_ms ms${NC}"
}


# UDP Loss and Jitter Measurement via iperf3
measure_udp_loss_and_jitter() {
    local logfile="$TMPDIR/udp_loss_jitter.log"

    # Run UDP test for 10s at 1Gbps, JSON output, suppress stderr warnings
    execute_with_realtime \
      "iperf3 -u -c $IP -b 1G -t 10 -i 1 -J 2>/dev/null" \
      "$logfile" \
      "Measuring UDP packet loss and jitter"

    # Parse loss percentage and jitter (ms)
    local lost_pct=$(jq -r '.end.sum.lost_percent' "$logfile")
    local jitter_ms=$(jq -r '.end.sum.jitter_ms' "$logfile")

    echo -e "UDP Packet Loss: ${GREEN}${lost_pct}%${NC}"
    echo -e "UDP Jitter (delay variation): ${GREEN}${jitter_ms} ms${NC}"
}

# TCP Throughput & Bitrate Metrics via iperf3, summary only
measure_tcp_metrics() {
    local logfile="$TMPDIR/tcp_metrics.log"
    local ratesfile="$TMPDIR/tcp_rates.list"

    # Run TCP test for 10s, JSON output, suppress stderr warnings
    execute_with_realtime \
      "iperf3 -c $IP -t 10 -i 1 -J 2>/dev/null" \
      "$logfile" \
      "Measuring TCP bitrate and overall throughput"

    # Extract bits_per_second for each interval
    > "$ratesfile"
    jq -r '.intervals[].sum.bits_per_second' "$logfile" > "$ratesfile"

    # Compute avg, peak, std (in Mbps)
    awk '
    {
        sum   += $1
        sumsq += ($1)^2
        if (NR==1 || $1>max) max=$1
    }
    END {
        if (NR>0) {
            avg = sum/NR
            var = sumsq/NR - avg^2
            if (var<0) var=0
            std = sqrt(var)
            printf "TCP Bitrate → Avg: %.2f Mbps, Peak: %.2f Mbps, StdDev: %.2f Mbps\n",\
                   (avg/1e6),(max/1e6),(std/1e6)
        } else {
            print "TCP Bitrate: No interval data"
        }
    }' "$ratesfile"

    # Extract overall throughput in Mbps
    local tput
    tput=$(jq -r '.end.sum_received.bits_per_second' "$logfile")
    local tput_mbps
    tput_mbps=$(awk "BEGIN {printf \"%.2f\", $tput/1e6}")
    echo -e "🟦 ${GREEN}TCP Throughput: $tput_mbps Mbps${NC}"
}



# =============== Run measurements ===============

# CMD: ping -c 10 147.83.39.190
#measure_rtt_loss

# CMD: ping -c 4 147.83.39.190
#measure_one_way_delay

# CMD: NO SIZE: iperf3 -u -c 147.83.39.190 -b 1G -t 10 -i 1
  # > 60KB | iperf3 -u -c 147.83.39.190 -b 1G -l 60KB
  # > 80KB | iperf3 -u -c 147.83.39.190 -b 1G -l 65507 -n 81920
  # > 200KB | iperf3 -u -c 147.83.39.190 -b 1G -l 65507 -n 204800
  # > 500KB | iperf3 -u -c 147.83.39.190 -b 1G -l 65507 -n 512000
  # > 1024KB | iperf3 -u -c 147.83.39.190 -b 1G -l 65507 -n 1048576
#measure_udp_bitrate_stats

# CMD: iperf3 -u -c 147.83.39.190 -b 1G -t 10 -i 1
#measure_udp_metrics

# CMD: iperf3 -c 147.83.39.190 -t 10 -i 1
measure_tcp_metrics