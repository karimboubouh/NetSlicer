#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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
    echo -e "${RED}Error: Please provide target IP address as argument${NC}"
    exit 1
fi

IP=$1

echo -e "${CYAN}Measuring network metrics for $IP...${NC}\n"

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

# Temporary file setup
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Generic real-time execution function
execute_with_realtime() {
    local command="$1"
    local logfile="$2"
    local description="$3"

    echo -e "${YELLOW}$description...${NC}"
    > "$logfile"  # Clear existing file

    # Execute command with real-time output
    eval "$command" 2>&1 | while IFS= read -r line; do
        $VERBOSE && echo "  $line"  # Show real-time output if verbose
        echo "$line" >> "$logfile"
    done

    return ${PIPESTATUS[0]}  # Return original command's exit code
}

# RTT and Packet Loss Measurement
measure_rtt_loss() {
    local logfile="$TMPDIR/ping.log"
    execute_with_realtime "ping -c 10 $IP" "$logfile" "Measuring RTT and Packet Loss"

    # Parse results from log file
    local rtt=$(awk -F'/' '/round-trip|rtt/ {print $5}' "$logfile")
    local loss=$(awk -F'[,%]' '/packet loss/ {print $3}' "$logfile")

    echo -e "Avg RTT: ${GREEN}$rtt ms${NC}"
    echo -e "Packet Loss: ${GREEN}$loss%${NC}"
}

# One-Way Delay Approximation
measure_one_way_delay() {
    local logfile="$TMPDIR/owd.log"
    execute_with_realtime "ping -c 4 $IP" "$logfile" "Approximating One-Way Delay"

    local avg_rtt=$(awk -F'/' '/round-trip|rtt/ {print $5}' "$logfile")
    local one_way=$(echo "scale=2; $avg_rtt / 2" | bc)
    echo -e "Approximated One-Way Delay: ${GREEN}$one_way ms${NC}"
    echo -e "${RED}Note: Real one-way delay requires clock synchronization${NC}"
}

# TCP Throughput
measure_tcp_throughput() {
    local logfile="$TMPDIR/tcp.log"
    execute_with_realtime "iperf3 -c $IP -t 10 -J" "$logfile" "Measuring TCP Throughput"

    if $VERBOSE; then
        echo -e "\n${YELLOW}Raw iperf3 TCP output:${NC}"
        jq . "$logfile"
    fi

    jq -r '.end.sum_received.bits_per_second / 1e6 | "%.2f Mbps\n"' "$logfile"
}

# UDP Throughput
measure_udp_throughput() {
    local logfile="$TMPDIR/udp.log"
    execute_with_realtime "iperf3 -u -c $IP -b 100M -t 10 -J" "$logfile" "Measuring UDP Throughput"

    if $VERBOSE; then
        echo -e "\n${YELLOW}Raw iperf3 UDP output:${NC}"
        jq . "$logfile"
    fi

    jq -r '.end.sum.bits_per_second / 1e6 | "%.2f Mbps\n"' "$logfile"
}

# Hop Count
measure_hop_count() {
    local logfile="$TMPDIR/traceroute.log"
    execute_with_realtime "traceroute -n -q 1 -w 1 $IP" "$logfile" "Measuring Hop Count"

    if $VERBOSE; then
        echo -e "\n${YELLOW}Raw traceroute output:${NC}"
        cat "$logfile"
    fi

    grep -cvE 'traceroute|^ *[0-9]+ $' "$logfile"
}

# Run measurements
measure_rtt_loss
measure_one_way_delay
echo -e "\nTCP Throughput: ${GREEN}$(measure_tcp_throughput)${NC}"
echo -e "UDP Throughput: ${GREEN}$(measure_udp_throughput)${NC}"
echo -e "Hop Count: ${GREEN}$(measure_hop_count)${NC}"