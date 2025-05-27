# Base image
FROM ubuntu:22.04

# Install Python and dependencies
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv iproute2 iptables libpcap-dev tcpdump iperf3
# && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /NetSlicer

# Copy project files into the container
COPY . /NetSlicer

# Install Python requirements
RUN pip3 install --upgrade pip
RUN if [ -f requirements.txt ]; then pip3 install -r requirements.txt; fi

EXPOSE 8080

# Run project
CMD ["python3", "main.py"]
