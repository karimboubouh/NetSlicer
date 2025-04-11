import platform
from typing import Optional

from core.parser import Args

# parser arguments
args: Optional[Args] = None

SLICE_POLICIES = {
    1: {"bw": "10mbit"},  # TOS 1
    2: {"bw": "5mbit"},  # TOS 2
    3: {"bw": "1mbit"}  # TOS 3
}

HANDLE = "1:"

# Platform Detection
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

# PROTOBUF

CHUNK_SIZE = 262144  # 256 KB per chunk

# Network configurations
MAX_RECONNECTION_ATTEMPTS = 2
RECONNECTION_TIMEOUT = 5  # seconds
HEARTBEAT_INTERVAL = 2  # seconds

# Registry configurations
REGISTRY_HOST = "127.0.0.1"
REGISTRY_PORT = 15000
