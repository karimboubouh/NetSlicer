import argparse
import random
from dataclasses import dataclass
from typing import Literal

import numpy as np

import config


@dataclass
class Args:
    # Network configuration
    display_packets: bool
    display_metrics: bool
    store_packets: bool
    interface: str
    rate_limit: str
    # System configuration
    gpu: bool
    verbose: Literal['DEBUG', 'INFO', 'WARNING', 'ERROR']
    seed: int
    fix_seed: bool


def parse_args() -> Args:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Net Slicer')
    # Network configuration
    parser.add_argument(
        '--interface',
        type=str,
        default='en1',
        help='Output interface'
    )
    parser.add_argument(
        '--display-packets',
        action='store_true',
        help='display sniffed packets in STDOUT'
    )
    parser.add_argument(
        '--display-metrics',
        action='store_true',
        help='display sniffing metrics such as speed, throughput, etc'
    )
    parser.add_argument(
        '--store-packets',
        action='store_true',
        help='Store sniffed packets in database'
    )

    parser.add_argument(
        '--rate-limit',
        type=str,
        default="20mbit",
        help='Rate limit'
    )

    # System configuration
    # parser.add_argument('--gpu', action='store_true', help='Enable GPU training')
    parser.add_argument('--no-gpu', action='store_false', dest='gpu', help='Disable GPU training')
    parser.add_argument('--verbose', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        default='DEBUG', help='Logging level')
    parser.add_argument('--seed', type=int, default=42, help='Random seed')
    parser.add_argument('--fix-seed', action='store_true', help='Fix the randomness seed')

    args = Args(**vars(parser.parse_args()))
    config.args = args
    if args.fix_seed:
        random.seed(args.seed)
        np.random.seed(args.seed)

    return Args(**vars(parser.parse_args()))
