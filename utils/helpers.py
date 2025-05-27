import inspect
import os
import subprocess
import sys
from typing import Literal

from termcolor import cprint

import config


def log(color: Literal["red", "green", "yellow", "blue", "cyan", "magenta"] | str, message=None, title=None, tsize=20,
        rjust=False):
    verbose = "DEBUG"
    if hasattr(config.args, 'verbose'):
        verbose = config.args.verbose
    # else:
    #     print(f"LOG: config.args={config.args}")
    frame = inspect.currentframe().f_back
    filename_with_ext = os.path.basename(frame.f_code.co_filename)
    filename, _ = os.path.splitext(filename_with_ext)
    line_number = frame.f_lineno
    debug = False
    if verbose.upper() == "ERROR":
        show = True if color in ["red", "green", "blue"] else False
    elif verbose.upper() == "WARNING":
        show = True if color in ["cyan", "yellow", "red", "green", "blue"] else False
    elif verbose.upper() == "INFO":
        show = True if color in ["cyan", "yellow", "red", "green", "blue", "white", "magenta"] else False
    else:  # verbose: DEBUG
        show = True
        if color not in ["cyan", "yellow", "red", "green", "blue", "white", "magenta"] and message is None:
            debug = True
    if show:
        if debug:
            message = color
            color = "cyan"
        if title == " ":
            cprint(f"\r{title}".ljust(tsize).upper(), end=' ', flush=True)
        elif title:
            if rjust:
                cprint(f"\r{title.rjust(tsize - 2).upper()} ", color=color, attrs=['reverse'], end=' ', flush=True)
            else:
                cprint(f"\r {title}".ljust(tsize).upper(), color=color, attrs=['reverse'], end=' ', flush=True)
        else:
            cprint(f"\r {filename}::{line_number} ".ljust(tsize).upper(), color=color, attrs=['reverse'], end=' ',
                   flush=True)
        cprint(str(message), color)


class Map(dict):
    """
    Example:
    m = Map({'first_name': 'Eduardo'}, last_name='Pool', age=24, sports=['Soccer'])
    """

    def __init__(self, *args, **kwargs):
        super(Map, self).__init__(*args, **kwargs)
        for arg in args:
            if isinstance(arg, dict):
                for k, v in arg.items():
                    self[k] = v

        if kwargs:
            for k, v in kwargs.items():
                self[k] = v

    def __getattr__(self, attr):
        return self.get(attr)

    def __setattr__(self, key, value):
        self.__setitem__(key, value)

    def __setitem__(self, key, value):
        super(Map, self).__setitem__(key, value)
        self.__dict__.update({key: value})

    def __delattr__(self, item):
        self.__delitem__(item)

    def __delitem__(self, key):
        super(Map, self).__delitem__(key)
        del self.__dict__[key]


def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()


def setup_environment(args):
    # reset_environment()
    """Configure system for routing and slicing"""
    log('blue', f"Configure NetSlicer system for routing")
    if config.IS_LINUX:
        log('cyan', "Enabling IP forwarding...")
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
        log('cyan', f"Adding iptables rule for NFQUEUE...")
        subprocess.run(
            ["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"],
            check=True,
        )
    elif config.IS_MACOS:

        log('cyan', "Enabling IP forwarding...")
        subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"], check=True)
        log('cyan', "Enable the Packet Filter (PF) firewall...")
        subprocess.run(["pfctl", "-e"], check=True)
    else:
        log('red', "Unsupported platform!")
        sys.exit(1)


def reset_environment(args=None):
    log('blue', f"Reset system environment...")
    if config.IS_LINUX:
        log('cyan', f"Disable IP forwarding (Linux)...")
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True)
        log('cyan', f"Remove iptables rule from NFQUEUE...")
        subprocess.run(
            ["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"],
            check=False,  # Use check=False as rule might not exist if setup failed
        )
    elif config.IS_MACOS:
        log('cyan', f"Disable IP forwarding (MacOS)...")
        subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=0"], check=True)  # CORRECT OID
        log('cyan', f"Disabling the Packet Filter...")
        subprocess.run(["pfctl", "-d"], check=False)  # Consider adding this
        log('cyan', f"Flushing PF rules...")
        subprocess.run(["pfctl", "-F", "all"], check=False)
