import argparse
from argparse import Namespace


def parse_args() -> Namespace:
    """Parses the command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument("address", help="Address, IP or domain")
    parser.add_argument("protocol", choices=["icmp", "tcp"], help="Protocol")
    parser.add_argument("-t", type=int, default=2, help="Timeout")
    parser.add_argument("-n", type=int, default=3, help="Number of requests")
    parser.add_argument("-mt", type=int, default=30, help="Max TTL")
    parser.add_argument("-i", type=int, default=0, help="Interval between requests")
    parser.add_argument("-s", type=int, default=40, help="Size of packet")
    parser.add_argument("-p", type=int, default=53, help="Port")
    return parser.parse_args()
