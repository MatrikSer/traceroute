import argparse

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="IP address")
    parser.add_argument("protocol", choices=["icmp", "tcp", "udp"], help="Protocol")
    parser.add_argument("-t", type=int, default=2, help="Timeout")
    parser.add_argument("-n", type=int, default=3, help="Number of requests")
    parser.add_argument("-p", type=int, default=53, help="Port")
    parser.add_argument("-v", action="store_true", help="Verbose")
    return parser.parse_args()