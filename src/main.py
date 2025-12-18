from src.parser import parse_args
from src.traceroute import Traceroute


def main() -> None:
    """Main function for starting the program"""
    args = parse_args()
    traceroute = Traceroute(
        port=args.p,
        ip=args.ip,
        timeout=args.t,
        number_of_requests=args.n,
        max_ttl=args.mt,
        interval=args.i,
        size_of_packet=args.s,
    )
    traceroute.analyze_ip()
    traceroute.run()
    traceroute.view_routers()
