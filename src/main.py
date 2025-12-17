from src.parser import parse_args
from src.traceroute import Traceroute


def main() -> None:
    """Main function for starting the program"""
    args = parse_args()
    traceroute = Traceroute(
        port=args.p,
        ip=Traceroute.parse_address(args.address),
        timeout=args.t,
        protocol=args.protocol,
        verbose=args.v,
        number_of_requests=args.n,
        max_ttl=args.mt,
        interval=args.i,
        size_of_packet=args.s,
    )
    traceroute.search_routers()
    traceroute._view_routers()


if __name__ == "__main__":
    main()
