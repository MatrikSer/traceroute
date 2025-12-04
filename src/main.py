from src.parser import parse_args
from src.traceroute import Traceroute


def solve():
    args = parse_args()
    traceroute = Traceroute(
        port=args.p, ip=args.ip, timeout=args.t, protocol=args.protocol, verbose=args.v, number_of_requests=args.n
    )
    traceroute.search_routers()
    traceroute.view_routers()


if __name__ == "__main__":
    solve()
