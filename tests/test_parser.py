from unittest.mock import patch

from src.parser import parse_args


class TestParseArgs:
    @patch('sys.argv', ['traceroute', 'google.com', 'icmp'])
    def test_parse_args_basic(self) -> None:
        args = parse_args()
        assert args.address == 'google.com'
        assert args.protocol == 'icmp'
        assert args.t == 2
        assert args.n == 3
        assert args.mt == 30
        assert args.i == 0
        assert args.s == 40
        assert args.p == 53

    @patch('sys.argv', ['traceroute', '192.168.1.1', 'tcp', '-t', '5', '-n', '2'])
    def test_parse_args_with_options(self) -> None:
        args = parse_args()
        assert args.address == '192.168.1.1'
        assert args.protocol == 'tcp'
        assert args.t == 5
        assert args.n == 2
        assert args.mt == 30
        assert args.i == 0
        assert args.s == 40
        assert args.p == 53
