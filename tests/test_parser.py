from unittest.mock import patch

import pytest

from src.parser import parse_args


class TestParseArgs:
    """Tests for argument parsing"""

    def test_parse_args_default_values(self):
        """Test parsing with minimal arguments"""
        with patch('sys.argv', ['traceroute', '192.168.1.1']):
            args = parse_args()
            assert args.ip == '192.168.1.1'
            assert args.t == 2  # default timeout
            assert args.n == 3  # default number of requests
            assert args.mt == 30  # default max ttl
            assert args.i == 0  # default interval
            assert args.s == 40  # default packet size
            assert args.p == 53  # default port

    def test_parse_args_all_arguments(self):
        """Test parsing with all arguments provided"""
        with patch(
            'sys.argv', ['traceroute', '10.0.0.1', '-t', '5', '-n', '2', '-mt', '25', '-i', '1', '-s', '60', '-p', '80']
        ):
            args = parse_args()
            assert args.ip == '10.0.0.1'
            assert args.t == 5
            assert args.n == 2
            assert args.mt == 25
            assert args.i == 1
            assert args.s == 60
            assert args.p == 80

    def test_parse_args_partial_arguments(self):
        """Test parsing with some arguments provided"""
        with patch('sys.argv', ['traceroute', '8.8.8.8', '-t', '3', '-s', '50']):
            args = parse_args()
            assert args.ip == '8.8.8.8'
            assert args.t == 3
            assert args.n == 3  # default
            assert args.s == 50
            assert args.mt == 30  # default
            assert args.i == 0  # default
            assert args.p == 53  # default

    def test_parse_args_missing_ip(self):
        """Test parsing without IP address argument"""
        with patch('sys.argv', ['traceroute']):
            with pytest.raises(SystemExit):  # argparse exits on missing required arg
                parse_args()

    @pytest.mark.parametrize(
        "invalid_value,flag",
        [
            ("not_int", "-t"),
            ("abc", "-mt"),
            ("xyz", "-i"),
            ("invalid", "-s"),
            ("not_port", "-p"),
        ],
    )
    def test_parse_args_invalid_values(self, invalid_value, flag):
        """Test parsing with invalid argument values"""
        with patch('sys.argv', ['traceroute', '192.168.1.1', flag, invalid_value]):
            with pytest.raises(SystemExit):  # argparse exits on invalid int values
                parse_args()
