import socket
from unittest.mock import MagicMock, patch

import pytest

from src.traceroute import Traceroute


class TestTraceroute:
    def test_analyze_address_ipv4(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="192.168.1.1",
            timeout=2,
            protocol="icmp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=40,
        )
        traceroute.analyze_address()
        assert traceroute.ipv4 is True
        assert traceroute.ipv6 is False
        assert traceroute.address == "192.168.1.1"

    def test_analyze_address_ipv6(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="2001:db8::1",
            timeout=2,
            protocol="icmp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=40,
        )
        traceroute.analyze_address()
        assert traceroute.ipv4 is False
        assert traceroute.ipv6 is True
        assert traceroute.address == "2001:db8::1"

    @patch('socket.getaddrinfo')
    def test_analyze_address_domain_ipv4(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.return_value = [(socket.AF_INET, None, None, None, ('93.184.216.34', 80))]
        traceroute = Traceroute(
            port=53,
            address="example.com",
            timeout=2,
            protocol="icmp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=40,
        )
        traceroute.analyze_address()
        assert traceroute.ipv4 is True
        assert traceroute.ipv6 is False
        assert traceroute.address == "93.184.216.34"

    @patch('socket.getaddrinfo')
    def test_analyze_address_domain_ipv6(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.return_value = [(socket.AF_INET6, None, None, None, ('2001:db8::1', 80))]
        traceroute = Traceroute(
            port=53,
            address="example.com",
            timeout=2,
            protocol="icmp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=40,
        )
        traceroute.analyze_address()
        assert traceroute.ipv4 is False
        assert traceroute.ipv6 is True
        assert traceroute.address == "2001:db8::1"

    def test_analyze_address_invalid(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="invalid.address",
            timeout=2,
            protocol="icmp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=40,
        )
        with pytest.raises(ValueError, match="Invalid address"):
            traceroute.analyze_address()

    def test_calculate_data_len_for_icmp_ipv4(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="192.168.1.1",
            timeout=2,
            protocol="icmp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=60,
        )
        traceroute.ipv4 = True
        data_len = traceroute._calculate_data_len_for_icmp()
        # 60 - 20 - 8 = 32
        assert data_len == 32

    def test_calculate_data_len_for_icmp_ipv6(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="2001:db8::1",
            timeout=2,
            protocol="icmp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=80,
        )
        traceroute.ipv4 = False
        traceroute.ipv6 = True
        data_len = traceroute._calculate_data_len_for_icmp()
        # 80 - 40 - 8 = 32
        assert data_len == 32

    def test_calculate_data_len_for_icmp_too_small(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="192.168.1.1",
            timeout=2,
            protocol="icmp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=20,
        )
        traceroute.ipv4 = True
        with pytest.raises(ValueError, match="Packet size is too small for ICMP"):
            traceroute._calculate_data_len_for_icmp()

    def test_calculate_data_len_for_tcp_ipv4(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="192.168.1.1",
            timeout=2,
            protocol="tcp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=80,
        )
        traceroute.ipv4 = True
        data_len = traceroute._calculate_data_len_for_tcp()
        # 80 - 20 - 20 = 40
        assert data_len == 40

    def test_calculate_data_len_for_tcp_ipv6(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="2001:db8::1",
            timeout=2,
            protocol="tcp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=100,
        )
        traceroute.ipv4 = False
        traceroute.ipv6 = True
        data_len = traceroute._calculate_data_len_for_tcp()
        # 100 - 40 - 20 = 40
        assert data_len == 40

    def test_calculate_data_len_for_tcp_too_small(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="192.168.1.1",
            timeout=2,
            protocol="tcp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=30,
        )
        traceroute.ipv4 = True
        with pytest.raises(ValueError, match="Packet size is too small for TCP"):
            traceroute._calculate_data_len_for_tcp()

    @patch('src.traceroute.IP')
    @patch('src.traceroute.Raw')
    def test_create_packet_for_icmp_ipv4(self, mock_raw: MagicMock, mock_ip: MagicMock) -> None:
        traceroute = Traceroute(
            port=53,
            address="192.168.1.1",
            timeout=2,
            protocol="icmp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=60,
        )
        traceroute.ipv4 = True
        packet = traceroute.create_packet_for_icmp(32, 5)  # noqa: F841
        mock_ip.assert_called_once_with(dst="192.168.1.1", ttl=5)

    @patch('src.traceroute.IPv6')
    @patch('src.traceroute.Raw')
    def test_create_packet_for_icmp_ipv6(self, mock_raw: MagicMock, mock_ipv6: MagicMock) -> None:
        traceroute = Traceroute(
            port=53,
            address="2001:db8::1",
            timeout=2,
            protocol="icmp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=80,
        )
        traceroute.ipv6 = True
        packet = traceroute.create_packet_for_icmp(32, 5)  # noqa: F841
        mock_ipv6.assert_called_once_with(dst="2001:db8::1", hlim=5)

    @patch('src.traceroute.IP')
    @patch('src.traceroute.TCP')
    @patch('src.traceroute.Raw')
    def test_create_packet_for_tcp_ipv4(self, mock_raw: MagicMock, mock_tcp: MagicMock, mock_ip: MagicMock) -> None:
        traceroute = Traceroute(
            port=53,
            address="192.168.1.1",
            timeout=2,
            protocol="tcp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=80,
        )
        traceroute.ipv4 = True
        packet = traceroute.create_packet_for_tcp(40, 5)  # noqa: F841
        mock_ip.assert_called_once_with(dst="192.168.1.1", ttl=5)
        mock_tcp.assert_called_once_with(dport=53, flags="S")

    @patch('src.traceroute.IPv6')
    @patch('src.traceroute.TCP')
    @patch('src.traceroute.Raw')
    def test_create_packet_for_tcp_ipv6(self, mock_raw: MagicMock, mock_tcp: MagicMock, mock_ipv6: MagicMock) -> None:
        traceroute = Traceroute(
            port=53,
            address="2001:db8::1",
            timeout=2,
            protocol="tcp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=100,
        )
        traceroute.ipv6 = True
        packet = traceroute.create_packet_for_tcp(40, 5)  # noqa: F841
        mock_ipv6.assert_called_once_with(dst="2001:db8::1", hlim=5)
        mock_tcp.assert_called_once_with(dport=53, flags="S")

    def test_analyze_response_icmp_ipv4_none(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="192.168.1.1",
            timeout=2,
            protocol="icmp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=60,
        )
        traceroute.ipv4 = True
        found = traceroute.analyze_response_icmp(1, None, 100)
        assert found is False
        assert len(traceroute.routers) == 1
        assert traceroute.routers[0].ip is None
        assert traceroute.routers[0].num == 1
        assert traceroute.routers[0].time == 100

    def test_analyze_response_icmp_ipv4_echo_reply(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="192.168.1.1",
            timeout=2,
            protocol="icmp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=60,
        )
        traceroute.ipv4 = True
        response = MagicMock()
        response.src = "192.168.1.2"
        response.type = 0  # Echo reply
        found = traceroute.analyze_response_icmp(1, response, 50)
        assert found is True
        assert len(traceroute.routers) == 1
        assert traceroute.routers[0].ip == "192.168.1.2"
        assert traceroute.routers[0].num == 1
        assert traceroute.routers[0].time == 50

    def test_analyze_response_icmp_ipv6_echo_reply(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="2001:db8::1",
            timeout=2,
            protocol="icmp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=80,
        )
        traceroute.ipv4 = False
        traceroute.ipv6 = True
        response = MagicMock()
        response.src = "2001:db8::2"
        response.type = 129  # Echo reply
        found = traceroute.analyze_response_icmp(1, response, 50)
        assert found is True
        assert len(traceroute.routers) == 1
        assert traceroute.routers[0].ip == "2001:db8::2"

    def test_analyze_response_tcp_none(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="192.168.1.1",
            timeout=2,
            protocol="tcp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=80,
        )
        traceroute.ipv4 = True
        found = traceroute.analyze_response_tcp(1, None, 100)
        assert found is False
        assert len(traceroute.routers) == 1
        assert traceroute.routers[0].ip is None

    def test_analyze_response_tcp_syn_ack(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="192.168.1.1",
            timeout=2,
            protocol="tcp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=80,
        )
        traceroute.ipv4 = True
        response = MagicMock()
        response.src = "192.168.1.2"
        response.haslayer.return_value = True
        response.TCP = MagicMock()
        response.TCP.flags = 0x12  # SYN-ACK
        found = traceroute.analyze_response_tcp(1, response, 50)
        assert found is True
        assert len(traceroute.routers) == 1
        assert traceroute.routers[0].ip == "192.168.1.2"

    def test_analyze_response_tcp_rst(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="192.168.1.1",
            timeout=2,
            protocol="tcp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=80,
        )
        traceroute.ipv4 = True
        response = MagicMock()
        response.src = "192.168.1.2"
        response.haslayer.return_value = True
        response.TCP = MagicMock()
        response.TCP.flags = 0x04  # RST
        found = traceroute.analyze_response_tcp(1, response, 50)
        assert found is True

    def test_analyze_response_tcp_icmp_unreachable_ipv4(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="192.168.1.1",
            timeout=2,
            protocol="tcp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=80,
        )
        traceroute.ipv4 = True
        response = MagicMock()
        response.src = "192.168.1.2"
        response.haslayer.return_value = False
        response.type = 3  # Destination unreachable
        found = traceroute.analyze_response_tcp(1, response, 50)
        assert found is True

    def test_analyze_response_tcp_icmp_unreachable_ipv6(self) -> None:
        traceroute = Traceroute(
            port=53,
            address="2001:db8::1",
            timeout=2,
            protocol="tcp",
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=100,
        )
        traceroute.ipv4 = False
        traceroute.ipv6 = True
        response = MagicMock()
        response.src = "2001:db8::2"
        response.haslayer.return_value = False
        response.type = 1  # Destination unreachable
        found = traceroute.analyze_response_tcp(1, response, 50)
        assert found is True
