import pytest

from src.router import Router
from src.traceroute import Traceroute


class TestTracerouteInit:
    """Tests for Traceroute initialization and validation"""

    def test_traceroute_creation_valid(self, valid_traceroute):
        """Test creating traceroute with valid parameters"""
        assert valid_traceroute.port == 53
        assert valid_traceroute.ip == "8.8.8.8"
        assert valid_traceroute.timeout == 2
        assert valid_traceroute.protocol == "icmp"
        assert valid_traceroute.number_of_requests == 3
        assert valid_traceroute.max_ttl == 30
        assert valid_traceroute.interval == 0
        assert valid_traceroute.size_of_packet == 40
        assert valid_traceroute.routers == []

    def test_traceroute_creation_invalid_port(self):
        """Test traceroute creation with invalid port"""
        with pytest.raises(ValueError):
            Traceroute(
                port=70000,  # Invalid port
                ip="8.8.8.8",
                timeout=2,
                number_of_requests=3,
                max_ttl=30,
                interval=0,
                size_of_packet=40,
            )

    def test_traceroute_creation_invalid_timeout(self):
        """Test traceroute creation with negative timeout"""
        with pytest.raises(ValueError):
            Traceroute(
                port=53,
                ip="8.8.8.8",
                timeout=-1,  # Invalid timeout
                number_of_requests=3,
                max_ttl=30,
                interval=0,
                size_of_packet=40,
            )


class TestTracerouteAnalyzeIp:
    """Tests for analyze_ip method"""

    def test_analyze_ip_valid_ipv4(self, valid_traceroute):
        """Test analyzing valid IPv4 address"""
        valid_traceroute.analyze_ip()  # Should not raise

    def test_analyze_ip_invalid_ip(self):
        """Test analyzing invalid IP address"""
        traceroute = Traceroute(
            port=53,
            ip="invalid.ip",
            timeout=2,
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=40,
        )
        with pytest.raises(ValueError, match="Invalid IP address"):
            traceroute.analyze_ip()

    def test_analyze_ip_ipv6(self):
        """Test analyzing IPv6 address (should fail as code expects IPv4)"""
        traceroute = Traceroute(
            port=53,
            ip="2001:db8::1",
            timeout=2,
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=40,
        )
        with pytest.raises(ValueError, match="Invalid IP address"):
            traceroute.analyze_ip()


class TestTracerouteCalculateDataLen:
    """Tests for _calculate_data_len_for_icmp method"""

    def test_calculate_data_len_normal(self, valid_traceroute):
        """Test calculating data length with normal packet size"""
        result = valid_traceroute._calculate_data_len_for_icmp()
        # IP header (20) + ICMP header (8) = 28, so data_len = 40 - 28 = 12
        assert result == 12

    def test_calculate_data_len_large_packet(self):
        """Test calculating data length with large packet"""
        traceroute = Traceroute(
            port=53,
            ip="8.8.8.8",
            timeout=2,
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=100,
        )
        result = traceroute._calculate_data_len_for_icmp()
        assert result == 72  # 100 - 20 - 8 = 72

    def test_calculate_data_len_too_small(self):
        """Test calculating data length with packet too small"""
        traceroute = Traceroute(
            port=53,
            ip="8.8.8.8",
            timeout=2,
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=20,  # Smaller than headers
        )
        with pytest.raises(ValueError, match="Packet size is too small"):
            traceroute._calculate_data_len_for_icmp()

    def test_calculate_data_len_minimum_valid(self):
        """Test calculating data length with minimum valid packet size"""
        traceroute = Traceroute(
            port=53,
            ip="8.8.8.8",
            timeout=2,
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=28,  # Exactly headers size
        )
        result = traceroute._calculate_data_len_for_icmp()
        assert result == 0


class TestTracerouteViewRouters:
    """Tests for view_routers method"""

    def test_view_routers_with_ip(self, capsys, sample_router):
        """Test viewing routers with IP addresses"""
        traceroute = Traceroute(
            port=53,
            ip="8.8.8.8",
            timeout=2,
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=40,
            routers=[sample_router],
        )

        traceroute.view_routers()

        captured = capsys.readouterr()
        assert "1 192.168.1.1    15,ms" in captured.out

    def test_view_routers_without_ip(self, capsys, router_no_ip):
        """Test viewing routers without IP addresses"""
        traceroute = Traceroute(
            port=53,
            ip="8.8.8.8",
            timeout=2,
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=40,
            routers=[router_no_ip],
        )

        traceroute.view_routers()

        captured = capsys.readouterr()
        # When IP is None, both IP and time show as *
        assert "2 *    *,ms" in captured.out

    def test_view_routers_multiple(self, capsys):
        """Test viewing multiple routers"""
        routers = [
            Router(ip="192.168.1.1", num=1, time=10),
            Router(ip=None, num=2, time=20),
            Router(ip="192.168.1.3", num=3, time=30),
        ]

        traceroute = Traceroute(
            port=53,
            ip="8.8.8.8",
            timeout=2,
            number_of_requests=3,
            max_ttl=30,
            interval=0,
            size_of_packet=40,
            routers=routers,
        )

        traceroute.view_routers()

        captured = capsys.readouterr()
        lines = captured.out.strip().split('\n')
        assert len(lines) == 3
        assert "1 192.168.1.1    10,ms" in lines[0]
        # When IP is None, both IP and time show as *
        assert "2 *    *,ms" in lines[1]
        assert "3 192.168.1.3    30,ms" in lines[2]
