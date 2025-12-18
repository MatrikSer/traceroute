import pytest

from src.router import Router
from src.traceroute import Traceroute


@pytest.fixture
def sample_router():
    """Fixture for a sample router"""
    return Router(ip="192.168.1.1", num=1, time=15)


@pytest.fixture
def router_no_ip():
    """Fixture for a router with no IP"""
    return Router(ip=None, num=2, time=25)


@pytest.fixture
def valid_traceroute():
    """Fixture for a valid traceroute instance"""
    return Traceroute(
        port=53,
        ip="8.8.8.8",
        timeout=2,
        protocol="icmp",
        number_of_requests=3,
        max_ttl=30,
        interval=0,
        size_of_packet=40,
    )


@pytest.fixture
def traceroute_minimal():
    """Fixture for minimal traceroute configuration"""
    return Traceroute(
        port=53,
        ip="127.0.0.1",
        timeout=1,
        protocol="icmp",
        number_of_requests=1,
        max_ttl=5,
        interval=0,
        size_of_packet=40,
    )
