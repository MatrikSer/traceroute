from src.router import Router


class TestRouter:
    """Tests for Router model"""

    def test_router_creation_valid(self) -> None:
        """Test creating a router with valid data"""
        router = Router(ip="192.168.1.1", num=1, time=10)
        assert router.ip == "192.168.1.1"
        assert router.num == 1
        assert router.time == 10

    def test_router_creation_none_ip(self) -> None:
        """Test creating a router with None IP"""
        router = Router(ip=None, num=2, time=20)
        assert router.ip is None
        assert router.num == 2
        assert router.time == 20

    def test_router_equality(self) -> None:
        """Test router equality comparison"""
        router1 = Router(ip="192.168.1.1", num=1, time=10)
        router2 = Router(ip="192.168.1.1", num=1, time=10)
        router3 = Router(ip="192.168.1.2", num=1, time=10)

        assert router1 == router2
        assert router1 != router3
