from src.router import Router


class TestRouter:
    def test_router_creation(self) -> None:
        router = Router(ip="192.168.1.1", num=1, time=10)
        assert router.ip == "192.168.1.1"
        assert router.num == 1
        assert router.time == 10

    def test_router_none_ip(self) -> None:
        router = Router(ip=None, num=2, time=20)
        assert router.ip is None
        assert router.num == 2
        assert router.time == 20
