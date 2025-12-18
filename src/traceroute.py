import ipaddress
import time
from ipaddress import IPv4Address

from pydantic import BaseModel, Field
from scapy.all import ICMP, IP, Raw, sr1  # type: ignore[attr-defined]

from src.router import Router


class Traceroute(BaseModel):
    """Class for searching routers"""

    port: int = Field(ge=0, lt=65535)
    ip: str
    timeout: int = Field(ge=0)
    protocol: str = "icmp"
    number_of_requests: int
    max_ttl: int = Field(ge=0)
    interval: int = Field(ge=0)
    size_of_packet: int
    routers: list[Router] = []

    def analyze_ip(self) -> None:
        """Analyzes the IP address"""
        try:
            ip = ipaddress.ip_address(self.ip)
            if not isinstance(ip, IPv4Address):
                raise ValueError("Invalid IP address")
        except ValueError:
            raise ValueError("Invalid IP address")

    def view_routers(self) -> None:
        """Prints the results of the search"""
        for router in self.routers:
            print(
                f"{router.num} {router.ip if router.ip is not None else '*'}"
                + f"    {router.time if router.ip is not None else '*'},ms"
            )

    def _calculate_data_len_for_icmp(self) -> int:
        """Calculates the length of the data for ICMP packets"""
        ip_len = 20
        icmp_len = 8
        data_len = self.size_of_packet - ip_len - icmp_len
        if data_len < 0:
            raise ValueError("Packet size is too small")
        return data_len

    def run(self) -> None:
        """Traceroute for ICMP protocol"""
        data_len = self._calculate_data_len_for_icmp()
        for ttl in range(1, self.max_ttl + 1):
            timeout = 0
            for _ in range(self.number_of_requests):
                packet = IP(dst=self.ip, ttl=ttl) / ICMP() / Raw(load=data_len * b"X")
                start_time = time.time()
                response = sr1(packet, timeout=self.timeout, verbose=0)
                if response is not None:
                    timeout = 0
                    break
                time.sleep(self.interval)
                timeout = self.interval
            rrt = (time.time() - start_time - timeout) * 1000
            if response is None:
                self.routers.append(Router(ip=None, num=ttl, time=int(rrt)))
            elif response.type == 11:
                self.routers.append(Router(ip=response.src, num=ttl, time=int(rrt)))
            elif response.type == 0:
                self.routers.append(Router(ip=response.src, num=ttl, time=int(rrt)))
                break
