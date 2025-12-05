import socket
import time

from pydantic import BaseModel, Field
from scapy.all import ICMP, IP, TCP, UDP, Raw, sr1  # type: ignore[attr-defined]

from src.router import Router


class Traceroute(BaseModel):
    port: int = Field(ge=0, lt=65535)
    ip: str
    timeout: int = Field(ge=0)
    protocol: str
    verbose: bool
    number_of_requests: int
    max_ttl: int = Field(ge=0)
    interval: int = Field(ge=0)
    size_of_packet: int
    routers: list[Router] = []

    def _raw_whois_query(self, ip: int) -> str | None:
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect(("whois.radb.net", 43))
            s.send(f"n + {ip}\n".encode())
            data = b""
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk

            s.close()
            text = data.decode()
            for line in text.split("\n"):
                if "origin" in line:
                    return line.split(":")[1].strip()
            return None
        except socket.timeout:
            return None

    def search_routers(self) -> None:
        if self.protocol == "icmp":
            self._icmp_traceroute()
        elif self.protocol == "tcp":
            self._tcp_traceroute()
        elif self.protocol == "udp":
            self._udp_traceroute()

    def _view_routers(self) -> None:
        for router in self.routers:
            if self.verbose:
                print(
                    f"{router.num} {router.ip if router.ip is not None else '*'} [{router.time},ms] "
                    + f"[{router.autonomous_system if router.autonomous_system is not None else '*'}]"
                )
            else:
                print(f"{router.num} {router.ip if router.ip is not None else '*'} [{router.time},ms]")

    def _calculate_data_len_for_icmp(self) -> int:
        ip_len = 20
        icmp_len = 8
        data_len = self.size_of_packet - ip_len - icmp_len
        if data_len < 0:
            raise ValueError("Packet size is too small")
        return data_len

    def _icmp_traceroute(self) -> None:
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
                self.routers.append(Router(ip=None, num=ttl, time=int(rrt), autonomous_system=None))
            elif response.type == 11:
                autonomous_system = self._raw_whois_query(response.src)
                self.routers.append(
                    Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=autonomous_system)
                )
            elif response.type == 0:
                autonomous_system = self._raw_whois_query(response.src)
                self.routers.append(
                    Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=autonomous_system)
                )
                break

    def _tcp_traceroute(self) -> None:
        for ttl in range(1, self.max_ttl + 1):
            packet = IP(dst=self.ip, ttl=ttl) / TCP(dport=self.port, flags="S")
            start_time = time.time()
            response = sr1(packet, timeout=self.timeout, verbose=0)
            rrt = (time.time() - start_time) * 1000
            if response is None:
                self.routers.append(Router(ip=None, num=ttl, time=int(rrt), autonomous_system=None))
            elif response.haslayer(TCP):
                autonomous_system = self._raw_whois_query(response.src)
                self.routers.append(
                    Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=autonomous_system)
                )
                break
            elif response.type == 11:
                autonomous_system = self._raw_whois_query(response.src)
                self.routers.append(
                    Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=autonomous_system)
                )

    def _udp_traceroute(self) -> None:
        for ttl in range(1, self.max_ttl + 1):
            packet = IP(dst=self.ip, ttl=ttl) / UDP(dport=self.port + ttl)
            start_time = time.time()
            response = sr1(packet, timeout=self.timeout, verbose=0)
            rrt = (time.time() - start_time) * 1000
            if response is None:
                self.routers.append(Router(ip=None, num=ttl, time=int(rrt), autonomous_system=None))
            elif response.type == 11:
                autonomous_system = self._raw_whois_query(response.src)
                self.routers.append(
                    Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=autonomous_system)
                )
            elif response.type == 3 and response.code == 3:
                autonomous_system = self._raw_whois_query(response.src)
                self.routers.append(
                    Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=autonomous_system)
                )
                break
