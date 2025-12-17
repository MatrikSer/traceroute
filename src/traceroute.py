import ipaddress
import socket
import time

from pydantic import BaseModel, Field
from scapy.all import ICMP, IP, TCP, Raw, sr1  # type: ignore[attr-defined]

from src.router import Router


class Traceroute(BaseModel):
    """Class for searching routers"""

    port: int = Field(ge=0, lt=65535)
    address: str
    timeout: int = Field(ge=0)
    protocol: str
    verbose: bool
    number_of_requests: int
    max_ttl: int = Field(ge=0)
    interval: int = Field(ge=0)
    size_of_packet: int
    routers: list[Router] = []
    ipv6: bool = False
    ipv4: bool = True

    def analyze_address(self) -> None:
        """Analyzes the address"""
        ip = ipaddress.ip_address(self.address)
        if isinstance(ip, ipaddress.IPv6Address):
            self.ipv6 = True
            self.ipv4 = False
        else:
            self.address = socket.gethostbyname(self.address)

    def _raw_whois_query(self, ip: str) -> str | None:
        """Sends a query to whois.radb.net and returns the autonomous system"""
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

    def _view_routers(self) -> None:
        """Prints the results of the search"""
        for router in self.routers:
            if self.verbose:
                print(
                    f"{router.num} {router.ip if router.ip is not None else '*'} [{router.time if router.ip is not None else '*'},ms]"
                    + f" [{router.autonomous_system if router.autonomous_system is not None else '*'}]"
                )
            else:
                print(
                    f"{router.num} {router.ip if router.ip is not None else '*'} [{router.time if router.ip is not None else '*'},ms]"
                )

    def search_routers(self) -> None:
        """Search routers for the specified protocol"""
        data_len = self.create_data_len_for_packet()
        for ttl in range(1, self.max_ttl + 1):
            timeout = 0
            for _ in range(self.number_of_requests):
                packet = self.create_packet(data_len, ttl)
                start_time = time.time()
                response = sr1(packet, timeout=self.timeout, verbose=0)
                if response is not None:
                    timeout = 0
                    break
                time.sleep(self.interval)
                timeout = self.interval
            rrt = (time.time() - start_time - timeout) * 1000
            found_answer = self.analyze_response(ttl, response, rrt)
            if found_answer:
                break

    def analyze_response(self, ttl, response, rrt):
        if self.protocol == "icmp":
            found_answer = self.analyze_response_icmp(ttl, response, rrt)
        elif self.protocol == "tcp":
            found_answer = self.analyze_response_tcp(ttl, response, rrt)
        return found_answer

    def create_packet(self, data_len, ttl):
        if self.protocol == "icmp":
            packet = IP(dst=self.address, ttl=ttl) / ICMP() / Raw(load=data_len * b"X")
        elif self.protocol == "tcp":
            packet = IP(dst=self.address, ttl=ttl) / TCP(dport=self.port, flags="S") / Raw(load=data_len * b"X")
        return packet

    def create_data_len_for_packet(self):
        if self.protocol == "icmp":
            data_len = self._calculate_data_len_for_icmp()
        elif self.protocol == "tcp":
            data_len = self._calculate_data_len_for_tcp()
        return data_len
    
    def _calculate_data_len_for_tcp(self) -> int:
        """Calculates the length of the data for TCP packets"""
        ip_len = 20 if self.ipv4 else 40
        tcp_headers_len = 20
        data_len = self.size_of_packet - ip_len - tcp_headers_len
        if data_len < 0:
            raise ValueError("Packet size is too small for TCP")
        return data_len

    def _calculate_data_len_for_icmp(self) -> int:
        """Calculates the length of the data for ICMP packets"""
        ip_len = 20 if self.ipv4 else 40
        icmp_len = 8
        data_len = self.size_of_packet - ip_len - icmp_len
        if data_len < 0:
            raise ValueError("Packet size is too small for ICMP")
        return data_len

    def analyze_response_icmp(self, ttl, response, rrt):
        if response is None:
            self.routers.append(Router(ip=None, num=ttl, time=int(rrt), autonomous_system=None))
        elif response.type == 11:
            autonomous_system = self._raw_whois_query(response.src)
            self.routers.append(Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=autonomous_system))
        elif response.type == 0:
            autonomous_system = self._raw_whois_query(response.src)
            self.routers.append(Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=autonomous_system))
            return True
        return False

    def analyze_response_tcp(self, ttl, response, rrt):
        if response is None:
            self.routers.append(Router(ip=None, num=ttl, time=int(rrt), autonomous_system=None))
        elif response.haslayer(TCP):
            autonomous_system = self._raw_whois_query(response.src)
            self.routers.append(Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=autonomous_system))
            return True
        elif response.type == 11:
            autonomous_system = self._raw_whois_query(response.src)
            self.routers.append(Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=autonomous_system))
        return False