import ipaddress
import socket
import time

from pydantic import BaseModel, Field
from scapy.all import ICMP  # type: ignore[attr-defined]
from scapy.all import IP  # type: ignore[attr-defined]
from scapy.all import TCP  # type: ignore[attr-defined]
from scapy.all import ICMPv6EchoRequest  # type: ignore[attr-defined]
from scapy.all import IPv6  # type: ignore[attr-defined]
from scapy.all import (
    Raw,
    sr1,
)

from src.router import Router


class Traceroute(BaseModel):
    """Class for searching routers"""

    port: int = Field(ge=0, lt=65535)
    address: str
    timeout: int = Field(ge=0)
    protocol: str
    number_of_requests: int
    max_ttl: int = Field(ge=0)
    interval: int = Field(ge=0)
    size_of_packet: int
    routers: list[Router] = Field(default_factory=list)
    ipv6: bool = False
    ipv4: bool = True

    def analyze_address(self) -> None:
        """Analyzes the address"""
        try:
            ip = ipaddress.ip_address(self.address)
            self.ipv6 = isinstance(ip, ipaddress.IPv6Address)
            self.ipv4 = isinstance(ip, ipaddress.IPv4Address)
        except ValueError:
            try:
                infos = socket.getaddrinfo(self.address, None)
                family, _, _, _, sockaddr = infos[0]
                self.address = str(sockaddr[0])
                if family == socket.AF_INET6:
                    self.ipv6, self.ipv4 = True, False
                else:
                    self.ipv6, self.ipv4 = False, True
            except socket.gaierror:
                raise ValueError("Invalid address")

    def _view_routers(self) -> None:
        """Prints the results of the search"""
        for router in self.routers:
            print(
                f"{router.num} {router.ip if router.ip is not None else '*'}    {router.time if router.ip is not None else '*'},ms"
            )

    def search_routers(self) -> None:
        """Search routers for the specified protocol"""
        data_len = self.create_data_len()
        for ttl in range(1, self.max_ttl + 1):
            for _ in range(self.number_of_requests):
                packet = self.create_packet(data_len, ttl)
                start_time = time.time()
                response = sr1(packet, timeout=self.timeout, verbose=0)
                rrt = (time.time() - start_time) * 1000
                if response is not None:
                    break
                time.sleep(self.interval)
            found_answer = self.analyze_response(ttl, response, rrt)
            if found_answer:
                break

    def analyze_response(self, ttl, response, rrt):
        """Analyzes the response"""
        if self.protocol == "icmp":
            found_answer = self.analyze_response_icmp(ttl, response, rrt)
        elif self.protocol == "tcp":
            found_answer = self.analyze_response_tcp(ttl, response, rrt)
        return found_answer

    def create_packet(self, data_len, ttl):
        """Creates the packet"""
        if self.protocol == "icmp":
            packet = self.create_packet_for_icmp(data_len, ttl)
        elif self.protocol == "tcp":
            packet = self.create_packet_for_tcp(data_len, ttl)
        return packet

    def create_packet_for_tcp(self, data_len, ttl):
        """Creates the TCP packet"""
        if self.ipv6:
            packet = IPv6(dst=self.address, hlim=ttl) / TCP(dport=self.port, flags="S") / Raw(load=data_len * b"X")
        else:
            packet = IP(dst=self.address, ttl=ttl) / TCP(dport=self.port, flags="S") / Raw(load=data_len * b"X")
        return packet

    def create_packet_for_icmp(self, data_len, ttl):
        """Creates the ICMP packet"""
        if self.ipv6:
            packet = IPv6(dst=self.address, hlim=ttl) / ICMPv6EchoRequest() / Raw(load=data_len * b"X")
        else:
            packet = IP(dst=self.address, ttl=ttl) / ICMP() / Raw(load=data_len * b"X")
        return packet

    def create_data_len(self):
        """Creates the data length for the packet"""
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
        """Analyzes the response for ICMP packets"""
        if response is None:
            self.routers.append(Router(ip=None, num=ttl, time=int(rrt)))
            return False
        src_ip = response.src
        self.routers.append(Router(ip=src_ip, num=ttl, time=int(rrt)))
        if self.ipv4:
            return response.type == 0
        else:
            return response.type == 129 or response.type == 1

    def analyze_response_tcp(self, ttl, response, rrt):
        """Analyzes the response for TCP packets"""
        if response is None:
            self.routers.append(Router(ip=None, num=ttl, time=int(rrt)))
            return False
        src_ip = response.src
        self.routers.append(Router(ip=src_ip, num=ttl, time=int(rrt)))
        if response.haslayer(TCP):
            tcp = response[TCP]
            return bool((tcp.flags & 0x12) or (tcp.flags & 0x04) or (tcp.flags & 0x14))
        if hasattr(response, "type"):
            if self.ipv4:
                return response.type == 3
            else:
                return response.type == 1
        return False
