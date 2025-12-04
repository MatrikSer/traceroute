from pydantic import BaseModel, Field

from src.router import Router
import time
from scapy.all import IP, ICMP, TCP, UDP, sr1, send  # type: ignore


class Traceroute(BaseModel):
    port: int
    ip: str
    timeout: int
    protocol: str
    verbose: bool
    number_of_requests: int
    routers: list[Router] = []

    def search_routers(self):
        if self.protocol == "icmp":
            self._icmp_traceroute()
        elif self.protocol == "tcp":
            self._tcp_traceroute()
        elif self.protocol == "udp":
            self._udp_traceroute()
    
    def view_routers(self):
        for router in self.routers:
            if self.verbose:
                print(f"{router.num} {router.ip} [{router.time},ms] [{router.autonomous_system}]")
            print(f"{router.num} {router.ip if router.ip is not None else '*'} [{router.time},ms]")

    def _icmp_traceroute(self):
        for ttl in range(1, self.number_of_requests + 1):
            packet = IP(dst=self.ip, ttl=ttl) / ICMP()
            start_time = time.time()
            response = sr1(packet, timeout=self.timeout, verbose=0)
            rrt = (time.time() - start_time) * 1000
            if response is None:
                self.routers.append(Router(ip=None, num=ttl, time=int(rrt), autonomous_system=None))
            elif response.type == 11:
                self.routers.append(Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=None))
            elif response.type == 0:
                self.routers.append(Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=None))
                break

    def _tcp_traceroute(self):
        for ttl in range(1, self.number_of_requests + 1):
            packet = IP(dst=self.ip, ttl=ttl) / TCP(dport=self.port, flags="S")
            start_time = time.time()
            response = sr1(packet, timeout=self.timeout, verbose=0)
            rrt = (time.time() - start_time) * 1000
            if response is None:
                self.routers.append(Router(ip=None, num=ttl, time=int(rrt), autonomous_system=None))
            elif response.haslayer(TCP):
                self.routers.append(Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=None))
                break
            elif response.type == 11:
                self.routers.append(Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=None))

    def _udp_traceroute(self):
        for ttl in range(1, self.number_of_requests + 1):
            packet = IP(dst=self.ip, ttl=ttl) / UDP(dport=self.port + ttl)
            start_time = time.time()
            response = sr1(packet, timeout=self.timeout, verbose=0)
            rrt = (time.time() - start_time) * 1000
            if response is None:
                self.routers.append(Router(ip=None, num=ttl, time=int(rrt), autonomous_system=None))
            elif response.type == 11:
                self.routers.append(Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=None))
            elif response.type == 3 and response.code == 3:
                self.routers.append(Router(ip=response.src, num=ttl, time=int(rrt), autonomous_system=None))
                break