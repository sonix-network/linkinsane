from scapy.all import *
import time

from . import lib


class ICMPRedirectCheck(lib.Check):

    def __init__(self):
        self.ok = True

    def run(self, iface):
        original_ip_packet = IP(src='192.168.1.100', dst='8.8.8.8') / ICMP()
        icmp_redirect_packet = (
            Ether(dst='ff:ff:ff:ff:ff:ff') /              # Ethernet frame with broadcast MAC address
            IP(src='192.168.1.1', dst='192.168.1.100') /  # IP packet from router to host
            ICMP(type=5, code=1, gw='192.168.1.2') /      # ICMP Redirect message
            original_ip_packet                            # Encapsulate the original IP packet
        )
        sendp(icmp_redirect_packet, iface=iface)
        self.end_time = time.time() + 0.5

    def receive(self, source, pkt):
        if not self.ok:
            return False

        if source == 'remote' and ICMP in pkt:
            pi = pkt[ICMP]
            if pi.gw == '192.168.1.2':
                self.ok = False
        return time.time() < self.end_time

    def result(self):
        return [
                ('IPv4 ICMP Redirect should not propagate', lib.PASSED if self.ok else lib.FAILED),
                ]


lib.register_check(ICMPRedirectCheck)
