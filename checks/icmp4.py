from scapy.all import *
import time

from . import lib


class ICMPRedirectCheck(lib.Check):

    def __init__(self, logger):
        self.ok = True

    def run(self, iface):
        original_ip_packet = IP(src='192.168.1.100', dst='8.8.8.8') / ICMP()
        icmp_redirect_packet = (
            Ether(dst='a2:47:28:92:1c:c5', src=get_if_hwaddr(iface)) /
            IP(src='192.168.1.1', dst='192.168.1.100') /  # IP packet from router to host
            ICMP(type=5, code=1, gw='192.168.1.2') /      # ICMP Redirect message
            original_ip_packet                            # Encapsulate the original IP packet
        )
        sendp(icmp_redirect_packet, iface=iface)
        self.end_time = time.time() + 0.5

    def receive(self, source, pkt):
        if source == 'remote' and ICMP in pkt:
            pi = pkt[ICMP]
            if pi.gw == '192.168.1.2':
                self.ok = False
        if not self.ok:
            return self.RECEIVE_DONE
        return self.RECEIVE_AGAIN if time.time() < self.end_time else self.RECEIVE_DONE

    def result(self):
        return [
                ('IPv4 ICMP Redirect should not propagate', lib.PASSED if self.ok else lib.FAILED, ''),
                ]


class ICMPEchoCheck(lib.Check):

    def __init__(self, logger):
        self.ok = False

    def run(self, iface):
        icmp_echo_packet = (
            Ether(dst='a2:47:28:92:1c:c5', src=get_if_hwaddr(iface)) /
            IP(src='192.168.1.1', dst='192.168.1.100') /  # IP packet from router to host
            ICMP() /
            Raw(load=b'ICMPEchoCheck')
        )
        sendp(icmp_echo_packet, iface=iface)
        self.end_time = time.time() + 0.5

    def receive(self, source, pkt):
        if source == 'remote' and ICMP in pkt:
            pi = pkt[ICMP]
            if pi[Raw].load.decode('utf-8', errors='ignore') == 'ICMPEchoCheck':
                self.ok = True
        if self.ok:
            return self.RECEIVE_DONE
        return self.RECEIVE_AGAIN if time.time() < self.end_time else self.RECEIVE_DONE

    def result(self):
        return [
                ('IPv4 ICMP Echo should be forwarded', lib.PASSED if self.ok else lib.FAILED, ''),
                ]


lib.register_check(ICMPRedirectCheck)
lib.register_check(ICMPEchoCheck)
