from scapy.all import *
import time

from . import lib


class IPv6RACheck(lib.Check):

    def __init__(self, logger):
        self.ok = True

    def run(self, iface):
        ra_packet = (
            Ether(dst='33:33:00:00:00:01') /  # Destination MAC address (IPv6 all-nodes multicast)
            IPv6(dst='ff02::1') /             # Destination IPv6 address (all-nodes multicast)
            ICMPv6ND_RA(                      # Router Advertisement message
                chlim=64,                     # Current Hop Limit
                H=0,                          # Managed address configuration flag
                M=0,                          # Other configuration flag
                routerlifetime=1800,          # Router lifetime in seconds
                reachabletime=600000,         # Reachable time in milliseconds
                retranstimer=0                # Retransmission timer in milliseconds
            ) /
            ICMPv6NDOptPrefixInfo(            # Prefix Information option
                prefixlen=64,                 # Prefix length
                L=1,                          # On-link flag
                A=1,                          # Autonomous address configuration flag
                validlifetime=3600,           # Valid lifetime in seconds
                preferredlifetime=1800,       # Preferred lifetime in seconds
                prefix='2001:db8:dead:beef::' # Prefix
            ) /
            ICMPv6NDOptSrcLLAddr(lladdr='aa:bb:cc:dd:ee:ff')  # Source Link-Layer Address option
        )
        sendp(ra_packet, iface=iface)
        self.end_time = time.time() + 0.5

    def receive(self, source, pkt):
        if source == 'remote' and ICMPv6NDOptPrefixInfo in pkt:
            pi = pkt[ICMPv6NDOptPrefixInfo]
            if pi.prefix == '2001:db8:dead:beef::':
                self.ok = False
        if not self.ok:
            return self.RECEIVE_DONE
        return self.RECEIVE_AGAIN if time.time() < self.end_time else self.RECEIVE_DONE

    def result(self):
        return [
                ('IPv6 RA should not propagate', lib.PASSED if self.ok else lib.FAILED),
                ]


lib.register_check(IPv6RACheck)
