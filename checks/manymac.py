from scapy.all import *
import time

from . import lib


class ManyMacCheck(lib.Check):

    def __init__(self, logger):
        self.seen_p2 = False
        self.logger = logger

    def run(self, iface):
        p1 = Ether(dst='ff:ff:ff:ff:ff:ff') / IP(dst='255.255.255.255') / UDP(dport=54321)
        p2 = Ether(dst='ff:ff:ff:ff:ff:ff', src='c2:37:d7:c7:99:f9') / IP(dst='255.255.255.255') / UDP(dport=54321)
        sendp(p1, iface=iface)
        # ensure the first packet is sent and its MAC has been learnt
        time.sleep(0.1)
        sendp(p2, iface=iface)
        self.end_time = time.time() + 1.0

    def receive(self, source, pkt):
        if source == 'remote' and UDP in pkt:
            ether = pkt[Ether]
            if ether.src == 'c2:37:d7:c7:99:f9':
                self.logger.debug('Saw P2')
                self.seen_p2 = True
        if self.seen_p2:
            return self.RECEIVE_DONE
        return self.RECEIVE_AGAIN if time.time() < self.end_time else self.RECEIVE_DONE

    def result(self):
        return [
                ('Packets from secondary MAC should be rejected', lib.FAILED if self.seen_p2 else lib.PASSED),
                ]


lib.register_check(ManyMacCheck)
