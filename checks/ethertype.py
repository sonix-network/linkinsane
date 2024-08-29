
from scapy.all import *
import time

from . import lib


class EtherTypeCheck(lib.Check):

    def __init__(self, logger):
        self.ok = True

    def run(self, iface):
        eth_frame = Ether(dst='ff:ff:ff:ff:ff:ff', type=0x88B5) / Raw(load='Hello!')
        sendp(eth_frame, iface=iface)
        self.end_time = time.time() + 0.5

    def receive(self, source, pkt):
        if source == 'remote' and Ether in pkt:
            eth = pkt[Ether]
            if eth.type == 0x88B5:
                self.ok = False
        if not self.ok:
            return self.RECEIVE_DONE
        return self.RECEIVE_AGAIN if time.time() < self.end_time else self.RECEIVE_DONE

    def result(self):
        return [
                ('Non-standard EtherTypes should be rejected', lib.PASSED if self.ok else lib.FAILED),
                ]


lib.register_check(EtherTypeCheck)
