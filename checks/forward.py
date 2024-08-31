from scapy.all import *
import time

from . import lib


class ForwardCheck(lib.Check):

    def __init__(self, logger):
        self.seen = False
        self.logger = logger

    def run(self, iface):
        p = (
            Ether(
                dst='8e:b3:7b:40:e5:93',
                src=get_if_hwaddr(iface)
            ) /
            IP(dst='255.255.255.255') /
            UDP(dport=54321)
        )
        sendp(p, iface=iface)
        self.end_time = time.time() + 1.0

    def receive(self, source, pkt):
        if source == 'remote' and UDP in pkt:
            ether = pkt[Ether]
            if ether.dst == '8e:b3:7b:40:e5:93':
                self.seen = True
        if self.seen:
            return self.RECEIVE_DONE
        return self.RECEIVE_AGAIN if time.time() < self.end_time else self.RECEIVE_DONE

    def result(self):
        return [
                ('Single unicast packet should be seen', lib.PASSED if self.seen else lib.FAILED, ''),
                ]


lib.register_check(ForwardCheck)
