from scapy.all import *
import time

from . import lib


class BroadcastCheck(lib.Check):

    def __init__(self, logger):
        self.seen_full_burst = False
        self.counter = None
        self.logger = logger

    def run(self, iface):
        packet = Ether(dst='ff:ff:ff:ff:ff:ff') / IP(dst='255.255.255.255') / UDP(dport=12345) / Raw(load='x' * 1000)
        sendpfast([packet]*100, iface=iface)
        self.counter = 100
        self.end_time = time.time() + 1.0

    def receive(self, source, pkt):
        if source == 'remote' and UDP in pkt:
            udp = pkt[UDP]
            if udp.dport == 12345:
                self.counter -= 1
                self.logger.debug('Missing %d packets from burst', self.counter)
                self.seen_full_burst = self.counter <= 0
        if self.seen_full_burst:
            return self.RECEIVE_DONE
        return self.RECEIVE_AGAIN if time.time() < self.end_time else self.RECEIVE_DONE

    def result(self):
        return [
                ('Broadcast burst should be supressed', lib.FAILED if self.seen_full_burst else lib.PASSED),
                ]


lib.register_check(BroadcastCheck)
