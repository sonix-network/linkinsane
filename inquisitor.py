#!/usr/bin/env python3
from scapy.all import *
from urllib.parse import urlunparse
import coloredlogs
import logging
import zmq
import sys


def construct_tcp_url(ip: str, port: int = 5555) -> str:
    if ':' in ip and not ip.startswith('['):
        ip = f'[{ip}]'
    return urlunparse(('tcp', f'{ip}:{port}', '', '', '', ''))


def action(logger, x):
    logger.debug(x)


def main():
    logger = logging.getLogger('inquisitor')
    coloredlogs.install(level='DEBUG')
    iface = sys.argv[1]
    peer = sys.argv[2]

    logger.info('linkinsane inquisitor starting up on interface %s with peer %s', iface, peer)

    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.connect(construct_tcp_url(peer, '5555'))
    socket.setsockopt(zmq.SUBSCRIBE, b'')

    conf.use_pcap = True
    t = AsyncSniffer(iface=iface, promisc=True, prn=lambda x: action(logger, x), store=False)
    t.start()

    try:
        while True:
            time, packet = socket.recv_multipart()
            pkt = Ether(packet)
            pkt.time = time
            logger.debug('receiver got: %s', pkt)
    except KeyboardInterrupt:
        print('Ok, shutting down')

    t.stop()
    t.join()


if __name__ == '__main__':
    main()
