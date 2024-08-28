#!/usr/bin/env python3
from scapy.all import *
from urllib.parse import urlunparse
import coloredlogs
import logging
import zmq
import sys
from zmq.utils.monitor import recv_monitor_message


def construct_tcp_url(ip: str, port: int = 5555) -> str:
    if ':' in ip and not ip.startswith('['):
        ip = f'[{ip}]'
    return urlunparse(('tcp', f'{ip}:{port}', '', '', '', ''))


def event_monitor(logger, monitor: zmq.Socket, connected) -> None:
    while monitor.poll():
        evt = recv_monitor_message(monitor)
        if evt['event'] == zmq.EVENT_HANDSHAKE_SUCCEEDED:
            logger.info('Peer handshake succeeded')
            connected.set()
        if evt['event'] == zmq.EVENT_MONITOR_STOPPED:
            break
    monitor.close()


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
    socket.setsockopt(zmq.IPV6, True)
    socket.connect(construct_tcp_url(peer, '5555'))
    socket.setsockopt(zmq.SUBSCRIBE, b'')

    monitor = socket.get_monitor_socket()
    connected = threading.Event()
    mt = threading.Thread(target=event_monitor, args=(logger, monitor, connected))
    mt.start()

    logger.info('Waiting for connection to be established to peer ...')
    try:
        connected.wait()
    except KeyboardInterrupt:
        logger.warning('Interrupted, shutting down')
        return

    conf.use_pcap = True
    t = AsyncSniffer(iface=iface, promisc=True, prn=lambda x: action(logger, x), store=False, filter='not ip host 10.10.10.1')
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
