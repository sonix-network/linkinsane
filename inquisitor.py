#!/usr/bin/env python3
from scapy.all import *
from urllib.parse import urlunparse
from zmq.utils.monitor import recv_monitor_message
import ansitable
import coloredlogs
import logging
import queue
import sys
import time
import zmq

import checks


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


def action(logger, x, q):
    q.put(('local', x))


def receiver(logger, socket, q, shutdown):
    while not shutdown.is_set():
        try:
            ts, packet = socket.recv_multipart(zmq.NOBLOCK)
            pkt = Ether(packet)
            pkt.time = ts
            q.put(('remote', pkt))
        except zmq.error.Again:
            time.sleep(0.1)
    logger.debug('Remote receiver thread terminated')


def main():
    logger = logging.getLogger('inquisitor')
    coloredlogs.install(level='INFO')
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
    shutdown = threading.Event()
    mt = threading.Thread(target=event_monitor, args=(logger, monitor, connected))
    mt.start()

    pkts = queue.Queue()

    logger.info('Waiting for connection to be established to peer ...')
    try:
        connected.wait()
    except KeyboardInterrupt:
        logger.warning('Interrupted, shutting down')
        return

    conf.use_pcap = True
    conf.verb = 0
    t = AsyncSniffer(iface=iface, promisc=True, prn=lambda x: action(logger, x, pkts), store=False, filter='not ip host 10.10.10.1')
    t.start()

    lt = threading.Thread(target=receiver, args=(logger, socket, pkts, shutdown))
    lt.start()

    try:
        c = [cls(logger) for cls in checks.checks()]
        for check in c:
            check.run(iface)

        running = c
        while running:
            try:
                source, pkt = pkts.get(timeout=1.0)
            except queue.Empty:
                break
            logger.debug('Packet from %s: %s', source, pkt)
            next_running = []
            for check in running:
                if check.receive(source, pkt) == checks.Check.RECEIVE_AGAIN:
                    logger.debug('%s still running', check)
                    next_running.append(check)
            running = next_running

        table = ansitable.ANSITable('Check', 'Status', 'Details', border='thick')
        for check in c:
            for (desc, result, details) in check.result():
                status = checks.STATUS_MAP[result]
                color = checks.COLOR_MAP[result]
                table.row(desc, ansitable.Cell(status), details)
        print()
        table.print()

    except KeyboardInterrupt:
        print('Ok, shutting down')

    shutdown.set()
    lt.join()
    t.stop()
    t.join()


if __name__ == '__main__':
    main()
