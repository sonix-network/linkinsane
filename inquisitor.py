#!/usr/bin/env python3
from scapy.all import *
from urllib.parse import urlunparse
from zmq.utils.monitor import recv_monitor_message
import ansitable
import argparse
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
    parser = argparse.ArgumentParser(description='linkinsane inquisitor: sends the probes and judges what the receiver saw')
    parser.add_argument('iface', help='interface connected to the IXP')
    parser.add_argument('peer', help='out-of-band IP address of the receiver')
    parser.add_argument('--dst-mac', metavar='MAC',
                        help='destination MAC for the unicast checks instead of random ones, '
                             'e.g. the receiver\'s MAC when its NIC drops frames for foreign MACs')
    parser.add_argument('--grace', type=float, default=0.0, metavar='SECONDS',
                        help='extra time to wait for the receiver\'s copies after all checks have sent, '
                             'for slow receivers or a long out-of-band path (default: none)')
    parser.add_argument('--sequential', action='store_true',
                        help='run one check at a time instead of all at once, so the broadcast burst '
                             'cannot drown the other checks\' frames at a slow receiver')
    args = parser.parse_args()
    iface = args.iface
    peer = args.peer
    if args.dst_mac:
        checks.lib.dst_mac_override = args.dst_mac.lower()

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
        # One round with every check, or one round per check with --sequential.
        rounds = [[check] for check in c] if args.sequential else [c]
        for batch in rounds:
            for check in batch:
                check.run(iface)
            # Every check judges its own window from the moment it sent, but the
            # queue is only drained once the batch has run. A slow receiver or
            # out-of-band path otherwise expires the early checks unseen.
            for check in batch:
                check.end_time += args.grace

            running = batch
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
            # Wait until the receiver has been quiet for the grace period, so a
            # backlog from this batch (the broadcast burst) is not mistaken for
            # the next check's frames, and discard those late copies.
            if args.sequential:
                while True:
                    try:
                        pkts.get(timeout=max(args.grace, 1.0))
                    except queue.Empty:
                        break

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
