#!/usr/bin/env python3
from scapy.all import *
import coloredlogs
import logging
import signal
import zmq
import sys
from zmq.utils.monitor import recv_monitor_message


def event_monitor(logger, monitor: zmq.Socket, connected) -> None:
    while monitor.poll():
        evt = recv_monitor_message(monitor)
        if evt['event'] == zmq.EVENT_HANDSHAKE_SUCCEEDED:
            logger.info('Peer handshake succeeded')
            connected.set()
        if evt['event'] == zmq.EVENT_MONITOR_STOPPED:
            break
    monitor.close()


def action(logger, x, s):
    s.send_multipart([struct.pack('f', x.time), bytes(x)])
    logger.debug(x)


def main():
    logger = logging.getLogger('reeiver')
    coloredlogs.install(level='DEBUG')
    iface = sys.argv[1]
    logger.info('linkinsane receiver starting up on interface %s, listening on port 5555', iface)
    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    socket.setsockopt(zmq.IPV6, True)
    socket.bind('tcp://*:5555')

    monitor = socket.get_monitor_socket()
    connected = threading.Event()
    mt = threading.Thread(target=event_monitor, args=(logger, monitor, connected))
    mt.start()

    conf.use_pcap = True
    t = AsyncSniffer(iface=iface, promisc=True, prn=lambda x: action(logger, x, socket), store=False, filter='not ip host 10.10.10.1')
    t.start()

    try:
        signal.pause()
    except KeyboardInterrupt:
        print('Ok, shutting down')

    socket.close()
    t.stop()
    t.join()


if __name__ == '__main__':
    main()
