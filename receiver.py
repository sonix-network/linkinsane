#!/usr/bin/env python3
from scapy.all import *
import coloredlogs
import logging
import signal
import zmq
import sys


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
    socket.bind('tcp://*:5555')

    conf.use_pcap = True
    t = AsyncSniffer(iface=iface, promisc=True, prn=lambda x: action(logger, x, socket), store=False)
    t.start()

    try:
        signal.pause()
    except KeyboardInterrupt:
        print('Ok, shutting down')

    t.stop()
    t.join()


if __name__ == '__main__':
    main()
