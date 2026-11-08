"""Receive copies until checks finish or their individual windows expire."""
import queue
import time


def receive_checks(batch, packets, receive_again, logger, now=time.time):
    running = list(batch)
    while running:
        current = now()
        running = [check for check in running if check.end_time > current]
        if not running:
            break
        timeout = min(1.0, min(check.end_time for check in running) - current)
        try:
            source, packet = packets.get(timeout=timeout)
        except queue.Empty:
            # A quiet queue does not imply that the checks' windows have ended.
            continue
        logger.debug('Packet from %s: %s', source, packet)
        current = now()
        running = [check for check in running
                   if check.end_time > current
                   and check.receive(source, packet) == receive_again]
