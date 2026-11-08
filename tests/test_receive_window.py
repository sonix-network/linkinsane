import logging
import queue
import unittest

from receive_window import receive_checks


class Clock:
    time = 0.0

    def now(self):
        return self.time


class PacketQueue:
    def __init__(self, clock, arrivals=()):
        self.clock = clock
        self.arrivals = list(arrivals)
        self.calls = 0

    def get(self, timeout):
        self.calls += 1
        deadline = self.clock.time + timeout
        if self.arrivals and self.arrivals[0] <= deadline:
            self.clock.time = self.arrivals.pop(0)
            return 'remote', 'probe'
        self.clock.time = deadline
        raise queue.Empty


class Check:
    def __init__(self, deadline, complete=True):
        self.end_time = deadline
        self.complete = complete
        self.seen = []

    def receive(self, source, packet):
        self.seen.append((source, packet))
        return 'done' if self.complete else 'again'


class ReceiveWindowTest(unittest.TestCase):
    def run_checks(self, checks, arrivals=()):
        clock = Clock()
        packets = PacketQueue(clock, arrivals)
        receive_checks(checks, packets, 'again', logging.getLogger(__name__), now=clock.now)
        return clock, packets

    def test_delayed_copy_after_quiet_second_within_grace(self):
        check = Check(3.5)
        clock, packets = self.run_checks([check], [2.0])
        self.assertEqual(check.seen, [('remote', 'probe')])
        self.assertEqual(clock.time, 2.0)
        self.assertEqual(packets.calls, 2)

    def test_no_copy_expires_at_deadline(self):
        check = Check(3.5)
        clock, packets = self.run_checks([check])
        self.assertEqual(clock.time, 3.5)
        self.assertEqual(check.seen, [])
        self.assertEqual(packets.calls, 4)

    def test_early_completion_does_not_wait_for_deadline(self):
        check = Check(3.5)
        clock, packets = self.run_checks([check], [0.2])
        self.assertEqual(clock.time, 0.2)
        self.assertEqual(len(check.seen), 1)
        self.assertEqual(packets.calls, 1)

    def test_individual_deadlines_and_unrelated_copies(self):
        early, late = Check(0.5), Check(3.5, complete=False)
        clock, _ = self.run_checks([early, late], [2.0])
        self.assertEqual(early.seen, [])
        self.assertEqual(len(late.seen), 1)
        self.assertEqual(clock.time, 3.5)

    def test_copy_at_deadline_is_outside_window(self):
        check = Check(0.5)
        clock, _ = self.run_checks([check], [0.5])
        self.assertEqual(check.seen, [])
        self.assertEqual(clock.time, 0.5)


if __name__ == '__main__':
    unittest.main()
