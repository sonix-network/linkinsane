

_all_checks_ = []

# Destination MAC used by the unicast checks. The defaults are random
# unicast addresses, which only work when the receiving NIC gets frames for
# foreign MACs; pass `inquisitor.py --dst-mac <receiver MAC>` otherwise
# (e.g. for VMs behind a hypervisor that filters on the guest MAC).
DEFAULT_DST_MAC = {
    'forward': '8e:b3:7b:40:e5:93',
    'icmp4': 'a2:47:28:92:1c:c5',
    'manymac': 'ee:84:bc:b2:d3:94',
    'ethertype': '9e:2c:a4:a8:e6:06',
}
dst_mac_override = None


def dst_mac(check):
    '''Destination MAC for a unicast check, honouring --dst-mac.'''
    return dst_mac_override or DEFAULT_DST_MAC[check]


PASSED = 1
WARNING = 2
FAILED = 3

STATUS_MAP = {
        PASSED: "PASSED",
        WARNING: "WARNING",
        FAILED: "FAILED",
}

COLOR_MAP = {
        PASSED: "green",
        WARNING: "yellow",
        FAILED: "orange",
}


class Check:
    '''Base class for all checks implemented'''
    RECEIVE_DONE = 1
    RECEIVE_AGAIN = 2
    pass


def register_check(cls):
    _all_checks_.append(cls)


def checks():
    return _all_checks_
