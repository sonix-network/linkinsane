

_all_checks_ = []


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
