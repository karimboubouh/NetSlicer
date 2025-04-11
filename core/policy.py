from config import HANDLE


class Policy:
    def __init__(self, classid, **kwargs):
        self.classid = f"{HANDLE}{classid}"
        # Guaranteed bandwidth
        self.rate = kwargs.get('rate', "10mbit")
        # Maximum bandwidth when spare is available (borrow unused bandwidth up to ceil.)
        self.ceil = kwargs.get('ceil', "20mbit")
        # Maximum burst size (in bytes) allowed at ceil rate
        self.burst = kwargs.get('burst', "15k")
        # Priority (lower = higher priority)
        self.prio = kwargs.get('prio', 0)
        # Maximum packet size for this class
        self.mtu = kwargs.get('prio', 1500)

    def __str__(self):
        attributes = ", ".join(f"{key}={value!r}" for key, value in self.__dict__.items())
        return f"Policy({attributes})"
