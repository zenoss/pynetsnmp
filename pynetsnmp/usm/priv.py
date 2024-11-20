from __future__ import absolute_import

from .protocols import PRIV_NOPRIV, priv_protocols


class Privacy(object):
    """
    Provides the privacy data for User objects.
    """

    __slots__ = ("protocol", "passphrase")

    @classmethod
    def new_nopriv(cls):
        return cls(None, None)

    def __init__(self, protocol, passphrase):
        if (
            not protocol
            or protocol is PRIV_NOPRIV
            or protocol == "PRIV_NOPRIV"
        ):
            self.protocol = PRIV_NOPRIV
            self.passphrase = None
        else:
            self.protocol = priv_protocols[protocol]
            if not passphrase:
                raise ValueError("Privacy protocol requires a passphrase")
            self.passphrase = passphrase

    def __eq__(self, other):
        if not isinstance(other, Privacy):
            return NotImplemented
        return (
            self.protocol == other.protocol
            and self.passphrase == other.passphrase
        )

    def __nonzero__(self):
        return self.protocol is not PRIV_NOPRIV

    def __repr__(self):
        return (
            "<{0.__module__}.{0.__class__.__name__} protocol={0.protocol}>"
        ).format(self)

    def __str__(self):
        return "{0.__class__.__name__}(protocol={0.protocol})".format(self)
