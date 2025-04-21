from __future__ import absolute_import

from .protocols import AUTH_NOAUTH, auth_protocols


class Authentication(object):
    """
    Provides the authentication data for User objects.
    """

    __slots__ = ("protocol", "passphrase")

    @classmethod
    def new_noauth(cls):
        return cls(None, None)

    def __init__(self, protocol, passphrase):
        if (
            not protocol
            or protocol is AUTH_NOAUTH
            or protocol == "AUTH_NOAUTH"
        ):
            self.protocol = AUTH_NOAUTH
            self.passphrase = None
        else:
            self.protocol = auth_protocols[protocol]
            if not passphrase:
                raise ValueError(
                    "Authentication protocol requires a passphrase"
                )
            self.passphrase = passphrase

    def __eq__(self, other):
        if not isinstance(other, Authentication):
            return NotImplemented
        return (
            self.protocol == other.protocol
            and self.passphrase == other.passphrase
        )

    def __bool__(self):
        return self.protocol is not AUTH_NOAUTH

    __nonzero__ = __bool__  # Python 2 compatibility

    def __repr__(self):
        return (
            "<{0.__module__}.{0.__class__.__name__} protocol={0.protocol}>"
        ).format(self)

    def __str__(self):
        return "{0.__class__.__name__}(protocol={0.protocol})".format(self)
