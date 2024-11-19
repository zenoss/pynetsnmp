from __future__ import absolute_import

from .CONSTANTS import SNMP_VERSION_1, SNMP_VERSION_2c, SNMP_VERSION_3
from .usm import AUTH_NOAUTH, auth_protocols, PRIV_NOPRIV, priv_protocols

__all__ = ("Community", "UsmUser", "Authentication", "Privacy")


class Community(object):
    """
    Provides the community based security model for SNMP v1/V2c.
    """

    def __init__(self, name, version=SNMP_VERSION_2c):
        mapped = _version_map.get(version)
        if mapped is None or mapped == "3":
            raise ValueError(
                "SNMP version '{}' not supported for Community".format(version)
            )
        self.name = name
        self.version = mapped

    def getArguments(self):
        community = ("-c", str(self.name)) if self.name else ()
        return ("-v", self.version) + community


class UsmUser(object):
    """
    Provides User-based Security Model configuration for SNMP v3.
    """

    def __init__(self, name, auth=None, priv=None, engine=None, context=None):
        self.name = name
        if auth is None:
            auth = Authentication.new_noauth()
        if not isinstance(auth, Authentication):
            raise ValueError("invalid authentication object")
        self.auth = auth
        if priv is None:
            priv = Privacy.new_nopriv()
        if not isinstance(priv, Privacy):
            raise ValueError("invalid privacy object")
        self.priv = priv
        self.engine = engine
        self.context = context
        self.version = _version_map.get(SNMP_VERSION_3)

    def getArguments(self):
        auth_args = (
            ("-a", self.auth.protocol.name, "-A", self.auth.passphrase)
            if self.auth
            else ()
        )
        if auth_args:
            # The privacy arguments are only given if the authentication
            # arguments are also provided.
            priv_args = (
                ("-x", self.priv.protocol.name, "-X", self.priv.passphrase)
                if self.priv
                else ()
            )
        else:
            priv_args = ()
        seclevel_arg = ("-l", _sec_level[(bool(self.auth), bool(self.priv))])

        return (
            ("-v", self.version)
            + (("-u", self.name) if self.name else ())
            + seclevel_arg
            + auth_args
            + priv_args
            + (("-e", self.engine) if self.engine else ())
            + (("-n", self.context) if self.context else ())
        )

    def __eq__(self, other):
        return (
            self.name == other.name
            and self.auth == other.auth
            and self.priv == other.priv
            and self.engine == other.engine
            and self.context == other.context
        )

    def __str__(self):
        info = ", ".join(
            "{0}={1}".format(k, v)
            for k, v in (
                ("name", self.name),
                ("auth", self.auth),
                ("priv", self.priv),
                ("engine", self.engine),
                ("context", self.context),
            )
            if v
        )
        return "{0.__class__.__name__}(version={0.version}{1}{2})".format(
            self, ", " if info else "", info
        )


_sec_level = {
    (True, True): "authPriv",
    (True, False): "authNoPriv",
    (False, False): "noAuthNoPriv",
}
_version_map = {
    "1": "1",
    "2c": "2c",
    "3": "3",
    SNMP_VERSION_1: "1",
    SNMP_VERSION_2c: "2c",
    SNMP_VERSION_3: "3",
    "v1": "1",
    "v2c": "2c",
    "v3": "3",
}


class Authentication(object):
    """
    Provides the authentication data for UsmUser objects.
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

    def __nonzero__(self):
        return self.protocol is not AUTH_NOAUTH

    def __repr__(self):
        return (
            "<{0.__module__}.{0.__class__.__name__} protocol={0.protocol}>"
        ).format(self)

    def __str__(self):
        return "{0.__class__.__name__}(protocol={0.protocol})".format(self)


class Privacy(object):
    """
    Provides the privacy data for UsmUser objects.
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
