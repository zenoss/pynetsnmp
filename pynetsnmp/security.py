from __future__ import absolute_import

from .CONSTANTS import SNMP_VERSION_1, SNMP_VERSION_2c, SNMP_VERSION_3
from .usm import auth_protocols, priv_protocols


class Community(object):
    """
    Provides the community based security model for SNMP v1/V2c.
    """

    def __init__(self, name, version=SNMP_VERSION_2c):
        version = _version_map.get(version)
        if version is None:
            raise ValueError("Unsupported SNMP version '{}'".format(version))
        self.name = name
        self.version = version

    def getArguments(self):
        community = ("-c", str(self.name)) if self.name else ()
        return ("-v", self.version) + community


class UsmUser(object):
    """
    Provides User-based Security Model configuration for SNMP v3.
    """

    def __init__(self, name, auth=None, priv=None, engine=None, context=None):
        self.name = name
        if not isinstance(auth, (type(None), Authentication)):
            raise ValueError("invalid authentication protocol")
        self.auth = auth
        if not isinstance(priv, (type(None), Privacy)):
            raise ValueError("invalid privacy protocol")
        self.priv = priv
        self.engine = engine
        self.context = context
        self.version = _version_map.get(SNMP_VERSION_3)

    def getArguments(self):
        auth = (
            ("-a", self.auth.protocol.name, "-A", self.auth.passphrase)
            if self.auth
            else ()
        )
        if auth:
            # The privacy arguments are only given if the authentication
            # arguments are also provided.
            priv = (
                ("-x", self.priv.protocol.name, "-X", self.priv.passphrase)
                if self.priv
                else ()
            )
        else:
            priv = ()
        seclevel = (
            "-l",
            _sec_level.get((bool(auth), bool(priv)), "noAuthNoPriv"),
        )

        return (
            ("-v", self.version)
            + (("-u", self.name) if self.name else ())
            + seclevel
            + auth
            + priv
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


_sec_level = {(True, True): "authPriv", (True, False): "authNoPriv"}
_version_map = {
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

    def __init__(self, protocol, passphrase):
        if protocol is None:
            raise ValueError(
                "Invalid Authentication protocol '{}'".format(protocol)
            )
        self.protocol = auth_protocols[protocol]
        if not passphrase:
            raise ValueError("Authentication protocol requires a passphrase")
        self.passphrase = passphrase

    def __eq__(self, other):
        if not isinstance(other, Authentication):
            return NotImplemented
        return (
            self.protocol == other.protocol
            and self.passphrase == other.passphrase
        )

    def __str__(self):
        return "{0.__class__.__name__}(protocol={0.protocol})".format(self)


class Privacy(object):
    """
    Provides the privacy data for UsmUser objects.
    """

    __slots__ = ("protocol", "passphrase")

    def __init__(self, protocol, passphrase):
        if protocol is None:
            raise ValueError("Invalid Privacy protocol '{}'".format(protocol))
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

    def __str__(self):
        return "{0.__class__.__name__}(protocol={0.protocol})".format(self)
