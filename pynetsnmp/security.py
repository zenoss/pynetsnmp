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
            ("-a", str(self.auth.protocol), "-A", self.auth.passphrase)
            if self.auth
            else ()
        )
        if auth:
            # The privacy arguments are only given if the authentication
            # arguments are also provided.
            priv = (
                ("-x", str(self.priv.protocol), "-X", self.priv.passphrase)
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

    def __init__(self, protocol, passphrase):
        if protocol is None:
            raise ValueError(
                "Invalid Authentication protocol '{}'".format(protocol)
            )
        self.protocol = auth_protocols[protocol]
        if not passphrase:
            raise ValueError(
                "authentication protocol requires an "
                "authentication passphrase"
            )
        self.passphrase = passphrase


class Privacy(object):
    """
    Provides the privacy data for UsmUser objects.
    """

    def __init__(self, protocol, passphrase):
        if protocol is None:
            raise ValueError("Invalid Privacy protocol '{}'".format(protocol))
        self.protocol = priv_protocols[protocol]
        if not passphrase:
            raise ValueError("privacy protocol requires a privacy passphrase")
        self.passphrase = passphrase
