from __future__ import absolute_import

from ..CONSTANTS import SNMP_VERSION_3 as _V3

from .auth import Authentication
from .common import version_map
from .priv import Privacy


_sec_level = {
    (True, True): "authPriv",
    (True, False): "authNoPriv",
    (False, False): "noAuthNoPriv",
}


class User(object):
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
        self.version = version_map.get(_V3)

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
