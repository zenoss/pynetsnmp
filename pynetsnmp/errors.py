from __future__ import absolute_import

from . import oids


class SnmpTimeoutError(Exception):
    pass


class ArgumentParseError(Exception):
    pass


class TransportError(Exception):
    pass


class SnmpNameError(Exception):
    def __init__(self, oid):
        Exception.__init__(self, "Bad Name", oid)


class SnmpError(Exception):
    def __init__(self, message, *args, **kwargs):
        self.message = message

    def __str__(self):
        return self.message

    def __repr__(self):
        return self.message


class SnmpUsmError(SnmpError):
    pass


class SnmpUsmStatsError(SnmpUsmError):
    def __init__(self, mesg, oid):
        super(SnmpUsmStatsError, self).__init__(mesg)
        self.oid = oid


_stats_oid_error_map = {
    oids.WrongDigest: SnmpUsmStatsError(
        "unexpected authentication digest", oids.WrongDigest
    ),
    oids.UnknownUserName: SnmpUsmStatsError(
        "unknown user", oids.UnknownUserName
    ),
    oids.UnknownSecurityLevel: SnmpUsmStatsError(
        "unknown or unavailable security level", oids.UnknownSecurityLevel
    ),
    oids.DecryptionError: SnmpUsmStatsError(
        "privacy decryption error", oids.DecryptionError
    ),
}


def get_stats_error(oid):
    return _stats_oid_error_map.get(oid)
