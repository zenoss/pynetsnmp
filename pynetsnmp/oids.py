from __future__ import absolute_import

from .conversions import asOidStr


class OID(object):
    __slots__ = ("oid",)

    def __init__(self, oid):
        super(OID, self).__setattr__("oid", oid)

    def __setattr__(self, key, value):
        if key in OID.__slots__:
            raise AttributeError(
                "can't set attribute '{}' on 'OID' object".format(key)
            )
        super(OID, self).__setattr__(key, value)

    def __eq__(this, that):
        if isinstance(that, (tuple, list)):
            return this.oid == that
        if isinstance(that, OID):
            return this.oid == that.oid
        return NotImplemented

    def __ne__(this, that):
        if isinstance(that, (tuple, list)):
            return this.oid != that
        if isinstance(that, OID):
            return this.oid != that.oid
        return NotImplemented

    def __hash__(self):
        return hash(self.oid)

    def __repr__(self):
        return "<{0.__module__}.{0.__class__.__name__} {1}>".format(
            self, asOidStr(self.oid)
        )

    def __str__(self):
        return asOidStr(self.oid)


_base_status_oid = (1, 3, 6, 1, 6, 3, 15, 1, 1)


class _UnknownSecurityLevel(OID):
    __slots__ = ()


UnknownSecurityLevel = _UnknownSecurityLevel(_base_status_oid + (1, 0))


class _NotInTimeWindow(OID):
    __slots__ = ()


NotInTimeWindow = _NotInTimeWindow(_base_status_oid + (2, 0))


class _UnknownUserName(OID):
    __slots__ = ()


UnknownUserName = _UnknownUserName(_base_status_oid + (3, 0))


class _UnknownEngineId(OID):
    __slots__ = ()


UnknownEngineId = _UnknownEngineId(_base_status_oid + (4, 0))


class _WrongDigest(OID):
    __slots__ = ()


WrongDigest = _WrongDigest(_base_status_oid + (5, 0))


class _DecryptionError(OID):
    __slots__ = ()


DecryptionError = _DecryptionError(_base_status_oid + (6, 0))


class _SysDescr(OID):
    __slots__ = ()


SysDescr = _SysDescr((1, 3, 6, 1, 2, 1, 1, 1, 0))
