from __future__ import absolute_import


def asOidStr(oid):
    """converts an oid int sequence to an oid string"""
    return "." + ".".join([str(x) for x in oid])


def asOid(oidStr):
    """converts an OID string into a tuple of integers"""
    return tuple([int(x) for x in oidStr.strip(".").split(".")])
