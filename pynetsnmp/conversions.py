from __future__ import absolute_import, unicode_literals

from ipaddress import ip_address

import six


def asOidStr(oid):
    """Converts an OID int sequence to an oid string."""
    return b"." + b".".join(bytes(x) for x in oid)


def asOid(oidStr):
    """Converts an OID string into a tuple of integers."""
    return tuple(int(x) for x in oidStr.strip(b".").split(b"."))


def asAgent(ip, port):
    """
    Returns a Net-SNMP agent specification from the given IP and port.

    @type ip: str | bytes
    @type port: int
    @rtype: str
    """
    ip = six.ensure_text(ip)

    ip, interface = ip.split("%") if "%" in ip else (ip, None)
    address = ip_address(ip)

    if address.version == 4:
        return "udp:{0}:{1}".format(address.compressed, port)

    if address.version == 6:
        if address.is_link_local:
            if interface is None:
                raise RuntimeError(
                    "Cannot create agent specification from link local "
                    "IPv6 address without an interface"
                )
            else:
                return "udp6:[{0}%{1}]:{2}".format(
                    address.compressed, interface, port
                )
        return "udp6:[{0}]:{1}".format(address.compressed, port)
