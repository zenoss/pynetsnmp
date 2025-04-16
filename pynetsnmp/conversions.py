from __future__ import absolute_import

from ipaddress import ip_address


def asOidStr(oid):
    """converts an oid int sequence to an oid string"""
    return "." + ".".join(str(x) for x in oid)


def asOid(oidStr):
    """converts an OID string into a tuple of integers"""
    return tuple(int(x) for x in oidStr.strip(".").split("."))


def asAgent(ip, port):
    """take a google ipaddr object and port number and produce a net-snmp
    agent specification (see the snmpcmd manpage)"""
    ip, interface = ip.split("%") if "%" in ip else (ip, None)
    address = ip_address(ip)

    if address.version == 4:
        return "udp:{}:{}".format(address.compressed, port)

    if address.version == 6:
        if address.is_link_local:
            if interface is None:
                raise RuntimeError(
                    "Cannot create agent specification from link local "
                    "IPv6 address without an interface"
                )
            else:
                return "udp6:[{}%{}]:{}".format(
                    address.compressed, interface, port
                )
        return "udp6:[{}]:{}".format(address.compressed, port)
