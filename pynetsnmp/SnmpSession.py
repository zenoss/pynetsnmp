from __future__ import absolute_import

"""Backwards compatible API for SnmpSession"""

from . import netsnmp


class SnmpSession(object):
    def __init__(self, ip, port=161, timeout=2, retries=2, cmdLineArgs=()):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.community = "public"
        self._version = netsnmp.SNMP_VERSION_1
        self.cmdLineArgs = cmdLineArgs

    def setVersion(self, version):
        if version.find("2") >= 0:
            self._version = netsnmp.SNMP_VERSION_2c
        else:
            self._version = netsnmp.SNMP_VERSION_1

    def get(self, oid):
        "Synchronous get implementation"
        self.session = netsnmp.Session(
            version=self._version,
            timeout=self.timeout,
            retries=int(self.retries - 1),
            peername="%s:%d" % (self.ip, self.port),
            community=self.community,
            community_len=len(self.community),
            cmdLineArgs=self.cmdLineArgs,
        )
        oid = tuple(map(int, oid.strip(".").split(".")))
        self.session.open()
        try:
            return self.session.sget([oid])
        finally:
            self.session.close()
