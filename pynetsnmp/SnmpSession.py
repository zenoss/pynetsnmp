from __future__ import print_function
__doc__ = "Backwards compatible API for SnmpSession"

from pynetsnmp import netsnmp
from ctypes import *

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
        if version.find('2') >= 0:
            self._version = netsnmp.SNMP_VERSION_2c
        else:
            self._version = netsnmp.SNMP_VERSION_1

    def get(self, oid):
        "Synchronous get implementation"
        self.session = netsnmp.Session(
            version=self._version,
            timeout=int(self.timeout*1e6),
            retries=int(self.retries-1),
            peername= '%s:%d' % (self.ip, self.port),
            community=self.community,
            community_len=len(self.community),
            cmdLineArgs=self.cmdLineArgs
            )
        oid = tuple(map(int, oid.strip('.').split('.')))
        self.session.open()
        try:
            return self.session.sget([oid])
        finally:
            self.session.close()

if __name__ == '__main__':
    session = SnmpSession('127.0.0.1', timeout=1.5, port=161)
    session.community = 'public'
    print(session.get('.1.3.6.1.2.1.1.5.0'))
    session.community = 'xyzzy'
    print(session.get('.1.3.6.1.2.1.1.5.0'))
