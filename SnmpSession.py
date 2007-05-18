__doc__ = "Backwards compatible API for SnmpSession"

import netsnmp
from ctypes import *

class SnmpSession(object):
    
    def __init__(self, ip, timeout, port):
        self.ip = ip
        self.timeout = timeout
        self.port = port
        self.community = "public"

    def get(self, oid):
        "Synchronous get implementation"
        self.session = netsnmp.Session(
            version=netsnmp.SNMP_VERSION_1,
            timeout=int(self.timeout*1e6),
            peername= '%s:%d' % (self.ip, self.port),
            community=self.community,
            community_len=len(self.community)
            )
        oid = tuple(map(int, oid.strip('.').split('.')))
        self.session.open()
        try:
            return self.session.sget([oid])
        finally:
            self.session.close()

if __name__ == '__main__':
    session = SnmpSession('127.0.0.1', 1.5, 161)
    session.community = 'public'
    print session.get('.1.3.6.1.2.1.1.5.0')
    session.community = 'xyzzy'
    print session.get('.1.3.6.1.2.1.1.5.0')
