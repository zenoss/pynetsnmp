import netsnmp
from ctypes import *
from CONSTANTS import *

import twistedsnmp
from twisted.internet import reactor, defer

def translateOid(oid):
    import os
    fp = os.popen('snmptranslate %s' % oid)
    result = fp.read().strip()
    fp.close()
    return result

class Trapd(netsnmp.Session):

    def callback(self, pdu):
        result = netsnmp.getResult(pdu)
        print result
        for oid, value in result:
            oid = '.'.join(map(str, oid))
            print translateOid(oid), value
        print pdu.command
        if pdu.command == SNMP_MSG_TRAP:
            pass
        elif pdu.command == SNMP_MSG_TRAP2:
            pass
        elif pdu.command == SNMP_MSG_INFORM:
            pass

def main(argv):
    import sys

    hostPort = argv[1]
    s = Trapd()
    s.awaitTraps(hostPort)
    twistedsnmp.updateReactor()
    reactor.run()
    
if __name__=='__main__':
    import sys
    import logging
    logging.basicConfig()
    main(sys.argv)

         
