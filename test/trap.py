import logging
import os
import sys

import CONSTANTS as C
import netsnmp
import twistedsnmp

from twisted.internet import reactor


def translateOid(oid):
    fp = os.popen("snmptranslate %s" % oid)
    result = fp.read().strip()
    fp.close()
    return result


class Trapd(netsnmp.Session):
    def callback(self, pdu):
        result = netsnmp.getResult(pdu, self._log)
        print result
        for oid, value in result:
            oid = ".".join(map(str, oid))
            print translateOid(oid), value
        print pdu.command
        if pdu.command == C.SNMP_MSG_TRAP:
            pass
        elif pdu.command == C.SNMP_MSG_TRAP2:
            pass
        elif pdu.command == C.SNMP_MSG_INFORM:
            pass


def main(argv):
    hostPort = argv[1]
    s = Trapd()
    s.awaitTraps(hostPort)
    twistedsnmp.updateReactor()
    reactor.run()


if __name__ == "__main__":
    logging.basicConfig()
    main(sys.argv)
