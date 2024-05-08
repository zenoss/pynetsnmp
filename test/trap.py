import argparse
import logging
import os
import sys

from pynetsnmp import CONSTANTS as C
from pynetsnmp import netsnmp
from pynetsnmp import twistedsnmp

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
    print "=================== \nSNMP Trap Receiver Test"

    parser = argparse.ArgumentParser(description="SNMP Trap Receiver")
    parser.add_argument("--host", default="localhost", help="Host to listen on")
    parser.add_argument("--port", type=int, default=162, help="Port to listen on")
    args = parser.parse_args()

    hostPort = ":".join([args.host, str(args.port)])

    s = Trapd()
    s.awaitTraps(hostPort)
    twistedsnmp.updateReactor()
    reactor.run()


if __name__ == "__main__":
    logging.basicConfig()
    main(sys.argv)
