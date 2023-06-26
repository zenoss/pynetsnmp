import logging
from pynetsnmp import netsnmp
from pynetsnmp import twistedsnmp
import sys

from twisted.internet import reactor


class Getter(netsnmp.Session):
    def callback(self, pdu):
        results = netsnmp.getResult(pdu, self._log)
        for oid, value in results:
            print oid, repr(value)
        reactor.stop()

    def timeout(self, reqid):
        print "Timeout"
        reactor.stop()


def main():
    name = "localhost"
    community = "public"
    if len(sys.argv) >= 2:
        name = sys.argv[1]
    oids = sys.argv[2:]
    g = Getter(
        version=netsnmp.SNMP_VERSION_1,
        peername=name,
        community=community,
        community_len=len(community),
    )
    oids = [tuple(map(int, oid.strip(".").split("."))) for oid in oids]
    g.open()
    g.get(oids)
    twistedsnmp.updateReactor()
    reactor.run()


if __name__ == "__main__":
    logging.basicConfig()
    main()
