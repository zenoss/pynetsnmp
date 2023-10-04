import argparse
import logging
from pynetsnmp import netsnmp
from pynetsnmp import twistedsnmp

from twisted.internet import reactor


class Getter(netsnmp.Session):
    def callback(self, pdu):
        results = netsnmp.getResult(pdu, self._log)
        for oid, value in results:
            print "OID:", oid
            print "Value:", repr(value)
        reactor.stop()

    def timeout(self, reqid):
        print "Timeout"
        reactor.stop()
        raise RuntimeError("Timeout occurred")


def main():
    print "=================== \nSNMP Get Test"

    parser = argparse.ArgumentParser(description="SNMP Getter")
    parser.add_argument("--host", default="localhost", help="SNMP peername (default: localhost)")
    parser.add_argument("--community", default="public", help="SNMP community string (default: public)")
    parser.add_argument("--oids", nargs="*", default=["1.3.6.1.2.1.1.1.0"], help="OIDs to retrieve (default: 1.3.6.1.2.1.1.1.0)")

    args = parser.parse_args()

    host = args.host
    community = args.community
    oids = args.oids

    g = Getter(
        version=netsnmp.SNMP_VERSION_1,
        peername=host,
        community=community
    )

    oids = [tuple(map(int, oid.strip(".").split("."))) for oid in oids]
    g.open()
    g.get(oids)
    twistedsnmp.updateReactor()
    reactor.run()

    print "==================="


if __name__ == "__main__":
    logging.basicConfig()
    main()
