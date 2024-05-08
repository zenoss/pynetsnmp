import argparse
import logging
from pynetsnmp import netsnmp
from pynetsnmp import twistedsnmp

from twisted.internet import reactor


class Table(netsnmp.Session):

    root = None
    max = None

    def getTable(self, root, max=40):
        self.max = max
        self.root = root
        self.getbulk(0, self.max, [root])

    def stop(self, why):
        print "stopping: %s" % why
        if reactor.running:
            reactor.stop()

    def callback(self, pdu):
        results = netsnmp.getResult(pdu, self._log)
        for oid, value in results:
            if oid[: len(self.root)] != self.root:
                self.stop("table end")
                return
            print ".".join(map(str, oid)), ":", repr(value)

        if not results:
            self.stop("empty result")
        else:
            self.getbulk(0, self.max, [results[-1][0]])

    def timeout(self, reqid):
        self.stop("Timeout")
        raise RuntimeError("Timeout occurred")


def main():
    print "=================== \nSNMP Get Bulk Test"
    parser = argparse.ArgumentParser(description="Get bulk")
    parser.add_argument("--host", default="localhost", help="SNMP peername (default: localhost)")
    parser.add_argument("--community", default="public", help="SNMP community string (default: public)")
    args = parser.parse_args()

    host = args.host
    community = args.community
    oid = (1, 3, 6, 1, 2, 1, 25, 4, 2, 1, 2)
    t = Table(
        version=netsnmp.SNMP_VERSION_2c,
        peername=host,
        community=community,
        community_len=len(community),
    )

    t.open()
    t.getTable(oid)
    twistedsnmp.updateReactor()
    reactor.run()
    print "==================="


if __name__ == "__main__":
    logging.basicConfig()
    main()
