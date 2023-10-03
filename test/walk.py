import logging
from pynetsnmp import netsnmp
from pynetsnmp import twistedsnmp
import sys

from twisted.internet import reactor, defer


class Walker(netsnmp.Session):

    lastOid = None

    def stop(self, why=None):
        host = self.sess.contents.peername
        print "stopping: %s %s" % (host, why or "")
        if not why:
            self.defer.callback((host, self.results))
        else:
            self.defer.errback(Exception("%s on %s" % (why, host)))
        import gc

        gc.collect()

    def callback(self, pdu):
        results = netsnmp.getResult(pdu, self._log)
        oid, value = results[0]
        if oid <= self.lastOid:
            self.stop()
        else:
            self.results.append((oid, value))
            self.lastOid = oid
            self.walk(oid)

    def timeout(self, reqid):
        self.stop("Timeout")
        raise RuntimeError("Timeout occurred")

    def start(self):
        self.open()
        self.defer = defer.Deferred()
        self.results = []
        self.walk((1,))
        return self.defer


def stop(results):
    for success, values in results:
        if success:
            host, values = values
            print "Host:", host

            print "Results length", len(values)
        else:
            print "Result", values
    if reactor.running:
        reactor.stop()


def main():
    print "=================== \nSNMP Walk Test"

    import getopt

    # from snmp_parse_args.c
    opts = "Y:VhHm:M:O:I:P:D:dv:r:t:c:Z:e:E:n:u:l:x:X:a:A:p:T:-:3:s:S:L:"
    args, hosts = getopt.getopt(sys.argv[1:], opts)

    if not hosts:
        hosts = ["localhost"]
    if not args:
        args = [('-v', '1'), ('-c', 'public')]
    d = defer.DeferredList(
        [Walker(peername=host, cmdLineArgs=args).start() for host in hosts],
        consumeErrors=True,
    )
    d.addBoth(stop)
    twistedsnmp.updateReactor()
    reactor.run()
    print "==================="


if __name__ == "__main__":
    logging.basicConfig()
    main()
