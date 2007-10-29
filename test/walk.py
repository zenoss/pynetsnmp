import netsnmp
import twistedsnmp
import sys

from twisted.internet import reactor, defer
from twisted.python import failure

class Walker(netsnmp.Session):

    lastOid = None

    def stop(self, why = None):
        host = self.sess.contents.peername
        print "stopping: %s %s" % (host, why or '')
        if not why:
            self.defer.callback( (host, self.results) )
        else:
            self.defer.errback(Exception('%s on %s' % (why, host)))
        import gc
        gc.collect()

    def callback(self, pdu):
        results = netsnmp.getResult(pdu)
        oid, value = results[0]
        if oid <= self.lastOid:
            self.stop()
        else:
            self.results.append( (oid, value) )
            self.lastOid = oid
            self.walk(oid)

    def timeout(self, reqid):
        self.stop("Timeout")

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
            print host, len(values)
        else:
            print values
    if reactor.running:
        reactor.stop()

def main():
    import getopt
    # from snmp_parse_args.c
    opts = 'Y:VhHm:M:O:I:P:D:dv:r:t:c:Z:e:E:n:u:l:x:X:a:A:p:T:-:3:s:S:L:'
    args, hosts = getopt.getopt(sys.argv[1:], opts)
    if not hosts:
        hosts = ['localhost']
    d = defer.DeferredList(
        [Walker(peername=host, cmdLineArgs=args).start() for host in hosts],
        consumeErrors=True)
    d.addBoth(stop)
    twistedsnmp.updateReactor()
    reactor.run()

if __name__ == '__main__':
    import logging
    logging.basicConfig()
    main()
