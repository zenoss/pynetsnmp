from twistedsnmp import AgentProxy
from twisted.python import failure
from twisted.internet import reactor

def printResults(results):
    if reactor.running:
        reactor.stop()
    if isinstance(results, failure.Failure):
        raise results.value
    import pprint
    pprint.pprint(results)
    return results

def close(results, proxy):
    proxy.close()
    reactor.callLater(0.1, reactor.stop)

def main():
    oids = [('1.3.6.1.2.1.2.2.1.7.5', 'i', '2')]
    proxy = AgentProxy(ip='127.0.0.1',
                       port=161,
                       community='priv',
                       snmpVersion='v2c')
    proxy.open()
    d = proxy.set(oids, 1.0, 3)
    d.addBoth(printResults)
    d.addCallback(close, proxy)
    reactor.run()
    print "end reactor"

if __name__ == '__main__':
    main()