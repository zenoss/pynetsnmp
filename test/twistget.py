from pynetsnmp.twistedsnmp import AgentProxy
from twisted.python import failure
from twisted.internet import reactor


class Bogus(object):
    pass


def print_results(results):
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
    oids = ['.1.3.6.1.2.1.1.1.0',
            '.1.3.6.1.2.1.1.2.0',
            '.1.3.6.1.2.1.1.3.0',
            '.1.3.6.1.2.1.1.4.0',
    ]
    proxy = AgentProxy(ip='127.0.0.1',
                       port=161,
                       community='public',
                       snmpVersion=1,
                       protocol=Bogus(),
                       allowCache=True)
    proxy.open()
    d = proxy.get(oids, 1.0, 3)
    d.addBoth(print_results)
    d.addCallback(close, proxy)
    reactor.run()
    print "end reactor"


if __name__ == '__main__':
    main()
