import argparse
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
    print "=================== \nSNMP Proxy Example Test"

    oids = ['.1.3.6.1.2.1.1.1.0',
            '.1.3.6.1.2.1.1.2.0',
            '.1.3.6.1.2.1.1.3.0',
            '.1.3.6.1.2.1.1.4.0',
    ]

    parser = argparse.ArgumentParser(description="SNMP Proxy Example")
    parser.add_argument("--host", default="127.0.0.1", help="SNMP server IP address")
    parser.add_argument("--port", type=int, default=161, help="SNMP server port")
    parser.add_argument("--community", default="public", help="SNMP community")
    parser.add_argument("--snmp_version", type=int, default=1, help="SNMP version")
    parser.add_argument("--oids", nargs="+", default=oids, help="List of OIDs")
    args = parser.parse_args()

    proxy = AgentProxy(
        ip=args.host,
        port=args.port,
        community=args.community,
        snmpVersion=args.snmp_version,
        protocol=Bogus(),
        allowCache=True
    )

    # open a lot of files, to push fd numbers into > 1024 so that we exercise
    # snmp_select_info2 / snmp_read2
    fds = []
    for n in range(1024):
        fds.append(open('/dev/null', 'r'))

    proxy.open()
    d = proxy.get(args.oids, 1.0, 3)
    d.addBoth(print_results)
    d.addCallback(close, proxy)
    reactor.run()
    print "==================="


if __name__ == '__main__':
    main()
