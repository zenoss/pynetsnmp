import argparse
from pynetsnmp.tableretriever import TableRetriever
from pynetsnmp.twistedsnmp import AgentProxy
from twisted.internet import reactor

import logging
logging.basicConfig()
log = logging.getLogger("tableget")


def error(why):
    reactor.stop()
    log.error('%s', why)
    raise Exception(why)


def success(result):
    import pprint
    pprint.pprint(result)
    reactor.stop()


def closer(result, proxy):
    proxy.close()
    return result


if __name__ == '__main__':
    print "=================== \nSNMP Table Retriever Test"

    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(description="SNMP Table Retriever")
    parser.add_argument("--host", default="127.0.0.1", help="IP address of the SNMP server")
    parser.add_argument("--snmp_version", default="v2", help="SNMP version (1 or v2)")
    parser.add_argument("--oids", nargs="+", default=('.1.3.6.1.2.1.1.5', '.1.3.6.1.2.1.25.4.2.1.4'), help="OIDs to retrieve")
    args = parser.parse_args()

    proxy = AgentProxy(ip=args.host, snmpVersion=args.snmp_version)
    proxy.open()
    tr = TableRetriever(proxy, oids=args.oids)
    d = tr()
    d.addBoth(closer, proxy)
    d.addCallback(success)
    d.addErrback(error)
    reactor.run()

    print "==================="
