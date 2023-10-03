"""prints the number of interfaces returned by a walk of ifIndex"""
import argparse
from pynetsnmp.tableretriever import TableRetriever
from pynetsnmp.twistedsnmp import AgentProxy
from twisted.internet import reactor

import logging
logging.basicConfig()
log = logging.getLogger("ifIndex")


def error(why):
    reactor.stop()
    log.error('%s', why)


def success(result):
    print "Number of interfaces returned by a walk of ifIndex :", len(result.values()[0])
    reactor.stop()


def closer(result, proxy):
    proxy.close()
    return result


def main():
    print "=================== \nSNMP Walk of ifIndex Test"
    parser = argparse.ArgumentParser(description="SNMP Walk of ifIndex")
    parser.add_argument("--host", default="colo3560g", help="IP address of the SNMP server")
    parser.add_argument("--community", default="zenoss", help="SNMP community string")
    parser.add_argument("--snmp_version", default="1", help="SNMP version (1 or v2)")
    parser.add_argument("--oids", nargs="+", default=['.1.3.6.1.2.1.2.2.1.1'], help="OIDs to retrieve")
    args = parser.parse_args()

    proxy = AgentProxy(ip=args.host, snmpVersion=args.snmp_version, community=args.community)
    proxy.open()
    tr = TableRetriever(proxy, oids=args.oids)
    d = tr()
    d.addBoth(closer, proxy)
    d.addCallback(success)
    d.addErrback(error)
    reactor.run()

    print "==================="


if __name__ == '__main__':
    main()
