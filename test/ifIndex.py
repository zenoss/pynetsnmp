"""prints the number of interfaces returned by a walk of ifIndex"""

from tableretriever import TableRetriever
from twistedsnmp import AgentProxy
from twisted.internet import reactor

import logging
log = logging.getLogger("ifIndex")

def error(why):
    reactor.stop()
    log.error('%s', why)

def success(result):
    print len(result.values()[0])
    reactor.stop()

def closer(result, proxy):
    proxy.close()
    return result

def main():
    proxy = AgentProxy('colo3560g', snmpVersion='v2', community='zenoss')
    proxy.open()
    tr = TableRetriever(proxy, ('.1.3.6.1.2.1.2.2.1.1',))
    d = tr()
    d.addBoth(closer, proxy)
    d.addCallback(success)
    d.addErrback(error)
    reactor.run()

if __name__=='__main__':
    main()
