from tableretriever import TableRetriever
from twistedsnmp import AgentProxy
from twisted.internet import reactor

import logging
log = logging.getLogger("tableget")


def error(why):
    reactor.stop()
    log.error('%s', why)

def success(result):
    import pprint
    pprint.pprint(result)
    reactor.stop()

def closer(result, proxy):
    proxy.close()
    return result

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    proxy = AgentProxy('127.0.0.1', snmpVersion='v1')
    proxy.open()
    tr = TableRetriever(proxy,
                        ('.1.3.6.1.2.1.25.4.2.1.2', '.1.3.6.1.2.1.25.4.2.1.4'))
    d = tr()
    d.addBoth(closer, proxy)
    d.addCallback(success)
    d.addErrback(error)
    reactor.run()
