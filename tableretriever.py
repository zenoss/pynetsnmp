from twisted.internet import defer
from twistedsnmp import asOidStr, asOid

class _TableStatus(object):

    def __init__(self, startOidStr):
        self.startOid = asOid(startOidStr)
        self.result = []
        self.finished = False


class TableRetriever(object):

    def __init__(self,
                 proxy,
                 oids,
                 timeout = 1.5,
                 retryCount = 3,
                 maxRepetitions = 100):
        self.proxy = proxy
        self.tableStatus = [_TableStatus(oid) for oid in oids]
        self.defer = defer.Deferred()
        if proxy.snmpVersion.find('1') > -1:
            self.how = proxy._walk
        else:
            self.how = lambda x: proxy._getbulk(0, maxRepetitions, [x])

    def __call__(self):
        self.fetchSomeMore()
        return self.defer

    def fetchSomeMore(self):
        for ts in self.tableStatus:
            if ts.finished: continue
            if ts.result:
                lastOid = ts.result[-1][0]
            else:
                lastOid = ts.startOid
            d = self.how(lastOid)
            d.addCallback(self.saveResults, ts)
            d.addErrback(self.error)
            return
        results = {}
        for ts in self.tableStatus:
            startOidStr=asOidStr(ts.startOid)
            results[startOidStr]=dict([(asOidStr(oid), value) for oid, value in ts.result])
        self.defer.callback(results)
        self.defer = None


    def saveResults(self, values, ts):
        if values:
            for oid, value in values:
                if oid[:len(ts.startOid)]==ts.startOid and oid > ts.startOid:
                    # defend against going backwards
                    if ts.result and oid<=ts.result[-1][0]:
                        ts.finished = True
                    else:
                        ts.result.append((oid, value))
                else:
                    ts.finished = True
        else:
            ts.finished = True
        self.fetchSomeMore()

    def error(self, why):
        self.defer.errback(why)
        self.defer = None
