from twisted.internet import defer
from pynetsnmp.twistedsnmp import asOidStr, asOid

class _TableStatus(object):

    def __init__(self, startOidStr):
        self.startOidStr = startOidStr
        self.startOid = asOid(startOidStr)
        self.result = []
        self.finished = False


class TableRetriever(object):

    def __init__(self,
                 proxy,
                 oids,
                 timeout = 1.5,
                 retryCount = 3,
                 maxRepetitions = 100,
                 limit = 1000):
        self.proxy = proxy
        self.tableStatus = [_TableStatus(oid) for oid in oids]
        self.defer = defer.Deferred()
        if proxy.snmpVersion.find('1') > -1:
            self.how = proxy._walk
        else:
            def v2v3how(oids):
                return proxy._getbulk(0, min(maxRepetitions, limit), [oids])
            self.how = v2v3how
        self.limit = limit
        self.count = 0
        self.hit_limit = False

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
            results[ts.startOidStr]=dict([(asOidStr(oid), value) for oid, value in ts.result])
        self.defer.callback(results)
        self.defer = None


    def saveResults(self, values, ts):
        if values:
            for oid, value in values:
                self.count += 1
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
        if not ts.finished and self.count >= self.limit: 
            ts.finished = True
            self.hit_limit = True
        self.fetchSomeMore()

    def error(self, why):
        self.defer.errback(why)
        self.defer = None
