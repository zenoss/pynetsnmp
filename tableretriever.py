from twisted.internet import defer
from twistedsnmp import translateOids

def cmpOids(a, b):
    "Compare two oid strings numerically"
    return cmp(map(int, a.strip('.').split('.')),
               map(int, b.strip('.').split('.')))
        
try:
    sortOids
except NameError:
    def sortOids(x):
        x = list(x)
        x.sort(cmp=cmpOids)
        return x

class _TableStatus(object):

    def __init__(self, startOid):
        self.startOid = startOid
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
            self.how = proxy.walk
        else:
            self.how = lambda x: proxy.getbulk(0, maxRepetitions, [x])

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
            results[ts.startOid] = dict(ts.result)
        self.defer.callback(results)
        self.defer = None
                    

    def saveResults(self, values, ts):
        if values:
            stem = ts.startOid + '.'
            for oid in sortOids(values.keys()):
                if oid.startswith(stem) and cmpOids(oid, ts.startOid) > 0:
                    # defend against going backwards
                    if ts.result and cmpOids(oid, ts.result[-1][0]) <= 0:
                        ts.finished = True
                    else:
                        value = values[oid]
                        ts.result.append( (oid, value) )
                else:
                    ts.finished = True
        else:
            ts.finished = True
        self.fetchSomeMore()

    def error(self, why):
        self.defer.errback(why)
        self.defer = None
