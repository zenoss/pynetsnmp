import re
import os

def process(f, output):
    lines = open('/usr/include/net-snmp/library/%s.h' % f).readlines()
    sp = '[ \t]*'
    comment = re.compile('/\\*(.*\\*/|[^*]*$)')
    define = re.compile(sp.join(['^',
                                 '#',
                                 'define',
                                 '([A-Za-z0-9_]+)',
                                 '([^\\\\]+)$']))
    junk = ['usm', '(x)', 'sizeof', '(string)', '(byte)', '{', '?', 'err']
    for line in lines:
        line = comment.sub('', line)
        m = define.match(line)
        if m:
            value = m.group(2).strip()
            value = value.replace('(u_char)', '')
            if value:
                for j in junk:
                    if value.find(j) > -1:
                        break
                else:
                    output.write('%s = %s\n' % (m.group(1), value))

def make_imports():
    try:
        out = open('CONSTANTS.py.new', 'w')
        out.write("USM_LENGTH_OID_TRANSFORM = 10\n")
        out.write("NULL = None\n")
        for f in 'callback asn1 snmp snmp_api snmp_impl snmp_logging'.split():
            process(f, out)
        out.close()
        os.rename('CONSTANTS.py.new', 'CONSTANTS.py')
    except IOError:                     # file not found, prolly
        pass

if __name__=='__main__':
    from CONSTANTS import *             # check the result

