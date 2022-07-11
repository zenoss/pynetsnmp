#!/usr/bin/env python

import re
import os
import logging

logging.basicConfig()
log = logging.getLogger("zen.genconstants")

global_vars = {}
local_vars = {}


def write_output(f, name, value):
    assignment = "%s = %s\n" % (name, value)
    try:
        exec(assignment, global_vars, local_vars)
        f.write(assignment)
    except Exception as e:
        log.error("Invalid python statement: %s, %s", assignment.strip(), e)


def process(f, output):
    lines = open("/usr/include/net-snmp/%s" % f).readlines()
    sp = "[ \t]*"
    comment = re.compile("/\\*(.*\\*/|[^*]*$)")
    define = re.compile(
        sp.join(["^", "#", "define", "([A-Za-z0-9_]+)", "([^\\\\]+)$"])
    )
    junk = ["usm", "(x)", "sizeof", "(string)", "(byte)", "{", "?", "err"]
    for line in lines:
        line = comment.sub("", line)
        m = define.match(line)
        if m:
            value = m.group(2).strip()
            value = value.replace("(u_char)", "")
            if value:
                for j in junk:
                    if value.find(j) > -1:
                        break
                else:
                    write_output(output, m.group(1), value)


def make_imports():
    try:
        out = open("CONSTANTS.py.new", "w")
        write_output(out, "USM_LENGTH_OID_TRANSFORM", "10")
        write_output(out, "NULL", "None")
        paths = []
        paths.extend(
            "library/" + x
            for x in (
                "callback.h",
                "asn1.h",
                "snmp.h",
                "snmp_api.h",
                "snmp_impl.h",
                "snmp_logging.h",
                "default_store.h",
            )
        )
        paths.append("types.h")
        for path in paths:
            process(path, out)
        out.close()
        os.rename("CONSTANTS.py.new", "CONSTANTS.py")
    except IOError:  # file not found, prolly
        pass


if __name__ == "__main__":
    make_imports()
