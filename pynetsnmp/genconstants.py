#!/usr/bin/env python

import logging
import os
import re

logging.basicConfig()
log = logging.getLogger("zen.genconstants")

global_vars = {}
local_vars = {}


def write_output(f, name, value):
    assignment = "{0} = {1}\n".format(name, value)
    try:
        exec(assignment, global_vars, local_vars)  # noqa S102
        f.write(assignment)
    except Exception as e:
        log.error("Invalid python statement: %s, %s", assignment.strip(), e)


def process(f, output):
    try:
        lines = open("/usr/include/net-snmp/%s" % f).readlines()
    except UnicodeDecodeError:
        lines = open(
            "/usr/include/net-snmp/%s" % f, encoding="latin-1"
        ).readlines()
    sp = "[ \t]*"
    comment = re.compile("/\\*(.*\\*/|[^*]*$)")
    define = re.compile(
        sp.join(["^", "#", "define", "([A-Za-z0-9_]+)", "([^\\\\]+)$"])
    )
    unsigned = re.compile("0x[A-Fa-f0-9]+U")
    wrapped_in_parens = re.compile("^\((.+)\)$")
    junk = ["usm", "(x)", "sizeof", "(string)", "(byte)", "{", "?", "err"]
    for line in lines:
        line = comment.sub("", line)
        m = define.match(line)
        # If no match, skip to next line
        if not m:
            continue
        value = m.group(2).strip()
        value = value.replace("(u_char)", "")
        # If no value, skip to next line
        if not value:
            continue
        # Rewrite 0x40U as 0x40
        if unsigned.match(value):
            value = value.replace("U", "")
        # Unwrap outer parenthesis
        matched_parens = wrapped_in_parens.match(value)
        if matched_parens:
            try:
                value = matched_parens.group(1)
            except IndexError:
                log.exception("false parenthesis match  value=%s", value)
        # If unwanted value, skip to next line
        if any(j in value for j in junk):
            continue
        write_output(output, m.group(1), value)


def make_imports():
    try:
        with open("CONSTANTS.py.new", "w") as out:
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
                try:
                    process(path, out)
                except Exception:
                    log.exception("failed to process file %s", path)
            out.close()
            os.rename("CONSTANTS.py.new", "CONSTANTS.py")
    except IOError:  # file not found, prolly
        pass


if __name__ == "__main__":
    make_imports()
