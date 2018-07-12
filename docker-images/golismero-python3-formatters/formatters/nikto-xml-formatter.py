#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

import csv
import sys
import mmh3
import json
import base64
import traceback
import lxml.etree
import urllib.parse

TOOL = "nikto"

EMPTY = """<?xml version="1.0" ?>
<!DOCTYPE niktoscan SYSTEM "/usr/share/doc/nikto/nikto.dtd">

</niktoscan>
"""

def simple_object(key, value):
    "Create a simple key/value object."
    return {
        "_id": mmh3.hash128(value),
        "_type": key,
        "_tool": TOOL,
        key: value,
    }

# XXX this is only a proof of concept, will not be like this in prod
def keyword_object(_type, **kwargs):
    "Create an object with multiple keys and values."
    j = dict(**kwargs)
    j["_type"] = _type
    j["_tool"] = TOOL
    j["_id"] = mmh3.hash128("|".join((
        key.replace("|", "||") + "|" + value.replace("|", "||") for key, value in kwargs.items()
    )))
    return j

COMMA = ""
def do_output(*args):
    global COMMA
    sys.stdout.write(COMMA)
    COMMA = ","
    json.dump(args, sys.stdout)

def simple_output(key, value):
    do_output(simple_object(key, value))

def main():
    global TOOL

    # We will remember the URLs we see.
    # This prevents outputting them multiple times.
    urls_seen = set()

    # Open the JSON list.
    sys.stdout.write("[")

    # Parse the XML input from stdin.
    try:
        try:
            raw = base64.b64decode( json.load(sys.stdin)["raw"] ).decode("utf-8")
            if raw == EMPTY:
                simple_output("error", "Empty Nikto scan results.")
                return
            xml = lxml.etree.fromstring(raw)

            # Get the Nikto version.
            assert xml.xpath("/niktoscan")[0].attrib["version"]

            # Get the scan target details.
            scandetails = xml.xpath("/niktoscan/scandetails")[0]
            ip = scandetails.attrib["targetip"].strip()
            host = scandetails.attrib["targethostname"].strip().lower()
            port = scandetails.attrib["targetport"].strip()
            banner = scandetails.attrib["targetbanner"].strip()
            ssl = scandetails.attrib["sitename"].strip().lower().startswith("https://")

            # Output the domain, ip, port and banner objects.
            d_obj = simple_object("domain", host)
            ip_obj = simple_object("ip", ip)
            p_obj = simple_object("port", port)
            b_obj = simple_object("banner", banner)
            do_output(ip_obj)
            do_output(ip_obj, p_obj)
            do_output(ip_obj, p_obj, b_obj)
            do_output(d_obj)
            do_output(d_obj, p_obj)             # not sure about these two...
            do_output(d_obj, p_obj, b_obj)      # do we really need them?

            # Find all the scan results.
            # NOTE: there it may be tempting to use xpath to filter out the
            # entries we don't want. Problem: we would miss any URLs in those
            # entries. So we need to process at least for the URLs.
            for item in xml.xpath("//item"):
                try:

                    # Get the URL, description and vuln tag.
                    vuln_tag = item.attrib["osvdbid"]
                    path = item.xpath("./uri/text()")[0].strip()
                    message = item.xpath("./description/text()")[0].strip()
                    message = message[ message.find(" ") + 1 : ]

                    # Output the URL object.
                    if ssl:
                        scheme = "https"
                    else:
                        scheme = "http"
                    if ssl and port == "443":
                        url = urllib.parse.urljoin("%s://%s/" % (scheme, host), path)
                    elif not ssl and port == "80":
                        url = urllib.parse.urljoin("%s://%s/" % (scheme, host), path)
                    else:
                        url = urllib.parse.urljoin("%s://%s:%s/" % (scheme, host, port), path)
                    u_obj = simple_object("url", url)
                    if url not in urls_seen:
                        urls_seen.add(url)
                        do_output(u_obj)

                    # Skip items not informing of vulnerabilities.
                    # OSVDB-0: Nikto log lines
                    # OSVDB-3092: content discovery plugin
                    if vuln_tag == "0" or vuln_tag == "3092":
                        continue

                    # Output the vulnerability object.
                    # XXX this is only a proof of concept, will not be like this in prod
                    vuln = keyword_object(
                        _type="vulnerability",
                        title="Web application vulnerability",
                        description=message,
                        url=url,
                    )
                    do_output(u_obj, vuln)

                # On error send an error object.
                except Exception:
                    simple_output("error", traceback.format_exc())

        # On error send an error object.
        except Exception:
            simple_output("error", traceback.format_exc())

    # Always close the JSON list.
    finally:
        sys.stdout.write("]")

# Boilerplate to execute main() when run as a script.
if __name__ == "__main__":
    main()