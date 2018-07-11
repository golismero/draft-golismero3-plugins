#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

import io
import csv
import sys
import json
import mmh3
import base64
import traceback
import urllib.parse

TOOL = "Nikto"

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

    # Get the CSV file from the raw data object.
    raw = base64.b64decode( json.load(sys.stdin)["raw"] )

    # Feed the raw data into the CSV parser.
    reader = csv.reader(io.StringIO(raw.decode("utf-8")))

    # Open the JSON list.
    sys.stdout.write("[")
    try:

        # First line is the Nikto version.
        # If we fail here, the file was empty or malformed.
        try:
            TOOL = next(reader)[0].split("/")[0]
        except Exception:
            simple_output("error", "Invalid Nikto scan results.")
            return

        # Second line is the scan target.
        # If there is no second line, the scan failed with an error.
        # So it's ok for us to fail with an error too.
        try:
            host, ip, port, _, _, _, banner = next(reader)
        except Exception:
            simple_output("error", "Empty Nikto scan results.")
            return
        host = host.lower()
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

        # Nikto in CSV format doesn't tell us if there was SSL or not.
        # So we need to guess from the port number.
        # It's ugly but unavoidable.
        if port != "443" and port != "80":
            simple_output(
                "warning", "Cannot determine if %s:%s is HTTP or HTTPS" % (host, port))

        # The remaining lines are the results of the scan.
        for row in reader:
            if not row:
                continue
            try:
                host, ip, port, vuln_tag, method, path, message = map(str.strip, row[:7])
                host = host.lower()
                vuln_tag = vuln_tag.upper()
                method = method.upper()
                
                # Extract URLs. For non standard port numbers, assume plaintext.
                if port == "443":
                    url = urllib.parse.urljoin("https://%s/" % host, path)
                elif port == "80":
                    url = urllib.parse.urljoin("http://%s/" % host, path)
                else:
                    url = urllib.parse.urljoin("http://%s:%s/" % (host, port), path)
                u_obj = simple_object("url", url)
                if url not in urls_seen:
                    urls_seen.add(url)
                    do_output(u_obj)
 
                # Skip rows not informing of vulnerabilities.
                # OSVDB-0: Nikto log lines
                # OSVDB-3092: content discovery plugin
                if not vuln_tag or vuln_tag == "OSVDB-0" or vuln_tag == "OSVDB-3092":
                    continue

                # Extract the vulnerabilities.
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

    # Always close the JSON list.
    finally:
        sys.stdout.write("]")

# Boilerplate to execute main() when run as a script.
if __name__ == "__main__":
    main()