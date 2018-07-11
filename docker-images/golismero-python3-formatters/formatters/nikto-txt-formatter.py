#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

import io
import re
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

    # Pre-compile the regular expression we will use later on.
    # This will give us a small performance gain.
    re_vuln = re.compile(r"^\+ (OSVDB\-[0-9]+)\: ([^ ]+) (.*)$")

    # We will remember the URLs we see.
    # This prevents outputting them multiple times.
    urls_seen = set()

    # Get the TXT file from the raw data object.
    txt = base64.b64decode( json.load(sys.stdin)["raw"] ).decode("utf-8").splitlines()

    # Open the JSON list.
    sys.stdout.write("[")
    try:
        try:

            # First line is the Nikto version.
            line = txt.pop(0)
            assert line.startswith("- Nikto")
            TOOL = line[2:]

            # Next, we have a separator.
            assert txt.pop(0) == "-" * 75

            # If the scan failed, we have an error message here.
            if txt[0].startswith("+ No web server found on "):
                simple_output("error", "Empty Nikto scan results.")
                return

            # Now we have the target host and port for the scan.
            line = txt.pop(0)
            assert line.startswith("+ Target IP:          ")
            ip = line[22:]
            line = txt.pop(0)
            assert line.startswith("+ Target Hostname:    ")
            host = line[22:]
            line = txt.pop(0)
            assert line.startswith("+ Target Port:        ")
            port = line[22:]

            # Next, we have another separator.
            assert txt.pop(0) == "-" * 75

            # If the scan was over SSL, we have that part now.
            # After that, there's a separator.
            # If it wasn't over SSL, this section won't exist.
            line = txt.pop(0)
            if line.startswith("+ SSL Info:"):
                ssl = True
                while line != "-" * 75:
                    line = txt.pop(0)
            else:
                ssl = False

            # First line of the scan results is always the server banner.
            assert line.startswith("+ Server: ")
            banner = line[10:]
            line = txt.pop(0)

            # Output the host, ip, port and banner objects.
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

            # At this point all the remaining results from the scan will appear.
            # All lines begin with a plus sign.
            # Normal log lines may have any text whatsoever, but issues
            # will always start with the OSVDB code.
            while True:
                try:
                    m = re_vuln.match(line)
                    if m is not None:
                        vuln_tag = m.group(1).upper()
                        path = m.group(2)[:-1]  # remove the trailing ":"
                        message = m.group(3)

                        # Extract URLs.
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

                # Continue parsing the text until we run out of lines.
                if not txt:
                    break
                line = txt.pop(0)

        except Exception:
            simple_output("error", "Invalid Nikto scan results.")
            return

    # Always close the JSON list.
    finally:
        sys.stdout.write("]")

# Boilerplate to execute main() when run as a script.
if __name__ == "__main__":
    main()