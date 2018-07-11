#!/bin/bash
cat example.csv | ./g3format --format nikto-csv | python3 ../../../docker-images/golismero-python3-formatters/formatters/nikto-csv-formatter.py | js-beautify > test-output.json
cat fail.csv | ./g3format --format nikto-csv | python3 ../../../docker-images/golismero-python3-formatters/formatters/nikto-csv-formatter.py | js-beautify > test-fail.json
