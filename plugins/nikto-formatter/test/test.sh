#!/bin/bash

set -e

rm test-output.json
cat example.csv | ./g3format --format nikto-csv | python3 ../../../docker-images/golismero-python3-formatters/formatters/nikto-csv-formatter.py | js-beautify > test-output.json
[[ $(diff example.json test-output.json  2>&1 | wc -l) == 0 ]]

rm test-fail.json
cat fail.csv | ./g3format --format nikto-csv | python3 ../../../docker-images/golismero-python3-formatters/formatters/nikto-csv-formatter.py | js-beautify > test-fail.json
[[ $(diff fail.json test-output.json  2>&1 | wc -l) == 0 ]]

rm test-output.json
cat example.txt | ./g3format --format nikto-txt | python3 ../../../docker-images/golismero-python3-formatters/formatters/nikto-txt-formatter.py | js-beautify > test-output.json
[[ $(diff example.json test-output.json 2>&1 | wc -l) == 0 ]]

rm test-fail.json
cat fail.txt | ./g3format --format nikto-txt | python3 ../../../docker-images/golismero-python3-formatters/formatters/nikto-txt-formatter.py | js-beautify > test-fail.json
[[ $(diff fail.json test-fail.json 2>&1 | wc -l) == 0 ]]
