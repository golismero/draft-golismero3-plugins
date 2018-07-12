#!/bin/bash

set -e

# Local tests
function local_test {
    rm -f test-$1-$2.json
    cat $2.$1 | ./g3format --format nikto-$1 | python3 ../../../docker-images/golismero-python3-formatters/formatters/nikto-$1-formatter.py | js-beautify > test-$1-$2.json
    if [[ $(diff $2.json test-$1-$2.json  2>&1 | wc -l) == 0 ]]
    then
        echo "OK: $1 test-$1-$2.json"
    else
        echo "FAIL: $1 test-$1-$2.json"
    fi
}

echo "Local tests:"
local_test xml fail
local_test csv fail
local_test txt fail
local_test xml example
local_test csv example
local_test txt example

echo

# Docker tests
function docker_test {
    rm -f test-$1-$2.json
    cat $2.$1 | ./g3format --format nikto-$1 | docker run -i --entrypoint /opt/formatters/nikto-$1-formatter.py golismero-python3-formatters | js-beautify > test-$1-$2.json
    if [[ $(diff $2.json test-$1-$2.json  2>&1 | wc -l) == 0 ]]
    then
        echo "OK: $1 test-$1-$2.json"
    else
        echo "FAIL: $1 test-$1-$2.json"
    fi
}

echo "Docker tests:"
docker_test xml fail
docker_test csv fail
docker_test txt fail
docker_test xml example
docker_test csv example
docker_test txt example
