#!/usr/bin/env sh

DOMAIN=$1

#
# Clean the url an extract the schema and the domain
#
TARGET=$(python -c "from urlparse import urlparse; h=urlparse(\"${DOMAIN}\");print('{}://{}'.format(h.scheme,h.netloc))")

# Launch a first small execution to get the unusual request word number
LINES=$(/usr/local/bin/wfuzz --filter 'code=200 and lines!=0' -z range,0-0 ${TARGET}/FUZZ | grep 00001 | awk '{print $3}')

# Launch again with a fine rules
#-w /wordlists/discovery/predictable-filepaths/webservers-appservers/BigPredictable.txt \
exec /usr/local/bin/wfuzz --filter "code != 404 and code=200 and lines!=${LINES}" \
    -w /wordlists/discovery/predictable-filepaths/webservers-appservers/Apache.txt \
    -f /tmp/results.json,json \
    ${TARGET}/FUZZ
