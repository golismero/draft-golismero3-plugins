FROM python:2.7-alpine
LABEL maintainer="Ilya Glotov <ilya@ilyaglotov.com>"

RUN apk --update --no-cache add curl-dev \
                                gcc \
                                musl-dev \
                                openssl-dev \
  && PYCURL_SSL_LIBRARY=openssl pip install pycurl \
  && apk --no-cache add git

# Instaling wfuzz
RUN pip install wfuzz \
    && rm -rf /wfuzz/.git

# Instaling fuzzdb
RUN git clone --branch=master \
              --depth=1 \
              https://github.com/fuzzdb-project/fuzzdb.git /wordlists \
    && rm -rf /wordlists/.git

# Build a big dictionary for predictable files
RUN cd /wordlists/discovery/predictable-filepaths/webservers-appservers/ \
    && rm -rf README.md \
    && cat * > BigPredictable.txt

# Remove compiling libraries
RUN apk del gcc \
    && apk del git
#
RUN adduser -D wfuzz

#USER wfuzz
WORKDIR /wordlists
ENTRYPOINT ["wfuzz"]
