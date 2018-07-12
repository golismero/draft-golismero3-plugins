FROM python:3.6-alpine

RUN apk update && \
    apk add g++ libxslt-dev && \
    pip install -U pip

COPY requirements.txt /tmp
RUN pip install -U -r /tmp/requirements.txt

# XXX DEBUG
COPY g3format /usr/local/bin/
RUN chmod +x /usr/local/bin/g3format
# XXX DEBUG

COPY formatters/ /opt/formatters
RUN chmod +x /opt/formatters/*.py

WORKDIR /opt/formatters
ENTRYPOINT [ "/usr/local/bin/python3" ]