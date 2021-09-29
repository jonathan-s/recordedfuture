FROM python:3.8-slim
EXPOSE 5002
ENV PHANTOM_BFI_SSL=${PHANTOM_BFI_SSL:-adhoc}
ENV PHANTOM_BFI_HOST=${PHANTOM_BFI_HOST:-0.0.0.0}
ENV RF_TOKEN=${RF_TOKEN}
ENV RF_ENV=${RF_ENV}

HEALTHCHECK --interval=1m --timeout=3s \
  CMD curl -fk https://localhost:5002/phantom/health || exit 1

RUN apt-get update && apt-get install -y \
        python3 curl bash
RUN pip3 install --upgrade pip
RUN pip3 install --no-cache-dir Flask
RUN pip3 install --no-cache-dir flask-swagger-ui
RUN pip3 install watchdog requests future python-logstash pyyaml cryptography apispec apispec-webframeworks marshmallow uptime
RUN pip3 install pymongo pika statsd
CMD [ "/tmp/python/bin/rfpython3", "recordedfuture.apps.bfi_phantom@bfi_phantom_local"]
