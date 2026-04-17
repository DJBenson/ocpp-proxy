ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.12-alpine3.20
FROM $BUILD_FROM

RUN pip3 install --no-cache-dir "aiohttp>=3.9"

WORKDIR /app
COPY ocpp-proxy.py .
COPY run.sh .
RUN chmod +x run.sh

CMD ["/app/run.sh"]
