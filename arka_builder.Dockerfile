
FROM python:3.10-alpine as build

LABEL org.opencontainers.image.source=https://github.com/trstovall/arka
LABEL org.opencontainers.image.description="`arka` Python package to interact with the `coin` network."
LABEL org.opencontainers.image.licenses=MIT

WORKDIR /

RUN apk add build-base git
RUN pip install --upgrade pip
