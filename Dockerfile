
FROM python:3.10-alpine as build

ENV ARKA_SOURCE https://github.com/trstovall/arka

LABEL org.opencontainers.image.source=https://github.com/trstovall/arka
LABEL org.opencontainers.image.description="`arka` Python package to interact with the `coin` network."
LABEL org.opencontainers.image.licenses=MIT

WORKDIR /

RUN apk add build-base git
RUN pip install --upgrade pip
RUN pip install "git+${ARKA_SOURCE}.git"

CMD ["python", "-m", "arka", "--help"]
