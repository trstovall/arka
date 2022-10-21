
FROM python:3.10-alpine as build

LABEL org.opencontainers.image.source=https://github.com/trstovall/coin
LABEL org.opencontainers.image.description="`arka` Python package to interact with the `coin` network."
LABEL org.opencontainers.image.licenses=MIT

RUN python -m pip install --upgrade pip \
    && python -m pip install arka

CMD ["python", "-m", "arka"]
