
FROM trstovall/arka_builder:latest

ENV ARKA_SOURCE https://github.com/trstovall/arka

LABEL org.opencontainers.image.source=https://github.com/trstovall/arka
LABEL org.opencontainers.image.description="`arka` Python package to interact with the `coin` network."
LABEL org.opencontainers.image.licenses=MIT

RUN pip install "git+${ARKA_SOURCE}.git"

CMD ["python", "-m", "arka", "--help"]
