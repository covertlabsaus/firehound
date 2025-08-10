FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash ca-certificates curl jq git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# ipatool is expected to be provided separately or mounted in PATH
# Example: COPY ipatool /usr/local/bin/ipatool

RUN chmod +x /app/pipeline.sh /app/scripts/install_ipatool.sh || true

# Try to install ipatool; continue if not available (user can mount it)
RUN /app/scripts/install_ipatool.sh || true

ENTRYPOINT ["/app/pipeline.sh"]


