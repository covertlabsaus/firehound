FROM python:3.11-slim

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash ca-certificates curl jq git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
CMD ["bash"]