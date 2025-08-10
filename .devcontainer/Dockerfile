FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git unzip jq python3 python3-venv python3-pip \
    expect locales gosu zsh \
 && rm -rf /var/lib/apt/lists/*

# Set locale
RUN locale-gen en_US.UTF-8 && update-locale LANG=en_US.UTF-8
ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

# Install ipatool via Go (smaller than full Xcode toolchain); or prebuilt if desired later
# We install Go, build, then clean up to keep image moderate size
ARG GO_VERSION=1.22.5
RUN curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -o /tmp/go.tgz \
 && tar -C /usr/local -xzf /tmp/go.tgz \
 && rm -f /tmp/go.tgz
ENV PATH="/usr/local/go/bin:${PATH}"

# Prefer prebuilt ipatool binary if available; fallback to go install
RUN bash -lc 'curl -fsSL https://github.com/majd/ipatool/releases/latest/download/ipatool-linux-amd64 -o /usr/local/bin/ipatool \
    && chmod +x /usr/local/bin/ipatool || true'
RUN which ipatool >/dev/null 2>&1 || GOPATH=/opt/go GOBIN=/usr/local/bin /usr/local/go/bin/go install github.com/majd/ipatool@latest || true

WORKDIR /work


