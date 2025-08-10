FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml /app/mcp/pyproject.toml
RUN pip install --no-cache-dir fastmcp httpx[http2] pydantic rapidfuzz

COPY . /app/mcp

CMD ["python", "-m", "mcp.server"]


