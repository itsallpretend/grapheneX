# syntax=docker/dockerfile:1
FROM python:3.12-alpine AS base
LABEL maintainer="graphenex.project@protonmail.com"
ENV LC_ALL=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POETRY_HOME=/opt/poetry \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_NO_INTERACTION=1 \
    GRAPHENEX_WEB_HOST=0.0.0.0
WORKDIR /app

FROM base AS builder
RUN apk update \
    && apk add --no-cache \
    gcc \
    libffi-dev \
    linux-headers \
    musl-dev \
    python3-dev
ENV PATH="$POETRY_HOME/bin:$PATH"
RUN pip install --no-cache-dir poetry
COPY pyproject.toml README.md ./
# Install dependencies first so that source changes do not invalidate this layer.
RUN poetry install --no-root --no-ansi
COPY . .
RUN poetry install --no-ansi

FROM base AS runtime
ENV PATH="/app/.venv/bin:$PATH"
COPY --from=builder /app /app
EXPOSE 8080

# The container intentionally runs as root because hardening modules manage
# system services and /etc. Prefer --cap-add over --privileged at runtime, and
# mount the state directory so the journal and backups survive the container.
VOLUME ["/root/.local/state/graphenex"]
HEALTHCHECK --interval=60s --timeout=5s --start-period=10s \
    CMD grapheneX --validate || exit 1

CMD ["grapheneX"]
