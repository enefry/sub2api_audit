FROM python:3.15.0rc1-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --gid 10001 recorder \
    && useradd --uid 10001 --gid recorder --no-create-home --shell /usr/sbin/nologin recorder

COPY requirements.lock /app/requirements.lock
RUN pip install --requirement /app/requirements.lock

COPY pyproject.toml README.md /app/
COPY sub2api_recorder /app/sub2api_recorder
RUN pip install --no-deps /app

USER 10001:10001
EXPOSE 8080

CMD ["uvicorn", "sub2api_recorder.app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-access-log"]
