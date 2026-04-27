FROM python:3.12-slim

WORKDIR /app

COPY ingest_api/pyproject.toml /app/pyproject.toml
COPY ingest_api /app/ingest_api

RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["uvicorn", "ingest_api.main:app", "--host", "0.0.0.0", "--port", "8000"]

