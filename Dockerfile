FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY src/analysis_tool/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p cache test_files/output dashboards/output runs \
    src/analysis_tool/core/mappings && \
    chmod -R 777 cache dashboards runs

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src:$PYTHONPATH

CMD ["python", "run_tools.py"]