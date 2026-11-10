# TrustLens backend — Python 3.13 slim (native peer-chain capture via
# ssl.SSLObject.get_unverified_chain(); the pyOpenSSL capture layer in
# app/pipeline/fetcher.py keeps full-chain support on 3.11/3.12 runtimes too).
FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY pyproject.toml .

# Reports DB lives on the mounted volume.
ENV TRUSTLENS_DATABASE_URL=sqlite:////data/trustlens.db
VOLUME ["/data"]

EXPOSE 8000

# Chain features activate when TRUSTLENS_REGISTRY_ADDRESS is set (compose wires
# this from the deployment file written by the one-shot deploy service).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
