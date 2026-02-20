# WeSense Archiver
# Build context: parent directory (wesense-project/)
# Build: docker build -f wesense-archiver/Dockerfile -t wesense-archiver .
#
# Archives signed readings from ClickHouse to IPFS.
# Verifies signatures, exports Parquet, builds trust snapshots,
# signs manifests, and submits attestations.
#
# Expects wesense-ingester-core at ../wesense-ingester-core when building
# with docker-compose (which sets the build context).

FROM python:3.11-slim

LABEL org.opencontainers.image.source=https://github.com/wesense-earth/wesense-archiver

WORKDIR /app

# Copy dependency files first for better layer caching
COPY wesense-ingester-core/ /tmp/wesense-ingester-core/
COPY wesense-archiver/requirements-docker.txt .

# Install gcc, build all pip packages, then remove gcc in one layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    pip install --no-cache-dir "/tmp/wesense-ingester-core[p2p]" && \
    pip install --no-cache-dir -r requirements-docker.txt && \
    apt-get purge -y --auto-remove gcc && \
    rm -rf /var/lib/apt/lists/* /tmp/wesense-ingester-core

# Copy application code
COPY wesense-archiver/archiver.py .

# Create directories for data, keys, staging
RUN mkdir -p /app/data/keys /app/data/staging

ENV TZ=UTC

CMD ["python", "-u", "archiver.py"]
