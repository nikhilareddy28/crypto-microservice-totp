########################################
# Stage 1: Builder
########################################
FROM python:3.11-slim AS builder

WORKDIR /app

# Copy dependency list first (optimizes caching)
COPY app/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt


########################################
# Stage 2: Runtime
########################################
FROM python:3.11-slim

# Set timezone to UTC (required)
ENV TZ=UTC
ENV DATA_PATH=/data
ENV CRON_LOG=/cron/last_code.txt

WORKDIR /app

# Install cron + timezone tools
RUN apt-get update && \
    apt-get install -y cron tzdata && \
    rm -rf /var/lib/apt/lists/*

# Configure timezone
RUN ln -snf /usr/share/zoneinfo/UTC /etc/localtime && echo "UTC" > /etc/timezone

# Copy installed Python dependencies from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application source code
COPY app/ ./app/
COPY utils_crypto.py ./utils_crypto.py

# Copy cron job script and config
COPY scripts/log_2fa_cron.py ./scripts/log_2fa_cron.py
COPY cron/2fa-cron /etc/cron.d/2fa-cron

# Copy RSA keys (required for decryption)
COPY student_private.pem student_public.pem instructor_public.pem ./

# Correct permissions
RUN chmod 0644 /etc/cron.d/2fa-cron && \
    chmod +x ./scripts/log_2fa_cron.py

# Create persistent storage mount points
RUN mkdir -p /data /cron && chmod 755 /data /cron

# Register cron job
RUN crontab /etc/cron.d/2fa-cron

# Expose port for FastAPI
EXPOSE 8080

# Start cron and API server
CMD cron && uvicorn app.main:app --host 0.0.0.0 --port 8080

