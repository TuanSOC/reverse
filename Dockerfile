# WebRecon — dashboard + CLI in a reproducible container.
# Uses the official Playwright image so Chromium (browser mode + PDF) works.
FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[engine,browser,api,report]"

# Default: serve the dashboard. Mount a volume at /data to persist scans.
ENV WEBRECON_DATABASE_URL="sqlite+aiosqlite:////data/webrecon.db"
VOLUME ["/data"]
EXPOSE 8000

ENTRYPOINT ["webrecon"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000", \
     "--database-url", "sqlite+aiosqlite:////data/webrecon.db"]
