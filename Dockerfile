FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY dnspoke ./dnspoke
RUN pip install --no-cache-dir '.[server]' && useradd --uid 10001 --create-home dnspoke && mkdir /data && chown dnspoke:dnspoke /data && chmod 700 /data
USER dnspoke
ENV DNS_DATABASE=/data/state.sqlite3 PYTHONUNBUFFERED=1 TLDEXTRACT_CACHE_PATH=/data/tld-cache
EXPOSE 8090
# Single thread: shared SQLite lock and provider timeout patch are deliberate.
CMD ["gunicorn", "--bind", "0.0.0.0:8090", "--workers", "1", "--threads", "1", "--timeout", "90", "--error-logfile", "-", "dnspoke.server:create_app()"]
