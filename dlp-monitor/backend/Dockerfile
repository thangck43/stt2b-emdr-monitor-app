FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir fastapi==0.115.6 "uvicorn[standard]==0.32.1"
COPY app ./app
ENV DLP_DB_PATH=/data/dlp_monitor.db
VOLUME ["/data"]
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
