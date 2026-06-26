# --- Stage 1: build the React frontend --------------------------------------
FROM node:20-slim AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# --- Stage 2: Python runtime serving API + built frontend -------------------
FROM python:3.12-slim AS runtime
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
# Built static assets from stage 1 (api.py serves frontend/dist).
COPY --from=frontend /app/frontend/dist ./frontend/dist

ENV PYTHONPATH=/app/src
EXPOSE 8000

# Render provides $PORT; default to 8000 locally.
CMD ["sh", "-c", "uvicorn threat_intel.api:app --host 0.0.0.0 --port ${PORT:-8000}"]
