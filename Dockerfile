FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# Runs as root (default) so the container can create /srv/agent-redteam/*
CMD ["gunicorn", "-b", "0.0.0.0:10000", "app:app"]
