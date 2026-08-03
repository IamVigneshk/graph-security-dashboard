FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (needed for compiling Kuzu if wheels don't match, though binary wheels are available)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy python dependencies list
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and build files
COPY src/ /app/src/

# Expose backend REST & static files port
EXPOSE 8000

# Set environment variable to make database folder persistent in a mounted directory
ENV KUZU_DB_DIR=/app/graph_db

# Run the FastAPI server
CMD ["python", "src/backend/app.py"]
