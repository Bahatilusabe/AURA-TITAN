# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory
WORKDIR /app

# Copy the project files
COPY . /app

# Set PYTHONPATH to include the app directory
ENV PYTHONPATH=/app

# Install system dependencies required by TensorFlow
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    wget \
    && apt-get clean

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port (if needed for APIs)
EXPOSE 5000

# Run the monitoring script
CMD ["python", "ai_engine/monitor.py"]