# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory
WORKDIR /app

# Copy the project files
COPY ./deception_engine /app

# Install dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Expose the ports for the honeypot services
EXPOSE 9090 8080

# Run the deception script
CMD ["python", "deception_script.py"]