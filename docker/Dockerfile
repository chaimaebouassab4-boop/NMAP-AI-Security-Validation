# Base lightweight Linux image
FROM python:3.10-slim

# Install Nmap
RUN apt-get update && \
    apt-get install -y nmap && \
    apt-get clean

# Create working directory
WORKDIR /app

# Copy Python requirements

COPY docker/requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy your validation code
COPY src /app/src
# Default command (can be overridden)
CMD ["python", "-c", "print('NMAP sandbox ready!')"]
