FROM python:3.11-slim

# Install Trivy
RUN apt-get update && \
    apt-get install -y wget apt-transport-https gnupg lsb-release curl && \
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y trivy && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /action

# Copy requirements and install Python dependencies
COPY requirements.txt /action/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Python script
COPY trivy_scan.py /action/

# Set the entrypoint
ENTRYPOINT ["python", "/action/trivy_scan.py"]
