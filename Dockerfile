FROM python:3.12-slim

# nmap does discovery, service and OS scans. iproute2 is handy for troubleshooting.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
ENV PYTHONUNBUFFERED=1 \
    NETWATCH_DATA=/data
VOLUME ["/data"]
EXPOSE 5000

CMD ["python", "app.py"]
