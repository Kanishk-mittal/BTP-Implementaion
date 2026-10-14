FROM python:3.11-slim
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*
COPY paramiko/ /paramiko/
RUN pip install --no-cache-dir /paramiko/
COPY docker/ca/init.sh /init.sh
RUN chmod +x /init.sh
ENTRYPOINT ["/init.sh"]
