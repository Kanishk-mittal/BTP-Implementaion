FROM python:3.11-slim
WORKDIR /app
COPY paramiko/ /paramiko/
RUN pip install --no-cache-dir /paramiko/
COPY docker/server/ssh_server.py ssh_server.py
EXPOSE 2222
CMD ["python", "ssh_server.py"]
