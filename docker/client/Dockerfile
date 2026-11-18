FROM python:3.11-slim
WORKDIR /app
COPY paramiko/ /paramiko/
RUN pip install --no-cache-dir /paramiko/
COPY docker/client/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY docker/client/ssh_client.py ssh_client.py
CMD ["python", "ssh_client.py"]
