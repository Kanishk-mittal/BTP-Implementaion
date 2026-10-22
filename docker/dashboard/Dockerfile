FROM python:3.11-slim
WORKDIR /app
COPY docker/dashboard/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY docker/dashboard/ .
EXPOSE 5000
CMD ["python", "app.py"]
