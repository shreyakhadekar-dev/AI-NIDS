FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p uploads reports models
CMD exec gunicorn app.main:app --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:${PORT:-8000} --workers 1
