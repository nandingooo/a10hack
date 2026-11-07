FROM python:3.12-slim
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
 && useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin gateway
COPY policy.py app.py /app/
USER gateway
WORKDIR /app
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
