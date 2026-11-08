FROM python:3.12-alpine
WORKDIR /app
COPY demo ./demo
COPY dist ./dist
USER 65534:65534
ENV AIRLOCK_BIND=0.0.0.0 PYTHONDONTWRITEBYTECODE=1
CMD ["python","demo/gateway.py"]
