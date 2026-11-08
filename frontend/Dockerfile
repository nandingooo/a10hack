# Stage 1: build the dashboard, so the image never depends on a committed or stale dist/.
FROM node:22-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY index.html vite.config.js ./
COPY src ./src
COPY demo ./demo
RUN npm run build

# Stage 2: the gateway. Python standard library only.
FROM python:3.12-alpine
WORKDIR /app
COPY demo ./demo
COPY --from=build /src/dist ./dist
USER 65534:65534
ENV AIRLOCK_BIND=0.0.0.0 PORT=8787 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8787
CMD ["python","demo/gateway.py"]
