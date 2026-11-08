FROM python:3.12-slim
# Build with --build-arg PROMPT_GUARD=1 to include torch + transformers for gateway/classifier.py.
ARG PROMPT_GUARD=0
COPY requirements.txt requirements-guard.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt \
 && if [ "$PROMPT_GUARD" = "1" ]; then \
      pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu -r /app/requirements-guard.txt; fi \
 && useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin gateway \
 && mkdir /hf && chown gateway /hf
# Model cache; run.sh mounts a named volume here so the model is downloaded once.
ENV HF_HOME=/hf
COPY policy.py egress.py classifier.py app.py llm.py mcp.py /app/
USER gateway
WORKDIR /app
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
