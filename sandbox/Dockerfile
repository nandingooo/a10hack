# Agent sandbox image: one container per session.
# Nothing sensitive is baked in. Files reach the agent only through gateway tools.
FROM python:3.12-slim

RUN pip install --no-cache-dir requests==2.32.3 \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin agent

USER agent
WORKDIR /home/agent/work

# Placeholder until the agent loop exists; the manager can override the command.
CMD ["sleep", "infinity"]
