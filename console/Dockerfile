# Antigent Console (viewer) -- part of the defense plane.
# Tails the event log under /console/runs and shows it in a browser. It has NO Docker
# access and no command execution (display-only). eval/streams.py merges the streams;
# eval/metrics.py summarises a run (also runnable on the host: python3 eval/metrics.py runs/demo).
FROM python:3.12-slim
WORKDIR /console
COPY server.py /console/
COPY static/ /console/static/
COPY eval/ /console/eval/
COPY scenarios/ /console/scenarios/
RUN mkdir -p /console/runs/defense /console/runs/attacker /console/runs/console
# Runs as root on purpose: ./runs is a host bind mount that Docker on Linux creates as
# root, and the console must write runs/console/. It holds no Docker socket or secrets.
ENV ANTIGENT_HOST=0.0.0.0 ANTIGENT_PORT=8765 \
    ANTIGENT_SCENARIO=/console/scenarios/cicd-goat PYTHONUNBUFFERED=1
EXPOSE 8765
CMD ["python", "server.py"]
