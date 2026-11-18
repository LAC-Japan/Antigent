# SPDX-License-Identifier: Apache-2.0
# Docker API guard for the defense plane (see docker_api_guard.py). Standard library only.
# Runs as root only to open the root-owned docker.sock; all capabilities are dropped in compose.
FROM python:3.12-slim
COPY docker_api_guard.py /guard/docker_api_guard.py
ENV PYTHONUNBUFFERED=1
EXPOSE 2375
ENTRYPOINT ["python3", "-I", "/guard/docker_api_guard.py"]
