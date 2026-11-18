# SPDX-License-Identifier: Apache-2.0
# Allowlist egress proxy for the Attack Box (see egress_proxy.py). Standard library only.
FROM python:3.12-slim
COPY egress_proxy.py /egress/egress_proxy.py
RUN mkdir -p /var/log/egress && chown 65534:65534 /var/log/egress
USER 65534:65534
ENV PYTHONUNBUFFERED=1
EXPOSE 3128
ENTRYPOINT ["python3", "-I", "/egress/egress_proxy.py"]
