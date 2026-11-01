FROM rust:1.96.0-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends procps python3 \
 && rm -rf /var/lib/apt/lists/*
