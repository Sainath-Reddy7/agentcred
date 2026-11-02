FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[api]"

# persistent registry state (mount a volume here)
ENV AGENTCRED_STATE=/data
VOLUME /data

EXPOSE 8000
CMD ["uvicorn", "agentcred.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
