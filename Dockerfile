FROM node:22-alpine AS web-build
WORKDIR /web
COPY web/package*.json web/pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm run build

FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir ".[api]"
COPY --from=web-build /web/dist ./web/dist
COPY examples/ ./examples/
COPY output/ ./output/
EXPOSE 8000
CMD ["uvicorn", "aegisflow.api:app", "--host", "0.0.0.0", "--port", "8000"]
