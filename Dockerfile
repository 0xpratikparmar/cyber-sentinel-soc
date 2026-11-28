FROM node:22-bookworm-slim
WORKDIR /app
COPY --chown=node:node . .
RUN mkdir -p /app/data && chown node:node /app/data
USER node
ENV SOC_BIND=0.0.0.0 PORT=8000 SOC_ORIGIN=http://127.0.0.1:8000
EXPOSE 8000
CMD ["node","server/start.mjs"]
