FROM oven/bun:alpine
 
WORKDIR /app

USER bun

COPY index.html .
COPY server.ts .

ENV PORT="7860"
ENV DOMAIN="userbotai-upswing.hf.space"
ENV UUID="3d6215c9-77b1-4cd6-a78a-2ab9d76582a2"
ENV SUB_PATH="3d6215c9-77b1-4cd6-a78a-2ab9d76582a2"
ENV USE_CUSTOM_DNS=""

EXPOSE 7860

CMD ["bun", "run", "server.ts"]
