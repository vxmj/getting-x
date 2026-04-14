FROM oven/bun:alpine
 
WORKDIR /app

USER bun

COPY index.html .
COPY server.ts .

ENV PORT="7860"

EXPOSE 7860

CMD ["bun", "run", "server.ts"]
