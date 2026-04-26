FROM oven/bun:alpine
 
WORKDIR /app

USER bun

COPY index.html .
COPY server.ts .

ENV PORT="8080"
ENV APP_KEY="B95A80E2-BE6F-40F9-9B68-452E4DA3EF41"
ENV APP_PATH="/api"

EXPOSE 8080

CMD ["bun", "run", "server.ts"]
