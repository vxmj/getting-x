import * as crypto from "node:crypto";

const APP_KEY = Bun.env.APP_KEY ?? "B95A80E2-BE6F-40F9-9B68-452E4DA3EF41";
const APP_PATH = Bun.env.APP_PATH ?? "api/v1/telemetry/sync";
const PORT = parseInt(Bun.env.PORT ?? "7860", 10);
const LOG_LEVEL = parseInt(Bun.env.LOG_LEVEL ?? "1", 10);

const CFG = Object.freeze({
  MAX_BUFFERED: 100,
  MAX_POST_BYTES: 2 * 1024 * 1024,
  MAX_SESSIONS: 5000,
  MAX_SESSION_AGE: 300_000,
  ENABLE_UDP: Bun.env.ENABLE_UDP !== "false",
});

const XHTTP_PATTERN = new RegExp(`^/${APP_PATH}/([^/?#]+)(?:/([0-9]+))?`);

const CFG_UUID_BYTES = (() => {
  const hex = APP_KEY.replaceAll("-", "");
  if (hex.length !== 32) throw new Error("启动失败: APP_KEY格式不合法");
  return new Uint8Array(hex.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
})();

const TEXT_DECODER = new TextDecoder();
const RESP_SUCCESS = new Uint8Array([0x00, 0x00]);
const INDEX_HTML = import.meta.dir + "/index.html";

const ts = () =>
  new Date(Date.now() + 8 * 3_600_000).toISOString().slice(11, 19);

const logger = {
  error: (...a: unknown[]) =>
    LOG_LEVEL >= 1 && console.error(`\x1b[31m[错误]\x1b[0m [${ts()}]`, ...a),
  info: (...a: unknown[]) =>
    LOG_LEVEL >= 2 && console.log(`\x1b[32m[信息]\x1b[0m [${ts()}]`, ...a),
  debug: (...a: unknown[]) =>
    LOG_LEVEL >= 3 && console.log(`\x1b[90m[调试]\x1b[0m [${ts()}]`, ...a),
  silent: (...a: unknown[]) =>
    LOG_LEVEL >= 3 && console.log(`\x1b[33m[拦截]\x1b[0m [${ts()}]`, ...a),
};

class SilentError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "SilentError";
  }
}
const isSilent = (e: unknown): boolean =>
  e instanceof SilentError || (e as any)?.silent === true;

function randomPad(min: number, max: number): string {
  const len = min + Math.floor(Math.random() * (max - min));
  return crypto
    .randomBytes(Math.ceil(len / 2))
    .toString("hex")
    .slice(0, len);
}

const PRIVATE_IP_RE =
  /^(127\.|0\.|10\.|192\.168\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\.|172\.(1[6-9]|2\d|3[01])\.)/;

function isPrivateIP(ip: string): boolean {
  return PRIVATE_IP_RE.test(ip);
}

function concatU8(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length === 0) return b;
  if (b.length === 0) return a;
  const c = new Uint8Array(a.length + b.length);
  c.set(a);
  c.set(b, a.length);
  return c;
}

interface AitestHeader {
  cmd: number;
  hostname: string;
  port: number;
  data: Uint8Array;
}

function parseAitestHeaderSync(chunk: Uint8Array): AitestHeader {
  if (chunk.length < 18) throw new Error("数据包过短");
  if (chunk[0] !== 0) throw new Error("不支持的协议版本");
  if (!crypto.timingSafeEqual(chunk.subarray(1, 17), CFG_UUID_BYTES))
    throw new Error("UUID验证失败");

  const cmdOff = 18 + chunk[17];
  if (chunk.length < cmdOff + 4) throw new Error("头部不完整");

  const cmd = chunk[cmdOff];
  if (cmd !== 1 && cmd !== 2) throw new SilentError(`未知指令: ${cmd}`);

  const port = (chunk[cmdOff + 1] << 8) | chunk[cmdOff + 2];
  const atype = chunk[cmdOff + 3];
  const addrStart = cmdOff + 4;
  let addrEnd = 0;
  let hostname = "";

  if (atype === 1) {
    addrEnd = addrStart + 4;
    hostname = `${chunk[addrStart]}.${chunk[addrStart + 1]}.${chunk[addrStart + 2]}.${chunk[addrStart + 3]}`;
  } else if (atype === 2) {
    const domLen = chunk[addrStart];
    addrEnd = addrStart + 1 + domLen;
    hostname = TEXT_DECODER.decode(chunk.subarray(addrStart + 1, addrEnd));
  } else if (atype === 3) {
    addrEnd = addrStart + 16;
    const b = chunk.subarray(addrStart, addrEnd);
    hostname = [0, 2, 4, 6, 8, 10, 12, 14]
      .map((i) => ((b[i] << 8) | b[i + 1]).toString(16))
      .join(":");
  } else {
    throw new Error(`不支持的地址类型: ${atype}`);
  }

  return { cmd, hostname, port, data: chunk.subarray(addrEnd) };
}

const sessions = new Map<string, Session>();

setInterval(() => {
  const now = Date.now();
  for (const [, s] of sessions)
    if (now - s.lastActivity > CFG.MAX_SESSION_AGE) s.cleanup();
}, 30_000).unref();

class Session {
  readonly id: string;
  lastActivity: number = Date.now();

  private nextSeq: number = 0;
  private processing: boolean = false;
  private pending: Map<number, Uint8Array> = new Map();

  private remoteSocket: any = null;
  private remoteUdpSocket: any = null;
  private udpBuffer: Uint8Array = new Uint8Array(0);
  private controller: ReadableStreamDefaultController<Uint8Array> | null = null;
  private cleaned: boolean = false;
  private targetHost: string = "";
  private targetPort: number = 0;

  private readyResolve!: () => void;
  private readyReject!: (err: Error) => void;
  private readyPromise: Promise<void>;

  constructor(id: string) {
    this.id = id;
    this.readyPromise = new Promise<void>((res, rej) => {
      this.readyResolve = res;
      this.readyReject = rej;
    });
    this.readyPromise.catch(() => {});
  }

  bindDownstream(controller: ReadableStreamDefaultController<Uint8Array>) {
    this.controller = controller;
  }

  resumeDownstream() {
    if (this.remoteSocket && !this.cleaned) this.remoteSocket.resume();
  }

  async receivePacket(seq: number, data: Uint8Array): Promise<void> {
    this.lastActivity = Date.now();
    this.pending.set(seq, data);
    if (this.pending.size > CFG.MAX_BUFFERED) throw new Error("缓冲超限");
    await this.drain();
  }

  private async drain(): Promise<void> {
    if (this.processing) return;
    this.processing = true;
    try {
      while (this.pending.has(this.nextSeq)) {
        const data = this.pending.get(this.nextSeq)!;
        this.pending.delete(this.nextSeq);

        if (this.nextSeq === 0) {
          await this.initAITest(data);
        } else if (this.remoteSocket && !this.cleaned) {
          try {
            this.remoteSocket.write(data);
          } catch {
            this.cleanup();
          }
        } else if (this.remoteUdpSocket && !this.cleaned) {
          this.processUdpData(data);
        }
        this.nextSeq++;
      }
    } finally {
      this.processing = false;
    }
  }

  private processUdpData(data: Uint8Array): void {
    this.udpBuffer = concatU8(this.udpBuffer, data);
    while (this.udpBuffer.length >= 2) {
      const len = (this.udpBuffer[0] << 8) | this.udpBuffer[1];
      if (this.udpBuffer.length < 2 + len) break;
      const payload = this.udpBuffer.subarray(2, 2 + len);
      this.udpBuffer = this.udpBuffer.subarray(2 + len);
      if (this.remoteUdpSocket && !this.cleaned) {
        try {
          this.remoteUdpSocket.send(payload, this.targetPort, this.targetHost);
        } catch {}
      }
    }
  }

  private readonly tcpHandlers = {
    data: (socket: any, data: Buffer) => {
      this.lastActivity = Date.now();
      try {
        this.controller?.enqueue(new Uint8Array(data));
        if (
          this.controller?.desiredSize !== null &&
          this.controller!.desiredSize <= 0
        )
          socket.pause();
      } catch {
        this.cleanup();
      }
    },
    close: () => this.cleanup(),
    error: () => this.cleanup(),
  };

  private readonly udpHandlers = {
    data: (_socket: any, buf: Buffer) => {
      this.lastActivity = Date.now();
      try {
        const packet = new Uint8Array(2 + buf.length);
        packet[0] = buf.length >> 8;
        packet[1] = buf.length & 0xff;
        packet.set(buf, 2);
        this.controller?.enqueue(packet);
      } catch {
        this.cleanup();
      }
    },
    error: () => this.cleanup(),
    close: () => this.cleanup(),
  };

  private async initAITest(firstChunk: Uint8Array): Promise<void> {
    try {
      const header = parseAitestHeaderSync(firstChunk);
      if (header.hostname.includes(":")) throw new SilentError("不支持IPv6");

      this.targetHost = header.hostname;
      this.targetPort = header.port;

      if (isPrivateIP(this.targetHost))
        throw new SilentError(`SSRF拦截: 禁止访问私有地址 ${this.targetHost}`);

      if (header.cmd === 1) {
        this.remoteSocket = await Bun.connect({
          hostname: this.targetHost,
          port: this.targetPort,
          socket: this.tcpHandlers,
        });
        logger.info(`[+] T连 ${header.hostname}:${header.port}`);
      } else {
        if (!CFG.ENABLE_UDP) throw new SilentError("U禁");
        this.remoteUdpSocket = await Bun.udpSocket({
          socket: this.udpHandlers,
        });
        logger.info(`[+] U连 ${header.hostname}:${header.port}`);
      }

      try {
        this.controller?.enqueue(RESP_SUCCESS);
      } catch {
        throw new Error("流提前关闭");
      }

      if (header.data.length > 0) {
        if (header.cmd === 1)
          try {
            this.remoteSocket!.write(header.data);
          } catch {}
        else this.processUdpData(header.data);
      }

      this.readyResolve();
    } catch (err: any) {
      if (isSilent(err)) logger.silent(`通道阻断: ${err.message}`);
      else logger.error(`连接失败: ${err.message}`);
      this.readyReject(err);
      this.cleanup();
    }
  }

  cleanup(): void {
    if (this.cleaned) return;
    this.cleaned = true;
    this.remoteSocket?.end();
    this.remoteSocket = null;
    this.remoteUdpSocket?.close();
    this.remoteUdpSocket = null;
    this.pending.clear();
    sessions.delete(this.id);
    try {
      this.controller?.close();
    } catch {}
    logger.info(`[-] 释放 [${this.id.slice(0, 6)}]`);
  }
}

const BASE_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Cache-Control": "no-store",
  "X-Accel-Buffering": "no",
} as const;

Bun.serve({
  port: PORT,
  idleTimeout: 255,

  async fetch(req: Request): Promise<Response> {
    const { pathname } = new URL(req.url);
    const method = req.method;

    if (method === "OPTIONS")
      return new Response(null, {
        status: 204,
        headers: { ...BASE_HEADERS, "X-Padding": randomPad(100, 1000) },
      });

    if (pathname === "/" || pathname === "/index.html") {
      try {
        return new Response(Bun.file(INDEX_HTML), {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      } catch {
        return new Response(
          `<!DOCTYPE html><html><body><h1>It works!</h1></body></html>`,
          { headers: { "Content-Type": "text/html" } },
        );
      }
    }

    const match = pathname.match(XHTTP_PATTERN);
    if (!match) return Response.redirect("/", 302);

    const sessionId = match[1];
    const seq = match[2] !== undefined ? parseInt(match[2], 10) : null;

    if (method === "GET" && seq === null) {
      if (sessions.size >= CFG.MAX_SESSIONS && !sessions.has(sessionId))
        return new Response("503 Server Busy", { status: 503 });

      const session = sessions.get(sessionId) ?? new Session(sessionId);
      sessions.set(sessionId, session);

      const stream = new ReadableStream<Uint8Array>({
        start(ctrl) {
          session.bindDownstream(ctrl);
        },
        pull() {
          session.resumeDownstream();
        },
        cancel() {
          session.cleanup();
        },
      });

      return new Response(stream, {
        headers: {
          ...BASE_HEADERS,
          "Content-Type": "application/octet-stream",
          Connection: "keep-alive",
          "X-Padding": randomPad(100, 1000),
        },
      });
    }

    if (method === "POST" && seq !== null) {
      let session = sessions.get(sessionId);
      if (!session) {
        if (sessions.size >= CFG.MAX_SESSIONS)
          return new Response(null, { status: 503 });
        session = new Session(sessionId);
        sessions.set(sessionId, session);
      }

      try {
        const body = await req.bytes();
        if (body.byteLength > CFG.MAX_POST_BYTES)
          return new Response(null, { status: 413 });

        await session.receivePacket(seq, body);
        return new Response(null, {
          status: 200,
          headers: { ...BASE_HEADERS, "X-Padding": randomPad(100, 1000) },
        });
      } catch (err: any) {
        if (err.message?.includes("缓冲超限")) session.cleanup();
        return new Response(null, { status: 500 });
      }
    }

    return new Response("404 Not Found", { status: 404 });
  },
});

console.log(`运行中～`);
