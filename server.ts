import { Resolver } from "node:dns/promises";
import * as crypto from "node:crypto";
import * as path from "node:path";

// ═══════════════════════════════════════════════════════════
//  基础配置 (极简纯原生版)
// ═══════════════════════════════════════════════════════════
const UUID = Bun.env.UUID ?? "3d6215c9-77b1-4cd6-a78a-2ab9d76582a2";
const XPATH = Bun.env.XPATH ?? "api/v1/telemetry/sync";
const SUB_PATH = Bun.env.SUB_PATH ?? "3d6215c9-77b1-4cd6-a78a-2ab9d76582a2";
const DOMAIN = Bun.env.DOMAIN ?? "userbotai-upswing.hf.space";
const NAME = Bun.env.NAME ?? "hug";
const PORT = parseInt(Bun.env.PORT ?? "7860", 10);
const LOG_LEVEL = parseInt(Bun.env.LOG_LEVEL ?? "1", 10);

const CFG = Object.freeze({
  XPATH_ENC: `%2F${XPATH.replace(/\//g, "%2F")}`,
  MAX_BUFFERED: 100,
  MAX_POST_BYTES: 2 * 1024 * 1024,
  MAX_SESSIONS: 5000,
  MAX_SESSION_AGE: 300_000,
  CONNECT_TIMEOUT: 30_000,
  ENABLE_UDP: Bun.env.ENABLE_UDP !== "false",
  DNS_POOL: ["1.1.1.1", "8.8.8.8"] as const,
});

// 【修复1】严格的环境变量逻辑判断 (true/1 才是开启)
const USE_CUSTOM_DNS = (() => {
  const v = Bun.env.USE_CUSTOM_DNS?.toLowerCase();
  return v === "true" || v === "1";
})();

const XHTTP_PATTERN = new RegExp(`^/${XPATH}/([^/?#]+)(?:/([0-9]+))?`);

// ═══════════════════════════════════════════════════════════
//  顶层全局缓存 (Perf: 拒绝在热路径重复计算)
// ═══════════════════════════════════════════════════════════
// 1. 缓存 UUID 字节数组
const CFG_UUID_BYTES = (() => {
  const hex = UUID.replaceAll("-", "");
  if (hex.length !== 32) throw new Error("启动失败: UUID格式不合法");
  return new Uint8Array(
    hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)),
  );
})();

// 2. 缓存文本解码器
const TEXT_DECODER = new TextDecoder();

// 3. 缓存订阅链接
const SUB_STRING =
  Buffer.from(
    `vless://${UUID}@${DOMAIN || "localhost"}:443?encryption=none&security=tls&sni=${DOMAIN || "localhost"}&fp=chrome&allowInsecure=0&type=xhttp&host=${DOMAIN || "localhost"}&path=${CFG.XPATH_ENC}&mode=packet-up#${NAME || "xhttp"}`,
  ).toString("base64") + "\n";

// ═══════════════════════════════════════════════════════════
//  极简日志系统
// ═══════════════════════════════════════════════════════════
const ts = () => {
  const d = new Date();
  return new Date(d.getTime() + 8 * 3600000).toISOString().substring(11, 19);
};

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

// ═══════════════════════════════════════════════════════════
//  线程安全的 DNS 解析器 (防并发冲突)
// ═══════════════════════════════════════════════════════════
// 【修复2】为每个 DNS 创建独立的 Resolver 实例，彻底避免全局 dns.setServers 的并发竞争污染
const dnsResolvers = CFG.DNS_POOL.map((ip) => {
  const r = new Resolver();
  r.setServers([ip]);
  return r;
});

function getHashIndex(str: string, max: number): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++)
    hash = (Math.imul(31, hash) + str.charCodeAt(i)) | 0;
  return Math.abs(hash) % max;
}

async function resolveHostname(hostname: string): Promise<string> {
  const resolver = dnsResolvers[getHashIndex(hostname, dnsResolvers.length)];
  const addrs = await resolver.resolve4(hostname).catch(() => null);
  if (addrs && addrs.length > 0) return addrs[0];
  throw new Error(`DNS解析失败: ${hostname}`);
}

// 【修复3】生成绝对规范的字符串Padding，避免 Base64 隐式转换隐患
function randomPad(min: number, max: number): string {
  const len = min + Math.floor(Math.random() * (max - min));
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let s = "";
  for (let i = 0; i < len; i++)
    s += chars.charAt(Math.floor(Math.random() * chars.length));
  return s;
}

// ═══════════════════════════════════════════════════════════
//  VLESS 头部极速解析
// ═══════════════════════════════════════════════════════════
interface VlessHeader {
  cmd: number;
  hostname: string;
  port: number;
  data: Uint8Array;
}

function parseVlessHeaderSync(chunk: Uint8Array): VlessHeader {
  if (chunk.length < 18) throw new Error("数据包过短");
  if (chunk[0] !== 0) throw new Error("不支持的协议版本");

  // 使用顶层缓存的 UUID 比对
  if (!crypto.timingSafeEqual(chunk.subarray(1, 17), CFG_UUID_BYTES)) {
    throw new Error("UUID验证失败");
  }

  const cmdOff = 18 + chunk[17];
  if (chunk.length < cmdOff + 4) throw new Error("头部不完整");

  const cmd = chunk[cmdOff];
  if (cmd !== 1 && cmd !== 2) throw new SilentError(`未知指令: ${cmd}`);

  const port = (chunk[cmdOff + 1] << 8) | chunk[cmdOff + 2];
  const atype = chunk[cmdOff + 3];
  let addrEnd = 0;
  let hostname = "";

  const addrStart = cmdOff + 4;
  if (atype === 1) {
    addrEnd = addrStart + 4;
    hostname = `${chunk[addrStart]}.${chunk[addrStart + 1]}.${chunk[addrStart + 2]}.${chunk[addrStart + 3]}`;
  } else if (atype === 2) {
    const domLen = chunk[addrStart];
    addrEnd = addrStart + 1 + domLen;
    // 使用顶层缓存的 Decoder
    hostname = TEXT_DECODER.decode(chunk.subarray(addrStart + 1, addrEnd));
  } else if (atype === 3) {
    addrEnd = addrStart + 16;
    const ipv6Buf = chunk.subarray(addrStart, addrEnd);
    hostname = Array.from({ length: 8 }, (_, i) =>
      ((ipv6Buf[i * 2] << 8) | ipv6Buf[i * 2 + 1]).toString(16),
    ).join(":");
  }

  return { cmd, hostname, port, data: chunk.subarray(addrEnd) };
}

// ═══════════════════════════════════════════════════════════
//  高性能 Session 管理 (Bun 原生网络)
// ═══════════════════════════════════════════════════════════
const sessions = new Map<string, Session>();
const RESP_SUCCESS = new Uint8Array([0x00, 0x00]);

setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now - s.lastActivity > CFG.MAX_SESSION_AGE) s.cleanup();
  }
}, 30_000).unref();

function concatU8(a: Uint8Array, b: Uint8Array): Uint8Array {
  const c = new Uint8Array(a.length + b.length);
  c.set(a, 0);
  c.set(b, a.length);
  return c;
}

class Session {
  readonly id: string;
  lastActivity: number = Date.now();

  private nextSeq: number = 0;
  private processing: boolean = false;
  private pending: Map<number, Uint8Array> = new Map();

  private remoteSocket: any = null;
  private remoteUdpSocket: any = null;

  private udpBuffer: Uint8Array = new Uint8Array(0);
  private downstreamController: ReadableStreamDefaultController | null = null;
  private cleaned: boolean = false;
  private targetHost: string = "";
  private targetPort: number = 0;

  private readyPromise: Promise<void>;
  private readyResolve!: () => void;
  private readyReject!: (err: Error) => void;

  constructor(id: string) {
    this.id = id;
    this.readyPromise = new Promise((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });
    this.readyPromise.catch(() => {});
  }

  bindDownstream(controller: ReadableStreamDefaultController) {
    this.downstreamController = controller;
  }

  resumeDownstream() {
    if (this.remoteSocket && !this.cleaned) this.remoteSocket.resume();
  }

  async receivePacket(seq: number, data: Uint8Array): Promise<void> {
    this.lastActivity = Date.now();
    this.pending.set(seq, data);
    if (this.pending.size > CFG.MAX_BUFFERED) throw new Error(`缓冲超限`);
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
          await this.initVLESS(data);
        } else {
          if (this.remoteSocket && !this.cleaned) {
            this.remoteSocket.write(data);
          } else if (this.remoteUdpSocket && !this.cleaned) {
            this.processUdpData(data);
          }
        }
        this.nextSeq++;
      }
    } finally {
      this.processing = false;
    }
  }

  private processUdpData(data: Uint8Array) {
    this.udpBuffer = concatU8(this.udpBuffer, data);
    while (this.udpBuffer.length >= 2) {
      const len = (this.udpBuffer[0] << 8) | this.udpBuffer[1];
      if (this.udpBuffer.length >= 2 + len) {
        const payload = this.udpBuffer.subarray(2, 2 + len);
        this.udpBuffer = this.udpBuffer.subarray(2 + len);
        if (this.remoteUdpSocket && !this.cleaned) {
          this.remoteUdpSocket.send(payload, this.targetPort, this.targetHost);
        }
      } else {
        break;
      }
    }
  }

  private async initVLESS(firstChunk: Uint8Array): Promise<void> {
    try {
      const header = parseVlessHeaderSync(firstChunk);
      if (header.hostname.includes(":")) throw new SilentError("不支持IPv6");

      const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(header.hostname);
      let target = header.hostname;
      if (!isIPv4 && USE_CUSTOM_DNS) {
        target = await resolveHostname(header.hostname).catch(
          () => header.hostname,
        );
      }

      this.targetHost = target;
      this.targetPort = header.port;
      const self = this;

      if (header.cmd === 1) {
        this.remoteSocket = await Bun.connect({
          hostname: target,
          port: header.port,
          socket: {
            data(socket, data) {
              self.lastActivity = Date.now();
              try {
                self.downstreamController?.enqueue(new Uint8Array(data));
                if (
                  self.downstreamController?.desiredSize !== null &&
                  self.downstreamController!.desiredSize <= 0
                ) {
                  socket.pause();
                }
              } catch (e) {
                self.cleanup();
              }
            },
            close() {
              self.cleanup();
            },
            error() {
              self.cleanup();
            },
          },
        });
        logger.info(`[+] TCP连通 ${header.hostname}:${header.port}`);
      } else if (header.cmd === 2) {
        if (!CFG.ENABLE_UDP) throw new SilentError("UDP被禁用");

        this.remoteUdpSocket = await Bun.udpSocket({
          socket: {
            data(socket, buf, port, addr) {
              self.lastActivity = Date.now();
              try {
                // 【修复4】极速 UDP 拼包，废弃 Spread 展开，使用 Uint8Array.set 手动对齐内存
                const packet = new Uint8Array(2 + buf.length);
                packet[0] = buf.length >> 8;
                packet[1] = buf.length & 0xff;
                packet.set(buf, 2);
                self.downstreamController?.enqueue(packet);
              } catch (e) {
                self.cleanup();
              }
            },
            error() {
              self.cleanup();
            },
            close() {
              self.cleanup();
            },
          },
        });
        logger.info(`[+] UDP连通 ${header.hostname}:${header.port}`);
      }

      try {
        this.downstreamController?.enqueue(RESP_SUCCESS);
      } catch (e) {
        throw new Error("流提前关闭");
      }

      if (header.data.length > 0) {
        if (header.cmd === 1) this.remoteSocket.write(header.data);
        else if (header.cmd === 2) this.processUdpData(header.data);
      }

      this.readyResolve();
    } catch (err: any) {
      if (isSilent(err)) logger.silent(`通道阻断: ${err.message}`);
      else logger.error(`连接失败: ${err.message}`);
      this.readyReject(err);
      this.cleanup();
    }
  }

  cleanup() {
    if (this.cleaned) return;
    this.cleaned = true;
    if (this.remoteSocket) {
      this.remoteSocket.end();
      this.remoteSocket = null;
    }
    if (this.remoteUdpSocket) {
      this.remoteUdpSocket.close();
      this.remoteUdpSocket = null;
    }
    this.pending.clear();
    sessions.delete(this.id);
    try {
      this.downstreamController?.close();
    } catch (e) {}
    logger.info(`[-] 通道释放 [${this.id.slice(0, 6)}]`);
  }
}

// ═══════════════════════════════════════════════════════════
//  Bun 原生 Web 服务器
// ═══════════════════════════════════════════════════════════
const BASE_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Cache-Control": "no-store",
  "X-Accel-Buffering": "no",
};

Bun.serve({
  port: PORT,
  idleTimeout: 255,

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const method = req.method;
    const pad = randomPad(100, 1000);

    if (method === "OPTIONS")
      return new Response(null, {
        status: 204,
        headers: { ...BASE_HEADERS, "X-Padding": pad },
      });

    if (url.pathname === "/" || url.pathname === "/index.html") {
      try {
        return new Response(
          Bun.file(path.join(import.meta.dir, "index.html")),
          { headers: { "Content-Type": "text/html; charset=utf-8" } },
        );
      } catch {
        return new Response(
          `<!DOCTYPE html><html><body><h1>It works!</h1></body></html>`,
          { headers: { "Content-Type": "text/html" } },
        );
      }
    }

    if (url.pathname === `/${SUB_PATH}`)
      return new Response(SUB_STRING, {
        headers: { "Content-Type": "text/plain" },
      });

    const match = url.pathname.match(XHTTP_PATTERN);
    if (!match) return Response.redirect("/", 302);

    const sessionId = match[1];
    const seq = match[2] !== undefined ? parseInt(match[2], 10) : null;

    if (method === "GET" && seq === null) {
      if (sessions.size >= CFG.MAX_SESSIONS && !sessions.has(sessionId))
        return new Response("503 Server Busy", { status: 503 });

      let session = sessions.get(sessionId) ?? new Session(sessionId);
      sessions.set(sessionId, session);

      const stream = new ReadableStream({
        start(controller) {
          session.bindDownstream(controller);
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
          "X-Padding": pad,
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
        // 【修复5】拥抱 Bun 终极杀手锏 req.bytes()，跳过 ArrayBuffer 包装，实现内存零拷贝！
        const reqBytes = await req.bytes();
        if (reqBytes.byteLength > CFG.MAX_POST_BYTES)
          return new Response(null, { status: 413 });
        await session.receivePacket(seq, reqBytes);
        return new Response(null, {
          status: 200,
          headers: { ...BASE_HEADERS, "X-Padding": pad },
        });
      } catch (err: any) {
        if (err.message.includes("缓冲超限")) session.cleanup();
        return new Response(null, { status: 500 });
      }
    }

    return new Response("404 Not Found", { status: 404 });
  },
});

console.log("╔══════════════════════════════════════════╗");
console.log(`║  VLESS + XHTTP [架构师级极致进化版]      ║`);
console.log("╠══════════════════════════════════════════╣");
console.log(`║  端口号 : ${String(PORT).padEnd(29)}║`);
console.log(
  `║  UDP状态: ${String(CFG.ENABLE_UDP ? "原生驱动 (已解锁)" : "已禁用").padEnd(25)}║`,
);
console.log(
  `║  DNS状态: ${String(USE_CUSTOM_DNS ? "独立线程安全池" : "Bun底层原生").padEnd(25)}║`,
);
console.log("╚══════════════════════════════════════════╝");
