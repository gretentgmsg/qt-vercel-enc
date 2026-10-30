#!/usr/bin/env node
'use strict';

/*
 * 精简加固版：仅保留 VLESS + Trojan (WebSocket)。
 * 已移除：哪吒探针、AUTO_ACCESS 保活上报、SS 节点(无认证)、第三方 IP/ISP 查询、调试日志。
 * 唯一依赖：ws
 *
 * 环境变量：
 *   UUID          必填，合法 UUID（8-4-4-4-12 十六进制）
 *   SUB_PATH      订阅路径，建议 ≥16 位随机串；未设置/过短则关闭订阅接口
 *   DOMAIN        订阅里使用的域名（不设置则取请求的 Host）
 *   NAME          节点名称，默认 Proxy
 *   WSPATH        可选，WebSocket 路径；默认由 UUID 派生的 16 位十六进制串
 *   PORT          监听端口，默认 3000
 *   MAX_CONN      最大并发隧道数，默认 100
 *   IDLE_TIMEOUT  单连接空闲超时(秒)，默认 300
 *   ALLOWED_HOSTS 可选，逗号分隔的 Host 白名单（注意：看到的是 Vercel 收到的 Host）
 *   FRONT_KEY     可选，前置密钥；设置后仅接受带匹配 x-front-key 头的请求，其余一律 404（配合 CF Worker 注入）
 *   REQ_LIMIT     每 IP 每分钟请求上限（HTTP + WS 升级合计），默认 200，超出返回 404
 *   SHOW_LOG        设为 1 时输出调试日志：每个 HTTP 请求、WS 升级、认证结果、隧道状态
 *
 * VLESS Encryption（可选，设置后 WSPATH 上跑的是加密 VLESS，平台/CDN 看不到 UUID 与目标地址）：
 *   VLESS_DECRYPTION  服务端 decryption 串，如 mlkem768x25519plus.native.0s.<私钥>
 *                     （Serverless 多实例，建议票据时间用 0s，即只用 1-RTT；生成：node vlessenc.js gen）
 *   VLESS_ENCRYPTION  可选，订阅里给客户端的 encryption 串；不设置则由 decryption 自动推导
 *   flow              订阅默认带 flow=xtls-rprx-vision（仅加密节点；明文 VLESS/Trojan 不支持 Vision，不带）
 *   ALLOW_PLAIN       设为 1 时，额外在 WSPATH-plain 上保留原来的明文 VLESS/Trojan
 *   依赖：ws、@noble/hashes、@noble/post-quantum（需要 Node >= 20.19）
 */

const http = require('http');
const net = require('net');
const dns = require('dns');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const wsLib = require('ws');
const WebSocketServer = wsLib.WebSocketServer || wsLib.Server;
const createWebSocketStream = wsLib.createWebSocketStream;

// ========================== 配置 ==========================
const env = (k, d = '') => (process.env[k] === undefined ? d : String(process.env[k]).trim());

const UUID = env('UUID').toLowerCase();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
if (!UUID_RE.test(UUID)) {
  console.error('[FATAL] 环境变量 UUID 缺失或格式不合法，需为 8-4-4-4-12 位十六进制 UUID。');
  process.exit(1);
}

const DOMAIN = env('DOMAIN');
const NAME = env('NAME', 'Proxy');
const PORT = parseInt(env('PORT', '3000'), 10) || 3000;
const MAX_CONN = parseInt(env('MAX_CONN', '100'), 10) || 100;
const IDLE_MS = (parseInt(env('IDLE_TIMEOUT', '300'), 10) || 300) * 1000;

const WSPATH = (env('WSPATH') ||
  crypto.createHash('sha256').update('ws:' + UUID).digest('hex').slice(0, 16)).replace(/^\/+/, '');
if (!/^[A-Za-z0-9._~-]+$/.test(WSPATH)) {
  console.error('[FATAL] WSPATH 只能包含字母、数字及 . _ ~ -');
  process.exit(1);
}
const WS_PATH = '/' + WSPATH;
const PLAIN_WS_PATH = WS_PATH + '-plain';

// VLESS Encryption：ENC 在 start() 中初始化
const ENC_STR = env('VLESS_DECRYPTION');
const ALLOW_PLAIN = env('ALLOW_PLAIN') === '1';
let ENC = null;
let ENC_CLIENT = '';

const SUB_PATH = env('SUB_PATH').replace(/^\/+/, '');
const SUB_ENABLED = SUB_PATH.length >= 12 && /^[A-Za-z0-9._~-]+$/.test(SUB_PATH);

const ALLOWED_HOSTS = env('ALLOWED_HOSTS').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

const FRONT_KEY = env('FRONT_KEY');
const FRONT_KEY_BUF = FRONT_KEY ? Buffer.from(FRONT_KEY) : null;
const REQ_LIMIT = parseInt(env('REQ_LIMIT', '200'), 10) || 200;
const REQ_WINDOW = 60 * 1000;

const SHOW_LOG = env('SHOW_LOG') === '1';
function dlog(...a) { if (SHOW_LOG) console.log(...a); }

const UUID_BUF = Buffer.from(UUID.replace(/-/g, ''), 'hex');
const TROJAN_HASH = Buffer.from(crypto.createHash('sha224').update(UUID).digest('hex')); // 56 字节 ASCII

const BLOCKED_PORTS = new Set([25, 135, 137, 138, 139, 445]);
const BLOCKED_DOMAINS = [
  'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
  'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
];

const FAIL_LIMIT = 10;                 // 窗口内允许的认证失败次数
const FAIL_WINDOW = 10 * 60 * 1000;    // 失败计数窗口
const FIRST_MSG_TIMEOUT = 10 * 1000;   // 握手后必须在此时间内发出首包
const CONNECT_TIMEOUT = 10 * 1000;     // 出站连接超时

// ========================== 页面与响应 ==========================
const PAGE_HTML = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
  '<meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome</title>' +
  '<style>body{font-family:system-ui,sans-serif;margin:15vh auto;max-width:32rem;padding:0 1rem;color:#333}' +
  'h1{font-weight:500}</style></head><body><h1>Welcome</h1>' +
  '<p>This site is under construction. Please check back later.</p></body></html>';
const NOT_FOUND_HTML = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>404 Not Found</title></head>' +
  '<body><h1>404 Not Found</h1></body></html>';

let INDEX_HTML = PAGE_HTML;
try { INDEX_HTML = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8'); } catch (e) { /* 使用默认页 */ }

const COMMON_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cache-Control': 'no-store'
};

function send(res, code, type, body) {
  res.writeHead(code, { ...COMMON_HEADERS, 'Content-Type': type, 'Content-Length': Buffer.byteLength(body) });
  res.end(res.req && res.req.method === 'HEAD' ? undefined : body);
}

function rejectUpgrade(socket, why) {
  dlog('[ws] upgrade rejected:', why);
  try {
    socket.write('HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\n' +
      'Content-Length: ' + Buffer.byteLength(NOT_FOUND_HTML) + '\r\nConnection: close\r\n\r\n' + NOT_FOUND_HTML);
  } catch (e) { /* ignore */ }
  socket.destroy();
}

// ========================== 限流 / 封禁 ==========================
const buckets = new Map();
function hit(key, limit, windowMs) {
  const now = Date.now();
  const b = buckets.get(key);
  if (!b || now - b.t > windowMs) { buckets.set(key, { t: now, n: 1 }); return false; }
  b.n++;
  return b.n > limit;
}
function isBanned(ip) {
  const b = buckets.get('fail:' + ip);
  return !!b && Date.now() - b.t <= FAIL_WINDOW && b.n > FAIL_LIMIT;
}
function strike(ip) { hit('fail:' + ip, FAIL_LIMIT, FAIL_WINDOW); }
function frontOK(req) {
  if (!FRONT_KEY_BUF) return true;
  const v = req.headers['x-front-key'];
  if (typeof v !== 'string') return false;
  const a = Buffer.from(v);
  return a.length === FRONT_KEY_BUF.length && crypto.timingSafeEqual(a, FRONT_KEY_BUF);
}
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) if (now - b.t > 3600 * 1000) buckets.delete(k);
}, 10 * 60 * 1000).unref();

function clientIP(req) {
  const h = req.headers;
  const v = h['cf-connecting-ip'] || h['x-real-ip'] || (h['x-forwarded-for'] || '').split(',')[0].trim();
  return String(v || req.socket.remoteAddress || 'unknown');
}

function hostAllowed(req) {
  if (!ALLOWED_HOSTS.length) return true;
  const h = (req.headers.host || '').split(':')[0].toLowerCase();
  return ALLOWED_HOSTS.includes(h);
}

// ========================== 目标地址校验（防 SSRF / 内网访问） ==========================
function v6groups(ip) {
  let s = ip.toLowerCase().split('%')[0];
  const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const p = v4[1].split('.').map(Number);
    s = s.slice(0, -v4[1].length) + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16);
  }
  const idx = s.indexOf('::');
  if (idx === -1) return s.split(':').map(x => parseInt(x, 16));
  const head = s.slice(0, idx) ? s.slice(0, idx).split(':') : [];
  const tail = s.slice(idx + 2) ? s.slice(idx + 2).split(':') : [];
  const fill = new Array(Math.max(0, 8 - head.length - tail.length)).fill(0);
  return [...head.map(x => parseInt(x, 16)), ...fill, ...tail.map(x => parseInt(x, 16))];
}

function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const [a, b, c] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0 && c === 0) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224;
  }
  if (net.isIPv6(ip)) {
    const g = v6groups(ip);
    if (g.length !== 8 || g.some(x => Number.isNaN(x))) return true;
    const v4of = (hi, lo) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
    if (g.slice(0, 5).every(x => x === 0)) {
      if (g[5] === 0xffff) return isPrivateIP(v4of(g[6], g[7])); // ::ffff:a.b.c.d
      if (g[5] === 0) return true;                                // ::, ::1, ::/96
    }
    if (g[0] === 0x64 && g[1] === 0xff9b) return isPrivateIP(v4of(g[6], g[7])); // NAT64
    if (g[0] === 0x2002) return isPrivateIP(v4of(g[1], g[2]));                  // 6to4
    if ((g[0] & 0xfe00) === 0xfc00) return true;  // fc00::/7
    if ((g[0] & 0xffc0) === 0xfe80) return true;  // fe80::/10
    if ((g[0] >> 8) === 0xff) return true;        // ff00::/8
    return false;
  }
  return true; // 无法识别 → 拦截
}

function isBlockedDomain(host) {
  const h = host.toLowerCase();
  return BLOCKED_DOMAINS.some(d => h === d || h.endsWith('.' + d));
}

function isBlockedTarget(host, port) {
  if (!host || host.length > 253 || !port) return true;
  if (BLOCKED_PORTS.has(port)) return true;
  if (isBlockedDomain(host)) return true;
  if (net.isIP(host) && isPrivateIP(host)) return true;
  return false;
}

// 解析后再校验 IP（域名解析到内网地址、DNS 重绑定同样会被拦截）
function safeLookup(hostname, options, cb) {
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return cb(err);
    if (Array.isArray(address)) {
      const ok = address.filter(a => !isPrivateIP(a.address));
      if (!ok.length) return cb(new Error('blocked'));
      return cb(null, ok);
    }
    if (isPrivateIP(address)) return cb(new Error('blocked'));
    cb(null, address, family);
  });
}

// ========================== 协议解析 ==========================
function ipv6From(buf, i) {
  const parts = [];
  for (let k = 0; k < 8; k++) parts.push(buf.readUInt16BE(i + k * 2).toString(16));
  return parts.join(':');
}

// VLESS: 版本1 + UUID16 + 附加信息长度1 + 附加信息 + 命令1 + 端口2 + 地址类型1 + 地址
function parseVless(msg) {
  if (msg.length < 22) return null;
  let i = 18 + msg[17];
  if (msg.length < i + 4) return null;
  if (msg[i++] !== 1) return null;                 // 仅支持 TCP
  const port = msg.readUInt16BE(i); i += 2;
  const atyp = msg[i++];
  let host;
  if (atyp === 1) {
    if (msg.length < i + 4) return null;
    host = `${msg[i]}.${msg[i + 1]}.${msg[i + 2]}.${msg[i + 3]}`; i += 4;
  } else if (atyp === 2) {
    const l = msg[i++];
    if (!l || msg.length < i + l) return null;
    host = msg.toString('utf8', i, i + l); i += l;
  } else if (atyp === 3) {
    if (msg.length < i + 16) return null;
    host = ipv6From(msg, i); i += 16;
  } else return null;
  return { host, port, payload: msg.subarray(i), version: msg[0] };
}

// Trojan: SHA224(密码)hex(56) + CRLF + 命令1 + 地址类型1 + 地址 + 端口2 + CRLF + 数据
function parseTrojan(msg) {
  if (msg.length < 62) return null;
  if (!crypto.timingSafeEqual(msg.subarray(0, 56), TROJAN_HASH)) return null;
  let i = 56;
  if (msg[i] === 0x0d && msg[i + 1] === 0x0a) i += 2;
  if (msg[i++] !== 1) return null;                 // 仅支持 CONNECT
  const atyp = msg[i++];
  let host;
  if (atyp === 1) {
    if (msg.length < i + 4) return null;
    host = `${msg[i]}.${msg[i + 1]}.${msg[i + 2]}.${msg[i + 3]}`; i += 4;
  } else if (atyp === 3) {
    const l = msg[i++];
    if (!l || msg.length < i + l) return null;
    host = msg.toString('utf8', i, i + l); i += l;
  } else if (atyp === 4) {
    if (msg.length < i + 16) return null;
    host = ipv6From(msg, i); i += 16;
  } else return null;
  if (msg.length < i + 2) return null;
  const port = msg.readUInt16BE(i); i += 2;
  if (msg[i] === 0x0d && msg[i + 1] === 0x0a) i += 2;
  return { host, port, payload: msg.subarray(i) };
}

// ========================== 隧道 ==========================
let activeConns = 0;

function openTunnel(ws, t, isVless) {
  const duplex = createWebSocketStream(ws);   // 先创建，缓冲连接建立期间到达的数据
  duplex.on('error', () => {});
  if (isVless) ws.send(Buffer.from([t.version, 0]));

  const socket = net.connect({ host: t.host, port: t.port, lookup: safeLookup });
  socket.setNoDelay(true);
  socket.setTimeout(IDLE_MS, () => socket.destroy());
  const ct = setTimeout(() => socket.destroy(), CONNECT_TIMEOUT);

  socket.once('connect', () => {
    clearTimeout(ct);
    dlog(`[tunnel] upstream connected ${t.host}:${t.port}`);
    if (t.payload.length) socket.write(t.payload);
    duplex.pipe(socket);
    socket.pipe(duplex);
  });
  socket.on('error', e => { dlog(`[tunnel] upstream error ${t.host}:${t.port}: ${e && e.message}`); clearTimeout(ct); socket.destroy(); duplex.destroy(); });
  socket.on('close', () => { clearTimeout(ct); if (!duplex.writableEnded) duplex.end(); });
  ws.on('close', () => { clearTimeout(ct); socket.destroy(); });
}

function fail(ws, ip) {
  strike(ip);
  setTimeout(() => { try { ws.terminate(); } catch (e) { /* ignore */ } }, 1000 + Math.random() * 3000);
}

function onConnection(ws, ip) {
  activeConns++;
  dlog(`[ws] plain conn ip=${ip} active=${activeConns}`);
  ws.on('close', () => { activeConns--; });
  ws.on('error', () => {});

  const timer = setTimeout(() => { dlog(`[ws] first msg timeout ip=${ip}`); try { ws.terminate(); } catch (e) { /* ignore */ } }, FIRST_MSG_TIMEOUT);

  ws.once('message', data => {
    clearTimeout(timer);
    const msg = Buffer.isBuffer(data) ? data : Buffer.from(data);

    let target = null, isVless = false;
    if (msg.length > 17 && msg[0] === 0 && crypto.timingSafeEqual(msg.subarray(1, 17), UUID_BUF)) {
      target = parseVless(msg);
      isVless = true;
    } else {
      target = parseTrojan(msg);
    }

    if (!target) {                                            // 认证/解析失败：计入失败次数
      dlog(`[ws] auth/parse fail ip=${ip} len=${msg.length} first=0x${msg[0] === undefined ? '-' : msg[0].toString(16)}`);
      return fail(ws, ip);
    }
    if (isBlockedTarget(target.host, target.port)) {         // 已认证但目标被禁止：直接断开
      dlog(`[ws] blocked target ${target.host}:${target.port}`);
      try { ws.close(); } catch (e) { /* ignore */ }
      return;
    }
    dlog(`[ws] ${isVless ? 'vless' : 'trojan'} tunnel open ${target.host}:${target.port}`);
    openTunnel(ws, target, isVless);
  });
}

// ========================== VLESS Encryption 连接 ==========================
// 从解密后的明文流里按字段读取 VLESS 请求头（不支持 flow/Vision、UDP、Mux）
async function readVlessRequest(chan) {
  const head = await chan.readPlainExact(18);            // 版本1 + UUID16 + 附加信息长度1
  if (head[0] !== 0 || !crypto.timingSafeEqual(head.subarray(1, 17), UUID_BUF)) return null;
  let flow = '';
  if (head[17] !== 0) {                                  // 附加信息（protobuf：字段1 = flow 字符串）
    flow = parseFlow(await chan.readPlainExact(head[17]));
    if (flow !== 'xtls-rprx-vision') return null;        // 只支持空 flow 或 Vision
  }
  const b = await chan.readPlainExact(4);                // 命令1 + 端口2 + 地址类型1
  if (b[0] !== 1) return null;                           // 仅支持 TCP
  const port = b.readUInt16BE(1);
  const atyp = b[3];
  let host;
  if (atyp === 1) {
    const a = await chan.readPlainExact(4);
    host = `${a[0]}.${a[1]}.${a[2]}.${a[3]}`;
  } else if (atyp === 2) {
    const l = (await chan.readPlainExact(1))[0];
    if (!l) return null;
    host = (await chan.readPlainExact(l)).toString('utf8');
  } else if (atyp === 3) {
    host = ipv6From(await chan.readPlainExact(16), 0);
  } else return null;
  return { host, port, version: head[0], flow, uuid: Buffer.from(head.subarray(1, 17)) };
}

// 解析 Addons protobuf，只取字段 1（flow）；格式异常返回 null
function parseFlow(b) {
  let flow = '';
  let i = 0;
  while (i < b.length) {
    const tag = b[i++];
    const wire = tag & 7;
    if (wire === 2) {
      let len = 0, shift = 0, c;
      do { c = b[i++]; if (c === undefined) return null; len |= (c & 0x7f) << shift; shift += 7; } while (c & 0x80);
      if (i + len > b.length) return null;
      if (tag >> 3 === 1) flow = b.subarray(i, i + len).toString('utf8');
      i += len;
    } else if (wire === 0) {
      let c;
      do { c = b[i++]; if (c === undefined) return null; } while (c & 0x80);
    } else return null;
  }
  return flow;
}

function waitDrain(socket) {
  return new Promise(resolve => {
    const done = () => { socket.off('drain', done); socket.off('close', done); resolve(); };
    socket.once('drain', done);
    socket.once('close', done);
  });
}

const { Vision } = require('./vision');

function openEncTunnel(ws, raw, chan, t) {
  // Vision：响应头随首个下行数据一起发出（与 Xray 一致）；普通模式立即发送
  const vision = t.flow === 'xtls-rprx-vision' ? new Vision(chan, t.uuid) : null;
  if (vision) vision.setPrefix(Buffer.from([t.version, 0]));
  else chan.write(Buffer.from([t.version, 0]));              // VLESS 响应头，同样走加密通道

  const socket = net.connect({ host: t.host, port: t.port, lookup: safeLookup });
  socket.setNoDelay(true);
  socket.setTimeout(IDLE_MS, () => socket.destroy());
  const ct = setTimeout(() => socket.destroy(), CONNECT_TIMEOUT);
  socket.once('connect', () => { clearTimeout(ct); dlog(`[enc] upstream connected ${t.host}:${t.port}`); });

  let closed = false;
  const closeAll = () => {
    if (closed) return;
    closed = true;
    clearTimeout(ct);
    socket.destroy();
    try { ws.terminate(); } catch (e) { /* ignore */ }
  };
  socket.on('error', e => { dlog(`[enc] upstream error ${t.host}:${t.port}: ${e && e.message}`); closeAll(); });
  socket.on('close', () => {
    clearTimeout(ct);
    if (!closed) { closed = true; try { ws.close(); } catch (e) { /* ignore */ } }
  });
  ws.on('close', () => { if (vision && env('VISION_DEBUG') === '1') console.log('[vision]', JSON.stringify(vision.info())); closeAll(); });

  // 上游 -> 客户端（加密后写入 WebSocket，带背压）
  socket.on('data', chunk => {
    try {
      const ok = vision ? vision.writeDown(chunk) : chan.write(chunk);
      if (!ok) { socket.pause(); raw.once('drain', () => socket.resume()); }
    } catch (e) { closeAll(); }
  });

  // 客户端 -> 上游（解密；net.Socket 在连接建立前会自动缓冲写入）
  (async () => {
    try {
      for (;;) {
        const p = vision ? await vision.readUp() : await chan.readPlainAny();
        if (!socket.write(p)) await waitDrain(socket);
      }
    } catch (e) { closeAll(); }
  })();
}

async function onEncConnection(ws, ip) {
  activeConns++;
  dlog(`[enc] conn ip=${ip} active=${activeConns}`);
  ws.on('close', () => { activeConns--; });
  ws.on('error', () => {});
  const raw = createWebSocketStream(ws);
  raw.on('error', () => {});

  // 握手 + 请求头必须在限定时间内完成
  const timer = setTimeout(() => { dlog(`[enc] handshake timeout ip=${ip}`); try { ws.terminate(); } catch (e) { /* ignore */ } }, FIRST_MSG_TIMEOUT);

  let chan, target;
  try {
    chan = await ENC.handshake(raw);
    dlog(`[enc] handshake ok ip=${ip}`);
    target = await readVlessRequest(chan);
  } catch (e) {
    clearTimeout(timer);
    if (e && e.expired) {                                // 多实例下票据不在本实例：不算攻击，让客户端重新握手
      dlog(`[enc] ticket expired on this instance ip=${ip}`);
      setTimeout(() => { try { ws.close(); } catch (x) { /* ignore */ } }, 200);
      return;
    }
    dlog(`[enc] handshake fail ip=${ip}: ${e && e.message}`);
    return fail(ws, ip);
  }
  clearTimeout(timer);

  if (!target) {
    dlog(`[enc] vless request parse fail / unsupported flow ip=${ip}`);
    return fail(ws, ip);
  }
  if (isBlockedTarget(target.host, target.port)) {
    dlog(`[enc] blocked target ${target.host}:${target.port}`);
    try { ws.close(); } catch (e) { /* ignore */ }
    return;
  }
  dlog(`[enc] tunnel open flow=${target.flow || '-'} ${target.host}:${target.port}`);
  openEncTunnel(ws, raw, chan, target);
}

// ========================== HTTP / WebSocket 服务 ==========================
function buildSubscription(req) {
  const domain = DOMAIN || (req.headers.host || '').split(':')[0];
  if (!/^[A-Za-z0-9.-]+$/.test(domain)) return null;
  const name = encodeURIComponent(NAME);
  const base = `security=tls&sni=${domain}&fp=chrome&type=ws&host=${domain}`;
  const links = [];
  if (ENC) {
    links.push(`vless://${UUID}@${domain}:443?encryption=${encodeURIComponent(ENC_CLIENT)}&flow=xtls-rprx-vision&${base}&path=${encodeURIComponent(WS_PATH)}#${name}`);
    if (ALLOW_PLAIN) {
      const q = `${base}&path=${encodeURIComponent(PLAIN_WS_PATH)}`;
      links.push(`vless://${UUID}@${domain}:443?encryption=none&${q}#${encodeURIComponent(NAME + '-plain')}`);
      links.push(`trojan://${UUID}@${domain}:443?${q}#${encodeURIComponent(NAME + '-plain-trojan')}`);
    }
  } else {
    const q = `${base}&path=${encodeURIComponent(WS_PATH)}`;
    links.push(`vless://${UUID}@${domain}:443?encryption=none&${q}#${name}`);
    links.push(`trojan://${UUID}@${domain}:443?${q}#${name}`);
  }
  return Buffer.from(links.join('\n')).toString('base64') + '\n';
}

const httpServer = http.createServer((req, res) => {
  req.on('error', () => {});
  const ip = clientIP(req);
  const pathname = (req.url || '/').split('?')[0];
  dlog(`[http] ${req.method} ${pathname} host=${req.headers.host || '-'} ip=${ip}`);

  if (isBanned(ip)) { dlog('[http] -> 404 (banned ip)'); return send(res, 404, 'text/html; charset=utf-8', NOT_FOUND_HTML); }
  if (hit('req:' + ip, REQ_LIMIT, REQ_WINDOW)) { dlog('[http] -> 404 (rate limited)'); return send(res, 404, 'text/html; charset=utf-8', NOT_FOUND_HTML); }
  if (!frontOK(req)) { dlog('[http] -> 404 (no front key)'); strike(ip); return send(res, 404, 'text/html; charset=utf-8', NOT_FOUND_HTML); }
  if ((req.method !== 'GET' && req.method !== 'HEAD') || !hostAllowed(req)) {
    dlog('[http] -> 404 (method or host rejected)'); strike(ip);
    return send(res, 404, 'text/html; charset=utf-8', NOT_FOUND_HTML);
  }
  if (pathname === '/' || pathname === '/index.html') {
    return send(res, 200, 'text/html; charset=utf-8', INDEX_HTML);
  }
  if (SUB_ENABLED && pathname === '/' + SUB_PATH && !hit('sub:' + ip, 30, 10 * 60 * 1000)) {
    const body = buildSubscription(req);
    if (body) { dlog('[http] -> 200 subscription'); return send(res, 200, 'text/plain; charset=utf-8', body); }
  }
  dlog('[http] -> 404 (unknown path or rate limited)'); strike(ip);
  return send(res, 404, 'text/html; charset=utf-8', NOT_FOUND_HTML);
});

const wss = new WebSocketServer({ noServer: true, maxPayload: 8 * 1024 * 1024 });

httpServer.on('upgrade', (req, socket, head) => {
  socket.on('error', () => {});
  const ip = clientIP(req);
  const pathname = (req.url || '').split('?')[0];
  dlog(`[ws] upgrade ${pathname} host=${req.headers.host || '-'} ip=${ip}`);
  // 路径不对、密钥缺失、来源被封禁、限流、并发已满：与普通 404 完全一致，不做 WebSocket 升级
  if (isBanned(ip)) return rejectUpgrade(socket, 'banned ip');
  if (hit('req:' + ip, REQ_LIMIT, REQ_WINDOW)) return rejectUpgrade(socket, 'rate limited');
  if (!frontOK(req)) { strike(ip); return rejectUpgrade(socket, 'no front key'); }
  let mode = null;
  if (pathname === WS_PATH) mode = ENC ? 'enc' : 'plain';
  else if (ENC && ALLOW_PLAIN && pathname === PLAIN_WS_PATH) mode = 'plain';
  if (!mode) { strike(ip); return rejectUpgrade(socket, 'unknown path (expect ' + WS_PATH + ')'); }
  if (!hostAllowed(req)) return rejectUpgrade(socket, 'host not allowed');
  if (activeConns >= MAX_CONN) return rejectUpgrade(socket, `too many connections (${activeConns}/${MAX_CONN})`);
  dlog(`[ws] upgrade accepted mode=${mode}`);
  wss.handleUpgrade(req, socket, head, ws => (mode === 'enc' ? onEncConnection(ws, ip) : onConnection(ws, ip)));
});

process.on('uncaughtException', e => console.error('uncaught:', e && e.message));
process.on('unhandledRejection', e => console.error('unhandled:', e && e.message));

async function start() {
  if (ENC_STR) {
    const lib = require('./vlessenc');
    await lib.init();
    ENC = lib.parseDecryption(ENC_STR);
    ENC_CLIENT = env('VLESS_ENCRYPTION') || ENC.clientString();
  }
  httpServer.listen(PORT, () => {
    console.log(`Server is running on ${PORT}${ENC ? ' (VLESS Encryption on)' : ''}`);
    console.log('[config] wsPath=/' + WSPATH +
      (ENC ? ' enc=on' + (ALLOW_PLAIN ? ' plain=/'+ WSPATH + '-plain' : ' plain=off') : ' enc=off') +
      ' sub=' + (SUB_ENABLED ? 'on' : 'off') +
      ' allowedHosts=' + (ALLOWED_HOSTS.join(',') || 'any') +
      ' maxConn=' + MAX_CONN +
      ' frontKey=' + (FRONT_KEY ? 'on' : 'off') +
      ' reqLimit=' + REQ_LIMIT + '/min' +
      ' showLog=' + SHOW_LOG);
    if (!SUB_ENABLED) console.warn('[WARN] SUB_PATH 未设置或少于 12 位，订阅接口已关闭');
  });
}

start().catch(e => { console.error('[FATAL]', e && e.message); process.exit(1); });
