'use strict';

/*
 * VLESS Encryption (mlkem768x25519plus) 服务端实现 —— 按 Xray-core proxy/vless/encryption
 * (common.go / server.go / xor.go) 移植到 Node.js，仅服务端（decryption）。
 *
 * 依赖：@noble/hashes（BLAKE3）、@noble/post-quantum（ML-KEM-768）。其余用 Node 内置 crypto。
 * 两个 noble 包是纯 ESM，所以在 init() 里用动态 import 加载。
 *
 * 用法：
 *   const enc = require('./vlessenc');
 *   await enc.init();
 *   const inst = enc.parseDecryption(process.env.VLESS_DECRYPTION);
 *   const chan = await inst.handshake(duplexStream);   // 如 ws.createWebSocketStream(ws)
 *   const buf  = await chan.readPlainExact(18);        // 读解密后的明文（上层协议，如 VLESS 请求头）
 *   chan.write(buf);                                   // 加密写出，返回 false 表示需要等 raw 的 'drain'
 *
 * 命令行生成密钥串（无需 xray 二进制）：
 *   node vlessenc.js gen [x25519|mlkem768] [native|xorpub|random] [秒数，默认0]
 */

const crypto = require('crypto');

let blake3 = null;
let ml_kem768 = null;

async function init() {
  if (blake3 && ml_kem768) return;
  ({ blake3 } = await import('@noble/hashes/blake3.js'));
  ({ ml_kem768 } = await import('@noble/post-quantum/ml-kem.js'));
}

// ========================== 基础工具 ==========================
const MAX_NONCE = Buffer.alloc(12, 0xff);
const sleep = ms => new Promise(r => setTimeout(r, ms));

// 与 Go 的 crypto.RandBetween 一致：[from, to)，from==to 返回 from
function randBetween(from, to) {
  if (to <= from) return from;
  return crypto.randomInt(from, to);
}

// BLAKE3 derive_key 模式：context 为原始字节（Go 里是 string(ctx)，可含任意字节）
function deriveKey(context, material) {
  return Buffer.from(blake3(new Uint8Array(material), { context: new Uint8Array(context), dkLen: 32 }));
}

function newCTR(key, iv) {
  const k = deriveKey(Buffer.from('VLESS'), key); // 不直接使用 key
  return crypto.createCipheriv('aes-256-ctr', k, iv);
}

// 对 buf 就地做 CTR 异或（保持 CTR 状态连续）
function xorInPlace(ctr, buf) {
  ctr.update(buf).copy(buf);
}

const encodeLength = l => Buffer.from([(l >> 8) & 255, l & 255]);

function encodeHeader(h, l) {
  h[0] = 23; h[1] = 3; h[2] = 3; h[3] = (l >> 8) & 255; h[4] = l & 255;
}

// 返回密文长度（含 16 字节 tag）；非法则抛错（17 ~ 16640）
function decodeHeader(h) {
  let l = (h[3] << 8) | h[4];
  if (h[0] !== 23 || h[1] !== 3 || h[2] !== 3) l = 0;
  if (l < 17 || l > 16640) throw new Error('invalid header');
  return l;
}

// ========================== X25519（Node 内置 crypto） ==========================
const X_PRIV_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X_PUB_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

function x25519PrivFromRaw(raw32) {
  return crypto.createPrivateKey({ key: Buffer.concat([X_PRIV_PREFIX, raw32]), format: 'der', type: 'pkcs8' });
}
function x25519PubRaw(privKeyObj) {
  return crypto.createPublicKey(privKeyObj).export({ type: 'spki', format: 'der' }).subarray(-32);
}
function x25519Generate() {
  const { privateKey } = crypto.generateKeyPairSync('x25519');
  return { priv: privateKey, pub: Buffer.from(x25519PubRaw(privateKey)) };
}
function x25519DH(privKeyObj, peerPub32) {
  const publicKey = crypto.createPublicKey({ key: Buffer.concat([X_PUB_PREFIX, peerPub32]), format: 'der', type: 'spki' });
  return crypto.diffieHellman({ privateKey: privKeyObj, publicKey }); // 全零结果会抛错，与 Go 一致
}

// ========================== AEAD（每方向一个，nonce 自增） ==========================
class AEAD {
  constructor(ctx, key, useAES) {
    this.key = deriveKey(ctx, key);
    this.alg = useAES ? 'aes-256-gcm' : 'chacha20-poly1305';
    this.nonce = Buffer.alloc(12);
  }
  _nonce(explicit) {
    if (explicit) return explicit;
    for (let i = 11; i >= 0; i--) { // 先自增再使用（首次使用的 nonce 为 0...01）
      this.nonce[i] = (this.nonce[i] + 1) & 255;
      if (this.nonce[i] !== 0) break;
    }
    return this.nonce;
  }
  isMaxNonce() { return this.nonce.equals(MAX_NONCE); }
  seal(plaintext, aad, explicitNonce) {
    const n = this._nonce(explicitNonce);
    const c = crypto.createCipheriv(this.alg, this.key, n, { authTagLength: 16 });
    if (aad) c.setAAD(aad, { plaintextLength: plaintext.length });
    const ct = Buffer.concat([c.update(plaintext), c.final()]);
    return Buffer.concat([ct, c.getAuthTag()]);
  }
  open(ciphertext, aad, explicitNonce) {
    const n = this._nonce(explicitNonce);
    if (ciphertext.length < 16) throw new Error('ciphertext too short');
    const body = ciphertext.subarray(0, ciphertext.length - 16);
    const d = crypto.createDecipheriv(this.alg, this.key, n, { authTagLength: 16 });
    d.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
    if (aad) d.setAAD(aad, { plaintextLength: body.length });
    return Buffer.concat([d.update(body), d.final()]); // tag 不符会抛错
  }
}

// ========================== 流式读取器 ==========================
const HIGH_WATER = 1024 * 1024;

class ByteReader {
  constructor(stream) {
    this.s = stream;
    this.q = [];
    this.n = 0;
    this.w = null;
    this.done = false;
    stream.on('data', c => {
      this.q.push(c); this.n += c.length;
      if (this.n >= HIGH_WATER) stream.pause();
      this._wake();
    });
    const fin = () => { this.done = true; this._wake(); };
    stream.on('end', fin); stream.on('close', fin); stream.on('error', fin);
  }
  _wake() { const w = this.w; if (w) { this.w = null; w(); } }
  async read(n) {
    if (n === 0) return Buffer.alloc(0);
    while (this.n < n) {
      if (this.done) throw new Error('unexpected EOF');
      await new Promise(r => { this.w = r; });
    }
    const parts = [];
    let need = n;
    while (need > 0) {
      const c = this.q[0];
      if (c.length <= need) { parts.push(c); this.q.shift(); need -= c.length; }
      else { parts.push(c.subarray(0, need)); this.q[0] = c.subarray(need); need = 0; }
    }
    this.n -= n;
    if (this.n < HIGH_WATER / 2) this.s.resume();
    return Buffer.from(parts.length === 1 ? parts[0] : Buffer.concat(parts)); // 返回副本，调用方可原地修改
  }
}

ByteReader.prototype.readAny = async function () {
  while (this.n === 0) {
    if (this.done) throw new Error('unexpected EOF');
    await new Promise(r => { this.w = r; });
  }
  const all = this.q.length === 1 ? this.q[0] : Buffer.concat(this.q);
  this.q = []; this.n = 0;
  this.s.resume();
  return Buffer.from(all);
};

// 对应 XorConn 对"记录头"的解析：前缀不符返回 0；长度越界也照样返回（与 Go 的 DecodeHeader 返回值一致）
function headerLenLoose(h) {
  let l = (h[3] << 8) | h[4];
  if (h[0] !== 23 || h[1] !== 3 || h[2] !== 3) l = 0;
  return l;
}

// ========================== 加密通道（对应 CommonConn + XorConn） ==========================
class Channel {
  constructor(rd, raw, o) {
    this.rd = rd;
    this.raw = raw;
    this.useAES = o.useAES;
    this.unitedKey = o.unitedKey;
    this.aead = o.aead;           // 发送方向
    this.peerAead = o.peerAead;   // 接收方向
    this.preWrite = o.preWrite || null; // 0-RTT：随首个记录一起发出的 16 字节 server random
    this.ctr = o.ctr || null;           // random 模式：发送记录头异或
    this.peerCtr = o.peerCtr || null;   // random 模式：接收记录头异或
    this.pbuf = [];
    this.plen = 0;
    // Vision 直接对拷阶段（绕过 AEAD）：random 模式下仍需对内层 TLS 记录头做异或（XorConn 的行为）
    this.xin = { skip: 0, hdr: Buffer.alloc(0) };
    this.xout = { skip: 0, hdr: Buffer.alloc(0) };
  }

  // 直接读取原始字节（不经 AEAD），random 模式下还原记录头
  async readRawAny() {
    const b = await this.rd.readAny();
    if (!this.peerCtr) return b;
    const x = this.xin;
    let p = 0;
    for (;;) {
      const remain = b.length - p;
      if (remain <= x.skip) { x.skip -= remain; break; }
      p += x.skip; x.skip = 0;
      const need = 5 - x.hdr.length;
      if (b.length - p < need) {
        const part = b.subarray(p);
        xorInPlace(this.peerCtr, part);
        x.hdr = Buffer.concat([x.hdr, part]);
        break;
      }
      const seg = b.subarray(p, p + need);
      xorInPlace(this.peerCtr, seg);
      x.skip = headerLenLoose(Buffer.concat([x.hdr, seg]));
      x.hdr = Buffer.alloc(0);
      p += need;
    }
    return b;
  }

  // 直接写原始字节（不经 AEAD），random 模式下对内层 TLS 记录头做异或
  writeRaw(buf) {
    const b = Buffer.from(buf);
    if (this.ctr) {
      const x = this.xout;
      let p = 0;
      for (;;) {
        const remain = b.length - p;
        if (remain <= x.skip) { x.skip -= remain; break; }
        p += x.skip; x.skip = 0;
        const need = 5 - x.hdr.length;
        if (b.length - p < need) {
          const part = b.subarray(p);
          x.hdr = Buffer.concat([x.hdr, part]); // 保存明文头
          xorInPlace(this.ctr, part);
          break;
        }
        const seg = b.subarray(p, p + need);
        x.skip = headerLenLoose(Buffer.concat([x.hdr, seg]));
        x.hdr = Buffer.alloc(0);
        xorInPlace(this.ctr, seg);
        p += need;
      }
    }
    return this.raw.write(b);
  }

  async _readRecord() {
    const hdr = await this.rd.read(5);
    if (this.peerCtr) xorInPlace(this.peerCtr, hdr);
    const l = decodeHeader(hdr);
    const body = await this.rd.read(l);
    let newAead = null;
    if (this.peerAead.isMaxNonce()) newAead = new AEAD(Buffer.concat([hdr, body]), this.unitedKey, this.useAES);
    let pt;
    try { pt = this.peerAead.open(body, hdr); } finally { if (newAead) this.peerAead = newAead; }
    return pt;
  }

  // 精确读取 n 字节明文
  async readPlainExact(n) {
    while (this.plen < n) {
      const pt = await this._readRecord();
      if (pt.length) { this.pbuf.push(pt); this.plen += pt.length; }
    }
    const all = this.pbuf.length === 1 ? this.pbuf[0] : Buffer.concat(this.pbuf);
    this.pbuf = all.length > n ? [all.subarray(n)] : [];
    this.plen = all.length - n;
    return Buffer.from(all.subarray(0, n));
  }

  // 读取一批明文（优先返回已缓冲数据，否则读下一条记录）
  async readPlainAny() {
    if (this.plen > 0) {
      const all = this.pbuf.length === 1 ? this.pbuf[0] : Buffer.concat(this.pbuf);
      this.pbuf = []; this.plen = 0;
      return all;
    }
    for (;;) {
      const pt = await this._readRecord();
      if (pt.length) return pt;
    }
  }

  // 加密发送；返回 false 表示底层写缓冲已满（等 raw 的 'drain'）
  write(buf) {
    let ok = true;
    for (let o = 0; o < buf.length;) {
      const chunk = buf.subarray(o, o + 8192);
      o += chunk.length;
      const hdr = Buffer.alloc(5);
      encodeHeader(hdr, chunk.length + 16);
      const isMax = this.aead.isMaxNonce();
      const ct = this.aead.seal(chunk, hdr); // AAD 为未异或的明文记录头
      if (isMax) this.aead = new AEAD(Buffer.concat([hdr, ct]), this.unitedKey, this.useAES);
      const outHdr = Buffer.from(hdr);
      if (this.ctr) xorInPlace(this.ctr, outHdr);
      let rec = Buffer.concat([outHdr, ct]);
      if (this.preWrite) { rec = Buffer.concat([this.preWrite, rec]); this.preWrite = null; }
      if (!this.raw.write(rec)) ok = false;
    }
    return ok;
  }
}

// ========================== padding 参数 ==========================
function parsePadding(padding) {
  const lens = [], gaps = [];
  if (!padding) return { lens, gaps };
  let maxLen = 0;
  padding.split('.').forEach((s, i) => {
    const x = s.split('-');
    if (x.length < 3 || !x[0] || !x[1] || !x[2]) throw new Error('invalid padding length/gap parameter: ' + s);
    const y = [parseInt(x[0], 10), parseInt(x[1], 10), parseInt(x[2], 10)];
    if (y.some(Number.isNaN)) throw new Error('invalid padding length/gap parameter: ' + s);
    if (i === 0 && (y[0] < 100 || y[1] < 18 + 17 || y[2] < 18 + 17)) throw new Error('first padding length must not be smaller than 35');
    if (i % 2 === 0) { lens.push(y); maxLen += Math.max(y[1], y[2]); } else gaps.push(y);
  });
  if (maxLen > 18 + 65535) throw new Error('total padding length must not be larger than 65553');
  return { lens, gaps };
}

function createPadding(paddingLens, paddingGaps) {
  if (paddingLens.length === 0) {
    paddingLens = [[100, 111, 1111], [50, 0, 3333]];
    paddingGaps = [[75, 0, 111]];
  }
  let length = 0;
  const lens = [], gaps = [];
  for (const y of paddingLens) {
    let l = 0;
    if (y[0] >= randBetween(0, 100)) l = randBetween(y[1], y[2]);
    lens.push(l); length += l;
  }
  for (const y of paddingGaps) {
    let g = 0;
    if (y[0] >= randBetween(0, 100)) g = randBetween(y[1], y[2]);
    gaps.push(g); // 毫秒
  }
  return { length, lens, gaps };
}

// ========================== 服务端实例 ==========================
class HandshakeError extends Error {
  constructor(msg, expired) { super(msg); this.expired = !!expired; }
}

class ServerInstance {
  // skeys: [{type:'x25519', raw:Buffer(32)} | {type:'mlkem768', seed:Buffer(64)}]
  constructor({ skeys, xorMode, secondsFrom, secondsTo, padding, paddingBlocks }) {
    if (!skeys.length) throw new Error('empty keys');
    this.keys = skeys.map(k => {
      if (k.type === 'x25519') {
        const priv = x25519PrivFromRaw(k.raw);
        return { type: 'x25519', priv, pub: Buffer.from(x25519PubRaw(priv)) };
      }
      const { publicKey, secretKey } = ml_kem768.keygen(new Uint8Array(k.seed));
      return { type: 'mlkem768', sk: secretKey, pub: Buffer.from(publicKey) };
    });
    this.hash32s = this.keys.map(k => Buffer.from(blake3(new Uint8Array(k.pub))));
    this.relaysLength = this.keys.reduce((n, k) => n + (k.type === 'x25519' ? 32 + 32 : 1088 + 32), 0) - 32;
    this.xorMode = xorMode;
    this.secondsFrom = secondsFrom;
    this.secondsTo = secondsTo;
    const p = parsePadding(padding);
    this.paddingLens = p.lens;
    this.paddingGaps = p.gaps;
    this.paddingBlocks = paddingBlocks || [];
    this.resumption = secondsFrom > 0 || secondsTo > 0;
    this.lasts = new Map();     // 分钟 -> 最后一个票据 hex
    this.tickets = [];          // 票据 hex（按创建顺序）
    this.sessions = new Map();  // 票据 hex -> { pfsKey, nfsKeys:Set }
    if (this.resumption) {
      this.timer = setInterval(() => this._gc(), 60 * 1000);
      this.timer.unref();
    }
  }

  _gc() {
    const minute = Math.floor(Date.now() / 1000 / 60);
    const last = this.lasts.get(minute);
    this.lasts.delete(minute);
    this.lasts.delete(minute - 1);
    if (last) {
      for (let j = 0; j < this.tickets.length; j++) {
        this.sessions.delete(this.tickets[j]);
        if (this.tickets[j] === last) { this.tickets = this.tickets.slice(j + 1); break; }
      }
    }
  }

  // 由服务端私钥派生出客户端的 encryption 字符串
  clientString() {
    const t = this.resumption ? '0rtt' : '1rtt';
    const mode = ['native', 'xorpub', 'random'][this.xorMode];
    const pubs = this.keys.map(k => k.pub.toString('base64url'));
    return ['mlkem768x25519plus', mode, t, ...this.paddingBlocks, ...pubs].join('.');
  }

  async handshake(raw) {
    const rd = new ByteReader(raw);
    let useAES = true;

    const ivAndRelays = await rd.read(16 + this.relaysLength);
    const iv = ivAndRelays.subarray(0, 16);
    let relays = ivAndRelays.subarray(16);
    let nfsKey = null;
    let lastCTR = null;
    for (let j = 0; j < this.keys.length; j++) {
      const k = this.keys[j];
      if (lastCTR) xorInPlace(lastCTR, relays.subarray(0, 32)); // 还原本级 relay 的外层异或
      const index = k.type === 'x25519' ? 32 : 1088;
      if (this.xorMode > 0) xorInPlace(newCTR(k.pub, iv), relays.subarray(0, index));
      if (k.type === 'x25519') {
        if (relays[31] > 127) throw new HandshakeError('x25519 public key high bit set');
        nfsKey = Buffer.from(x25519DH(k.priv, relays.subarray(0, 32)));
      } else {
        nfsKey = Buffer.from(ml_kem768.decapsulate(new Uint8Array(relays.subarray(0, 1088)), k.sk));
      }
      if (j === this.keys.length - 1) break;
      relays = relays.subarray(index);
      lastCTR = newCTR(nfsKey, iv);
      xorInPlace(lastCTR, relays.subarray(0, 32));
      if (!relays.subarray(0, 32).equals(this.hash32s[j + 1])) throw new HandshakeError('unexpected hash32');
      relays = relays.subarray(32);
    }
    let nfsAEAD = new AEAD(iv, nfsKey, useAES);

    const encryptedLength = await rd.read(18);
    let decryptedLength;
    try {
      decryptedLength = nfsAEAD.open(encryptedLength);
    } catch (e) {
      useAES = !useAES; // 客户端可能用 ChaCha20-Poly1305
      nfsAEAD = new AEAD(iv, nfsKey, useAES);
      decryptedLength = nfsAEAD.open(encryptedLength);
    }
    const length = (decryptedLength[0] << 8) | decryptedLength[1];

    // ---------- 0-RTT ----------
    if (length === 32) {
      if (!this.resumption) throw new HandshakeError('0-RTT is not allowed');
      const encryptedTicket = await rd.read(32);
      const ticket = nfsAEAD.open(encryptedTicket);
      const sess = this.sessions.get(ticket.toString('hex'));
      if (!sess) {
        let noises;
        do { noises = crypto.randomBytes(randBetween(1279, 2279)); } while (isValidHeader(noises)); // 让客户端重新握手
        raw.write(noises);
        throw new HandshakeError('expired ticket', true);
      }
      const nk = nfsKey.toString('hex');
      if (sess.nfsKeys.has(nk)) throw new HandshakeError('replay detected');
      sess.nfsKeys.add(nk);
      const unitedKey = Buffer.concat([sess.pfsKey, nfsKey]);
      const preWrite = crypto.randomBytes(16);
      return new Channel(rd, raw, {
        useAES, unitedKey, preWrite,
        aead: new AEAD(preWrite, unitedKey, useAES),
        peerAead: new AEAD(encryptedTicket, unitedKey, useAES),
        ctr: this.xorMode === 2 ? newCTR(unitedKey, preWrite) : null,
        peerCtr: this.xorMode === 2 ? newCTR(unitedKey, iv) : null
      });
    }

    // ---------- 1-RTT ----------
    if (length < 1184 + 32 + 16) throw new HandshakeError('too short length');
    const encryptedPfs = await rd.read(length);
    const pfsPlain = nfsAEAD.open(encryptedPfs); // 客户端的 ML-KEM-768 封装公钥(1184) + X25519 公钥(32)
    const kemOut = ml_kem768.encapsulate(new Uint8Array(pfsPlain.subarray(0, 1184)));
    const mlkemKey = Buffer.from(kemOut.sharedSecret);
    const encapsulatedPfsKey = Buffer.from(kemOut.cipherText);
    const x = x25519Generate();
    const x25519Key = Buffer.from(x25519DH(x.priv, pfsPlain.subarray(1184, 1184 + 32)));
    const pfsKey = Buffer.concat([mlkemKey, x25519Key]);
    const pfsPublicKey = Buffer.concat([encapsulatedPfsKey, x.pub]);
    const unitedKey = Buffer.concat([pfsKey, nfsKey]);
    const aead = new AEAD(pfsPublicKey, unitedKey, useAES);
    const peerAead = new AEAD(pfsPlain.subarray(0, 1184 + 32), unitedKey, useAES);

    const ticket = crypto.randomBytes(16);
    let seconds;
    if (this.secondsTo === 0) seconds = Math.floor(this.secondsFrom * randBetween(50, 100) / 100);
    else seconds = randBetween(this.secondsFrom, this.secondsTo);
    seconds = Math.min(seconds, 65535);
    encodeLength(seconds).copy(ticket, 0);
    if (seconds > 0) {
      const hex = ticket.toString('hex');
      const bucket = Math.floor((Date.now() / 1000 + Math.max(this.secondsFrom, this.secondsTo)) / 60) + 2;
      this.lasts.set(bucket, hex);
      this.tickets.push(hex);
      this.sessions.set(hex, { pfsKey, nfsKeys: new Set() });
    }

    const pfsKeyExchangeLength = 1088 + 32 + 16;
    const encryptedTicketLength = 32;
    const pad = createPadding(this.paddingLens, this.paddingGaps);
    const hello = Buffer.alloc(pfsKeyExchangeLength + encryptedTicketLength + pad.length);
    nfsAEAD.seal(pfsPublicKey, null, MAX_NONCE).copy(hello, 0);
    aead.seal(ticket).copy(hello, pfsKeyExchangeLength);
    const padding = hello.subarray(pfsKeyExchangeLength + encryptedTicketLength);
    aead.seal(encodeLength(pad.length - 18)).copy(padding, 0);
    aead.seal(Buffer.from(padding.subarray(18, pad.length - 16))).copy(padding, 18);

    // 分片 + 间隔发送 server hello（制造可变流量特征）
    pad.lens[0] = pfsKeyExchangeLength + encryptedTicketLength + pad.lens[0];
    let off = 0;
    for (let i = 0; i < pad.lens.length; i++) {
      const l = pad.lens[i];
      if (l > 0) { raw.write(hello.subarray(off, off + l)); off += l; }
      if (pad.gaps.length > i && pad.gaps[i] > 0) await sleep(pad.gaps[i]);
    }

    // 客户端的 padding（可能发得很慢）
    const encLen2 = await rd.read(18);
    const padLen = nfsAEAD.open(encLen2);
    const encPadding = await rd.read((padLen[0] << 8) | padLen[1]);
    nfsAEAD.open(encPadding);

    return new Channel(rd, raw, {
      useAES, unitedKey, aead, peerAead,
      ctr: this.xorMode === 2 ? newCTR(unitedKey, ticket) : null,
      peerCtr: this.xorMode === 2 ? newCTR(unitedKey, iv) : null
    });
  }
}

function isValidHeader(b) {
  try { decodeHeader(b); return true; } catch (e) { return false; }
}

// ========================== 解析 decryption 字符串 ==========================
// 格式：mlkem768x25519plus.<native|xorpub|random>.<600s | 100-500s | 0s>.[padding...].<私钥1>.<私钥2>...
// 私钥：32 字节 X25519 私钥，或 64 字节 ML-KEM-768 seed（base64url，无填充）
function parseDecryption(str) {
  const p = String(str || '').trim().split('.');
  if (p.length < 4 || p[0] !== 'mlkem768x25519plus') throw new Error('invalid VLESS_DECRYPTION');
  const xorMode = { native: 0, xorpub: 1, random: 2 }[p[1]];
  if (xorMode === undefined) throw new Error('invalid VLESS_DECRYPTION: mode must be native/xorpub/random');
  const m = /^(\d+)(?:-(\d+))?s$/.exec(p[2]);
  if (!m) throw new Error('invalid VLESS_DECRYPTION: ticket time must look like 600s, 100-500s or 0s');
  const secondsFrom = parseInt(m[1], 10);
  const secondsTo = m[2] ? parseInt(m[2], 10) : 0;
  let i = 3;
  const paddingBlocks = [];
  while (i < p.length && p[i].length < 20) paddingBlocks.push(p[i++]); // padding 块很短，密钥块很长
  const skeys = [];
  for (; i < p.length; i++) {
    const raw = Buffer.from(p[i], 'base64url');
    if (raw.length === 32) skeys.push({ type: 'x25519', raw });
    else if (raw.length === 64) skeys.push({ type: 'mlkem768', seed: raw });
    else throw new Error('invalid VLESS_DECRYPTION: key must be 32 bytes (X25519) or 64 bytes (ML-KEM-768 seed)');
  }
  if (!skeys.length) throw new Error('invalid VLESS_DECRYPTION: no keys');
  return new ServerInstance({ skeys, xorMode, secondsFrom, secondsTo, padding: paddingBlocks.join('.'), paddingBlocks });
}

// ========================== 命令行：生成密钥 ==========================
async function cli() {
  await init();
  const [, , cmd, kind = 'mlkem768', mode = 'native', secs = '0'] = process.argv;
  if (cmd !== 'gen') {
    console.log('用法: node vlessenc.js gen [x25519|mlkem768] [native|xorpub|random] [票据秒数，默认0]');
    return;
  }
  const key = kind === 'x25519' ? crypto.randomBytes(32) : crypto.randomBytes(64);
  const dec = ['mlkem768x25519plus', mode, `${parseInt(secs, 10) || 0}s`, key.toString('base64url')].join('.');
  const inst = parseDecryption(dec);
  console.log('VLESS_DECRYPTION=' + dec);
  console.log('客户端 encryption=' + inst.clientString());
}

module.exports = { init, parseDecryption, ServerInstance, HandshakeError };

if (require.main === module) cli().catch(e => { console.error(e.message); process.exit(1); });
