'use strict';

/*
 * XTLS Vision（flow = xtls-rprx-vision）服务端实现，按 Xray-core proxy/proxy.go 移植
 * （TrafficState / VisionReader / VisionWriter / XtlsPadding / XtlsUnpadding / XtlsFilterTls）。
 *
 * 只能叠在 VLESS Encryption 通道（vlessenc.js 的 Channel）之上使用：
 *   - 内层是 TLS 1.3 时，握手阶段做随机填充；握手结束后切到"直接对拷"，
 *     之后的内层 TLS 记录不再经过 AEAD 加解密（节省 CPU），这是本模块的主要价值。
 *   - 上行/下行各自独立切换：收到对端 command=2 后，上行改读原始字节；
 *     自己发出 command=2 的块后，下行改写原始字节。
 *
 * 用法（index.js 中）：
 *   const v = new Vision(chan, uuid16);
 *   v.setPrefix(Buffer.from([version, 0]));   // 响应头，随首个下行数据一起发出（与 Xray 一致）
 *   const data = await v.readUp();            // 客户端 -> 上游
 *   const ok = v.writeDown(chunk);            // 上游 -> 客户端；false 表示需等 raw 的 'drain'
 */

const crypto = require('crypto');

const BUF_SIZE = 8192; // 对应 Go 的 buf.Size
const TLS_APP = Buffer.from([0x17, 0x03, 0x03]);
const TLS13_SUPPORTED = Buffer.from([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
const CIPHERS = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0x1304: 'TLS_AES_128_CCM_SHA256',
  0x1305: 'TLS_AES_128_CCM_8_SHA256'
};
const CMD_CONTINUE = 0, CMD_END = 1, CMD_DIRECT = 2;

const randBelow = n => (n > 0 ? crypto.randomInt(0, n) : 0);

// 对应 IsCompleteRecord：整个 multi-buffer 恰好是若干个完整的 0x17 0x03 0x03 记录
function isCompleteRecord(mb) {
  const b = mb.length === 1 ? mb[0] : Buffer.concat(mb);
  let headerLen = 5, recordLen = 0, i = 0;
  const total = b.length;
  while (i < total) {
    if (headerLen > 0) {
      const d = b[i++];
      switch (headerLen) {
        case 5: if (d !== 0x17) return false; break;
        case 4: if (d !== 0x03) return false; break;
        case 3: if (d !== 0x03) return false; break;
        case 2: recordLen = d << 8; break;
        case 1: recordLen |= d; break;
      }
      headerLen--;
    } else if (recordLen > 0) {
      if (total - i < recordLen) return false;
      i += recordLen; recordLen = 0; headerLen = 5;
    } else return false;
  }
  return headerLen === 5 && recordLen === 0;
}

// 对应 ReshapeMultiBuffer：为 padding 结构（最多 21 字节）留出空间
function reshape(mb) {
  let need = 0;
  for (const b of mb) if (b.length >= BUF_SIZE - 21) need++;
  if (need === 0) return mb;
  const out = [];
  for (const b of mb) {
    if (b.length >= BUF_SIZE - 21) {
      let index = b.lastIndexOf(TLS_APP);
      if (index < 21 || index > BUF_SIZE - 21) index = BUF_SIZE / 2;
      out.push(b.subarray(0, index), b.subarray(index));
    } else out.push(b);
  }
  return out;
}

// 模拟 Go 每次最多读 8192 字节的缓冲
function splitBuffers(chunk) {
  const out = [];
  for (let o = 0; o < chunk.length; o += BUF_SIZE) out.push(chunk.subarray(o, Math.min(o + BUF_SIZE, chunk.length)));
  return out;
}

class Vision {
  constructor(chan, userUUID, testseed) {
    this.chan = chan;
    this.uuid = Buffer.from(userUUID);        // 用于识别对端首个填充块
    this.writeUUID = Buffer.from(userUUID);   // 我方首个填充块前缀，发出后置空
    this.testseed = (testseed && testseed.length >= 4) ? testseed : [900, 500, 900, 256];
    this.prefix = null;
    this.downRaw = false;           // 下行已切换为直接写
    this.downSwitchPending = false; // 对应 Inbound.DownlinkWriterDirectCopy
    this.st = {
      numberOfPacketToFilter: 8,
      enableXtls: false,
      isTLS12orAbove: false,
      isTLS: false,
      cipher: 0,
      remainingServerHello: -1,
      // Inbound 状态（服务端：上行读 + 下行写）
      within: true,                 // WithinPaddingBuffers
      upDirect: false,              // UplinkReaderDirectCopy
      remCmd: -1, remContent: -1, remPadding: -1, curCmd: 0,
      isPadding: true
    };
  }

  setPrefix(buf) { this.prefix = buf; }

  // ---------------- 上行：客户端 -> 上游 ----------------
  async readUp() {
    const st = this.st;
    for (;;) {
      if (st.upDirect) return this.chan.readRawAny(); // 已切到直接对拷
      const chunk = await this.chan.readPlainAny();
      let out = [chunk];
      if (st.within || st.numberOfPacketToFilter > 0) {
        out = [];
        const n = this._unpad(chunk);
        if (n.length > 0) out.push(n);
        if (st.remContent > 0 || st.remPadding > 0 || st.curCmd === CMD_CONTINUE) st.within = true;
        else if (st.curCmd === CMD_END) st.within = false;
        else if (st.curCmd === CMD_DIRECT) { st.within = false; st.upDirect = true; }
      }
      if (st.numberOfPacketToFilter > 0) this._filter(out);
      const data = out.length === 1 ? out[0] : Buffer.concat(out);
      if (data.length) return data;
    }
  }

  // 对应 XtlsUnpadding（isUplink=true）：去掉填充，返回内容
  _unpad(b) {
    const st = this.st;
    let p = 0;
    if (st.remCmd === -1 && st.remContent === -1 && st.remPadding === -1) { // 初始状态
      if (b.length >= 21 && b.subarray(0, 16).equals(this.uuid)) { p = 16; st.remCmd = 5; }
      else return b;
    }
    const out = [];
    while (p < b.length) {
      if (st.remCmd > 0) {
        const data = b[p++];
        switch (st.remCmd) {
          case 5: st.curCmd = data; break;
          case 4: st.remContent = data << 8; break;
          case 3: st.remContent |= data; break;
          case 2: st.remPadding = data << 8; break;
          case 1: st.remPadding |= data; break;
        }
        st.remCmd--;
      } else if (st.remContent > 0) {
        const len = Math.min(st.remContent, b.length - p);
        out.push(b.subarray(p, p + len));
        p += len;
        st.remContent -= len;
      } else { // remainingPadding > 0
        const len = Math.min(st.remPadding, b.length - p);
        p += len;
        st.remPadding -= len;
      }
      if (st.remCmd <= 0 && st.remContent <= 0 && st.remPadding <= 0) { // 本块结束
        if (st.curCmd === CMD_CONTINUE) {
          st.remCmd = 5;
        } else {
          st.remCmd = -1; st.remContent = -1; st.remPadding = -1;
          if (p < b.length) out.push(b.subarray(p)); // 理论上不会发生
          break;
        }
      }
    }
    return out.length === 1 ? out[0] : Buffer.concat(out);
  }

  // 对应 XtlsFilterTls：识别 TLS 1.3 以及密码套件
  _filter(mb) {
    const s = this.st;
    for (const b of mb) {
      if (!b) continue;
      s.numberOfPacketToFilter--;
      if (b.length >= 6) {
        if (b[0] === 0x16 && b[1] === 0x03 && b[2] === 0x03 && b[5] === 0x02) { // ServerHello
          s.remainingServerHello = ((b[3] << 8) | b[4]) + 5;
          s.isTLS12orAbove = true;
          s.isTLS = true;
          if (b.length >= 79 && s.remainingServerHello >= 79) {
            const sid = b[43];
            s.cipher = (b[43 + sid + 1] << 8) | b[43 + sid + 2];
          }
        } else if (b[0] === 0x16 && b[1] === 0x03 && b[5] === 0x01) { // ClientHello
          s.isTLS = true;
        }
      }
      if (s.remainingServerHello > 0) {
        const end = Math.min(s.remainingServerHello, b.length);
        s.remainingServerHello -= b.length;
        if (b.subarray(0, end).includes(TLS13_SUPPORTED)) {
          const v = CIPHERS[s.cipher];
          if (v !== undefined && v !== 'TLS_AES_128_CCM_8_SHA256') s.enableXtls = true;
          s.numberOfPacketToFilter = 0;
          return;
        } else if (s.remainingServerHello <= 0) {
          s.numberOfPacketToFilter = 0; // TLS 1.2
          return;
        }
      }
    }
  }

  // ---------------- 下行：上游 -> 客户端 ----------------
  writeDown(chunk) {
    const st = this.st;
    let mb = splitBuffers(chunk);

    if (this.downSwitchPending) { // 上一次写入已发出 command=2，此后改为直接写
      this.downRaw = true;
      this.downSwitchPending = false;
    }
    if (st.numberOfPacketToFilter > 0) this._filter(mb);

    if (st.isPadding) {
      const isComplete = isCompleteRecord(mb);
      mb = reshape(mb);
      let longPadding = st.isTLS;
      for (let i = 0; i < mb.length; i++) {
        const b = mb[i];
        if (st.isTLS && b.length >= 6 && b.subarray(0, 3).equals(TLS_APP) && isComplete) {
          if (st.enableXtls) this.downSwitchPending = true;
          let command = CMD_CONTINUE;
          if (i === mb.length - 1) {
            command = CMD_END;
            if (st.enableXtls) command = CMD_DIRECT;
          }
          mb[i] = this._pad(b, command, true);
          st.isPadding = false; // 填充即将结束
          longPadding = false;
          continue;
        } else if (!st.isTLS12orAbove && st.numberOfPacketToFilter <= 1) { // 与旧版 Vision 接收端兼容：提前一个包结束
          st.isPadding = false;
          mb[i] = this._pad(b, CMD_END, longPadding);
          break;
        }
        let command = CMD_CONTINUE;
        if (i === mb.length - 1 && !st.isPadding) {
          command = CMD_END;
          if (st.enableXtls) command = CMD_DIRECT;
        }
        mb[i] = this._pad(b, command, longPadding);
      }
    }

    let data = mb.length === 1 ? mb[0] : Buffer.concat(mb);
    if (this.prefix) { data = Buffer.concat([this.prefix, data]); this.prefix = null; }
    return this.downRaw ? this.chan.writeRaw(data) : this.chan.write(data);
  }

  // 对应 XtlsPadding
  _pad(b, command, longPadding) {
    const content = b || Buffer.alloc(0);
    const cl = content.length;
    const ts = this.testseed;
    let pl;
    if (cl < ts[0] && longPadding) pl = randBelow(ts[1]) + ts[2] - cl;
    else pl = randBelow(ts[3]);
    if (pl > BUF_SIZE - 21 - cl) pl = BUF_SIZE - 21 - cl;
    if (pl < 0) pl = 0;
    const parts = [];
    if (this.writeUUID) { parts.push(this.writeUUID); this.writeUUID = null; }
    parts.push(Buffer.from([command, (cl >> 8) & 255, cl & 255, (pl >> 8) & 255, pl & 255]), content, Buffer.alloc(pl));
    return Buffer.concat(parts);
  }

  // 调试用状态
  info() {
    const s = this.st;
    return { isTLS: s.isTLS, tls13: s.enableXtls, upDirect: s.upDirect, downRaw: this.downRaw };
  }
}

module.exports = { Vision };
