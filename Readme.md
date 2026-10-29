
# qt-vercel-enc

这个如何配置 实现vless 加密+Vision native

先执行 npm install

**第 1 步：生成密钥**

在项目目录执行（先 `npm install`）：

```
node vlessenc.js gen x25519 native 0

node vlessenc.js gen mlkem768 native 1

```

- 想用抗量子的认证就把 `x25519` 换成 `mlkem768`。
- `native` 是外观模式，`0` 是票据秒数。Vercel 多实例必须用 0。
- 会输出两行：`VLESS_DECRYPTION=…` 给服务端，`客户端 encryption=…` 给客户端。

**第 2 步：Vercel 环境变量**

| 变量 | 值 |
|---|---|
| `UUID` | 你的 UUID |
| `WSPATH` | 路径名，如 `abc123` |
| `SUB_PATH` | 至少 12 位的订阅路径 |
| `VLESS_DECRYPTION` | 第 1 步输出的服务端串 |
| `DOMAIN` | 你的 Cloudflare 域名（订阅里用） |

设置后重新部署。Cloudflare Worker 不用改。

**第 3 步：客户端（对应你截图的界面）**

- 类型：VLESS
- 地址：Cloudflare 域名，端口 443
- UUID：同服务端
- 加密：粘贴第 1 步的 `encryption=` 后面那一整串
- 流控：`xtls-rprx-vision`
- 传输方式：**ws**，路径 `/WSPATH`，Host 填 Cloudflare 域名
- TLS：开启，SNI 填 Cloudflare 域名，**不要开 reality**
- 多路复用：**关闭**，Vision 不支持 Mux
- UDP 转发：建议关闭，服务端不支持 UDP

也可以直接导入订阅链接 `https://域名/SUB_PATH`，里面已带好 encryption 和 flow。

**需要留意：**
- 排查连接问题：Vercel 环境变量加 `SHOW_LOG=1` 重新部署，Logs 里会打印每个 HTTP 请求、WS 升级、认证与隧道日志。
- 如果 `SUB_PATH` 不满足至少 12 位，订阅接口会被关闭。
- 连不上时先检查两点：客户端的 encryption 串必须与服务端的密钥成对；flow 只能是 `xtls-rprx-vision` 或留空。
- 想确认 Vision 是否切到直接对拷，临时加环境变量 `VISION_DEBUG=1`，在 Vercel 日志里看每个连接关闭时的 `upDirect` 和 `downRaw`。
- 只有访问 HTTPS（内层 TLS 1.3）的连接才会切换并省 CPU，这是正常现象。



