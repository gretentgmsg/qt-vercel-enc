// 与 Vercel 环境变量 FRONT_KEY 保持一致的随机串（两侧必须完全相同）
// 生成方法：node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
// 未启用前置密钥（Vercel 未设置 FRONT_KEY）时此值无效果，可先保持占位
const FRONT_KEY = 'CHANGE_ME_TO_A_RANDOM_STRING';

// 客户端认证，格式 '用户名:密码'（建议只用 ASCII 字符）
// 实际值配置在 Cloudflare Worker 的环境变量 AUTH_KEY（Settings → Variables），优先级高于此常量
// 请求必须带 ?auth=用户名:密码 或 Authorization: Basic base64(用户名:密码)，否则 401
const AUTH_KEY = 'user:password';

export default {
    async fetch(request, env) {
        let url = new URL(request.url);
        if (url.pathname.startsWith('/')) {
            const authKey = env.AUTH_KEY || AUTH_KEY;
            if (url.searchParams.get('auth') !== authKey &&
                request.headers.get('Authorization') !== 'Basic ' + btoa(authKey)) {
                return new Response('Unauthorized', {
                    status: 401,
                    headers: { 'WWW-Authenticate': 'Basic realm="auth"' }
                });
            }
            var arrStr = [
                'ahrchmdawh.vercel.app',   // 此处单引号里填写你的vercel分配的域名，不包含https://
            ];
            url.protocol = 'https:'
            url.hostname = getRandomArray(arrStr)
            // 认证参数不转发给 Vercel
            url.search = '';
            let new_request = new Request(url, request);
            new_request.headers.set('x-front-key', FRONT_KEY);
            return fetch(new_request);
        }
        return env.ASSETS.fetch(request);
    },
};
function getRandomArray(array) {
  const randomIndex = Math.floor(Math.random() * array.length);
  return array[randomIndex];
}
