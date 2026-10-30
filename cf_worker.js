// 与 Vercel 环境变量 FRONT_KEY 保持一致的随机串（两侧必须完全相同）
// 生成方法：node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
// 未启用前置密钥（Vercel 未设置 FRONT_KEY）时此值无效果，可先保持占位
const FRONT_KEY = 'CHANGE_ME_TO_A_RANDOM_STRING';

export default {
    async fetch(request, env) {
        let url = new URL(request.url);
        if (url.pathname.startsWith('/')) {
            var arrStr = [
                'ahrchmdawh.vercel.app',   // 此处单引号里填写你的vercel分配的域名，不包含https://
            ];
            url.protocol = 'https:'
            url.hostname = getRandomArray(arrStr)
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
