# Xray 订阅管理（Cloudflare Workers）

Vue / MDUI 页面与 API 一起部署到 Cloudflare Workers，数据存放在 Workers KV。

## 配置

`wrangler.jsonc` 已绑定现有命名空间 `xray-subscription`：

- 绑定变量：`SUBSCRIPTION_KV`
- Namespace ID：`e6289f8940c44de5bee7b9733d97eae5`
- 数据键：`db`，值为原 `db.json` 的完整 JSON。

`JWT_SECRET` 必须通过 Worker Secret 配置；`SUBSCRIPTION_UA_SECRET` 为可选的订阅 User-Agent 校验字符串。新 JWT 密钥会让旧登录令牌失效，重新登录即可。管理员密码和分组 ID 在迁移后保留；订阅路径不变，切换域名时需更新客户端订阅域名。

## 迁移与部署

```bash
npm install
npx wrangler login
npm run migrate -- --remote
npx wrangler secret put JWT_SECRET
# 如原服务使用 UA 校验，请设置同一个值：
# npx wrangler secret put SUBSCRIPTION_UA_SECRET
npm run check
npm run deploy
```

迁移前停止旧服务的数据修改。迁移脚本保留本地 `db.json`，先检查目标键；目标存在相同内容时跳过，存在不同内容时中止，避免覆盖线上修改。写入后通过远端回读进行 SHA-256 校验，不输出数据内容。不要在迁移后继续修改旧服务并重复导入。

运行时不再读取或写入本地 `db.json`。KV 为空、JSON 损坏或保存失败时返回错误，不创建默认数据或返回虚假的保存成功。

## 本地开发与验证

```bash
cp .dev.vars.example .dev.vars
# 修改 .dev.vars 中的 JWT_SECRET 为本地随机密钥
npm run migrate -- --local
npm run dev
# http://localhost:3000
npm test
```

本地开发默认使用 `.wrangler/` 中独立的 KV，不修改远端。`db.json`、`.dev.vars` 和 `.wrangler/` 均不提交版本控制。Node.js 建议使用 22 或更新版本。

## KV 与限流行为

KV 是最终一致存储，在其他边缘位置读取到修改可能延迟约 60 秒。当前沿用整份数据读改写，适合单管理员、低频修改；并发修改可能互相覆盖，同一键写入也受 KV 每秒一次的限制。不要同时打开多个管理页面频繁保存。如果需要多人同时管理，应改用 Durable Objects 或 D1 协调写入。

订阅通过 Cloudflare 原生 Rate Limiting binding 限流，同一边缘位置的订阅请求共用每 10 秒 1 次的窗口；这是按位置的近似限制，不是严格的全球限流。限流、分组不存在或 UA 不匹配时沿用空响应、HTTP 200。订阅内容保持 UTF-8 Base64，保留旧版分组与优选 Host 兼容逻辑。

参考：[KV 一致性](https://developers.cloudflare.com/kv/concepts/how-kv-works/)、[Workers 限流](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)、[静态资源](https://developers.cloudflare.com/workers/static-assets/)。
