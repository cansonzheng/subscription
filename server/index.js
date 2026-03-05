const Koa = require("koa");
const Router = require("koa-router");
const bodyParser = require("koa-bodyparser");
const serve = require("koa-static");
const jwt = require("jsonwebtoken");
const CryptoJS = require("crypto-js");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const { loadData, saveData } = require("./data");

const app = new Koa();
const router = new Router();

// 配置
const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "v2ray-subscription-jwt-secret-key-2026";
const TOKEN_EXPIRY = "24h";
const SUBSCRIPTION_UA_SECRET = process.env.SUBSCRIPTION_UA_SECRET;

// 全局限流记录：{ lastAccess: timestamp }
let rateLimitRecord = null;
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 分钟

// MD5 加密
function md5(str) {
  return CryptoJS.MD5(str).toString();
}

// 验证 JWT Token
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

// 生成 JWT Token
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
}

// 中间件
app.use(bodyParser());
app.use(serve(path.join(__dirname, "../public")));

// 认证中间件
const requireAuth = async (ctx, next) => {
  const authHeader = ctx.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    ctx.status = 401;
    ctx.body = { error: "未授权访问" };
    return;
  }

  const token = authHeader.substring(7);
  const decoded = verifyToken(token);

  if (!decoded) {
    ctx.status = 401;
    ctx.body = { error: "Token 无效或已过期" };
    return;
  }

  ctx.user = decoded;
  await next();
};

// API 路由
// 登录
router.post("/api/login", async (ctx) => {
  const { password } = ctx.request.body;

  if (!password) {
    ctx.status = 400;
    ctx.body = { error: "缺少密码" };
    return;
  }

  const data = loadData();
  // 前端已做 MD5 加密，后端再加一层 MD5 后比较
  const storedPassword = data.adminPassword || md5(md5("admin123"));
  const inputPassword = md5(password);

  if (inputPassword === storedPassword) {
    const token = generateToken({
      loggedIn: true,
      iat: Math.floor(Date.now() / 1000),
    });
    ctx.body = { success: true, token };
  } else {
    ctx.status = 401;
    ctx.body = { error: "密码错误" };
  }
});

// 检查登录状态
router.get("/api/auth/status", async (ctx) => {
  const authHeader = ctx.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    ctx.body = { loggedIn: false };
    return;
  }

  const token = authHeader.substring(7);
  const decoded = verifyToken(token);

  ctx.body = { loggedIn: !!decoded };
});

// 修改密码
router.put("/api/password", requireAuth, async (ctx) => {
  const { oldPassword, newPassword } = ctx.request.body;

  if (!oldPassword || !newPassword) {
    ctx.status = 400;
    ctx.body = { error: "缺少必要参数" };
    return;
  }

  const data = loadData();
  // 前端已做 MD5 加密，后端再加一层 MD5 后比较
  const storedPassword = data.adminPassword || md5(md5("admin123"));
  const inputOldPassword = md5(oldPassword);

  if (inputOldPassword !== storedPassword) {
    ctx.status = 401;
    ctx.body = { error: "原密码错误" };
    return;
  }

  // 新密码也做双层 MD5 存储
  data.adminPassword = md5(newPassword);
  saveData(data);

  ctx.body = { success: true };
});

// 获取所有分组
router.get("/api/groups", requireAuth, async (ctx) => {
  const data = loadData();
  ctx.body = { groups: data.groups };
});

// 创建分组
router.post("/api/groups", requireAuth, async (ctx) => {
  const { name, proxies } = ctx.request.body;

  if (!name || !Array.isArray(proxies)) {
    ctx.status = 400;
    ctx.body = { error: "缺少必要参数" };
    return;
  }

  const data = loadData();
  const uuid = uuidv4();

  // 过滤空行
  const filteredProxies = proxies.filter((p) => p.trim());

  const newGroup = {
    id: uuid,
    name,
    proxies: filteredProxies,
    createdAt: new Date().toISOString(),
  };

  data.groups.push(newGroup);
  saveData(data);

  ctx.body = { success: true, group: newGroup };
});

// 更新分组
router.put("/api/groups/:id", requireAuth, async (ctx) => {
  const { id } = ctx.params;
  const { name, proxies } = ctx.request.body;

  const data = loadData();
  const groupIndex = data.groups.findIndex((g) => g.id === id);

  if (groupIndex === -1) {
    ctx.status = 404;
    ctx.body = { error: "分组不存在" };
    return;
  }

  // 过滤空行
  const filteredProxies = (Array.isArray(proxies) ? proxies : []).filter((p) =>
    p.trim()
  );

  data.groups[groupIndex].name = name || data.groups[groupIndex].name;
  data.groups[groupIndex].proxies = filteredProxies;
  data.groups[groupIndex].updatedAt = new Date().toISOString();

  saveData(data);
  ctx.body = { success: true, group: data.groups[groupIndex] };
});

// 删除分组
router.delete("/api/groups/:id", requireAuth, async (ctx) => {
  const { id } = ctx.params;

  const data = loadData();
  const groupIndex = data.groups.findIndex((g) => g.id === id);

  if (groupIndex === -1) {
    ctx.status = 404;
    ctx.body = { error: "分组不存在" };
    return;
  }

  data.groups.splice(groupIndex, 1);
  saveData(data);

  ctx.body = { success: true };
});

// 订阅地址 - 获取分组内容（每行一个代理地址）
router.get("/subscription/:id", async (ctx) => {
  const { id } = ctx.params;
  const data = loadData();
  const group = data.groups.find((g) => g.id === id);

  // 分组不存在时返回空内容和 200 状态
  if (!group) {
    ctx.set("Content-Type", "text/plain; charset=utf-8");
    ctx.body = "";
    return;
  }

  // UA 验证：如果配置了 SUBSCRIPTION_UA_SECRET，则验证 UA 是否包含该字符串
  if (SUBSCRIPTION_UA_SECRET) {
    const userAgent = ctx.headers["user-agent"] || "";
    if (!userAgent.includes(SUBSCRIPTION_UA_SECRET)) {
      ctx.set("Content-Type", "text/plain; charset=utf-8");
      ctx.body = "";
      return;
    }
  }

  // 限流检查：每分钟只能有效访问一次（全局）
  const now = Date.now();

  if (rateLimitRecord && now - rateLimitRecord.lastAccess < RATE_LIMIT_WINDOW) {
    // 在限流时间内，返回空内容
    ctx.set("Content-Type", "text/plain; charset=utf-8");
    ctx.body = "";
    return;
  }

  // 更新限流记录
  rateLimitRecord = { lastAccess: now };

  // 将数组转换为每行一个的文本格式
  ctx.set("Content-Type", "text/plain; charset=utf-8");
  ctx.body = group.proxies.join("\n");
});

app.use(router.routes());
app.use(router.allowedMethods());

// 启动服务器
app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
  console.log(`管理界面：http://localhost:${PORT}/`);
});
