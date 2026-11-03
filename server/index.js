import { Hono } from "hono";
import { SignJWT, jwtVerify } from "jose";
import CryptoJS from "crypto-js";
import { loadData, saveData } from "./data.js";

const app = new Hono();

function md5(value) {
  return CryptoJS.MD5(value).toString();
}

function jwtKey(secret) {
  if (!secret) throw new Error("JWT_SECRET is required");
  return new TextEncoder().encode(secret);
}

async function verifyToken(token, secret) {
  try {
    const { payload } = await jwtVerify(token, jwtKey(secret), { algorithms: ["HS256"] });
    return payload.loggedIn === true ? payload : null;
  } catch {
    return null;
  }
}

function generateToken(payload, secret) {
  return new SignJWT(payload).setProtectedHeader({ alg: "HS256" })
    .setIssuedAt().setExpirationTime("24h").sign(jwtKey(secret));
}

async function readBody(ctx) {
  try {
    const body = await ctx.req.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error();
    return body;
  } catch {
    throw Object.assign(new Error("请求体必须为 JSON 对象"), { status: 400 });
  }
}

function toBase64(value) {
  return btoa(Array.from(new TextEncoder().encode(value), (byte) => String.fromCharCode(byte)).join(""));
}

app.onError((error, ctx) => {
  if (error.status === 400) return ctx.json({ error: error.message }, 400);
  console.error("请求处理失败:", error.message);
  return ctx.json({ error: "服务暂时不可用，请稍后重试" }, 500);
});

app.use("/api/*", async (ctx, next) => {
  ctx.header("Cache-Control", "no-store");
  jwtKey(ctx.env.JWT_SECRET);
  await next();
});

const requireAuth = async (ctx, next) => {
  const authHeader = ctx.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return ctx.json({ error: "未授权访问" }, 401);
  }
  const decoded = await verifyToken(authHeader.substring(7), ctx.env.JWT_SECRET);
  if (!decoded) return ctx.json({ error: "Token 无效或已过期" }, 401);
  await next();
};

function cleanPreferredHosts(preferredHosts) {
  if (!Array.isArray(preferredHosts)) return [];
  return preferredHosts
    .map((host) => ({
      label: String(host?.label || "").trim(),
      value: String(host?.value || "").trim(),
    }))
    .filter((host) => host.label && host.value);
}

function replaceNodeHost(proxy, host) {
  // Only replace the address after `@`; query parameters such as `host=` stay intact.
  return proxy.replace(
    /^(vless:\/\/[^@]+@)(\[[^\]]+\]|[^:/?#]+)(?=:\d|[/?#]|$)/i,
    `$1${host}`
  );
}

function replaceNodeName(proxy, nodeName, preferredHostLabel) {
  const displayName = `${nodeName}【${preferredHostLabel}】`;
  return proxy.includes("#")
    ? proxy.replace(/#[^#]*$/, `#${displayName}`)
    : `${proxy}#${displayName}`;
}

function getGroupProxies(group, data) {
  // Keep old groups working while new groups reference managed nodes.
  if (!Array.isArray(group.nodeIds)) return Array.isArray(group.proxies) ? group.proxies : [];

  const nodes = group.nodeIds
    .map((id) => data.nodes.find((node) => node.id === id))
    .filter(Boolean);
  return nodes.flatMap((node) => {
    if (!node.usePreferredHosts) return [node.proxy];
    const hosts = cleanPreferredHosts(data.preferredHosts);
    // Keep a usable subscription if Hosts have not been configured yet.
    if (!hosts.length) return [node.proxy];
    return hosts.map((host) =>
      replaceNodeName(
        replaceNodeHost(node.proxy, host.value),
        node.name,
        host.label
      )
    );
  });
}

// API 路由
// 登录
app.post("/api/login", async (ctx) => {
  const { password } = await readBody(ctx);

  if (typeof password !== "string" || !password) {
    return ctx.json({ error: "缺少密码" }, 400);
  }

  const data = await loadData(ctx.env);
  // 前端已做 MD5 加密，后端再加一层 MD5 后比较
  const storedPassword = data.adminPassword;
  const inputPassword = md5(password);

  if (inputPassword === storedPassword) {
    const token = await generateToken({
      loggedIn: true,
      iat: Math.floor(Date.now() / 1000),
    }, ctx.env.JWT_SECRET);
    return ctx.json({ success: true, token });
  } else {
    return ctx.json({ error: "密码错误" }, 401);
  }
});

// 检查登录状态
app.get("/api/auth/status", async (ctx) => {
  const authHeader = ctx.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return ctx.json({ loggedIn: false });
  }

  const token = authHeader.substring(7);
  const decoded = await verifyToken(token, ctx.env.JWT_SECRET);

  return ctx.json({ loggedIn: !!decoded });
});

// 修改密码
app.put("/api/password", requireAuth, async (ctx) => {
  const { oldPassword, newPassword } = await readBody(ctx);

  if (typeof oldPassword !== "string" || typeof newPassword !== "string" || !oldPassword || !newPassword) {
    return ctx.json({ error: "缺少必要参数" }, 400);
  }

  const data = await loadData(ctx.env);
  // 前端已做 MD5 加密，后端再加一层 MD5 后比较
  const storedPassword = data.adminPassword;
  const inputOldPassword = md5(oldPassword);

  if (inputOldPassword !== storedPassword) {
    return ctx.json({ error: "原密码错误" }, 401);
  }

  // 新密码也做双层 MD5 存储
  data.adminPassword = md5(newPassword);
  await saveData(ctx.env, data);

  return ctx.json({ success: true });
});

// 获取和保存统一管理的优选 Host
app.get("/api/preferred-hosts", requireAuth, async (ctx) => {
  const data = await loadData(ctx.env);
  return ctx.json({ preferredHosts: cleanPreferredHosts(data.preferredHosts) });
});

app.put("/api/preferred-hosts", requireAuth, async (ctx) => {
  const data = await loadData(ctx.env);
  const { preferredHosts } = await readBody(ctx);
  data.preferredHosts = cleanPreferredHosts(preferredHosts);
  await saveData(ctx.env, data);
  return ctx.json({ success: true, preferredHosts: data.preferredHosts });
});

// 获取所有节点
app.get("/api/nodes", requireAuth, async (ctx) => {
  const data = await loadData(ctx.env);
  return ctx.json({ nodes: data.nodes });
});

// 创建节点
app.post("/api/nodes", requireAuth, async (ctx) => {
  const { name, proxy, usePreferredHosts } = await readBody(ctx);
  if (!proxy || typeof proxy !== "string" || !proxy.trim()) {
    return ctx.json({ error: "请输入节点地址" }, 400);
  }

  const data = await loadData(ctx.env);
  const node = {
    id: crypto.randomUUID(),
    name: String(name || "").trim() || "未命名节点",
    proxy: proxy.trim(),
    usePreferredHosts: usePreferredHosts === true,
    createdAt: new Date().toISOString(),
  };
  data.nodes.push(node);
  await saveData(ctx.env, data);
  return ctx.json({ success: true, node });
});

// 更新节点
app.put("/api/nodes/:id", requireAuth, async (ctx) => {
  const { name, proxy, usePreferredHosts } = await readBody(ctx);
  const data = await loadData(ctx.env);
  const node = data.nodes.find((item) => item.id === ctx.req.param("id"));
  if (!node) {
    return ctx.json({ error: "节点不存在" }, 404);
  }
  if (!proxy || typeof proxy !== "string" || !proxy.trim()) {
    return ctx.json({ error: "请输入节点地址" }, 400);
  }
  node.name = String(name || "").trim() || "未命名节点";
  node.proxy = proxy.trim();
  node.usePreferredHosts = usePreferredHosts === true;
  node.updatedAt = new Date().toISOString();
  await saveData(ctx.env, data);
  return ctx.json({ success: true, node });
});

// 删除节点
app.delete("/api/nodes/:id", requireAuth, async (ctx) => {
  const data = await loadData(ctx.env);
  const index = data.nodes.findIndex((node) => node.id === ctx.req.param("id"));
  if (index === -1) {
    return ctx.json({ error: "节点不存在" }, 404);
  }
  data.nodes.splice(index, 1);
  data.groups.forEach((group) => {
    if (Array.isArray(group.nodeIds)) {
      group.nodeIds = group.nodeIds.filter((id) => id !== ctx.req.param("id"));
    }
  });
  await saveData(ctx.env, data);
  return ctx.json({ success: true });
});

// 获取所有分组
app.get("/api/groups", requireAuth, async (ctx) => {
  const data = await loadData(ctx.env);
  return ctx.json({ groups: data.groups });
});

// 创建分组
app.post("/api/groups", requireAuth, async (ctx) => {
  const { name, nodeIds, proxies } = await readBody(ctx);

  if (!name || (!Array.isArray(nodeIds) && !Array.isArray(proxies))) {
    return ctx.json({ error: "缺少必要参数" }, 400);
  }

  const data = await loadData(ctx.env);
  const uuid = crypto.randomUUID();

  const filteredNodeIds = Array.isArray(nodeIds)
    ? nodeIds.filter((id) => data.nodes.some((node) => node.id === id))
    : null;
  if (Array.isArray(nodeIds) && filteredNodeIds.length === 0) {
    return ctx.json({ error: "请至少选择一个节点" }, 400);
  }
  const newGroup = {
    id: uuid,
    name,
    nodeIds: filteredNodeIds,
    createdAt: new Date().toISOString(),
  };
  if (!Array.isArray(nodeIds)) newGroup.proxies = proxies.filter((proxy) => typeof proxy === "string" && proxy.trim());

  data.groups.push(newGroup);
  await saveData(ctx.env, data);

  return ctx.json({ success: true, group: newGroup });
});

// 更新分组
app.put("/api/groups/:id", requireAuth, async (ctx) => {
  const { id } = ctx.req.param();
  const { name, nodeIds, proxies } = await readBody(ctx);

  const data = await loadData(ctx.env);
  const groupIndex = data.groups.findIndex((g) => g.id === id);

  if (groupIndex === -1) {
    return ctx.json({ error: "分组不存在" }, 404);
  }

  // 过滤空行
  const filteredNodeIds = Array.isArray(nodeIds)
    ? nodeIds.filter((nodeId) => data.nodes.some((node) => node.id === nodeId))
    : null;
  if (Array.isArray(nodeIds) && filteredNodeIds.length === 0) {
    return ctx.json({ error: "请至少选择一个节点" }, 400);
  }
  data.groups[groupIndex].name = name || data.groups[groupIndex].name;
  if (Array.isArray(nodeIds)) {
    data.groups[groupIndex].nodeIds = filteredNodeIds;
    delete data.groups[groupIndex].proxies;
  } else if (Array.isArray(proxies)) {
    // Legacy groups can still be updated by older clients.
    data.groups[groupIndex].proxies = proxies.filter((proxy) => proxy.trim());
  }
  data.groups[groupIndex].updatedAt = new Date().toISOString();

  await saveData(ctx.env, data);
  return ctx.json({ success: true, group: data.groups[groupIndex] });
});

// 删除分组
app.delete("/api/groups/:id", requireAuth, async (ctx) => {
  const { id } = ctx.req.param();

  const data = await loadData(ctx.env);
  const groupIndex = data.groups.findIndex((g) => g.id === id);

  if (groupIndex === -1) {
    return ctx.json({ error: "分组不存在" }, 404);
  }

  data.groups.splice(groupIndex, 1);
  await saveData(ctx.env, data);

  return ctx.json({ success: true });
});

// 订阅地址 - 获取分组内容（Base64 编码后的每行一个代理地址）
app.get("/subscription/:id", async (ctx) => {
  ctx.header("Cache-Control", "no-store");
  // Cloudflare 原生限流：每个边缘位置的订阅请求共用 10 秒窗口。

  if (!(await ctx.env.SUBSCRIPTION_RATE_LIMITER.limit({ key: "subscription" })).success) {
    // 在限流时间内，返回空内容
    ctx.header("Content-Type", "text/plain; charset=utf-8");
    return ctx.text("");
  }

  const { id } = ctx.req.param();
  const data = await loadData(ctx.env);
  const group = data.groups.find((g) => g.id === id);

  // 分组不存在时返回空内容和 200 状态
  if (!group) {
    ctx.header("Content-Type", "text/plain; charset=utf-8");
    return ctx.text("");
  }

  // UA 验证：如果配置了 SUBSCRIPTION_UA_SECRET，则验证 UA 是否包含该字符串
  if (ctx.env.SUBSCRIPTION_UA_SECRET) {
    const userAgent = ctx.req.header("User-Agent") || "";
    if (!userAgent.includes(ctx.env.SUBSCRIPTION_UA_SECRET)) {
      ctx.header("Content-Type", "text/plain; charset=utf-8");
      return ctx.text("");
    }
  }

  // 将数组转换为每行一个的文本格式，再使用 UTF-8 做标准 Base64 编码。
  const content = getGroupProxies(group, data).join("\n");
  ctx.header("Content-Type", "text/plain; charset=utf-8");
  return ctx.text(toBase64(content));
});

app.notFound((ctx) => ctx.json({ error: "未找到请求的资源" }, 404));

export default app;
