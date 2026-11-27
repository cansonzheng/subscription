import test, { beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import CryptoJS from "crypto-js";
import { SignJWT } from "jose";
import app from "../server/index.js";

const md5 = (value) => CryptoJS.MD5(value).toString();

beforeEach(() => {
  mock.method(globalThis, "fetch", async () => Response.json({ success: true, action: "login", hostname: "localhost" }));
});
afterEach(() => mock.restoreAll());

function fixture() {
  let stored = JSON.stringify({
    adminPassword: md5(md5("test-password")),
    nodes: [{ id: "node-1", name: "香港", proxy: "vless://test@example.com:443?host=original.example#原名", usePreferredHosts: true }],
    groups: [{ id: "group-1", name: "测试", nodeIds: ["node-1"] }],
    preferredHosts: [{ label: "优选", value: "preferred.example" }],
  });
  const env = {
    JWT_SECRET: "test-only-secret-with-at-least-32-characters",
    TURNSTILE_SITE_KEY: "test-site-key",
    Turnstile_Key: { async get() { return "test-secret-key"; } },
    SUBSCRIPTION_KV: {
      async get(key, type) {
        assert.equal(key, "db");
        assert.equal(type, "json");
        return stored === null ? null : JSON.parse(stored);
      },
      async put(key, value) {
        assert.equal(key, "db");
        stored = value;
      },
    },
    SUBSCRIPTION_RATE_LIMITER: { async limit() { return { success: true }; } },
  };
  async function request(path, method = "GET", body, token) {
    if (path === "/api/login" && body) body = { turnstileToken: "valid-test-token", ...body };
    return app.request(path, {
      method,
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }, env);
  }
  async function login(password = "test-password") {
    const response = await request("/api/login", "POST", { password: md5(password) });
    assert.equal(response.status, 200);
    return (await response.json()).token;
  }
  return { env, request, login, data: () => JSON.parse(stored), clear: () => { stored = null; } };
}

test("login, authenticated reads and password changes survive new requests", async () => {
  const f = fixture();
  assert.equal((await f.request("/api/nodes")).status, 401);
  assert.equal((await f.request("/api/login", "POST", { password: md5("wrong") })).status, 401);
  const token = await f.login();
  assert.deepEqual(await (await f.request("/api/auth/status", "GET", undefined, token)).json(), { loggedIn: true });
  const nodes = await (await f.request("/api/nodes", "GET", undefined, token)).json();
  assert.equal(nodes.nodes.length, 1);
  assert.equal(nodes.adminPassword, undefined);
  assert.equal((await f.request("/api/password", "PUT", { oldPassword: md5("test-password"), newPassword: md5("changed") }, token)).status, 200);
  assert.equal(f.data().adminPassword, md5(md5("changed")));
  await f.login("changed");
});

test("Turnstile config exposes only the public Site Key", async () => {
  const f = fixture();
  const response = await f.request("/api/turnstile/config");
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.deepEqual(await response.json(), { siteKey: "test-site-key" });
  assert.equal(globalThis.fetch.mock.callCount(), 0);
});

test("missing, empty, non-string and oversized Turnstile tokens cannot reach password storage", async () => {
  const f = fixture();
  f.env.SUBSCRIPTION_KV.get = async () => assert.fail("Rejected challenge must not read KV");
  for (const turnstileToken of [undefined, "", "   ", 42, "x".repeat(2049)]) {
    const response = await f.request("/api/login", "POST", { password: md5("test-password"), turnstileToken });
    assert.equal(response.status, 403);
    assert.equal((await response.json()).token, undefined);
  }
  assert.equal(globalThis.fetch.mock.callCount(), 0);
});

test("login verifies the token with Secrets Store before issuing JWT", async () => {
  const f = fixture();
  let secretReads = 0;
  f.env.Turnstile_Key.get = async () => { secretReads++; return "private-secret"; };
  globalThis.fetch.mock.mockImplementation(async (url, options) => {
    assert.equal(url, "https://challenges.cloudflare.com/turnstile/v0/siteverify");
    assert.equal(options.method, "POST");
    assert.deepEqual(JSON.parse(options.body), { secret: "private-secret", response: "valid-test-token" });
    assert.ok(options.signal instanceof AbortSignal);
    return Response.json({ success: true, action: "login", hostname: "localhost" });
  });
  assert.ok(await f.login());
  assert.equal(secretReads, 1);
});

test("invalid, expired, reused and cross-host or cross-action challenges fail closed", async () => {
  const f = fixture();
  f.env.SUBSCRIPTION_KV.get = async () => assert.fail("Rejected challenge must not read KV");
  for (const result of [
    { success: false, "error-codes": ["invalid-input-response"] },
    { success: false, "error-codes": ["timeout-or-duplicate"] },
    { success: true, action: "other", hostname: "localhost" },
    { success: true, action: "login", hostname: "other.example" },
    { success: true },
  ]) {
    globalThis.fetch.mock.mockImplementation(async () => Response.json(result));
    const response = await f.request("/api/login", "POST", { password: md5("test-password") });
    assert.equal(response.status, 403);
    assert.equal((await response.json()).token, undefined);
  }
});

test("Secrets Store failures and Siteverify outages never allow login", async () => {
  const f = fixture();
  f.env.SUBSCRIPTION_KV.get = async () => assert.fail("Unavailable verification must not read KV");
  for (const implementation of [
    async () => { throw new Error("network timeout"); },
    async () => new Response("unavailable", { status: 503 }),
    async () => new Response("invalid json"),
    async () => Response.json({ success: false, "error-codes": ["invalid-input-secret"] }),
  ]) {
    globalThis.fetch.mock.mockImplementation(implementation);
    assert.equal((await f.request("/api/login", "POST", { password: md5("test-password") })).status, 503);
  }
  f.env.Turnstile_Key.get = async () => { throw new Error("secret unavailable"); };
  assert.equal((await f.request("/api/login", "POST", { password: md5("test-password") })).status, 503);
  delete f.env.Turnstile_Key;
  assert.equal((await f.request("/api/login", "POST", { password: md5("test-password") })).status, 503);
  delete f.env.TURNSTILE_SITE_KEY;
  assert.equal((await f.request("/api/turnstile/config")).status, 503);
});

test("node, group and Host mutations persist and deletion removes node references", async () => {
  const f = fixture();
  const token = await f.login();
  const node = (await (await f.request("/api/nodes", "POST", { name: "新增", proxy: "vless://new@server:443" }, token)).json()).node;
  const group = (await (await f.request("/api/groups", "POST", { name: "新增分组", nodeIds: [node.id] }, token)).json()).group;
  assert.equal((await f.request(`/api/nodes/${node.id}`, "PUT", { name: "更新", proxy: "vless://new@updated:443" }, token)).status, 200);
  assert.equal((await f.request(`/api/groups/${group.id}`, "PUT", { name: "更新分组", nodeIds: [node.id, "node-1"] }, token)).status, 200);
  assert.equal((await f.request("/api/preferred-hosts", "PUT", { preferredHosts: [{ label: "  新 Host  ", value: " new.example " }] }, token)).status, 200);
  assert.deepEqual((await (await f.request("/api/preferred-hosts", "GET", undefined, token)).json()).preferredHosts, [{ label: "新 Host", value: "new.example" }]);
  assert.equal((await f.request(`/api/nodes/${node.id}`, "DELETE", undefined, token)).status, 200);
  assert.deepEqual(f.data().groups.find((item) => item.id === group.id).nodeIds, ["node-1"]);
  assert.equal((await f.request(`/api/groups/${group.id}`, "DELETE", undefined, token)).status, 200);
  assert.equal((await (await f.request("/api/groups", "GET", undefined, token)).json()).groups.length, 1);
});

test("UTF-8 subscription, preferred hosts, UA restriction and rate limiter", async () => {
  const f = fixture();
  const response = await f.request("/subscription/group-1");
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.equal(Buffer.from(await response.text(), "base64").toString("utf8"), "vless://test@preferred.example:443?host=original.example#香港【优选】");
  f.env.SUBSCRIPTION_UA_SECRET = "allowed-client";
  assert.equal(await (await f.request("/subscription/group-1")).text(), "");
  const allowed = await app.request("/subscription/group-1", { headers: { "User-Agent": "allowed-client" } }, f.env);
  assert.ok((await allowed.text()).length > 0);
  delete f.env.SUBSCRIPTION_UA_SECRET;
  f.env.SUBSCRIPTION_RATE_LIMITER.limit = async () => ({ success: false });
  assert.equal(await (await f.request("/subscription/group-1")).text(), "");
});

test("legacy groups and per-node preferred Hosts stay usable", async () => {
  const f = fixture();
  await f.env.SUBSCRIPTION_KV.put("db", JSON.stringify({
    nodes: [{ id: "old", name: "旧节点", proxy: "vless://id@original:443", preferredHosts: [{ label: "旧 Host", value: "legacy.example" }] }],
    groups: [{ id: "old-group", proxies: ["vless://legacy@host:443#旧订阅"] }, { id: "managed", nodeIds: ["old"] }],
  }));
  const legacy = await f.request("/subscription/old-group");
  assert.equal(Buffer.from(await legacy.text(), "base64").toString("utf8"), "vless://legacy@host:443#旧订阅");
  const managed = await f.request("/subscription/managed");
  assert.equal(Buffer.from(await managed.text(), "base64").toString("utf8"), "vless://id@legacy.example:443#旧节点【旧 Host】");
});

test("expired and forged tokens and malformed JSON are rejected", async () => {
  const f = fixture();
  assert.equal((await f.request("/api/nodes", "GET", undefined, "forged")).status, 401);
  const expired = await new SignJWT({ loggedIn: true }).setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(1).sign(new TextEncoder().encode(f.env.JWT_SECRET));
  assert.equal((await f.request("/api/nodes", "GET", undefined, expired)).status, 401);
  const response = await app.request("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{" }, f.env);
  assert.equal(response.status, 400);
});

test("missing KV and failed writes return errors without silently initializing data", async () => {
  const f = fixture();
  const token = await f.login();
  f.env.SUBSCRIPTION_KV.put = async () => { throw new Error("simulated KV failure"); };
  const response = await f.request("/api/nodes", "POST", { proxy: "vless://id@server:443" }, token);
  assert.equal(response.status, 500);
  assert.equal(f.data().nodes.length, 1);
  f.clear();
  assert.equal((await f.request("/api/login", "POST", { password: md5("test-password") })).status, 500);
});
