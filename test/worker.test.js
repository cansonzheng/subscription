import test from "node:test";
import assert from "node:assert/strict";
import CryptoJS from "crypto-js";
import { SignJWT } from "jose";
import app from "../server/index.js";

const md5 = (value) => CryptoJS.MD5(value).toString();

function fixture() {
  let stored = JSON.stringify({
    adminPassword: md5(md5("test-password")),
    nodes: [{ id: "node-1", name: "香港", proxy: "vless://test@example.com:443?host=original.example#原名", usePreferredHosts: true }],
    groups: [{ id: "group-1", name: "测试", nodeIds: ["node-1"] }],
    preferredHosts: [{ label: "优选", value: "preferred.example" }],
  });
  const env = {
    JWT_SECRET: "test-only-secret-with-at-least-32-characters",
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
