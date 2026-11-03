import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { DATA_KEY, normalizeData } from "../server/data.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const wrangler = fileURLToPath(new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url));
const args = process.argv.slice(2);
if (args.length !== 1 || !["--local", "--remote"].includes(args[0])) {
  console.error("请明确指定目标：npm run migrate -- --local 或 --remote");
  process.exit(1);
}
const target = args[0];
const binding = ["--binding", "SUBSCRIPTION_KV", target];

function run(command) {
  const result = spawnSync(process.execPath, [wrangler, ...command], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    env: { ...process.env, WRANGLER_SEND_METRICS: "false" },
  });
  // Never print stdout: key get contains password hashes and subscription credentials.
  if (result.error || result.status !== 0) {
    throw new Error(`Wrangler 执行失败：${command.slice(0, 3).join(" ")}。请检查登录状态、账户权限和网络。`);
  }
  return result.stdout;
}

const digest = (value) => createHash("sha256").update(value).digest("hex");

try {
  const sourcePath = fileURLToPath(new URL("../db.json", import.meta.url));
  const source = readFileSync(sourcePath, "utf8");
  const data = JSON.parse(source);
  normalizeData(data);
  if (typeof data.adminPassword !== "string" || !/^[a-f0-9]{32}$/i.test(data.adminPassword)
    || !Array.isArray(data.nodes) || !Array.isArray(data.groups)) {
    throw new Error("db.json 缺少有效密码散列、节点或分组，已中止迁移。");
  }
  const keys = JSON.parse(run(["kv", "key", "list", ...binding, "--prefix", DATA_KEY]));
  if (keys.some((entry) => entry.name === DATA_KEY)) {
    const existing = run(["kv", "key", "get", DATA_KEY, ...binding]);
    if (digest(existing) !== digest(source)) {
      throw new Error("目标 KV 已有不同的 db 数据，已停止，未覆盖远端内容。");
    }
    console.log("目标 KV 已有完全相同的数据，无需重复迁移。");
  } else {
    run(["kv", "key", "put", DATA_KEY, ...binding, "--path", sourcePath]);
    const migrated = run(["kv", "key", "get", DATA_KEY, ...binding]);
    if (digest(migrated) !== digest(source)) {
      throw new Error("KV 回读校验未通过，请检查远端数据后再使用服务。");
    }
    console.log("迁移成功，SHA-256 回读校验通过。");
  }
  console.log(`目标：${target}；节点：${data.nodes.length}；分组：${data.groups.length}；优选 Host：${data.preferredHosts?.length ?? 0}。本地 db.json 已保留。`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
