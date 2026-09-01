const fs = require("fs");
const path = require("path");

const DATA_FILE = path.join(__dirname, "../db.json");

const defaultData = {
  adminPassword: "admin123",
  nodes: [],
  groups: [],
  preferredHosts: [],
};

function getLegacyPreferredHosts(nodes) {
  const seen = new Set();
  return nodes.flatMap((node) => node.preferredHosts || []).filter((host) => {
    const label = String(host?.label || "").trim();
    const value = String(host?.value || "").trim();
    const key = `${label}\u0000${value}`;
    if (!label || !value || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function loadData() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      saveData(defaultData);
      return defaultData;
    }
    const data = fs.readFileSync(DATA_FILE, "utf8");
    const parsed = JSON.parse(data);
    const nodes = Array.isArray(parsed.nodes) ? parsed.nodes : [];
    const hasManagedPreferredHosts = Array.isArray(parsed.preferredHosts);
    return {
      ...defaultData,
      ...parsed,
      // Migrate per-node Hosts from older data while preserving their output behavior.
      nodes: nodes.map(({ preferredHosts, ...node }) => ({
        ...node,
        usePreferredHosts:
          typeof node.usePreferredHosts === "boolean"
            ? node.usePreferredHosts
            : Array.isArray(preferredHosts) && preferredHosts.length > 0,
      })),
      groups: Array.isArray(parsed.groups) ? parsed.groups : [],
      preferredHosts: hasManagedPreferredHosts
        ? parsed.preferredHosts
        : getLegacyPreferredHosts(nodes),
    };
  } catch (error) {
    console.error("加载数据失败:", error);
    return defaultData;
  }
}

function saveData(data) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
    return true;
  } catch (error) {
    console.error("保存数据失败:", error);
    return false;
  }
}

module.exports = { loadData, saveData, DATA_FILE };
