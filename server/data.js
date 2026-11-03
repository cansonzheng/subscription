export const DATA_KEY = "db";

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

export function normalizeData(parsed) {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Invalid subscription data");
  }
  const nodes = Array.isArray(parsed.nodes) ? parsed.nodes : [];
  const hasManagedPreferredHosts = Array.isArray(parsed.preferredHosts);
  return {
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
}

export async function loadData(env) {
  const data = await env.SUBSCRIPTION_KV.get(DATA_KEY, "json");
  // Missing or corrupt data must never silently replace existing subscriptions.
  if (!data) throw new Error("KV data missing; migrate db.json before starting");
  return normalizeData(data);
}

export async function saveData(env, data) {
  await env.SUBSCRIPTION_KV.put(DATA_KEY, JSON.stringify(data));
}
