const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

export async function verifyTurnstile(env, token, hostname, remoteip) {
  if (!env.TURNSTILE_SITE_KEY || !env.Turnstile_Key) {
    throw new Error("Turnstile configuration missing");
  }
  const secret = await env.Turnstile_Key.get();
  if (typeof secret !== "string" || !secret) {
    throw new Error("Turnstile secret unavailable");
  }
  const response = await fetch(SITEVERIFY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ secret, response: token, ...(remoteip ? { remoteip } : {}) }),
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error("Turnstile verification unavailable");
  const result = await response.json();
  if (result["error-codes"]?.some((code) => ["missing-input-secret", "invalid-input-secret", "internal-error"].includes(code))) {
    throw new Error("Turnstile verification unavailable");
  }
  return result.success === true
    && result.action === "login"
    && result.hostname === hostname;
}
