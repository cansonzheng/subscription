let scriptPromise;

function loadTurnstile() {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (scriptPromise) return scriptPromise;
  scriptPromise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    const timer = setTimeout(() => fail(), 15000);
    function fail() {
      clearTimeout(timer);
      script.remove();
      scriptPromise = null;
      reject(new Error("安全验证加载失败，请重试"));
    }
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.onload = () => {
      if (!window.turnstile) return fail();
      window.turnstile.ready(() => {
        clearTimeout(timer);
        resolve(window.turnstile);
      });
    };
    script.onerror = fail;
    document.head.append(script);
  });
  return scriptPromise;
}

window.TurnstileChallenge = {
  emits: ["verified"],
  template: `
    <div class="login-verification">
      <div ref="widget"></div>
      <p v-if="initializing" class="helper" role="status">正在加载安全验证…</p>
      <p v-if="error" class="helper verification-error" role="alert">{{ error }}</p>
      <mdui-button v-if="error" type="button" variant="text" @click="initialize">重试验证</mdui-button>
    </div>
  `,
  data() {
    return { widgetId: null, initializing: false, error: "", disposed: false };
  },
  mounted() {
    this.initialize();
  },
  beforeUnmount() {
    this.disposed = true;
    this.removeWidget();
  },
  methods: {
    removeWidget() {
      if (this.widgetId !== null && window.turnstile) {
        window.turnstile.remove(this.widgetId);
        this.widgetId = null;
      }
    },
    reset() {
      this.$emit("verified", "");
      this.error = "";
      if (this.widgetId !== null && window.turnstile) {
        window.turnstile.reset(this.widgetId);
      } else {
        this.initialize();
      }
    },
    async initialize() {
      if (this.initializing || this.disposed) return;
      this.initializing = true;
      this.error = "";
      this.$emit("verified", "");
      this.removeWidget();
      try {
        const { data } = await axios.get("/api/turnstile/config", { timeout: 10000 });
        if (!data.siteKey) throw new Error();
        const turnstile = await loadTurnstile();
        if (this.disposed) return;
        this.widgetId = turnstile.render(this.$refs.widget, {
          sitekey: data.siteKey,
          action: "login",
          size: this.$refs.widget.clientWidth < 300 ? "compact" : "flexible",
          theme: "auto",
          "response-field": false,
          callback: (token) => {
            this.error = "";
            this.$emit("verified", token);
          },
          "expired-callback": () => this.reset(),
          "timeout-callback": () => this.reset(),
          "error-callback": () => {
            this.$emit("verified", "");
            this.error = "安全验证失败，请重试";
            return true;
          },
        });
      } catch {
        if (!this.disposed) this.error = "安全验证加载失败，请重试";
      } finally {
        this.initializing = false;
      }
    },
  },
};
