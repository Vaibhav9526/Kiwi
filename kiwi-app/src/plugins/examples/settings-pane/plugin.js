// KIWI reference plugin (T-280): Settings pane via the settings-page cap.
// `kiwi` is a PluginClient injected by the host at load time.
// Trusted-code alpha (T-306): runs in a dedicated Worker — no DOM/localStorage.

kiwi.onEvent("host.ready", async () => {
  try {
    await kiwi.request("settings.registerPane", {
      paneId: "about",
      title: "Demo Plugin",
      icon: "puzzle",
      // Static fallback body; refreshed dynamically on pane.mount.
      html: "<p><strong>Demo plugin pane</strong> — waiting for mount…</p>",
    });
  } catch (e) {
    // e.code: capability-denied | locked | …
  }
});

// The host emits pane.mount when Settings→Plugins shows the pane —
// respond with live markup via settings.renderPane.
kiwi.onEvent("pane.mount", async (data) => {
  if (!data || data.paneId !== "about") return;
  try {
    await kiwi.request("settings.renderPane", {
      paneId: "about",
      html:
        "<p><strong>Demo plugin pane</strong> — rendered by the plugin via " +
        "<code>settings.renderPane</code>.</p>" +
        "<p><small>Mounted at " + new Date().toLocaleTimeString() +
        ". Body markup is plugin-supplied (trusted-code alpha).</small></p>",
    });
    await kiwi.request("notify.show", { kind: "info", text: "demo pane mounted" });
  } catch (e) {
    // capability-denied | locked | …
  }
});
