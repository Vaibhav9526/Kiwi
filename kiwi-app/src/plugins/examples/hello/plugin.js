// KIWI plugin starter (T-268). `kiwi` is a PluginClient injected by the host.
// Trusted-code alpha (T-306): runs in a dedicated Worker — no DOM/localStorage.
kiwi.onEvent("host.ready", async () => {
  try {
    await kiwi.request("notify.show", { kind: "info", text: "Hello plugin loaded." });
  } catch (e) {
    // e.code: capability-denied | locked | unknown-method | timeout …
  }
});
