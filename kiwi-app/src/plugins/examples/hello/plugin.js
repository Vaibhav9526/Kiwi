// KIWI plugin starter (T-268). `kiwi` is a PluginClient injected by the host.
// Trusted-code alpha: this file runs in the app context — behave.
kiwi.onEvent("host.ready", async () => {
  try {
    await kiwi.request("notify.show", { kind: "info", text: "Hello plugin loaded." });
  } catch (e) {
    // e.code: capability-denied | locked | unknown-method | timeout …
  }
});
