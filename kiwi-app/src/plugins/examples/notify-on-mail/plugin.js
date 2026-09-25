// KIWI reference plugin (T-274): toast on new mail.
// `kiwi` is a PluginClient injected by the host at load time.
// Trusted-code alpha: this file runs in the app context — behave.
kiwi.onEvent("mail-changed", async (data) => {
  const added = data && typeof data.added === "number" ? data.added : 0;
  if (added <= 0) return;
  try {
    await kiwi.request("notify.show", {
      kind: "info",
      text: `${added} new message${added === 1 ? "" : "s"} — ${data.folder ?? "Inbox"}`,
    });
  } catch (e) {
    // e.code: capability-denied | locked | unknown-method | not-implemented | timeout
  }
});
