/**
 * Minimal hash router (T-112) — no router dependency on purpose (offline-safe
 * scaffold, fewer deps). Routes mirror ui-spec views; selection state that
 * must survive reload (folder, message) lives in the hash.
 */
import { useEffect, useState } from "react";

export type RouteName = "mail" | "compose" | "setup" | "settings" | "security" | "search" | "contacts";

export interface Route {
  name: RouteName;
  folder?: string;
  messageId?: string;
}

const DEFAULT_ROUTE: Route = { name: "mail", folder: "all-inboxes" };

export function parseHash(hash: string): Route {
  const clean = hash.replace(/^#\/?/, "");
  const [name, ...rest] = clean.split("/");
  switch (name) {
    case "compose":
      return { name: "compose" };
    case "setup":
      return { name: "setup" };
    case "settings":
      return { name: "settings" };
    case "security":
      return { name: "security" };
    case "search":
      return { name: "search" };
    case "contacts":
      return { name: "contacts" };
    case "mail":
      return { name: "mail", folder: rest[0] || "all-inboxes", messageId: rest[1] };
    default:
      return DEFAULT_ROUTE;
  }
}

export function toHash(route: Route): string {
  switch (route.name) {
    case "mail":
      return `#/mail/${route.folder ?? "all-inboxes"}${route.messageId ? `/${route.messageId}` : ""}`;
    case "contacts":
      return "#/contacts";
    default:
      return `#/${route.name}`;
  }
}

export function navigate(route: Route): void {
  window.location.hash = toHash(route);
}

/** Reactive current route (subscribes to hashchange). */
export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}
