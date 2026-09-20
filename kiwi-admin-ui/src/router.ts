/** Minimal hash router (T-134) — same dependency-free pattern as kiwi-app. */
import { useEffect, useState } from "react";

export type RouteName = "orgs" | "users" | "policies" | "mailflow" | "audit";

export interface Route {
  name: RouteName;
}

export function parseHash(hash: string): Route {
  const name = hash.replace(/^#\/?/, "").split("/")[0];
  switch (name) {
    case "users":
      return { name: "users" };
    case "policies":
      return { name: "policies" };
    case "mailflow":
      return { name: "mailflow" };
    case "audit":
      return { name: "audit" };
    default:
      return { name: "orgs" };
  }
}

export function navigate(route: Route): void {
  window.location.hash = `#/${route.name}`;
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}
