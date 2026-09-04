import { NextRequest } from "next/server";

export const MASTER_COOKIE = "eg_master_session";

export function backendUrl(path: string) {
  const base = (process.env.API_BASE_URL ?? "https://ia-contra-fraude.fly.dev").replace(/\/$/, "");
  return `${base}/${path.replace(/^\//, "")}`;
}

export function backendHeaders(request?: NextRequest) {
  const headers = new Headers({ accept: "application/json" });
  if (process.env.API_KEY_SECRET) headers.set("x-api-key", process.env.API_KEY_SECRET);
  const session = request?.cookies.get(MASTER_COOKIE)?.value;
  if (session) headers.set("x-master-session", session);
  return headers;
}
