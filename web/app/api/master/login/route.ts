import { NextRequest, NextResponse } from "next/server";
import { backendHeaders, backendUrl, MASTER_COOKIE } from "@/lib/master-backend";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  if (!request.headers.get("content-type")?.includes("application/json")) {
    return NextResponse.json({ detail: "Formato inválido." }, { status: 415 });
  }
  const origin = request.headers.get("origin");
  if (origin && new URL(origin).host !== request.nextUrl.host) {
    return NextResponse.json({ detail: "Origem não autorizada." }, { status: 403 });
  }
  try {
    const body = await request.json();
    const response = await fetch(backendUrl("api/v1/master/login"), {
      method: "POST",
      headers: new Headers({ ...Object.fromEntries(backendHeaders()), "content-type": "application/json" }),
      body: JSON.stringify({ password: body.password }),
      cache: "no-store",
      signal: AbortSignal.timeout(15_000),
    });
    const data = await response.json();
    if (!response.ok || !data.token) {
      return NextResponse.json({ detail: data.detail || "Credenciais inválidas." }, { status: response.status });
    }
    const result = NextResponse.json({ authenticated: true });
    result.cookies.set(MASTER_COOKIE, data.token, { httpOnly: true, secure: true, sameSite: "strict", path: "/", maxAge: 8 * 60 * 60 });
    return result;
  } catch {
    return NextResponse.json({ detail: "Não foi possível validar o acesso." }, { status: 503 });
  }
}
