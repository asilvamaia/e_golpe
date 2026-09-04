import { NextRequest, NextResponse } from "next/server";
import { backendHeaders, backendUrl, MASTER_COOKIE } from "@/lib/master-backend";

export const runtime = "nodejs";
const allowed = new Set(["summary", "dataset", "feedbacks", "domains", "logs", "backup"]);

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  if (!request.cookies.get(MASTER_COOKIE)) return NextResponse.json({ detail: "Não autorizado." }, { status: 401 });
  const { path } = await context.params;
  const resource = path[0];
  if (path.length !== 1 || !allowed.has(resource)) return NextResponse.json({ detail: "Rota não permitida." }, { status: 404 });
  const target = new URL(backendUrl(`api/v1/master/${resource}`));
  request.nextUrl.searchParams.forEach((value, key) => target.searchParams.set(key, value));
  const headers = backendHeaders(request);
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);
  try {
    const response = await fetch(target, { method: request.method, headers, body: request.method === "GET" ? undefined : await request.arrayBuffer(), cache: "no-store", signal: AbortSignal.timeout(30_000) });
    return new NextResponse(response.body, { status: response.status, headers: { "content-type": response.headers.get("content-type") || "application/json", "content-disposition": response.headers.get("content-disposition") || "", "cache-control": "no-store" } });
  } catch {
    return NextResponse.json({ detail: "Serviço administrativo indisponível." }, { status: 503 });
  }
}

export const GET = proxy;
export const POST = proxy;
