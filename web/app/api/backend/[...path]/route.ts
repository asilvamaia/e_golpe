import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const maxDuration = 60;

const allowedPaths = new Set([
  "api/v1/analyze",
  "api/v1/analyze-text",
  "api/v1/analyze-file",
  "api/v1/check-password",
  "api/v1/feedback",
  "api/v1/stats",
  "health",
]);

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  const joinedPath = path.join("/");
  if (!allowedPaths.has(joinedPath)) {
    return NextResponse.json({ detail: "Rota não permitida." }, { status: 404 });
  }

  const baseUrl = (
    process.env.API_BASE_URL ?? "https://ia-contra-fraude.fly.dev"
  ).replace(/\/$/, "");

  try {
    const target = new URL(`${baseUrl}/${joinedPath}`);
    request.nextUrl.searchParams.forEach((value, key) => target.searchParams.set(key, value));

    const headers = new Headers();
    const contentType = request.headers.get("content-type");
    if (contentType) headers.set("content-type", contentType);
    headers.set("accept", "application/json");
    if (process.env.API_KEY_SECRET) headers.set("x-api-key", process.env.API_KEY_SECRET);

    const response = await fetch(target, {
      method: request.method,
      headers,
      body: request.method === "GET" ? undefined : await request.arrayBuffer(),
      cache: "no-store",
      signal: AbortSignal.timeout(58_000),
    });
    const responseType = response.headers.get("content-type") ?? "application/json";
    return new NextResponse(response.body, {
      status: response.status,
      headers: { "content-type": responseType, "cache-control": "no-store" },
    });
  } catch (error) {
    console.error("Backend proxy request failed", error);
    return NextResponse.json(
      { detail: "O serviço de análise demorou mais que o esperado. Tente novamente." },
      { status: 504 },
    );
  }
}

export const GET = proxy;
export const POST = proxy;
