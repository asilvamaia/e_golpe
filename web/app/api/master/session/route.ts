import { NextRequest, NextResponse } from "next/server";
import { backendHeaders, backendUrl } from "@/lib/master-backend";

export async function GET(request: NextRequest) {
  if (!request.cookies.get("eg_master_session")) return NextResponse.json({ authenticated: false }, { status: 401 });
  try {
    const response = await fetch(backendUrl("api/v1/master/session"), { headers: backendHeaders(request), cache: "no-store", signal: AbortSignal.timeout(10_000) });
    if (!response.ok) return NextResponse.json({ authenticated: false }, { status: 401 });
    return NextResponse.json({ authenticated: true }, { headers: { "cache-control": "no-store" } });
  } catch {
    return NextResponse.json({ authenticated: false }, { status: 503 });
  }
}
