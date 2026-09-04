import { NextRequest, NextResponse } from "next/server";
import { MASTER_COOKIE } from "@/lib/master-backend";

export async function POST(request: NextRequest) {
  const origin = request.headers.get("origin");
  if (origin && new URL(origin).host !== request.nextUrl.host) return NextResponse.json({ detail: "Origem não autorizada." }, { status: 403 });
  const response = NextResponse.json({ authenticated: false });
  response.cookies.set(MASTER_COOKIE, "", { httpOnly: true, secure: true, sameSite: "strict", path: "/", maxAge: 0 });
  return response;
}
