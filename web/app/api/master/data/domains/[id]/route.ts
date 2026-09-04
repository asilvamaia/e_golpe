import { NextRequest, NextResponse } from "next/server";
import { backendHeaders, backendUrl, MASTER_COOKIE } from "@/lib/master-backend";

export async function DELETE(request: NextRequest, context: { params: Promise<{ id: string }> }) {
  if (!request.cookies.get(MASTER_COOKIE)) return NextResponse.json({ detail: "Não autorizado." }, { status: 401 });
  const { id } = await context.params;
  if (!/^\d+$/.test(id)) return NextResponse.json({ detail: "Identificador inválido." }, { status: 400 });
  const response = await fetch(backendUrl(`api/v1/master/domains/${id}`), { method: "DELETE", headers: backendHeaders(request), cache: "no-store" });
  return new NextResponse(response.body, { status: response.status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}
