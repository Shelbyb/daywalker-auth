import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { configInput, configView, getConfig, removeConfig, saveConfig } from "@/lib/audit-export";

/** Backend API: push of the audit log to your S3-compatible bucket. The secret is write-only. */
export const GET = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json(configView(await getConfig(inst.id), inst.id));
});

export const PUT = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json(await saveConfig(inst.id, configInput.parse(await req.json()), { type: "api" }));
});

export const DELETE = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json({ removed: await removeConfig(inst.id, { type: "api" }) });
});
