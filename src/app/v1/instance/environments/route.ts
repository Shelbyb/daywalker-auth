import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { environmentsView } from "@/lib/auth/application";

/** Backend API: which environment this instance is, and its application's other environments (publishable keys only). */
export const GET = handler(async (req: Request) => NextResponse.json(await environmentsView(await instanceFromSecretKey(req))));
