import { NextResponse } from "next/server";
import { ZodError } from "zod";
import { ApiError } from "./http";
import { ScimError, SCHEMAS } from "./auth/scim";

const TYPE = "application/scim+json";
const headers = { "content-type": TYPE, "cache-control": "no-store" };

export const scimJson = (body: unknown, status = 200) => NextResponse.json(body, { status, headers });

const scimErr = (status: number, detail: string, scimType?: string) =>
  NextResponse.json({ schemas: [SCHEMAS.error], status: String(status), ...(scimType ? { scimType } : {}), detail }, { status, headers });

/** Like `handler`, but errors use SCIM's shape so identity providers can read them. */
export function scimHandler<A extends unknown[]>(fn: (...args: A) => Promise<Response>) {
  return async (...args: A): Promise<Response> => {
    try {
      return await fn(...args);
    } catch (e) {
      if (e instanceof ScimError) return scimErr(e.status, e.message, e.scimType);
      if (e instanceof ApiError) return scimErr(e.status, e.message);
      if (e instanceof ZodError) return scimErr(400, "Invalid request", "invalidSyntax");
      console.error(e);
      return scimErr(500, "Something went wrong");
    }
  };
}

/** Reads a JSON body, refusing anything unreasonably large. */
export async function readScimBody(req: Request) {
  const text = await req.text();
  if (text.length > 65_536) throw new ScimError(413, "tooLarge", "The request body is too large");
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ScimError(400, "invalidSyntax", "The request body isn't valid JSON");
  }
}
