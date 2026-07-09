import { NextResponse } from "next/server";
import jwt from "jsonwebtoken";

export async function POST(request: Request) {
  try {
    const authHeader = request.headers.get("x-internal-secret");

    if (
      !process.env.INTERNAL_API_SECRET ||
      authHeader !== process.env.INTERNAL_API_SECRET
    ) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const appId = process.env.GITHUB_APP_ID;
    const privateKey = process.env.GITHUB_PRIVATE_KEY?.replace(/\\n/g, "\n");

    if (!appId || !privateKey) {
      return NextResponse.json(
        { error: "GitHub credentials not configured" },
        { status: 500 }
      );
    }

    const now = Math.floor(Date.now() / 1000);
    
    const payload = {
      iat: now - 60,
      exp: now + 9 * 60,
      iss: appId,
    };

    const token = jwt.sign(payload, privateKey, { algorithm: "RS256" });

    return NextResponse.json({ jwt: token });
  } catch (error: any) {
    console.error("Generate GitHub JWT error:", error);
    return NextResponse.json(
      { error: error.message || "Internal server error" },
      { status: 500 }
    );
  }
}
