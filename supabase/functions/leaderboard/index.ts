// Edge Function: leaderboard
// Handles two routes:
//   POST /leaderboard?action=start   → create a game session, return token
//   POST /leaderboard?action=submit  → validate & record a score
//   GET  /leaderboard                → return top scores (public)

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

// --- Anti-cheat constants ---
const MAX_REASONABLE_SCORE = 200;
const MIN_GAME_DURATION_MS = 3_000; // no one scores in under 3s
const SESSION_TTL_MINUTES = 15;
const ALLOWED_ORIGIN = "https://yuvalarbel.github.io";

// CORS headers
function corsHeaders(origin: string | null) {
  // Allow both GitHub Pages and localhost for development
  const allowedOrigins = [ALLOWED_ORIGIN, "http://localhost:3000", "http://127.0.0.1:5500"];
  const allowed = origin && allowedOrigins.includes(origin) ? origin : ALLOWED_ORIGIN;
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey",
  };
}

// Hash a token using SHA-256
async function hashToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Generate a crypto-random token (32 bytes, hex)
function generateToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

Deno.serve(async (req) => {
  const origin = req.headers.get("origin");
  const cors = corsHeaders(origin);

  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  const url = new URL(req.url);
  const action = url.searchParams.get("action");

  // Service-role client (bypasses RLS)
  const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

  try {
    // ─── GET: Read leaderboard (top 50) ───
    if (req.method === "GET" && !action) {
      const { data, error } = await supabase
        .from("game_sessions")
        .select("username, score, submitted_at")
        .not("submitted_at", "is", null)
        .order("score", { ascending: false })
        .order("submitted_at", { ascending: true })
        .limit(50);

      if (error) throw error;
      return new Response(JSON.stringify(data), {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    // ─── POST: Start session ───
    if (req.method === "POST" && action === "start") {
      const token = generateToken();
      const tokenHash = await hashToken(token);

      const { error } = await supabase.from("game_sessions").insert({
        token_hash: tokenHash,
      });

      if (error) throw error;

      return new Response(JSON.stringify({ token }), {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    // ─── POST: Submit score ───
    if (req.method === "POST" && action === "submit") {
      const body = await req.json();
      const { token, username, score } = body;

      // --- Input validation ---
      if (!token || typeof token !== "string") {
        return new Response(JSON.stringify({ error: "Missing token" }), {
          status: 400,
          headers: { ...cors, "Content-Type": "application/json" },
        });
      }

      if (
        !username ||
        typeof username !== "string" ||
        username.trim().length < 1 ||
        username.trim().length > 24
      ) {
        return new Response(
          JSON.stringify({ error: "Username must be 1-24 characters" }),
          { status: 400, headers: { ...cors, "Content-Type": "application/json" } }
        );
      }

      if (
        typeof score !== "number" ||
        !Number.isInteger(score) ||
        score < 0 ||
        score > MAX_REASONABLE_SCORE
      ) {
        return new Response(
          JSON.stringify({ error: "Invalid score" }),
          { status: 400, headers: { ...cors, "Content-Type": "application/json" } }
        );
      }

      // --- Look up the session ---
      const tokenHash = await hashToken(token);
      const { data: session, error: fetchErr } = await supabase
        .from("game_sessions")
        .select("*")
        .eq("token_hash", tokenHash)
        .single();

      if (fetchErr || !session) {
        return new Response(JSON.stringify({ error: "Invalid session" }), {
          status: 403,
          headers: { ...cors, "Content-Type": "application/json" },
        });
      }

      // Already submitted?
      if (session.submitted_at) {
        return new Response(
          JSON.stringify({ error: "Score already submitted for this session" }),
          { status: 409, headers: { ...cors, "Content-Type": "application/json" } }
        );
      }

      // Expired?
      if (new Date(session.expires_at) < new Date()) {
        return new Response(JSON.stringify({ error: "Session expired" }), {
          status: 410,
          headers: { ...cors, "Content-Type": "application/json" },
        });
      }

      // Plausibility: was the game long enough?
      const elapsedMs =
        new Date().getTime() - new Date(session.started_at).getTime();
      if (elapsedMs < MIN_GAME_DURATION_MS) {
        return new Response(
          JSON.stringify({ error: "Game too short to be real" }),
          { status: 400, headers: { ...cors, "Content-Type": "application/json" } }
        );
      }

      // --- All checks passed — record the score ---
      const { error: updateErr } = await supabase
        .from("game_sessions")
        .update({
          username: username.trim(),
          score,
          submitted_at: new Date().toISOString(),
        })
        .eq("id", session.id);

      if (updateErr) throw updateErr;

      return new Response(JSON.stringify({ success: true }), {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404,
      headers: { ...cors, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error(err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { ...cors, "Content-Type": "application/json" } }
    );
  }
});
