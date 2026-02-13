// supabase/functions/create-user/index.ts
// =============================================
// Secure User Creation Edge Function v2
// =============================================

import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const rateLimits = new Map<string, { count: number; window: number }>();
const RATE_LIMIT = 10;
const RATE_WINDOW = 3600000;

function checkRateLimit(callerId: string): boolean {
  const now = Date.now();
  const entry = rateLimits.get(callerId);
  if (!entry || now - entry.window > RATE_WINDOW) {
    rateLimits.set(callerId, { count: 1, window: now });
    return true;
  }
  if (entry.count >= RATE_LIMIT) return false;
  entry.count++;
  return true;
}

function sanitize(str: string, maxLen = 200): string {
  return str.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/javascript:/gi, "").replace(/on\w+\s*=/gi, "").trim().slice(0, maxLen);
}

function isValidEmail(email: string): boolean {
  return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email);
}

function validatePassword(pw: string): { valid: boolean; error?: string } {
  if (!pw || pw.length < 12) return { valid: false, error: "Password must be at least 12 characters" };
  if (!/[A-Z]/.test(pw)) return { valid: false, error: "Must contain an uppercase letter" };
  if (!/[a-z]/.test(pw)) return { valid: false, error: "Must contain a lowercase letter" };
  if (!/[0-9]/.test(pw)) return { valid: false, error: "Must contain a number" };
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pw)) return { valid: false, error: "Must contain a special character" };
  if (/^(.)\1+$/.test(pw)) return { valid: false, error: "Cannot be all the same character" };
  return { valid: true };
}

const ROLE_LEVELS: Record<string, number> = {
  super_admin: 0, employee: 1, client_admin: 2, client_user: 3, client_employee: 4,
};

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const fail = (msg: string, status: number) => new Response(
    JSON.stringify({ error: msg }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) return fail("Missing authorization", 401);

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const serviceRoleKey = Deno.env.get("SERVICE_ROLE_KEY")!;

    const callerClient = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    const { data: { user: caller }, error: authError } = await callerClient.auth.getUser();
    if (authError || !caller) return fail("Invalid token", 401);

    if (!checkRateLimit(caller.id)) return fail("Rate limit exceeded. Try again later.", 429);

    const { data: callerRoles } = await callerClient
      .from("user_org_roles")
      .select("role, org_id, status")
      .eq("user_id", caller.id)
      .eq("status", "active");

    const callerRole = callerRoles?.[0];
    if (!callerRole) return fail("No active role assigned", 403);

    const body = await req.json();
    const email = (body.email || "").toLowerCase().trim();
    const password = body.password || "";
    const name = sanitize(body.name || "");
    const role = body.role || "";
    const org_id = body.org_id || null;

    if (!email || !password || !name || !role) return fail("Missing required fields", 400);
    if (!isValidEmail(email)) return fail("Invalid email format", 400);
    if (!(role in ROLE_LEVELS)) return fail("Invalid role", 400);

    const pwCheck = validatePassword(password);
    if (!pwCheck.valid) return fail(pwCheck.error!, 400);

    // Role hierarchy: can only create strictly below (except super_admin→employee)
    const callerLevel = ROLE_LEVELS[callerRole.role] ?? 99;
    const targetLevel = ROLE_LEVELS[role] ?? 99;

    const isAllowed = (
      (callerRole.role === "super_admin") ||
      (callerRole.role === "employee" && targetLevel > callerLevel) ||
      (callerRole.role === "client_admin" && ["client_user", "client_employee"].includes(role))
    );
    if (!isAllowed) return fail(`Cannot create role: ${role}`, 403);

    if (callerRole.role === "client_admin" && org_id !== callerRole.org_id) {
      return fail("Can only create users in your own organization", 403);
    }

    // Create with service_role (server-side only)
    const adminClient = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: newUser, error: createError } = await adminClient.auth.admin.createUser({
      email, password, email_confirm: true,
    });

    if (createError) {
      const msg = createError.message?.includes("already been registered")
        ? "This email is already registered" : "Account creation failed";

      await adminClient.from("audit_log").insert({
        user_id: caller.id, user_email: caller.email, action: "create_user",
        resource_type: "user", org_id: org_id || "platform",
        details: { target_email: email, target_role: role, error: msg },
        severity: "warning", success: false,
      });

      return fail(msg, 400);
    }

    const { error: roleError } = await adminClient.from("user_org_roles").insert({
      user_id: newUser.user.id, email, name, role,
      org_id: ["super_admin", "employee"].includes(role) ? null : org_id,
      created_by: caller.email,
      must_change_password: true,
    });

    if (roleError) {
      await adminClient.auth.admin.deleteUser(newUser.user.id);
      return fail("Failed to assign role", 500);
    }

    await adminClient.from("audit_log").insert({
      user_id: caller.id, user_email: caller.email, action: "create_user",
      resource_type: "user", resource_id: newUser.user.id,
      org_id: org_id || "platform",
      details: { target_email: email, target_role: role, created_by: caller.email },
      severity: "critical", success: true,
    });

    return new Response(JSON.stringify({
      user: { id: newUser.user.id, email: newUser.user.email },
      message: "User created successfully",
    }), {
      status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (err) {
    console.error("Edge function error:", err);
    return fail("Internal server error", 500);
  }
});
