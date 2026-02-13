// Netlify Function: Create employee via Supabase Admin API (no email invite sent)
// Requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY env vars in Netlify

export default async (req) => {
  // CORS headers
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Content-Type": "application/json",
  };

  if (req.method === "OPTIONS") {
    return new Response("", { status: 200, headers });
  }

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers });
  }

  try {
    const { email, password, name, role, orgId, callerToken } = await req.json();

    if (!email || !password || !name || !role) {
      return new Response(JSON.stringify({ error: "Missing required fields: email, password, name, role" }), { status: 400, headers });
    }

    const SUPABASE_URL = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL;
    const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
      return new Response(JSON.stringify({ error: "Server configuration error: missing Supabase credentials" }), { status: 500, headers });
    }

    // Verify caller is authenticated by checking their token against Supabase
    if (callerToken) {
      const verifyRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
        headers: { Authorization: `Bearer ${callerToken}`, apikey: SERVICE_ROLE_KEY },
      });
      if (!verifyRes.ok) {
        return new Response(JSON.stringify({ error: "Unauthorized: invalid caller token" }), { status: 401, headers });
      }
    }

    // Create user via Supabase Admin API — this does NOT send any confirmation/invite email
    const createRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
        apikey: SERVICE_ROLE_KEY,
      },
      body: JSON.stringify({
        email: email.toLowerCase().trim(),
        password,
        email_confirm: true,  // Auto-confirm — no verification email sent
        user_metadata: { name: name.trim(), role },
      }),
    });

    const createData = await createRes.json();

    if (!createRes.ok) {
      const msg = createData.msg || createData.error_description || createData.message || createData.error || "";
      if (msg.includes("already") || msg.includes("exists")) {
        return new Response(JSON.stringify({ error: "This email is already registered. Use a different email." }), { status: 409, headers });
      }
      return new Response(JSON.stringify({ error: msg || `Account creation failed (HTTP ${createRes.status})` }), { status: createRes.status, headers });
    }

    const userId = createData.id || createData.user?.id;
    if (!userId) {
      return new Response(JSON.stringify({ error: "Account created but no user ID returned" }), { status: 500, headers });
    }

    // Insert into user_org_roles using service role key
    const ANON_KEY = process.env.VITE_SUPABASE_KEY || process.env.SUPABASE_ANON_KEY;
    const roleRes = await fetch(`${SUPABASE_URL}/rest/v1/user_org_roles`, {
      method: "POST",
      headers: {
        apikey: ANON_KEY || SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
        "Content-Type": "application/json",
        Prefer: "return=minimal",
      },
      body: JSON.stringify({
        user_id: userId,
        email: email.toLowerCase().trim(),
        name: name.trim(),
        role,
        org_id: ["super_admin", "employee"].includes(role) ? null : orgId,
        created_by: "platform",
        status: "active",
        must_change_password: true,
      }),
    });

    if (!roleRes.ok) {
      console.warn("Role insert failed — user created but role not assigned.");
    }

    return new Response(JSON.stringify({ id: userId, email: email.toLowerCase().trim() }), { status: 200, headers });
  } catch (err) {
    console.error("create-employee error:", err);
    return new Response(JSON.stringify({ error: err.message || "Internal server error" }), { status: 500, headers });
  }
};
